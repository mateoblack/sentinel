package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
)

// SentinelExecCommandInput contains the input for the sentinel exec command.
type SentinelExecCommandInput struct {
	ProfileName     string
	PolicyParameter string // SSM parameter path, e.g., /sentinel/policies/default
	Command         string
	Args            []string
	Region          string
	NoSession       bool
	SessionDuration time.Duration
	LogFile         string // Path to log file (empty = no file logging)
	LogStderr       bool   // Log to stderr (default: false)
}

// ConfigureSentinelExecCommand sets up the sentinel exec command with kingpin.
func ConfigureSentinelExecCommand(app *kingpin.Application, s *Sentinel) {
	input := SentinelExecCommandInput{}

	cmd := app.Command("exec", "Execute a command with policy-gated AWS credentials")

	cmd.Flag("profile", "Name of the AWS profile").
		Required().
		StringVar(&input.ProfileName)

	cmd.Flag("policy-parameter", "SSM parameter path containing the policy (e.g., /sentinel/policies/default)").
		Required().
		StringVar(&input.PolicyParameter)

	cmd.Flag("region", "The AWS region").
		StringVar(&input.Region)

	cmd.Flag("no-session", "Skip creating STS session with GetSessionToken").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Flag("duration", "Duration of the temporary or assume-role session. Defaults to 1h").
		Short('d').
		DurationVar(&input.SessionDuration)

	cmd.Flag("log-file", "Path to write decision logs (JSON Lines format)").
		StringVar(&input.LogFile)

	cmd.Flag("log-stderr", "Write decision logs to stderr").
		BoolVar(&input.LogStderr)

	cmd.Arg("cmd", "Command to execute, defaults to $SHELL").
		StringVar(&input.Command)

	cmd.Arg("args", "Command arguments").
		StringsVar(&input.Args)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitcode, err := SentinelExecCommand(context.Background(), input, s)
		app.FatalIfError(err, "exec")
		if exitcode != 0 {
			os.Exit(exitcode)
		}
		return nil
	})
}

// SentinelExecCommand executes the sentinel exec command logic.
// It evaluates policy before spawning a subprocess with credentials.
// Returns exit code and error.
func SentinelExecCommand(ctx context.Context, input SentinelExecCommandInput, s *Sentinel) (int, error) {
	// 0. Check if already in a sentinel subshell
	if os.Getenv("AWS_SENTINEL") != "" {
		return 0, fmt.Errorf("running in an existing sentinel subshell; 'exit' from the subshell or unset AWS_SENTINEL to force")
	}

	// 0.5. Validate profile exists in AWS config
	if err := s.ValidateProfile(input.ProfileName); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1, err
	}

	// 1. Create logger based on configuration
	var logger logging.Logger
	if input.LogFile != "" || input.LogStderr {
		writers := []io.Writer{}
		if input.LogStderr {
			writers = append(writers, os.Stderr)
		}
		if input.LogFile != "" {
			f, err := os.OpenFile(input.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
				return 1, err
			}
			defer f.Close()
			writers = append(writers, f)
		}
		logger = logging.NewJSONLogger(io.MultiWriter(writers...))
	}

	// 2. Get current user
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current user: %v\n", err)
		return 1, err
	}
	username := currentUser.Username

	// 3. Create AWS config for SSM
	awsCfgOpts := []func(*config.LoadOptions) error{}
	if input.Region != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load AWS config: %v\n", err)
		return 1, err
	}

	// 4. Create policy loader chain
	loader := policy.NewLoader(awsCfg)
	cachedLoader := policy.NewCachedLoader(loader, 5*time.Minute)

	// 5. Load policy
	loadedPolicy, err := cachedLoader.Load(ctx, input.PolicyParameter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		return 1, err
	}

	// 6. Build policy.Request
	policyRequest := &policy.Request{
		User:    username,
		Profile: input.ProfileName,
		Time:    time.Now(),
	}

	// 7. Evaluate policy
	decision := policy.Evaluate(loadedPolicy, policyRequest)

	// 8. Log decision (before handling, so both allow and deny are logged)
	if logger != nil {
		entry := logging.NewDecisionLogEntry(policyRequest, decision, input.PolicyParameter)
		logger.LogDecision(entry)
	}

	// 9. Handle decision
	if decision.Effect == policy.EffectDeny {
		fmt.Fprintf(os.Stderr, "Access denied: %s\n", decision.String())
		return 1, fmt.Errorf("access denied: %s", decision.String())
	}

	// 10. EffectAllow: proceed to credential retrieval
	credReq := SentinelCredentialRequest{
		ProfileName:     input.ProfileName,
		Region:          input.Region,
		NoSession:       input.NoSession,
		SessionDuration: input.SessionDuration,
	}

	creds, err := s.GetCredentials(ctx, credReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to retrieve credentials: %v\n", err)
		return 1, err
	}

	// 11. Default to shell if no command specified
	command := input.Command
	if command == "" {
		command = getDefaultShell()
	}

	// 12. Prepare subprocess environment
	cmdEnv := createEnv(input.ProfileName, input.Region, "")

	// 13. Set AWS_SENTINEL to indicate running in sentinel subshell
	cmdEnv.Set("AWS_SENTINEL", input.ProfileName)

	// 14. Inject credentials into environment
	log.Println("Setting subprocess env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
	cmdEnv.Set("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	cmdEnv.Set("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	if creds.SessionToken != "" {
		log.Println("Setting subprocess env: AWS_SESSION_TOKEN")
		cmdEnv.Set("AWS_SESSION_TOKEN", creds.SessionToken)
	}
	if creds.CanExpire {
		log.Println("Setting subprocess env: AWS_CREDENTIAL_EXPIRATION")
		cmdEnv.Set("AWS_CREDENTIAL_EXPIRATION", iso8601.Format(creds.Expiration))
	}

	// 15. Try exec syscall first (replaces process, more efficient)
	err = doExecSyscall(command, input.Args, cmdEnv)
	if err != nil {
		log.Println("Error doing execve syscall:", err.Error())
		log.Println("Falling back to running a subprocess")
	}

	// 16. Fall back to subprocess execution
	return runSubProcess(command, input.Args, cmdEnv)
}
