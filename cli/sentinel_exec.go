package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/breakglass"
	sentinelerrors "github.com/byteness/aws-vault/v7/errors"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/sso"
	"github.com/byteness/aws-vault/v7/vault"
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
	LogFile         string           // Path to log file (empty = no file logging)
	LogStderr       bool             // Log to stderr (default: false)
	Store           request.Store    // Optional: for approved request checking (nil = no checking)
	BreakGlassStore breakglass.Store // Optional: for break-glass checking (nil = no checking)
	STSClient       identity.STSAPI  // Optional: for testing (nil = create from AWS config)
	AutoLogin       bool             // Enable automatic SSO login on credential errors
	UseStdout       bool             // Print SSO URL instead of opening browser (for --auto-login)
	ConfigFile      *vault.ConfigFile // Optional: for auto-login SSO config lookup (nil = load from env)
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

	cmd.Flag("auto-login", "Automatically trigger SSO login when credentials are expired or missing").
		BoolVar(&input.AutoLogin)

	cmd.Flag("stdout", "Print SSO URL instead of opening browser (used with --auto-login)").
		BoolVar(&input.UseStdout)

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

	// 0.6. Load AWS config file for auto-login SSO lookup (if needed)
	configFile := input.ConfigFile
	if input.AutoLogin && configFile == nil {
		var loadErr error
		configFile, loadErr = vault.LoadConfigFromEnv()
		if loadErr != nil {
			log.Printf("Warning: failed to load AWS config file for auto-login: %v", loadErr)
			// Continue without auto-login capability
		}
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

	// 2. Create AWS config for SSM and STS
	// Include profile to enable SSO credential loading from the specified profile
	awsCfgOpts := []func(*config.LoadOptions) error{
		config.WithSharedConfigProfile(input.ProfileName),
	}
	if input.Region != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
	if err != nil {
		configErr := sentinelerrors.New(
			sentinelerrors.ErrCodeConfigMissingCredentials,
			fmt.Sprintf("Failed to load AWS config: %v", err),
			sentinelerrors.GetSuggestion(sentinelerrors.ErrCodeConfigMissingCredentials),
			err,
		)
		FormatErrorWithSuggestion(configErr)
		return 1, configErr
	}

	// 3. Get AWS identity for policy evaluation (with optional auto-login retry)
	stsClient := input.STSClient
	if stsClient == nil {
		stsClient = sts.NewFromConfig(awsCfg)
	}

	var username string
	if input.AutoLogin && configFile != nil {
		// Wrap identity retrieval with auto-login retry for SSO errors
		autoConfig := sso.AutoLoginConfig{
			ProfileName: input.ProfileName,
			ConfigFile:  configFile,
			Keyring:     nil, // Keyring managed by AWS SDK
			UseStdout:   input.UseStdout,
			Stderr:      os.Stderr,
		}
		username, err = sso.WithAutoLogin(ctx, autoConfig, func() (string, error) {
			return identity.GetAWSUsername(ctx, stsClient)
		})
	} else {
		username, err = identity.GetAWSUsername(ctx, stsClient)
	}

	if err != nil {
		identityErr := sentinelerrors.New(
			sentinelerrors.ErrCodeSTSError,
			fmt.Sprintf("Failed to get AWS identity: %v", err),
			"Ensure your AWS credentials are valid and have sts:GetCallerIdentity permission",
			err,
		)
		FormatErrorWithSuggestion(identityErr)
		return 1, identityErr
	}

	// 4. Create policy loader chain
	loader := policy.NewLoader(awsCfg)
	cachedLoader := policy.NewCachedLoader(loader, 5*time.Minute)

	// 5. Load policy
	loadedPolicy, err := cachedLoader.Load(ctx, input.PolicyParameter)
	if err != nil {
		FormatErrorWithSuggestion(err)
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

	// 8. Handle deny decision - check for approved request or break-glass first
	var approvedReq *request.Request
	var activeBreakGlass *breakglass.BreakGlassEvent
	if decision.Effect == policy.EffectDeny {
		// Check for approved request before denying
		if input.Store != nil {
			var storeErr error
			approvedReq, storeErr = request.FindApprovedRequest(ctx, input.Store, username, input.ProfileName)
			if storeErr != nil {
				// Log store error but don't fail - fall through to deny
				log.Printf("Warning: failed to check approved requests: %v", storeErr)
			}
		}

		// If no approved request, check for active break-glass
		if approvedReq == nil && input.BreakGlassStore != nil {
			var bgErr error
			activeBreakGlass, bgErr = breakglass.FindActiveBreakGlass(ctx, input.BreakGlassStore, username, input.ProfileName)
			if bgErr != nil {
				log.Printf("Warning: failed to check break-glass: %v", bgErr)
			}
		}

		if approvedReq == nil && activeBreakGlass == nil {
			// No approved request and no active break-glass - proceed with deny
			if logger != nil {
				entry := logging.NewDecisionLogEntry(policyRequest, decision, input.PolicyParameter)
				logger.LogDecision(entry)
			}
			// Create structured error with context
			var matchedRule *sentinelerrors.PolicyRule
			if decision.MatchedRule != "" {
				matchedRule = &sentinelerrors.PolicyRule{
					Name:        decision.MatchedRule,
					Effect:      string(decision.Effect),
					Description: decision.Reason,
				}
			}
			policyErr := sentinelerrors.NewPolicyDeniedError(
				username,
				input.ProfileName,
				matchedRule,
				input.Store != nil,           // hasApprovalWorkflow
				input.BreakGlassStore != nil, // hasBreakGlass
			)
			FormatErrorWithSuggestion(policyErr)
			return 1, policyErr
		}
		// Approved request or active break-glass found - continue to credential issuance
	}

	// 8.5. Cap session duration to remaining break-glass time if applicable
	sessionDuration := input.SessionDuration
	if activeBreakGlass != nil {
		remainingTime := breakglass.RemainingDuration(activeBreakGlass)
		if sessionDuration == 0 || sessionDuration > remainingTime {
			sessionDuration = remainingTime
			log.Printf("Capping session duration to break-glass remaining time: %v", remainingTime)
		}
	}

	// 9. EffectAllow (or approved request): generate request-id and retrieve credentials
	requestID := identity.NewRequestID()

	// Create credential request with User for SourceIdentity stamping
	credReq := SentinelCredentialRequest{
		ProfileName:     input.ProfileName,
		Region:          input.Region,
		NoSession:       input.NoSession,
		SessionDuration: sessionDuration, // May be capped to break-glass remaining time
		User:            username,         // For SourceIdentity stamping on role assumption
		RequestID:       requestID,        // For CloudTrail correlation
	}

	// Retrieve credentials with SourceIdentity stamping (if profile has role_arn)
	creds, err := s.GetCredentialsWithSourceIdentity(ctx, credReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to retrieve credentials: %v\n", err)
		return 1, err
	}

	// 10. Log allow decision with credential context
	if logger != nil {
		credFields := &logging.CredentialIssuanceFields{
			RequestID:       requestID,
			SourceIdentity:  creds.SourceIdentity,
			RoleARN:         creds.RoleARN,
			SessionDuration: sessionDuration, // May be capped to break-glass remaining time
		}
		// Include approved request ID if credentials were issued via approval override
		if approvedReq != nil {
			credFields.ApprovedRequestID = approvedReq.ID
		}
		// Include break-glass event ID if credentials were issued via break-glass override
		if activeBreakGlass != nil {
			credFields.BreakGlassEventID = activeBreakGlass.ID
		}
		entry := logging.NewEnhancedDecisionLogEntry(policyRequest, decision, input.PolicyParameter, credFields)
		logger.LogDecision(entry)
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
