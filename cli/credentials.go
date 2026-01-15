package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// CredentialsCommandInput contains the input for the credentials command.
type CredentialsCommandInput struct {
	ProfileName     string
	PolicyParameter string // SSM parameter path, e.g., /sentinel/policies/default
	Region          string
	NoSession       bool
	SessionDuration time.Duration
	Logger          logging.Logger   // nil means no logging
	LogFile         string           // Path to log file (empty = no file logging)
	LogStderr       bool             // Log to stderr (default: false)
	Store           request.Store    // Optional: for approved request checking (nil = no checking)
	BreakGlassStore breakglass.Store // Optional: for break-glass checking (nil = no checking)
}

// CredentialProcessOutput represents the JSON output format for AWS credential_process.
// See https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
type CredentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

// ConfigureCredentialsCommand sets up the credentials command with kingpin.
func ConfigureCredentialsCommand(app *kingpin.Application, s *Sentinel) {
	input := CredentialsCommandInput{}

	cmd := app.Command("credentials", "Retrieve AWS credentials after policy evaluation")

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

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := CredentialsCommand(context.Background(), input, s)
		app.FatalIfError(err, "credentials")
		return nil
	})
}

// CredentialsCommand executes the credentials command logic.
// It evaluates policy before retrieving credentials.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns non-zero.
func CredentialsCommand(ctx context.Context, input CredentialsCommandInput, s *Sentinel) error {
	// 0. Create logger based on configuration
	if input.LogFile != "" || input.LogStderr {
		writers := []io.Writer{}
		if input.LogStderr {
			writers = append(writers, os.Stderr)
		}
		if input.LogFile != "" {
			f, err := os.OpenFile(input.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
				return err
			}
			defer f.Close()
			writers = append(writers, f)
		}
		input.Logger = logging.NewJSONLogger(io.MultiWriter(writers...))
	}

	// 1. Get current user
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current user: %v\n", err)
		return err
	}
	username := currentUser.Username

	// 1.5. Validate profile exists in AWS config
	if err := s.ValidateProfile(input.ProfileName); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return err
	}

	// 2. Create AWS config for SSM
	awsCfgOpts := []func(*config.LoadOptions) error{}
	if input.Region != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load AWS config: %v\n", err)
		return err
	}

	// 3. Create policy loader chain
	loader := policy.NewLoader(awsCfg)
	cachedLoader := policy.NewCachedLoader(loader, 5*time.Minute)

	// 4. Load policy
	loadedPolicy, err := cachedLoader.Load(ctx, input.PolicyParameter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		return err
	}

	// 5. Build policy.Request
	policyRequest := &policy.Request{
		User:    username,
		Profile: input.ProfileName,
		Time:    time.Now(),
	}

	// 6. Evaluate policy
	decision := policy.Evaluate(loadedPolicy, policyRequest)

	// 7. Handle deny decision - check for approved request or break-glass first
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
			if input.Logger != nil {
				entry := logging.NewDecisionLogEntry(policyRequest, decision, input.PolicyParameter)
				input.Logger.LogDecision(entry)
			}
			fmt.Fprintf(os.Stderr, "Access denied: %s\n", decision.String())
			return fmt.Errorf("access denied")
		}
		// Approved request or active break-glass found - continue to credential issuance
	}

	// 7.5. Cap session duration to remaining break-glass time if applicable
	sessionDuration := input.SessionDuration
	if activeBreakGlass != nil {
		remainingTime := breakglass.RemainingDuration(activeBreakGlass)
		if sessionDuration == 0 || sessionDuration > remainingTime {
			sessionDuration = remainingTime
			log.Printf("Capping session duration to break-glass remaining time: %v", remainingTime)
		}
	}

	// 8. EffectAllow (or approved request): generate request-id and retrieve credentials
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
		return err
	}

	// 9. Log allow decision with credential context for CloudTrail correlation
	if input.Logger != nil {
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
		input.Logger.LogDecision(entry)
	}

	// Build credential_process output
	output := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
	}

	// Only include Expiration if credentials can expire
	if creds.CanExpire {
		output.Expiration = iso8601.Format(creds.Expiration)
	}

	// Marshal to JSON with indentation (matches cli/export.go pattern)
	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal credentials to JSON: %v\n", err)
		return err
	}

	// Output to stdout
	fmt.Println(string(jsonBytes))

	return nil
}
