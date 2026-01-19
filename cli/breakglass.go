package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/notification"
)

// BreakGlassCommandInput contains the input for the breakglass command.
type BreakGlassCommandInput struct {
	ProfileName     string
	Duration        time.Duration
	ReasonCode      string
	Justification   string
	BreakGlassTable string
	Region          string

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the BreakGlassTable and Region.
	Store breakglass.Store

	// Notifier is an optional BreakGlassNotifier for sending notifications on break-glass invocation.
	// If nil, no notifications are sent. Notification errors are logged but don't fail the command.
	Notifier notification.BreakGlassNotifier

	// Logger is an optional Logger for audit trail logging.
	// If nil, no break-glass events are logged.
	Logger logging.Logger

	// RateLimitPolicy is an optional policy for rate limiting break-glass invocations.
	// If nil, no rate limiting is enforced.
	RateLimitPolicy *breakglass.RateLimitPolicy

	// BreakGlassPolicy is an optional policy for authorization control.
	// If nil, any user can invoke break-glass (no policy enforcement).
	BreakGlassPolicy *breakglass.BreakGlassPolicy

	// STSClient is an optional STS client for AWS identity extraction.
	// If nil, a new client will be created from AWS config.
	STSClient identity.STSAPI
}

// BreakGlassCommandOutput represents the JSON output from the breakglass command.
type BreakGlassCommandOutput struct {
	EventID    string    `json:"event_id"`
	Profile    string    `json:"profile"`
	ReasonCode string    `json:"reason_code"`
	Status     string    `json:"status"`
	ExpiresAt  time.Time `json:"expires_at"`
	RequestID  string    `json:"request_id,omitempty"`
}

// ConfigureBreakGlassCommand sets up the breakglass command with kingpin.
func ConfigureBreakGlassCommand(app *kingpin.Application, s *Sentinel) {
	input := BreakGlassCommandInput{}

	cmd := app.Command("breakglass", "Invoke emergency break-glass access")

	cmd.Flag("profile", "AWS profile to invoke break-glass access for").
		Required().
		StringVar(&input.ProfileName)

	cmd.Flag("duration", "How long emergency access is needed (max 4h)").
		Default("1h").
		DurationVar(&input.Duration)

	cmd.Flag("reason-code", "Reason for break-glass (incident, maintenance, security, recovery, other)").
		Required().
		StringVar(&input.ReasonCode)

	cmd.Flag("justification", "Detailed explanation for emergency access (20-1000 chars)").
		Required().
		StringVar(&input.Justification)

	cmd.Flag("breakglass-table", "DynamoDB table name for break-glass events").
		Required().
		StringVar(&input.BreakGlassTable)

	cmd.Flag("region", "AWS region for DynamoDB").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := BreakGlassCommand(context.Background(), input, s)
		app.FatalIfError(err, "breakglass")
		return nil
	})
}

// BreakGlassCommand executes the breakglass command logic.
// It creates a break-glass emergency access event and stores it in DynamoDB.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns error.
func BreakGlassCommand(ctx context.Context, input BreakGlassCommandInput, s *Sentinel) error {
	// 1. Validate profile exists in AWS config
	if err := s.ValidateProfile(input.ProfileName); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return err
	}

	// 2. Load AWS config (needed for STS and DynamoDB)
	awsCfgOpts := []func(*config.LoadOptions) error{}
	if input.Region != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load AWS config: %v\n", err)
		return err
	}

	// 3. Get AWS identity for invoker
	stsClient := input.STSClient
	if stsClient == nil {
		stsClient = sts.NewFromConfig(awsCfg)
	}
	username, err := identity.GetAWSUsername(ctx, stsClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get AWS identity: %v\n", err)
		return err
	}

	// 4. Parse and validate reason code
	reasonCode := breakglass.ReasonCode(input.ReasonCode)
	if !reasonCode.IsValid() {
		errMsg := fmt.Sprintf("Invalid reason code: %q (must be one of: incident, maintenance, security, recovery, other)", input.ReasonCode)
		fmt.Fprintf(os.Stderr, "%s\n", errMsg)
		return errors.New(errMsg)
	}

	// 4.5 Check break-glass policy authorization if policy is provided
	if input.BreakGlassPolicy != nil {
		rule := breakglass.FindBreakGlassPolicyRule(input.BreakGlassPolicy, input.ProfileName)
		if rule == nil {
			// Policy exists but no rule matches - deny access
			errMsg := fmt.Sprintf("No break-glass policy rule matches profile %q", input.ProfileName)
			fmt.Fprintf(os.Stderr, "%s\n", errMsg)
			return errors.New(errMsg)
		}

		// Check full authorization (user, reason code, time window, duration)
		if !breakglass.IsBreakGlassAllowed(rule, username, reasonCode, time.Now(), input.Duration) {
			// Determine specific reason for denial
			if !breakglass.CanInvokeBreakGlass(rule, username) {
				errMsg := fmt.Sprintf("Not authorized to invoke break-glass for profile %q", input.ProfileName)
				fmt.Fprintf(os.Stderr, "%s\n", errMsg)
				return errors.New(errMsg)
			}
			// Check reason code (empty = all allowed)
			if len(rule.AllowedReasonCodes) > 0 {
				found := false
				for _, rc := range rule.AllowedReasonCodes {
					if rc == reasonCode {
						found = true
						break
					}
				}
				if !found {
					errMsg := fmt.Sprintf("Reason code %q not allowed for this profile", input.ReasonCode)
					fmt.Fprintf(os.Stderr, "%s\n", errMsg)
					return errors.New(errMsg)
				}
			}
			// Check time window
			if rule.Time != nil {
				errMsg := "Break-glass not allowed at this time"
				fmt.Fprintf(os.Stderr, "%s\n", errMsg)
				return errors.New(errMsg)
			}
			// Check duration cap
			if rule.MaxDuration > 0 && input.Duration > rule.MaxDuration {
				errMsg := fmt.Sprintf("Duration %v exceeds maximum allowed %v for this profile", input.Duration, rule.MaxDuration)
				fmt.Fprintf(os.Stderr, "%s\n", errMsg)
				return errors.New(errMsg)
			}
		}
	}

	// 5. Cap duration at MaxDuration (4h)
	duration := input.Duration
	if duration > breakglass.MaxDuration {
		fmt.Fprintf(os.Stderr, "Warning: duration %v exceeds maximum, capping at %v\n", duration, breakglass.MaxDuration)
		duration = breakglass.MaxDuration
	}

	// 6. Get or create store
	store := input.Store
	if store == nil {
		// Create DynamoDB store using already-loaded AWS config
		store = breakglass.NewDynamoDBStore(awsCfg, input.BreakGlassTable)
	}

	// 7. Check for existing active break-glass for same user+profile
	existingEvent, err := store.FindActiveByInvokerAndProfile(ctx, username, input.ProfileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to check for active break-glass: %v\n", err)
		return err
	}
	if existingEvent != nil {
		errMsg := fmt.Sprintf("Active break-glass already exists for this profile (event_id: %s, expires: %s)",
			existingEvent.ID, existingEvent.ExpiresAt.Format(time.RFC3339))
		fmt.Fprintf(os.Stderr, "%s\n", errMsg)
		return errors.New("active break-glass already exists for this profile")
	}

	// 7.5 Check rate limits if policy is provided
	if input.RateLimitPolicy != nil {
		result, err := breakglass.CheckRateLimit(ctx, store, input.RateLimitPolicy, username, input.ProfileName, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to check rate limits: %v\n", err)
			return err
		}
		if !result.Allowed {
			errMsg := fmt.Sprintf("Break-glass rate limited: %s", result.Reason)
			if result.RetryAfter > 0 {
				errMsg += fmt.Sprintf(" (retry after %v)", result.RetryAfter.Round(time.Second))
			}
			fmt.Fprintf(os.Stderr, "%s\n", errMsg)
			return errors.New("rate limit exceeded")
		}
		// If escalation threshold reached, emit warning (notification handled elsewhere)
		if result.ShouldEscalate {
			fmt.Fprintf(os.Stderr, "Warning: break-glass usage approaching escalation threshold\n")
		}
	}

	// 8. Build BreakGlassEvent struct
	now := time.Now()
	requestID := breakglass.NewBreakGlassID() // Generate unique request ID for CloudTrail correlation
	event := &breakglass.BreakGlassEvent{
		ID:            breakglass.NewBreakGlassID(),
		Invoker:       username,
		Profile:       input.ProfileName,
		ReasonCode:    reasonCode,
		Justification: input.Justification,
		Duration:      duration,
		Status:        breakglass.StatusActive, // Break-glass starts active immediately
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(duration),
		RequestID:     requestID,
	}

	// 9. Validate event
	if err := event.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid break-glass event: %v\n", err)
		return err
	}

	// 10. Store event
	if err := store.Create(ctx, event); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create break-glass event: %v\n", err)
		return err
	}

	// 11. Log break-glass invocation if Logger is provided
	if input.Logger != nil {
		entry := logging.NewBreakGlassLogEntry(logging.BreakGlassEventInvoked, event)
		input.Logger.LogBreakGlass(entry)
	}

	// 12. Fire notification if Notifier is provided
	// Notification errors are logged but don't fail the command (security alerts are best-effort)
	if input.Notifier != nil {
		bgEvent := notification.NewBreakGlassEvent(notification.EventBreakGlassInvoked, event, username)
		if err := input.Notifier.NotifyBreakGlass(ctx, bgEvent); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to send break-glass notification: %v\n", err)
		}
	}

	// 13. Output success JSON
	output := BreakGlassCommandOutput{
		EventID:    event.ID,
		Profile:    event.Profile,
		ReasonCode: string(event.ReasonCode),
		Status:     string(event.Status),
		ExpiresAt:  event.ExpiresAt,
		RequestID:  requestID,
	}

	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
		return err
	}

	fmt.Println(string(jsonBytes))

	return nil
}
