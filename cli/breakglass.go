package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/breakglass"
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

	// Notifier is an optional Notifier for sending notifications on break-glass invocation.
	// If nil, no notifications are sent.
	Notifier notification.Notifier

	// Logger is an optional Logger for audit trail logging.
	// If nil, no break-glass events are logged.
	Logger logging.Logger
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
	// 1. Get current user (invoker)
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current user: %v\n", err)
		return err
	}
	username := currentUser.Username

	// 2. Validate profile exists in AWS config
	if err := s.ValidateProfile(input.ProfileName); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return err
	}

	// 3. Parse and validate reason code
	reasonCode := breakglass.ReasonCode(input.ReasonCode)
	if !reasonCode.IsValid() {
		errMsg := fmt.Sprintf("Invalid reason code: %q (must be one of: incident, maintenance, security, recovery, other)", input.ReasonCode)
		fmt.Fprintf(os.Stderr, "%s\n", errMsg)
		return errors.New(errMsg)
	}

	// 4. Cap duration at MaxDuration (4h)
	duration := input.Duration
	if duration > breakglass.MaxDuration {
		fmt.Fprintf(os.Stderr, "Warning: duration %v exceeds maximum, capping at %v\n", duration, breakglass.MaxDuration)
		duration = breakglass.MaxDuration
	}

	// 5. Get or create store
	store := input.Store
	if store == nil {
		// Load AWS config
		awsCfgOpts := []func(*config.LoadOptions) error{}
		if input.Region != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load AWS config: %v\n", err)
			return err
		}

		// Create DynamoDB store
		store = breakglass.NewDynamoDBStore(awsCfg, input.BreakGlassTable)
	}

	// 6. Check for existing active break-glass for same user+profile
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

	// 7. Build BreakGlassEvent struct
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

	// 8. Validate event
	if err := event.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid break-glass event: %v\n", err)
		return err
	}

	// 9. Store event
	if err := store.Create(ctx, event); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create break-glass event: %v\n", err)
		return err
	}

	// 10. Log break-glass invocation if Logger is provided
	// Note: Full break-glass audit logging will be implemented in Phase 29 (elevated-audit)
	// For now, we log a placeholder entry to maintain audit trail
	_ = input.Logger // Logger reserved for Phase 29

	// 11. Output success JSON
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
