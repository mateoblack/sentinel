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

// BreakGlassCloseCommandInput contains the input for the breakglass-close command.
type BreakGlassCloseCommandInput struct {
	EventID         string
	Reason          string
	BreakGlassTable string
	Region          string

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the BreakGlassTable and Region.
	Store breakglass.Store

	// Notifier is an optional BreakGlassNotifier for sending notifications on close.
	// If nil, no notifications are sent. Notification errors are logged but don't fail the command.
	Notifier notification.BreakGlassNotifier

	// Logger is an optional Logger for audit trail logging.
	// If nil, no break-glass events are logged.
	Logger logging.Logger
}

// BreakGlassCloseCommandOutput represents the JSON output from the breakglass-close command.
type BreakGlassCloseCommandOutput struct {
	ID           string    `json:"id"`
	Profile      string    `json:"profile"`
	Status       string    `json:"status"`
	ClosedBy     string    `json:"closed_by"`
	ClosedReason string    `json:"closed_reason"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ConfigureBreakGlassCloseCommand sets up the breakglass-close command with kingpin.
func ConfigureBreakGlassCloseCommand(app *kingpin.Application, s *Sentinel) {
	input := BreakGlassCloseCommandInput{}

	cmd := app.Command("breakglass-close", "Close an active break-glass event")

	cmd.Arg("event-id", "The break-glass event ID to close").
		Required().
		StringVar(&input.EventID)

	cmd.Flag("reason", "Reason for closing the break-glass event early").
		Required().
		StringVar(&input.Reason)

	cmd.Flag("breakglass-table", "DynamoDB table name for break-glass events").
		Required().
		StringVar(&input.BreakGlassTable)

	cmd.Flag("region", "AWS region for DynamoDB").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := BreakGlassCloseCommand(context.Background(), input)
		app.FatalIfError(err, "breakglass-close")
		return nil
	})
}

// BreakGlassCloseCommand executes the breakglass-close command logic.
// It closes an active break-glass event, transitioning it to closed status.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns error.
func BreakGlassCloseCommand(ctx context.Context, input BreakGlassCloseCommandInput) error {
	// 1. Validate event ID format
	if !breakglass.ValidateBreakGlassID(input.EventID) {
		fmt.Fprintf(os.Stderr, "Invalid event ID: %s (must be 16 lowercase hex characters)\n", input.EventID)
		return errors.New("invalid event ID format")
	}

	// 2. Validate reason is non-empty (required for audit trail)
	if input.Reason == "" {
		fmt.Fprintf(os.Stderr, "Reason is required for closing break-glass events\n")
		return errors.New("reason is required")
	}

	// 3. Get current user as closer identity
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current user: %v\n", err)
		return err
	}
	closer := currentUser.Username

	// 4. Create or use provided Store
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

	// 5. Fetch event using store.Get()
	event, err := store.Get(ctx, input.EventID)
	if err != nil {
		if errors.Is(err, breakglass.ErrEventNotFound) {
			fmt.Fprintf(os.Stderr, "Break-glass event not found: %s\n", input.EventID)
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to get break-glass event: %v\n", err)
		return err
	}

	// 6. Check transition validity
	if !event.CanTransitionTo(breakglass.StatusClosed) {
		fmt.Fprintf(os.Stderr, "Cannot close event: current status is %s (only active events can be closed)\n", event.Status)
		return errors.New("invalid state transition")
	}

	// 7. Update event fields
	event.Status = breakglass.StatusClosed
	event.ClosedBy = closer
	event.ClosedReason = input.Reason
	event.UpdatedAt = time.Now()

	// 8. Store updated event
	if err := store.Update(ctx, event); err != nil {
		if errors.Is(err, breakglass.ErrConcurrentModification) {
			fmt.Fprintf(os.Stderr, "Event was modified by another process, please retry\n")
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to update break-glass event: %v\n", err)
		return err
	}

	// 9. Log break-glass close event if Logger is provided
	if input.Logger != nil {
		entry := logging.NewBreakGlassLogEntry(logging.BreakGlassEventClosed, event)
		input.Logger.LogBreakGlass(entry)
	}

	// 10. Fire notification if Notifier is provided (best-effort, errors logged but don't fail)
	if input.Notifier != nil {
		bgEvent := notification.NewBreakGlassEvent(notification.EventBreakGlassClosed, event, closer)
		if err := input.Notifier.NotifyBreakGlass(ctx, bgEvent); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to send close notification: %v\n", err)
		}
	}

	// 11. Output success JSON
	output := BreakGlassCloseCommandOutput{
		ID:           event.ID,
		Profile:      event.Profile,
		Status:       string(event.Status),
		ClosedBy:     event.ClosedBy,
		ClosedReason: event.ClosedReason,
		UpdatedAt:    event.UpdatedAt,
	}

	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
		return err
	}

	fmt.Println(string(jsonBytes))

	return nil
}
