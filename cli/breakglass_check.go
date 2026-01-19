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
	"github.com/byteness/aws-vault/v7/breakglass"
)

// BreakGlassCheckCommandInput contains the input for the breakglass-check command.
type BreakGlassCheckCommandInput struct {
	EventID         string
	BreakGlassTable string
	Region          string
	AWSProfile      string // Optional AWS profile for credentials

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the BreakGlassTable and Region.
	Store breakglass.Store
}

// BreakGlassCheckCommandOutput represents the JSON output from the breakglass-check command.
type BreakGlassCheckCommandOutput struct {
	ID            string    `json:"id"`
	Invoker       string    `json:"invoker"`
	Profile       string    `json:"profile"`
	ReasonCode    string    `json:"reason_code"`
	Justification string    `json:"justification"`
	Duration      string    `json:"duration"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	ClosedBy      string    `json:"closed_by,omitempty"`
	ClosedReason  string    `json:"closed_reason,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
}

// ConfigureBreakGlassCheckCommand sets up the breakglass-check command with kingpin.
func ConfigureBreakGlassCheckCommand(app *kingpin.Application, s *Sentinel) {
	input := BreakGlassCheckCommandInput{}

	cmd := app.Command("breakglass-check", "Check details of a break-glass event")

	cmd.Arg("event-id", "The break-glass event ID to check").
		Required().
		StringVar(&input.EventID)

	cmd.Flag("breakglass-table", "DynamoDB table name for break-glass events").
		Required().
		StringVar(&input.BreakGlassTable)

	cmd.Flag("region", "AWS region for DynamoDB").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := BreakGlassCheckCommand(context.Background(), input)
		app.FatalIfError(err, "breakglass-check")
		return nil
	})
}

// BreakGlassCheckCommand executes the breakglass-check command logic.
// It retrieves a specific break-glass event by ID from DynamoDB.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns error.
func BreakGlassCheckCommand(ctx context.Context, input BreakGlassCheckCommandInput) error {
	// 1. Validate event ID format
	if !breakglass.ValidateBreakGlassID(input.EventID) {
		fmt.Fprintf(os.Stderr, "Invalid event ID: %s (must be 16 lowercase hex characters)\n", input.EventID)
		return errors.New("invalid event ID format")
	}

	// 2. Get or create store
	store := input.Store
	if store == nil {
		// Load AWS config
		awsCfgOpts := []func(*config.LoadOptions) error{}
		if input.AWSProfile != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(input.AWSProfile))
		}
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

	// 3. Fetch event from store
	event, err := store.Get(ctx, input.EventID)
	if err != nil {
		if errors.Is(err, breakglass.ErrEventNotFound) {
			fmt.Fprintf(os.Stderr, "Event not found: %s\n", input.EventID)
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to get event: %v\n", err)
		return err
	}

	// 4. Format duration as human-readable string (reuse formatDuration from check.go)
	duration := formatDuration(event.Duration)

	// 5. Output success JSON
	output := BreakGlassCheckCommandOutput{
		ID:            event.ID,
		Invoker:       event.Invoker,
		Profile:       event.Profile,
		ReasonCode:    string(event.ReasonCode),
		Justification: event.Justification,
		Duration:      duration,
		Status:        string(event.Status),
		CreatedAt:     event.CreatedAt,
		UpdatedAt:     event.UpdatedAt,
		ExpiresAt:     event.ExpiresAt,
		ClosedBy:      event.ClosedBy,
		ClosedReason:  event.ClosedReason,
		RequestID:     event.RequestID,
	}

	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
		return err
	}

	fmt.Println(string(jsonBytes))

	return nil
}
