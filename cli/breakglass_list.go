package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/breakglass"
)

// BreakGlassListCommandInput contains the input for the breakglass-list command.
type BreakGlassListCommandInput struct {
	Invoker         string
	Status          string
	Profile         string
	Limit           int
	BreakGlassTable string
	Region          string

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the BreakGlassTable and Region.
	Store breakglass.Store
}

// BreakGlassEventSummary represents a single event in the list output.
type BreakGlassEventSummary struct {
	ID         string    `json:"id"`
	Profile    string    `json:"profile"`
	Status     string    `json:"status"`
	Invoker    string    `json:"invoker"`
	ReasonCode string    `json:"reason_code"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// BreakGlassListCommandOutput represents the JSON output from the breakglass-list command.
type BreakGlassListCommandOutput struct {
	Events []BreakGlassEventSummary `json:"events"`
}

// ConfigureBreakGlassListCommand sets up the breakglass-list command with kingpin.
func ConfigureBreakGlassListCommand(app *kingpin.Application, s *Sentinel) {
	input := BreakGlassListCommandInput{}

	cmd := app.Command("breakglass-list", "List break-glass events")

	cmd.Flag("invoker", "Filter by invoker username (default: current user)").
		StringVar(&input.Invoker)

	cmd.Flag("status", "Filter by status (active, closed, expired)").
		StringVar(&input.Status)

	cmd.Flag("profile", "Filter by AWS profile").
		StringVar(&input.Profile)

	cmd.Flag("limit", "Maximum number of results").
		Default("100").
		IntVar(&input.Limit)

	cmd.Flag("breakglass-table", "DynamoDB table name for break-glass events").
		Required().
		StringVar(&input.BreakGlassTable)

	cmd.Flag("region", "AWS region for DynamoDB").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := BreakGlassListCommand(context.Background(), input)
		app.FatalIfError(err, "breakglass-list")
		return nil
	})
}

// BreakGlassListCommand executes the breakglass-list command logic.
// It retrieves break-glass events from DynamoDB based on filter flags.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns error.
func BreakGlassListCommand(ctx context.Context, input BreakGlassListCommandInput) error {
	// 1. Get current user if Invoker not specified and no other filter
	invoker := input.Invoker
	if invoker == "" && input.Status == "" && input.Profile == "" {
		currentUser, err := user.Current()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get current user: %v\n", err)
			return err
		}
		invoker = currentUser.Username
	}

	// 2. Get or create store
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

	// 3. Query based on flags (priority: status > profile > invoker)
	var events []*breakglass.BreakGlassEvent
	var err error
	limit := input.Limit

	if input.Status != "" {
		// Query by status
		status := breakglass.BreakGlassStatus(input.Status)
		if !status.IsValid() {
			fmt.Fprintf(os.Stderr, "Invalid status: %s\n", input.Status)
			return fmt.Errorf("invalid status: %s", input.Status)
		}
		events, err = store.ListByStatus(ctx, status, limit)
	} else if input.Profile != "" {
		// Query by profile
		events, err = store.ListByProfile(ctx, input.Profile, limit)
	} else {
		// Query by invoker (default to current user's events)
		events, err = store.ListByInvoker(ctx, invoker, limit)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list break-glass events: %v\n", err)
		return err
	}

	// 4. Filter by invoker if specified AND query was not by invoker
	if input.Invoker != "" && (input.Status != "" || input.Profile != "") {
		filtered := make([]*breakglass.BreakGlassEvent, 0, len(events))
		for _, event := range events {
			if event.Invoker == input.Invoker {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

	// 5. Format results as JSON array
	summaries := make([]BreakGlassEventSummary, 0, len(events))
	for _, event := range events {
		summaries = append(summaries, BreakGlassEventSummary{
			ID:         event.ID,
			Profile:    event.Profile,
			Status:     string(event.Status),
			Invoker:    event.Invoker,
			ReasonCode: string(event.ReasonCode),
			CreatedAt:  event.CreatedAt,
			ExpiresAt:  event.ExpiresAt,
		})
	}

	output := BreakGlassListCommandOutput{
		Events: summaries,
	}

	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
		return err
	}

	fmt.Println(string(jsonBytes))

	return nil
}
