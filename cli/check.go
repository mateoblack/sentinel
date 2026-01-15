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
	"github.com/byteness/aws-vault/v7/request"
)

// CheckCommandInput contains the input for the check command.
type CheckCommandInput struct {
	RequestID    string
	RequestTable string
	Region       string

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the RequestTable and Region.
	Store request.Store
}

// CheckCommandOutput represents the JSON output from the check command.
type CheckCommandOutput struct {
	ID              string    `json:"id"`
	Requester       string    `json:"requester"`
	Profile         string    `json:"profile"`
	Justification   string    `json:"justification"`
	Duration        string    `json:"duration"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Approver        string    `json:"approver,omitempty"`
	ApproverComment string    `json:"approver_comment,omitempty"`
}

// ConfigureCheckCommand sets up the check command with kingpin.
func ConfigureCheckCommand(app *kingpin.Application, s *Sentinel) {
	input := CheckCommandInput{}

	cmd := app.Command("check", "Check status of an access request")

	cmd.Arg("request-id", "The request ID to check").
		Required().
		StringVar(&input.RequestID)

	cmd.Flag("request-table", "DynamoDB table name for requests").
		Required().
		StringVar(&input.RequestTable)

	cmd.Flag("region", "AWS region for DynamoDB").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := CheckCommand(context.Background(), input)
		app.FatalIfError(err, "check")
		return nil
	})
}

// CheckCommand executes the check command logic.
// It retrieves a specific access request by ID from DynamoDB.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns error.
func CheckCommand(ctx context.Context, input CheckCommandInput) error {
	// 1. Validate request ID format
	if !request.ValidateRequestID(input.RequestID) {
		fmt.Fprintf(os.Stderr, "Invalid request ID: %s (must be 16 lowercase hex characters)\n", input.RequestID)
		return errors.New("invalid request ID format")
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
		store = request.NewDynamoDBStore(awsCfg, input.RequestTable)
	}

	// 3. Fetch request from store
	req, err := store.Get(ctx, input.RequestID)
	if err != nil {
		if errors.Is(err, request.ErrRequestNotFound) {
			fmt.Fprintf(os.Stderr, "Request not found: %s\n", input.RequestID)
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to get request: %v\n", err)
		return err
	}

	// 4. Format duration as human-readable string
	duration := formatDuration(req.Duration)

	// 5. Output success JSON
	output := CheckCommandOutput{
		ID:              req.ID,
		Requester:       req.Requester,
		Profile:         req.Profile,
		Justification:   req.Justification,
		Duration:        duration,
		Status:          string(req.Status),
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.UpdatedAt,
		ExpiresAt:       req.ExpiresAt,
		Approver:        req.Approver,
		ApproverComment: req.ApproverComment,
	}

	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
		return err
	}

	fmt.Println(string(jsonBytes))

	return nil
}

// formatDuration converts a time.Duration to a human-readable string like "1h30m".
func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours == 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	if minutes == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh%dm", hours, minutes)
}
