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
	"github.com/byteness/aws-vault/v7/request"
)

// DenyCommandInput contains the input for the deny command.
type DenyCommandInput struct {
	RequestID    string
	Comment      string
	RequestTable string
	Region       string

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the RequestTable and Region.
	Store request.Store
}

// DenyCommandOutput represents the JSON output from the deny command.
type DenyCommandOutput struct {
	ID              string    `json:"id"`
	Profile         string    `json:"profile"`
	Status          string    `json:"status"`
	Approver        string    `json:"approver"`
	ApproverComment string    `json:"approver_comment,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ConfigureDenyCommand sets up the deny command with kingpin.
func ConfigureDenyCommand(app *kingpin.Application, s *Sentinel) {
	input := DenyCommandInput{}

	cmd := app.Command("deny", "Deny a pending access request")

	cmd.Arg("request-id", "The request ID to deny").
		Required().
		StringVar(&input.RequestID)

	cmd.Flag("comment", "Optional comment for the denial").
		StringVar(&input.Comment)

	cmd.Flag("request-table", "DynamoDB table name for requests").
		Required().
		StringVar(&input.RequestTable)

	cmd.Flag("region", "AWS region for DynamoDB").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := DenyCommand(context.Background(), input)
		app.FatalIfError(err, "deny")
		return nil
	})
}

// DenyCommand executes the deny command logic.
// It denies a pending access request, transitioning it to denied status.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns error.
func DenyCommand(ctx context.Context, input DenyCommandInput) error {
	// 1. Validate request ID format
	if !request.ValidateRequestID(input.RequestID) {
		fmt.Fprintf(os.Stderr, "Invalid request ID: %s (must be 16 lowercase hex characters)\n", input.RequestID)
		return errors.New("invalid request ID format")
	}

	// 2. Get current user for approver identity
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current user: %v\n", err)
		return err
	}
	approver := currentUser.Username

	// 3. Get or create store
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

	// 4. Fetch request from store
	req, err := store.Get(ctx, input.RequestID)
	if err != nil {
		if errors.Is(err, request.ErrRequestNotFound) {
			fmt.Fprintf(os.Stderr, "Request not found: %s\n", input.RequestID)
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to get request: %v\n", err)
		return err
	}

	// 5. Check if transition is valid
	if !req.CanTransitionTo(request.StatusDenied) {
		fmt.Fprintf(os.Stderr, "Cannot deny request: current status is %s (only pending requests can be denied)\n", req.Status)
		return errors.New("invalid state transition")
	}

	// 6. Update request fields
	req.Status = request.StatusDenied
	req.Approver = approver
	req.ApproverComment = input.Comment
	req.UpdatedAt = time.Now()

	// 7. Store updated request
	if err := store.Update(ctx, req); err != nil {
		if errors.Is(err, request.ErrConcurrentModification) {
			fmt.Fprintf(os.Stderr, "Request was modified by another process, please retry\n")
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to update request: %v\n", err)
		return err
	}

	// 8. Output success JSON
	output := DenyCommandOutput{
		ID:              req.ID,
		Profile:         req.Profile,
		Status:          string(req.Status),
		Approver:        req.Approver,
		ApproverComment: req.ApproverComment,
		UpdatedAt:       req.UpdatedAt,
	}

	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
		return err
	}

	fmt.Println(string(jsonBytes))

	return nil
}
