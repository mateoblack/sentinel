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
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/request"
)

// DenyCommandInput contains the input for the deny command.
type DenyCommandInput struct {
	RequestID    string
	Comment      string
	RequestTable string
	Region       string
	AWSProfile   string // Optional AWS profile for credentials

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the RequestTable and Region.
	Store request.Store

	// Notifier is an optional Notifier for sending notifications on denial.
	// If nil, no notifications are sent. If set, the store is wrapped with NotifyStore.
	Notifier notification.Notifier

	// Logger is an optional Logger for audit trail logging.
	// If nil, no approval events are logged.
	Logger logging.Logger

	// STSClient is an optional STS client for AWS identity extraction.
	// If nil, a new client will be created from AWS config.
	STSClient identity.STSAPI
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

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

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

	// 2. Load AWS config (needed for STS and DynamoDB)
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

	// 3. Get AWS identity for denier
	stsClient := input.STSClient
	if stsClient == nil {
		stsClient = sts.NewFromConfig(awsCfg)
	}
	approver, err := identity.GetAWSUsername(ctx, stsClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get AWS identity: %v\n", err)
		return err
	}

	// 4. Get or create store
	store := input.Store
	if store == nil {
		// Create DynamoDB store
		store = request.NewDynamoDBStore(awsCfg, input.RequestTable)
	}

	// Wrap store with NotifyStore if Notifier is provided
	if input.Notifier != nil {
		store = notification.NewNotifyStore(store, input.Notifier)
	}

	// 5. Fetch request from store
	req, err := store.Get(ctx, input.RequestID)
	if err != nil {
		if errors.Is(err, request.ErrRequestNotFound) {
			fmt.Fprintf(os.Stderr, "Request not found: %s\n", input.RequestID)
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to get request: %v\n", err)
		return err
	}

	// 6. Check if transition is valid
	if !req.CanTransitionTo(request.StatusDenied) {
		fmt.Fprintf(os.Stderr, "Cannot deny request: current status is %s (only pending requests can be denied)\n", req.Status)
		return errors.New("invalid state transition")
	}

	// 7. Update request fields
	req.Status = request.StatusDenied
	req.Approver = approver
	req.ApproverComment = input.Comment
	// Note: UpdatedAt is set internally by store.Update() for optimistic locking

	// 8. Store updated request
	if err := store.Update(ctx, req); err != nil {
		if errors.Is(err, request.ErrConcurrentModification) {
			fmt.Fprintf(os.Stderr, "Request was modified by another process, please retry\n")
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to update request: %v\n", err)
		return err
	}

	// 9. Log denial event if Logger is provided
	if input.Logger != nil {
		entry := logging.NewApprovalLogEntry(notification.EventRequestDenied, req, approver)
		input.Logger.LogApproval(entry)
	}

	// 10. Output success JSON
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
