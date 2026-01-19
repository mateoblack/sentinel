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
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// ApproveCommandInput contains the input for the approve command.
type ApproveCommandInput struct {
	RequestID    string
	Comment      string
	RequestTable string
	Region       string

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the RequestTable and Region.
	Store request.Store

	// Notifier is an optional Notifier for sending notifications on approval.
	// If nil, no notifications are sent. If set, the store is wrapped with NotifyStore.
	Notifier notification.Notifier

	// ApprovalPolicy is an optional approval policy for approver authorization.
	// If nil, any user can approve any request.
	ApprovalPolicy *policy.ApprovalPolicy

	// Logger is an optional Logger for audit trail logging.
	// If nil, no approval events are logged.
	Logger logging.Logger

	// STSClient is an optional STS client for AWS identity extraction.
	// If nil, a new client will be created from AWS config.
	STSClient identity.STSAPI
}

// ApproveCommandOutput represents the JSON output from the approve command.
type ApproveCommandOutput struct {
	ID              string    `json:"id"`
	Profile         string    `json:"profile"`
	Status          string    `json:"status"`
	Approver        string    `json:"approver"`
	ApproverComment string    `json:"approver_comment,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ConfigureApproveCommand sets up the approve command with kingpin.
func ConfigureApproveCommand(app *kingpin.Application, s *Sentinel) {
	input := ApproveCommandInput{}

	cmd := app.Command("approve", "Approve a pending access request")

	cmd.Arg("request-id", "The request ID to approve").
		Required().
		StringVar(&input.RequestID)

	cmd.Flag("comment", "Optional comment for the approval").
		StringVar(&input.Comment)

	cmd.Flag("request-table", "DynamoDB table name for requests").
		Required().
		StringVar(&input.RequestTable)

	cmd.Flag("region", "AWS region for DynamoDB").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := ApproveCommand(context.Background(), input)
		app.FatalIfError(err, "approve")
		return nil
	})
}

// ApproveCommand executes the approve command logic.
// It approves a pending access request, transitioning it to approved status.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns error.
func ApproveCommand(ctx context.Context, input ApproveCommandInput) error {
	// 1. Validate request ID format
	if !request.ValidateRequestID(input.RequestID) {
		fmt.Fprintf(os.Stderr, "Invalid request ID: %s (must be 16 lowercase hex characters)\n", input.RequestID)
		return errors.New("invalid request ID format")
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

	// 3. Get AWS identity for approver
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

	// 6. Check approver authorization if policy is provided
	if input.ApprovalPolicy != nil {
		rule := policy.FindApprovalRule(input.ApprovalPolicy, req.Profile)
		if rule != nil {
			if !policy.CanApprove(rule, approver) {
				errMsg := fmt.Sprintf("user %s is not authorized to approve requests for profile %s", approver, req.Profile)
				fmt.Fprintf(os.Stderr, "%s\n", errMsg)
				return errors.New(errMsg)
			}
		}
		// If no rule found, allow (passthrough - no approval routing for this profile)
	}

	// 7. Check if transition is valid
	if !req.CanTransitionTo(request.StatusApproved) {
		fmt.Fprintf(os.Stderr, "Cannot approve request: current status is %s (only pending requests can be approved)\n", req.Status)
		return errors.New("invalid state transition")
	}

	// 8. Update request fields
	req.Status = request.StatusApproved
	req.Approver = approver
	req.ApproverComment = input.Comment
	req.UpdatedAt = time.Now()

	// 9. Store updated request
	if err := store.Update(ctx, req); err != nil {
		if errors.Is(err, request.ErrConcurrentModification) {
			fmt.Fprintf(os.Stderr, "Request was modified by another process, please retry\n")
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to update request: %v\n", err)
		return err
	}

	// 10. Log approval event if Logger is provided
	if input.Logger != nil {
		entry := logging.NewApprovalLogEntry(notification.EventRequestApproved, req, approver)
		input.Logger.LogApproval(entry)
	}

	// 11. Output success JSON
	output := ApproveCommandOutput{
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
