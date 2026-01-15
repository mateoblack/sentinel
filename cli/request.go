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
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// RequestCommandInput contains the input for the request command.
type RequestCommandInput struct {
	ProfileName   string
	Duration      time.Duration
	Justification string
	RequestTable  string
	Region        string

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the RequestTable and Region.
	Store request.Store

	// Notifier is an optional Notifier for sending notifications on request creation.
	// If nil, no notifications are sent. If set, the store is wrapped with NotifyStore.
	Notifier notification.Notifier

	// ApprovalPolicy is an optional approval policy for auto-approve checking.
	// If nil, no auto-approve checking is performed.
	ApprovalPolicy *policy.ApprovalPolicy

	// Logger is an optional Logger for audit trail logging.
	// If nil, no approval events are logged.
	Logger logging.Logger
}

// RequestCommandOutput represents the JSON output from the request command.
type RequestCommandOutput struct {
	RequestID    string    `json:"request_id"`
	Profile      string    `json:"profile"`
	Status       string    `json:"status"`
	ExpiresAt    time.Time `json:"expires_at"`
	AutoApproved bool      `json:"auto_approved,omitempty"`
}

// ConfigureRequestCommand sets up the request command with kingpin.
func ConfigureRequestCommand(app *kingpin.Application, s *Sentinel) {
	input := RequestCommandInput{}

	cmd := app.Command("request", "Submit an access request for approval")

	cmd.Flag("profile", "AWS profile to request access to").
		Required().
		StringVar(&input.ProfileName)

	cmd.Flag("duration", "How long access is needed (max 8h)").
		Default("1h").
		DurationVar(&input.Duration)

	cmd.Flag("justification", "Reason for access (10-500 chars)").
		Required().
		StringVar(&input.Justification)

	cmd.Flag("request-table", "DynamoDB table name for requests").
		Required().
		StringVar(&input.RequestTable)

	cmd.Flag("region", "AWS region for DynamoDB").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := RequestCommand(context.Background(), input, s)
		app.FatalIfError(err, "request")
		return nil
	})
}

// RequestCommand executes the request command logic.
// It creates an access request and stores it in DynamoDB.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns error.
func RequestCommand(ctx context.Context, input RequestCommandInput, s *Sentinel) error {
	// 1. Get current user
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

	// 3. Cap duration at MaxDuration
	duration := input.Duration
	if duration > request.MaxDuration {
		fmt.Fprintf(os.Stderr, "Warning: duration %v exceeds maximum, capping at %v\n", duration, request.MaxDuration)
		duration = request.MaxDuration
	}

	// 4. Get or create store
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

	// Wrap store with NotifyStore if Notifier is provided
	if input.Notifier != nil {
		store = notification.NewNotifyStore(store, input.Notifier)
	}

	// 5. Build Request struct
	now := time.Now()
	req := &request.Request{
		ID:            request.NewRequestID(),
		Requester:     username,
		Profile:       input.ProfileName,
		Justification: input.Justification,
		Duration:      duration,
		Status:        request.StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(request.DefaultRequestTTL),
	}

	// 6. Check auto-approve if approval policy is provided
	autoApproved := false
	if input.ApprovalPolicy != nil {
		rule := policy.FindApprovalRule(input.ApprovalPolicy, input.ProfileName)
		if rule != nil && policy.ShouldAutoApprove(rule, username, now, duration) {
			req.Status = request.StatusApproved
			req.Approver = username
			req.ApproverComment = "auto-approved by policy"
			autoApproved = true
		}
	}

	// 7. Validate request
	if err := req.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid request: %v\n", err)
		return err
	}

	// 8. Store request
	if err := store.Create(ctx, req); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create request: %v\n", err)
		return err
	}

	// 9. Log approval events if Logger is provided
	if input.Logger != nil {
		// Log request created event
		createdEntry := logging.NewApprovalLogEntry(notification.EventRequestCreated, req, username)
		input.Logger.LogApproval(createdEntry)

		// If auto-approved, also log the approval event
		if autoApproved {
			approvedEntry := logging.NewApprovalLogEntry(notification.EventRequestApproved, req, username)
			input.Logger.LogApproval(approvedEntry)
		}
	}

	// 10. Output success JSON
	output := RequestCommandOutput{
		RequestID:    req.ID,
		Profile:      req.Profile,
		Status:       string(req.Status),
		ExpiresAt:    req.ExpiresAt,
		AutoApproved: autoApproved,
	}

	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
		return err
	}

	fmt.Println(string(jsonBytes))

	return nil
}
