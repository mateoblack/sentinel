package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/request"
)

// SentinelListCommandInput contains the input for the sentinel list command.
type SentinelListCommandInput struct {
	Requester    string
	Status       string
	Profile      string
	Limit        int
	RequestTable string
	Region       string
	AWSProfile   string // Optional AWS profile for credentials

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the RequestTable and Region.
	Store request.Store

	// STSClient is an optional STS client for AWS identity extraction.
	// If nil, a new client will be created from AWS config.
	STSClient identity.STSAPI
}

// RequestSummary represents a single request in the list output.
type RequestSummary struct {
	ID        string    `json:"id"`
	Profile   string    `json:"profile"`
	Status    string    `json:"status"`
	Requester string    `json:"requester"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SentinelListCommandOutput represents the JSON output from the sentinel list command.
type SentinelListCommandOutput struct {
	Requests []RequestSummary `json:"requests"`
}

// ConfigureSentinelListCommand sets up the sentinel list command with kingpin.
func ConfigureSentinelListCommand(app *kingpin.Application, s *Sentinel) {
	input := SentinelListCommandInput{}

	cmd := app.Command("list", "List access requests")

	cmd.Flag("requester", "Filter by requester username (default: current user)").
		StringVar(&input.Requester)

	cmd.Flag("status", "Filter by status (pending, approved, denied, expired, cancelled)").
		StringVar(&input.Status)

	cmd.Flag("profile", "Filter by AWS profile").
		StringVar(&input.Profile)

	cmd.Flag("limit", "Maximum number of results").
		Default("100").
		IntVar(&input.Limit)

	cmd.Flag("request-table", "DynamoDB table name for requests").
		Required().
		StringVar(&input.RequestTable)

	cmd.Flag("region", "AWS region for DynamoDB").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := SentinelListCommand(context.Background(), input)
		app.FatalIfError(err, "list")
		return nil
	})
}

// SentinelListCommand executes the sentinel list command logic.
// It retrieves access requests from DynamoDB based on filter flags.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns error.
func SentinelListCommand(ctx context.Context, input SentinelListCommandInput) error {
	// 1. Load AWS config (needed for STS and DynamoDB)
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

	// 2. Get AWS identity if Requester not specified and no other filter
	requester := input.Requester
	if requester == "" && input.Status == "" && input.Profile == "" {
		stsClient := input.STSClient
		if stsClient == nil {
			stsClient = sts.NewFromConfig(awsCfg)
		}
		username, err := identity.GetAWSUsername(ctx, stsClient)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get AWS identity: %v\n", err)
			return err
		}
		requester = username
	}

	// 3. Get or create store
	store := input.Store
	if store == nil {
		// Create DynamoDB store
		store = request.NewDynamoDBStore(awsCfg, input.RequestTable)
	}

	// 4. Query based on flags (priority: status > profile > requester)
	var requests []*request.Request
	limit := input.Limit

	if input.Status != "" {
		// Query by status
		status := request.RequestStatus(input.Status)
		if !status.IsValid() {
			fmt.Fprintf(os.Stderr, "Invalid status: %s\n", input.Status)
			return fmt.Errorf("invalid status: %s", input.Status)
		}
		requests, err = store.ListByStatus(ctx, status, limit)
	} else if input.Profile != "" {
		// Query by profile
		requests, err = store.ListByProfile(ctx, input.Profile, limit)
	} else {
		// Query by requester (default to current user's requests)
		requests, err = store.ListByRequester(ctx, requester, limit)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list requests: %v\n", err)
		return err
	}

	// 5. Filter by requester if specified AND query was not by requester
	if input.Requester != "" && (input.Status != "" || input.Profile != "") {
		filtered := make([]*request.Request, 0, len(requests))
		for _, req := range requests {
			if req.Requester == input.Requester {
				filtered = append(filtered, req)
			}
		}
		requests = filtered
	}

	// 6. Format results as JSON array
	summaries := make([]RequestSummary, 0, len(requests))
	for _, req := range requests {
		summaries = append(summaries, RequestSummary{
			ID:        req.ID,
			Profile:   req.Profile,
			Status:    string(req.Status),
			Requester: req.Requester,
			CreatedAt: req.CreatedAt,
			ExpiresAt: req.ExpiresAt,
		})
	}

	output := SentinelListCommandOutput{
		Requests: summaries,
	}

	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
		return err
	}

	fmt.Println(string(jsonBytes))

	return nil
}
