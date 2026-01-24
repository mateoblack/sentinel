package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/session"
)

// ServerSessionsCommandInput contains the input for the server sessions command.
type ServerSessionsCommandInput struct {
	Region       string
	TableName    string
	Status       string // Optional filter: active, revoked, expired
	User         string // Optional filter by user
	Profile      string // Optional filter by AWS profile served
	Limit        int
	OutputFormat string // human, json, csv
	Since        string // Duration filter: "7d", "30d", etc.
	AWSProfile   string // For SSO credential loading

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the TableName and Region.
	Store session.Store

	// STSClient is an optional STS client for AWS identity extraction.
	// If nil, a new client will be created from AWS config.
	STSClient identity.STSAPI
}

// ServerSessionSummary represents a single session in the list output.
type ServerSessionSummary struct {
	ID               string    `json:"id"`
	User             string    `json:"user"`
	Profile          string    `json:"profile"`
	Status           string    `json:"status"`
	StartedAt        time.Time `json:"started_at"`
	LastAccessAt     time.Time `json:"last_access_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	RequestCount     int64     `json:"request_count"`
	ServerInstanceID string    `json:"server_instance_id"`
	SourceIdentity   string    `json:"source_identity"`
}

// ServerSessionsCommandOutput represents the JSON output from the server sessions command.
type ServerSessionsCommandOutput struct {
	Sessions []ServerSessionSummary `json:"sessions"`
}

// ConfigureServerSessionsCommand sets up the server sessions command with kingpin.
func ConfigureServerSessionsCommand(app *kingpin.Application, s *Sentinel) {
	input := ServerSessionsCommandInput{}

	cmd := app.Command("server-sessions", "List server sessions")

	cmd.Flag("region", "AWS region for DynamoDB").
		Required().
		StringVar(&input.Region)

	cmd.Flag("table", "DynamoDB table name for sessions").
		Required().
		StringVar(&input.TableName)

	cmd.Flag("status", "Filter by status (active, revoked, expired)").
		StringVar(&input.Status)

	cmd.Flag("user", "Filter by user").
		StringVar(&input.User)

	cmd.Flag("profile", "Filter by AWS profile served").
		StringVar(&input.Profile)

	cmd.Flag("limit", "Maximum number of results").
		Default("100").
		IntVar(&input.Limit)

	cmd.Flag("output", "Output format (human, json, csv)").
		Default("human").
		EnumVar(&input.OutputFormat, "human", "json", "csv")

	cmd.Flag("since", "Only show sessions started within this duration (e.g., 7d, 30d)").
		StringVar(&input.Since)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := ServerSessionsCommand(context.Background(), input)
		app.FatalIfError(err, "server-sessions")
		return nil
	})
}

// ServerSessionsCommand executes the server sessions command logic.
// It retrieves server sessions from DynamoDB based on filter flags.
// On success, outputs to stdout. On failure, outputs error to stderr and returns error.
func ServerSessionsCommand(ctx context.Context, input ServerSessionsCommandInput) error {
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

	// 2. Parse --since duration if provided
	var sinceTime time.Time
	if input.Since != "" {
		sinceDuration, err := ParseDuration(input.Since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --since duration: %v\n", err)
			return fmt.Errorf("invalid --since duration: %w", err)
		}
		sinceTime = time.Now().Add(-sinceDuration)
	}

	// 3. Get AWS identity if User not specified and no other filter
	user := input.User
	if user == "" && input.Status == "" && input.Profile == "" && input.Since == "" {
		stsClient := input.STSClient
		if stsClient == nil {
			stsClient = sts.NewFromConfig(awsCfg)
		}
		user, err = identity.GetAWSUsername(ctx, stsClient)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get AWS identity: %v\n", err)
			return err
		}
	}

	// 4. Get or create store
	store := input.Store
	if store == nil {
		store = session.NewDynamoDBStore(awsCfg, input.TableName)
	}

	// 5. Query based on flags (priority: since > status > profile > user, default to active sessions)
	var sessions []*session.ServerSession
	limit := input.Limit

	if input.Since != "" {
		// Query by time range (from sinceTime to now)
		sessions, err = store.ListByTimeRange(ctx, sinceTime, time.Now(), limit)
	} else if input.Status != "" {
		// Query by status
		status := session.SessionStatus(input.Status)
		if !status.IsValid() {
			fmt.Fprintf(os.Stderr, "Invalid status: %s (valid: active, revoked, expired)\n", input.Status)
			return fmt.Errorf("invalid status: %s", input.Status)
		}
		sessions, err = store.ListByStatus(ctx, status, limit)
	} else if input.Profile != "" {
		// Query by profile
		sessions, err = store.ListByProfile(ctx, input.Profile, limit)
	} else if user != "" {
		// Query by user
		sessions, err = store.ListByUser(ctx, user, limit)
	} else {
		// Default to active sessions
		sessions, err = store.ListByStatus(ctx, session.StatusActive, limit)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list sessions: %v\n", err)
		return err
	}

	// 6. Filter by user if specified AND query was not by user
	if input.User != "" && (input.Status != "" || input.Profile != "" || input.Since != "") {
		filtered := make([]*session.ServerSession, 0, len(sessions))
		for _, sess := range sessions {
			if sess.User == input.User {
				filtered = append(filtered, sess)
			}
		}
		sessions = filtered
	}

	// 7. Filter by status if specified AND query was by time range or profile
	if input.Status != "" && input.Since != "" {
		status := session.SessionStatus(input.Status)
		filtered := make([]*session.ServerSession, 0, len(sessions))
		for _, sess := range sessions {
			if sess.Status == status {
				filtered = append(filtered, sess)
			}
		}
		sessions = filtered
	}

	// 8. Filter by profile if specified AND query was by time range
	if input.Profile != "" && input.Since != "" {
		filtered := make([]*session.ServerSession, 0, len(sessions))
		for _, sess := range sessions {
			if sess.Profile == input.Profile {
				filtered = append(filtered, sess)
			}
		}
		sessions = filtered
	}

	// 9. Format output
	summaries := make([]ServerSessionSummary, 0, len(sessions))
	for _, sess := range sessions {
		summaries = append(summaries, ServerSessionSummary{
			ID:               sess.ID,
			User:             sess.User,
			Profile:          sess.Profile,
			Status:           string(sess.Status),
			StartedAt:        sess.StartedAt,
			LastAccessAt:     sess.LastAccessAt,
			ExpiresAt:        sess.ExpiresAt,
			RequestCount:     sess.RequestCount,
			ServerInstanceID: sess.ServerInstanceID,
			SourceIdentity:   sess.SourceIdentity,
		})
	}

	switch input.OutputFormat {
	case "json":
		output := ServerSessionsCommandOutput{
			Sessions: summaries,
		}
		jsonBytes, err := json.MarshalIndent(&output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
			return err
		}
		fmt.Println(string(jsonBytes))
	case "csv":
		// CSV output for audit exports
		// Header
		fmt.Println("id,user,profile,status,started_at,last_access_at,expires_at,request_count,server_instance_id,source_identity")
		for _, s := range summaries {
			fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%d,%s,%s\n",
				s.ID,
				csvEscape(s.User),
				csvEscape(s.Profile),
				s.Status,
				s.StartedAt.Format(time.RFC3339),
				s.LastAccessAt.Format(time.RFC3339),
				s.ExpiresAt.Format(time.RFC3339),
				s.RequestCount,
				s.ServerInstanceID,
				csvEscape(s.SourceIdentity),
			)
		}
	default:
		// Human-readable format
		if len(summaries) == 0 {
			fmt.Println("No sessions found.")
			return nil
		}

		// Print header
		fmt.Printf("%-16s  %-12s  %-20s  %-8s  %-20s  %-20s  %s\n",
			"ID", "User", "Profile", "Status", "Started", "Last Access", "Requests")
		fmt.Println("----------------  ------------  --------------------  --------  --------------------  --------------------  --------")

		for _, s := range summaries {
			fmt.Printf("%-16s  %-12s  %-20s  %-8s  %-20s  %-20s  %d\n",
				s.ID,
				truncateString(s.User, 12),
				truncateString(s.Profile, 20),
				s.Status,
				s.StartedAt.Format("2006-01-02 15:04:05"),
				s.LastAccessAt.Format("2006-01-02 15:04:05"),
				s.RequestCount,
			)
		}
	}

	return nil
}

// csvEscape escapes a string for CSV output by wrapping in quotes if it contains special characters.
func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// ServerSessionCommandInput contains the input for the server session detail command.
type ServerSessionCommandInput struct {
	Region       string
	TableName    string
	SessionID    string // Required, positional arg
	OutputFormat string // human, json
	AWSProfile   string

	// Store is an optional Store implementation for testing.
	Store session.Store
}

// ConfigureServerSessionCommand sets up the server session detail command with kingpin.
func ConfigureServerSessionCommand(app *kingpin.Application, s *Sentinel) {
	input := ServerSessionCommandInput{}

	cmd := app.Command("server-session", "Show server session details")

	cmd.Arg("session-id", "Session ID to view").
		Required().
		StringVar(&input.SessionID)

	cmd.Flag("region", "AWS region for DynamoDB").
		Required().
		StringVar(&input.Region)

	cmd.Flag("table", "DynamoDB table name for sessions").
		Required().
		StringVar(&input.TableName)

	cmd.Flag("output", "Output format (human, json)").
		Default("human").
		EnumVar(&input.OutputFormat, "human", "json")

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := ServerSessionCommand(context.Background(), input)
		app.FatalIfError(err, "server-session")
		return nil
	})
}

// ServerSessionCommand executes the server session detail command logic.
// It retrieves a single session by ID and displays all details.
func ServerSessionCommand(ctx context.Context, input ServerSessionCommandInput) error {
	// 1. Validate session ID format
	if !session.ValidateSessionID(input.SessionID) {
		fmt.Fprintf(os.Stderr, "Invalid session ID format: %s (must be 16 lowercase hex characters)\n", input.SessionID)
		return fmt.Errorf("invalid session ID format: %s", input.SessionID)
	}

	// 2. Load AWS config
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

	// 3. Get or create store
	store := input.Store
	if store == nil {
		store = session.NewDynamoDBStore(awsCfg, input.TableName)
	}

	// 4. Get session by ID
	sess, err := store.Get(ctx, input.SessionID)
	if err != nil {
		// Check for not found error
		if isSessionNotFound(err) {
			fmt.Fprintf(os.Stderr, "Session not found: %s\n", input.SessionID)
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to get session: %v\n", err)
		return err
	}

	// 5. Format output
	if input.OutputFormat == "json" {
		jsonBytes, err := json.MarshalIndent(sess, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
			return err
		}
		fmt.Println(string(jsonBytes))
	} else {
		// Human-readable detailed format
		fmt.Printf("Session: %s\n", sess.ID)
		fmt.Printf("User: %s\n", sess.User)
		fmt.Printf("Profile: %s\n", sess.Profile)
		fmt.Printf("Status: %s\n", sess.Status)
		fmt.Printf("Server Instance: %s\n", sess.ServerInstanceID)
		fmt.Printf("Started: %s\n", sess.StartedAt.Format(time.RFC3339))
		fmt.Printf("Last Access: %s\n", sess.LastAccessAt.Format(time.RFC3339))
		fmt.Printf("Expires: %s\n", sess.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Request Count: %d\n", sess.RequestCount)
		fmt.Printf("Source Identity: %s\n", sess.SourceIdentity)

		// Show revocation info if applicable
		if sess.RevokedBy != "" {
			fmt.Printf("\nRevocation:\n")
			fmt.Printf("  Revoked By: %s\n", sess.RevokedBy)
			fmt.Printf("  Reason: %s\n", sess.RevokedReason)
		}
	}

	return nil
}

// truncateString truncates a string to maxLen, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// isSessionNotFound checks if the error indicates a session was not found.
func isSessionNotFound(err error) bool {
	return errors.Is(err, session.ErrSessionNotFound)
}

// ServerRevokeCommandInput contains the input for the server revoke command.
type ServerRevokeCommandInput struct {
	Region       string
	TableName    string
	SessionID    string // Required, positional arg
	Reason       string // Required
	OutputFormat string // human, json
	AWSProfile   string

	// Store is an optional Store implementation for testing.
	Store session.Store

	// STSClient is an optional STS client for AWS identity extraction.
	// If nil, a new client will be created from AWS config.
	STSClient identity.STSAPI
}

// ServerRevokeCommandOutput represents the JSON output from the server revoke command.
type ServerRevokeCommandOutput struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	RevokedBy     string `json:"revoked_by"`
	RevokedReason string `json:"revoked_reason"`
	Message       string `json:"message"`
}

// ConfigureServerRevokeCommand sets up the server revoke command with kingpin.
func ConfigureServerRevokeCommand(app *kingpin.Application, s *Sentinel) {
	input := ServerRevokeCommandInput{}

	cmd := app.Command("server-revoke", "Revoke a server session for immediate access termination")

	cmd.Arg("session-id", "Session ID to revoke").
		Required().
		StringVar(&input.SessionID)

	cmd.Flag("reason", "Reason for revocation (required)").
		Required().
		StringVar(&input.Reason)

	cmd.Flag("region", "AWS region for DynamoDB").
		Required().
		StringVar(&input.Region)

	cmd.Flag("table", "DynamoDB table name for sessions").
		Required().
		StringVar(&input.TableName)

	cmd.Flag("output", "Output format (human, json)").
		Default("human").
		EnumVar(&input.OutputFormat, "human", "json")

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := ServerRevokeCommand(context.Background(), input)
		app.FatalIfError(err, "server-revoke")
		return nil
	})
}

// ServerRevokeCommand executes the server revoke command logic.
// It revokes a session for immediate credential denial.
func ServerRevokeCommand(ctx context.Context, input ServerRevokeCommandInput) error {
	// 1. Validate session ID format
	if !session.ValidateSessionID(input.SessionID) {
		fmt.Fprintf(os.Stderr, "Invalid session ID format: %s (must be 16 lowercase hex characters)\n", input.SessionID)
		return fmt.Errorf("invalid session ID format: %s", input.SessionID)
	}

	// 2. Validate reason is non-empty
	if input.Reason == "" {
		fmt.Fprintf(os.Stderr, "Reason is required for revocation\n")
		return fmt.Errorf("reason is required for revocation")
	}

	// 3. Load AWS config
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

	// 4. Get AWS identity for RevokedBy
	stsClient := input.STSClient
	if stsClient == nil {
		stsClient = sts.NewFromConfig(awsCfg)
	}
	revokedBy, err := identity.GetAWSUsername(ctx, stsClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get AWS identity: %v\n", err)
		return err
	}

	// 5. Get or create store
	store := input.Store
	if store == nil {
		store = session.NewDynamoDBStore(awsCfg, input.TableName)
	}

	// 6. Revoke session
	revokeInput := session.RevokeInput{
		SessionID: input.SessionID,
		RevokedBy: revokedBy,
		Reason:    input.Reason,
	}

	revokedSession, err := session.Revoke(ctx, store, revokeInput)
	if err != nil {
		// Handle specific error cases
		if errors.Is(err, session.ErrSessionNotFound) {
			fmt.Fprintf(os.Stderr, "Session not found: %s\n", input.SessionID)
			return err
		}
		if errors.Is(err, session.ErrSessionAlreadyRevoked) {
			fmt.Fprintf(os.Stderr, "Session already revoked: %s\n", input.SessionID)
			return err
		}
		if errors.Is(err, session.ErrSessionExpired) {
			fmt.Fprintf(os.Stderr, "Session already expired: %s\n", input.SessionID)
			return err
		}
		fmt.Fprintf(os.Stderr, "Failed to revoke session: %v\n", err)
		return err
	}

	// 7. Output result
	if input.OutputFormat == "json" {
		output := ServerRevokeCommandOutput{
			ID:            revokedSession.ID,
			Status:        string(revokedSession.Status),
			RevokedBy:     revokedSession.RevokedBy,
			RevokedReason: revokedSession.RevokedReason,
			Message:       fmt.Sprintf("Session %s revoked by %s", revokedSession.ID, revokedSession.RevokedBy),
		}
		jsonBytes, err := json.MarshalIndent(&output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
			return err
		}
		fmt.Println(string(jsonBytes))
	} else {
		// Human-readable format
		fmt.Printf("Session %s revoked by %s\n", revokedSession.ID, revokedSession.RevokedBy)
		fmt.Printf("Reason: %s\n", revokedSession.RevokedReason)
	}

	return nil
}
