package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/audit"
	"github.com/byteness/aws-vault/v7/session"
)

// AuditUntrackedSessionsCommandInput contains the input for the audit untracked-sessions command.
type AuditUntrackedSessionsCommandInput struct {
	Since      string // Duration string: "7d", "24h", etc.
	Until      string // Optional end time duration
	Region     string
	TableName  string
	RoleARN    string
	Profile    string // Filter by profile
	JSONOutput bool
	AWSProfile string

	// Detector is an optional implementation for testing.
	Detector audit.UntrackedSessionsDetector

	Stdout *os.File
	Stderr *os.File
}

// ConfigureAuditUntrackedSessionsCommand sets up the audit untracked-sessions command.
func ConfigureAuditUntrackedSessionsCommand(app *kingpin.Application, s *Sentinel) {
	input := AuditUntrackedSessionsCommandInput{}

	// Get or create the audit command (might already exist from audit verify)
	auditCmd := app.GetCommand("audit")
	if auditCmd == nil {
		auditCmd = app.Command("audit", "Audit and verification commands")
	}

	cmd := auditCmd.Command("untracked-sessions", "Detect credential usage that bypassed session tracking")

	cmd.Flag("since", "How far back to search (e.g., 7d, 24h, 30m)").
		Required().
		StringVar(&input.Since)

	cmd.Flag("until", "End of search window (e.g., 1d for 1 day ago, default: now)").
		StringVar(&input.Until)

	cmd.Flag("region", "AWS region for CloudTrail and DynamoDB").
		Required().
		StringVar(&input.Region)

	cmd.Flag("table", "DynamoDB table name for sessions").
		Required().
		StringVar(&input.TableName)

	cmd.Flag("role", "Filter by role ARN").
		StringVar(&input.RoleARN)

	cmd.Flag("profile", "Filter by AWS profile").
		StringVar(&input.Profile)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Flag("aws-profile", "AWS profile for credentials").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := AuditUntrackedSessionsCommand(context.Background(), input)
		if err != nil {
			if strings.Contains(err.Error(), "untracked session") {
				os.Exit(1)
			}
			app.FatalIfError(err, "audit untracked-sessions")
		}
		return nil
	})
}

// AuditUntrackedSessionsCommand executes the audit untracked-sessions command logic.
func AuditUntrackedSessionsCommand(ctx context.Context, input AuditUntrackedSessionsCommandInput) error {
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Parse --since duration
	sinceDuration, err := ParseDuration(input.Since)
	if err != nil {
		fmt.Fprintf(stderr, "Invalid --since duration: %v\n", err)
		return err
	}

	// Calculate time window
	endTime := time.Now()
	if input.Until != "" {
		untilDuration, err := ParseDuration(input.Until)
		if err != nil {
			fmt.Fprintf(stderr, "Invalid --until duration: %v\n", err)
			return err
		}
		endTime = time.Now().Add(-untilDuration)
	}
	startTime := endTime.Add(-sinceDuration)

	// Get or create detector
	detector := input.Detector
	if detector == nil {
		// Load AWS config
		awsCfgOpts := []func(*config.LoadOptions) error{
			config.WithRegion(input.Region),
		}
		if input.AWSProfile != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(input.AWSProfile))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to load AWS config: %v\n", err)
			return err
		}

		store := session.NewDynamoDBStore(awsCfg, input.TableName)
		detector = audit.NewDetector(awsCfg, store)
	}

	// Run detection
	detectInput := &audit.UntrackedSessionsInput{
		StartTime:   startTime,
		EndTime:     endTime,
		RoleARN:     input.RoleARN,
		ProfileName: input.Profile,
	}

	result, err := detector.Detect(ctx, detectInput)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to detect untracked sessions: %v\n", err)
		return err
	}

	// Output results
	if input.JSONOutput {
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Failed to format results as JSON: %v\n", err)
			return err
		}
		fmt.Fprintln(stdout, string(jsonBytes))
	} else {
		outputUntrackedHumanFormat(stdout, result)
	}

	// Return error if untracked sessions found (for scripting exit code)
	if result.UntrackedEvents > 0 {
		return fmt.Errorf("%d untracked session(s) found", result.UntrackedEvents)
	}

	return nil
}

func outputUntrackedHumanFormat(stdout *os.File, result *audit.UntrackedSessionsResult) {
	fmt.Fprintln(stdout, "Untracked Session Detection")
	fmt.Fprintln(stdout, "===========================")
	fmt.Fprintln(stdout)

	fmt.Fprintf(stdout, "Time Window: %s to %s\n",
		result.StartTime.Format(time.RFC3339),
		result.EndTime.Format(time.RFC3339))
	fmt.Fprintln(stdout)

	fmt.Fprintln(stdout, "Summary")
	fmt.Fprintln(stdout, "-------")
	fmt.Fprintf(stdout, "Total events:     %d\n", result.TotalEvents)
	fmt.Fprintf(stdout, "Tracked:          %d (%.1f%%)\n", result.TrackedEvents, result.ComplianceRate())
	fmt.Fprintf(stdout, "Untracked:        %d\n", result.UntrackedEvents)
	fmt.Fprintf(stdout, "Orphaned:         %d\n", result.OrphanedEvents)
	fmt.Fprintln(stdout)

	if len(result.UntrackedSessions) > 0 {
		fmt.Fprintf(stdout, "Untracked Sessions (%d)\n", len(result.UntrackedSessions))
		fmt.Fprintln(stdout, "----------------------")
		for _, s := range result.UntrackedSessions {
			fmt.Fprintf(stdout, "[%s] %s\n", s.Category, s.EventTime.Format(time.RFC3339))
			fmt.Fprintf(stdout, "  Event ID: %s\n", s.EventID)
			fmt.Fprintf(stdout, "  Role: %s\n", s.RoleARN)
			fmt.Fprintf(stdout, "  Source IP: %s\n", s.SourceIP)
			fmt.Fprintf(stdout, "  Reason: %s\n", s.Reason)
			fmt.Fprintln(stdout)
		}
	}

	if result.UntrackedEvents > 0 {
		fmt.Fprintf(stdout, "Result: %d untracked session(s) detected - compliance gap\n", result.UntrackedEvents)
	} else {
		fmt.Fprintln(stdout, "Result: All sessions properly tracked")
	}
}
