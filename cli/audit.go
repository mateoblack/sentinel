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
)

// AuditVerifyCommandInput contains the input for the audit verify command.
type AuditVerifyCommandInput struct {
	StartTime  time.Time
	EndTime    time.Time
	RoleARN    string
	Username   string
	Region     string
	JSONOutput bool

	// Verifier is an optional SessionVerifier implementation for testing.
	// If nil, a new Verifier will be created using AWS config.
	Verifier audit.SessionVerifier

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File
}

// ConfigureAuditVerifyCommand sets up the audit verify command.
func ConfigureAuditVerifyCommand(app *kingpin.Application, s *Sentinel) {
	input := AuditVerifyCommandInput{}

	// Create audit command group
	auditCmd := app.Command("audit", "Audit and verification commands")

	// Create verify subcommand
	cmd := auditCmd.Command("verify", "Verify CloudTrail sessions for Sentinel enforcement")

	var startStr, endStr string

	cmd.Flag("start", "Start of time window (RFC3339 format, e.g., 2026-01-16T00:00:00Z)").
		Required().
		StringVar(&startStr)

	cmd.Flag("end", "End of time window (RFC3339 format, e.g., 2026-01-16T12:00:00Z)").
		Required().
		StringVar(&endStr)

	cmd.Flag("role", "Role ARN filter").
		StringVar(&input.RoleARN)

	cmd.Flag("user", "Username filter").
		StringVar(&input.Username)

	cmd.Flag("region", "AWS region for CloudTrail operations").
		StringVar(&input.Region)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Action(func(c *kingpin.ParseContext) error {
		// Parse time strings
		var err error
		input.StartTime, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			return fmt.Errorf("invalid --start time: %w", err)
		}
		input.EndTime, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			return fmt.Errorf("invalid --end time: %w", err)
		}

		err = AuditVerifyCommand(context.Background(), input)
		if err != nil {
			// Don't call FatalIfError for "issues found" errors - we still want to exit with non-zero
			// but we've already printed the output
			if strings.Contains(err.Error(), "issue(s) found") {
				os.Exit(1)
			}
			app.FatalIfError(err, "audit verify")
		}
		return nil
	})
}

// AuditVerifyCommand executes the audit verify command logic.
// It queries CloudTrail for sessions and analyzes them for Sentinel enforcement.
func AuditVerifyCommand(ctx context.Context, input AuditVerifyCommandInput) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Validate inputs
	if input.EndTime.Before(input.StartTime) || input.EndTime.Equal(input.StartTime) {
		fmt.Fprintln(stderr, "Error: --end must be after --start")
		return fmt.Errorf("--end must be after --start")
	}

	// Get or create Verifier
	verifier := input.Verifier
	if verifier == nil {
		// Load AWS config
		awsCfgOpts := []func(*config.LoadOptions) error{}
		if input.Region != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to load AWS config: %v\n", err)
			return err
		}
		verifier = audit.NewVerifier(awsCfg)
	}

	// Build verify input
	verifyInput := &audit.VerifyInput{
		StartTime: input.StartTime,
		EndTime:   input.EndTime,
		RoleARN:   input.RoleARN,
		Username:  input.Username,
	}

	// Run verification
	result, err := verifier.Verify(ctx, verifyInput)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to verify sessions: %v\n", err)
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
		outputAuditHumanFormat(stdout, result)
	}

	// Return non-nil error if issues found (for scripting exit code)
	if result.HasIssues() {
		return fmt.Errorf("%d issue(s) found", len(result.Issues))
	}

	return nil
}

// outputAuditHumanFormat outputs verification results in human-readable format.
func outputAuditHumanFormat(stdout *os.File, result *audit.VerificationResult) {
	fmt.Fprintln(stdout, "CloudTrail Session Verification")
	fmt.Fprintln(stdout, "================================")
	fmt.Fprintln(stdout)

	// Time window
	fmt.Fprintf(stdout, "Time Window: %s to %s\n", result.StartTime.Format(time.RFC3339), result.EndTime.Format(time.RFC3339))
	fmt.Fprintln(stdout)

	// Summary
	fmt.Fprintln(stdout, "Summary")
	fmt.Fprintln(stdout, "-------")
	fmt.Fprintf(stdout, "Total sessions:       %d\n", result.TotalSessions)
	fmt.Fprintf(stdout, "Sentinel sessions:    %d (%.1f%%)\n", result.SentinelSessions, result.PassRate())
	fmt.Fprintf(stdout, "Non-Sentinel:         %d\n", result.NonSentinelSessions)
	fmt.Fprintln(stdout)

	// Issues
	if len(result.Issues) > 0 {
		fmt.Fprintf(stdout, "Issues (%d)\n", len(result.Issues))
		fmt.Fprintln(stdout, "----------")
		for _, issue := range result.Issues {
			fmt.Fprintf(stdout, "[%s] %s\n", strings.ToUpper(issue.Severity.String()), issue.Message)
			if issue.SessionInfo != nil {
				fmt.Fprintf(stdout, "  Event ID: %s\n", issue.SessionInfo.EventID)
				fmt.Fprintf(stdout, "  Time: %s\n", issue.SessionInfo.EventTime.Format(time.RFC3339))
			}
			fmt.Fprintln(stdout)
		}
	}

	// Result
	if result.HasIssues() {
		fmt.Fprintf(stdout, "Result: %d issue(s) found\n", len(result.Issues))
	} else {
		fmt.Fprintln(stdout, "Result: All sessions verified with Sentinel SourceIdentity")
	}
}
