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
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/session"
)

// AuditSessionComplianceCommandInput contains the input for the audit session-compliance command.
type AuditSessionComplianceCommandInput struct {
	Since      string // Duration string: "7d", "24h", etc.
	Until      string // Optional end time duration
	Region     string
	TableName  string
	Profile    string // Optional: specific profile to check
	PolicyPath string // Optional: policy file for requirement checking
	JSONOutput bool
	AWSProfile string

	// Reporter is an optional ComplianceReporter implementation for testing.
	Reporter audit.ComplianceReporter

	Stdout *os.File
	Stderr *os.File
}

// ConfigureAuditSessionComplianceCommand sets up the audit session-compliance command.
func ConfigureAuditSessionComplianceCommand(app *kingpin.Application, s *Sentinel) {
	input := AuditSessionComplianceCommandInput{}

	// Get or create the audit command (might already exist)
	auditCmd := app.GetCommand("audit")
	if auditCmd == nil {
		auditCmd = app.Command("audit", "Audit and verification commands")
	}

	cmd := auditCmd.Command("session-compliance", "Report session tracking compliance by profile")

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

	cmd.Flag("profile", "Check specific profile only").
		StringVar(&input.Profile)

	cmd.Flag("policy", "Policy file for requirement checking").
		StringVar(&input.PolicyPath)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Flag("aws-profile", "AWS profile for credentials").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := AuditSessionComplianceCommand(context.Background(), input)
		if err != nil {
			if strings.Contains(err.Error(), "compliance gap") {
				os.Exit(1)
			}
			app.FatalIfError(err, "audit session-compliance")
		}
		return nil
	})
}

// AuditSessionComplianceCommand executes the audit session-compliance command logic.
func AuditSessionComplianceCommand(ctx context.Context, input AuditSessionComplianceCommandInput) error {
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

	// Load policy if specified
	var pol *policy.Policy
	if input.PolicyPath != "" {
		pol, err = audit.LoadPolicyFile(input.PolicyPath)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to load policy: %v\n", err)
			return err
		}
	}

	// Get or create reporter
	reporter := input.Reporter
	if reporter == nil {
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
		reporter = audit.NewReporter(awsCfg, store, pol)
	}

	// Generate report
	reportInput := &audit.SessionComplianceInput{
		StartTime:   startTime,
		EndTime:     endTime,
		ProfileName: input.Profile,
		PolicyPath:  input.PolicyPath,
	}

	result, err := reporter.Report(ctx, reportInput)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to generate compliance report: %v\n", err)
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
		outputComplianceHumanFormat(stdout, result)
	}

	// Return error if compliance gaps found
	if result.HasComplianceGaps() {
		return fmt.Errorf("%d profile(s) with compliance gaps", result.ProfilesWithGaps)
	}

	return nil
}

func outputComplianceHumanFormat(stdout *os.File, result *audit.SessionComplianceResult) {
	fmt.Fprintln(stdout, "Session Compliance Report")
	fmt.Fprintln(stdout, "=========================")
	fmt.Fprintln(stdout)

	fmt.Fprintf(stdout, "Time Window: %s to %s\n",
		result.StartTime.Format(time.RFC3339),
		result.EndTime.Format(time.RFC3339))
	fmt.Fprintln(stdout)

	fmt.Fprintln(stdout, "Profile Compliance")
	fmt.Fprintln(stdout, "------------------")
	fmt.Fprintf(stdout, "%-20s  %-15s  %-10s  %-10s  %s\n",
		"Profile", "Policy Required", "Tracked", "Untracked", "Compliance")

	for _, p := range result.Profiles {
		required := "No"
		if p.PolicyRequired {
			required = "Yes"
		}

		gap := ""
		if p.HasGap {
			gap = " !"
		}

		fmt.Fprintf(stdout, "%-20s  %-15s  %-10d  %-10d  %.1f%%%s\n",
			truncateString(p.Profile, 20),
			required,
			p.TrackedCount,
			p.UntrackedCount,
			p.ComplianceRate,
			gap,
		)
	}
	fmt.Fprintln(stdout)

	fmt.Fprintln(stdout, "Summary")
	fmt.Fprintln(stdout, "-------")
	fmt.Fprintf(stdout, "Profiles with require_server_session: %d\n", result.RequiredProfiles)
	fmt.Fprintf(stdout, "Fully compliant profiles: %d\n", result.FullyCompliantProfiles)
	fmt.Fprintf(stdout, "Profiles with gaps: %d\n", result.ProfilesWithGaps)
	fmt.Fprintln(stdout)

	if result.HasComplianceGaps() {
		fmt.Fprintf(stdout, "Result: %d profile(s) with compliance gaps\n", result.ProfilesWithGaps)
	} else {
		fmt.Fprintln(stdout, "Result: All required profiles fully compliant")
	}
}
