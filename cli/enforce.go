package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/enforce"
)

// EnforcePlanCommandInput contains the input for the enforce plan command.
type EnforcePlanCommandInput struct {
	RoleARNs   []string
	Region     string
	JSONOutput bool
	AWSProfile string // Optional AWS profile for credentials

	// Advisor is an optional Advisor implementation for testing.
	// If nil, a new Advisor will be created using AWS config.
	Advisor *enforce.Advisor

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File
}

// ConfigureEnforcePlanCommand sets up the enforce plan command.
func ConfigureEnforcePlanCommand(app *kingpin.Application, s *Sentinel) {
	input := EnforcePlanCommandInput{}

	// Create enforce command group
	enforceCmd := app.Command("enforce", "Enforcement status and guidance")

	// Create plan subcommand
	cmd := enforceCmd.Command("plan", "Analyze role trust policies for Sentinel enforcement")

	cmd.Flag("role", "Role ARN to analyze (repeatable)").
		Required().
		StringsVar(&input.RoleARNs)

	cmd.Flag("region", "AWS region for IAM operations").
		StringVar(&input.Region)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := EnforcePlanCommand(context.Background(), input)
		app.FatalIfError(err, "enforce plan")
		return nil
	})
}

// EnforcePlanCommand executes the enforce plan command logic.
// It analyzes IAM role trust policies for Sentinel enforcement and outputs recommendations.
func EnforcePlanCommand(ctx context.Context, input EnforcePlanCommandInput) error {
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
	if len(input.RoleARNs) == 0 {
		fmt.Fprintln(stderr, "Error: at least one --role is required")
		return fmt.Errorf("at least one --role is required")
	}

	// Get or create Advisor
	advisor := input.Advisor
	if advisor == nil {
		// Load AWS config
		awsCfgOpts := []func(*config.LoadOptions) error{}
		if input.AWSProfile != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(input.AWSProfile))
		}
		if input.Region != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to load AWS config: %v\n", err)
			return err
		}
		advisor = enforce.NewAdvisor(awsCfg)
	}

	// Analyze roles
	results, err := advisor.AnalyzeRoles(ctx, input.RoleARNs)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to analyze roles: %v\n", err)
		return err
	}

	// Output results
	if input.JSONOutput {
		jsonBytes, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Failed to format results as JSON: %v\n", err)
			return err
		}
		fmt.Fprintln(stdout, string(jsonBytes))
	} else {
		outputHumanFormat(stdout, results)
	}

	// Check for errors in results
	hasErrors := false
	for _, r := range results {
		if r.Error != "" {
			hasErrors = true
			break
		}
	}

	if hasErrors {
		return fmt.Errorf("one or more roles failed to analyze")
	}

	return nil
}

// outputHumanFormat outputs role analysis results in human-readable format.
func outputHumanFormat(stdout *os.File, results []*enforce.RoleAnalysis) {
	fmt.Fprintln(stdout, "Sentinel Enforcement Analysis")
	fmt.Fprintln(stdout, "=============================")
	fmt.Fprintln(stdout)

	var fullCount, partialCount, noneCount, errorCount int

	for _, r := range results {
		fmt.Fprintf(stdout, "Role: %s\n", r.RoleARN)

		if r.Error != "" {
			fmt.Fprintf(stdout, "Status: ERROR\n")
			fmt.Fprintf(stdout, "Error: %s\n", r.Error)
			fmt.Fprintln(stdout)
			errorCount++
			continue
		}

		if r.Analysis == nil {
			fmt.Fprintf(stdout, "Status: ERROR\n")
			fmt.Fprintf(stdout, "Error: analysis result is nil\n")
			fmt.Fprintln(stdout)
			errorCount++
			continue
		}

		// Status with symbols
		switch r.Analysis.Status {
		case enforce.EnforcementStatusFull:
			fmt.Fprintf(stdout, "Status: FULL \u2713\n") // checkmark
			fullCount++
		case enforce.EnforcementStatusPartial:
			fmt.Fprintf(stdout, "Status: PARTIAL \u26A0\n") // warning
			partialCount++
		case enforce.EnforcementStatusNone:
			fmt.Fprintf(stdout, "Status: NONE \u2717\n") // X mark
			noneCount++
		}

		// Level
		fmt.Fprintf(stdout, "Level: %s\n", r.Analysis.Level)

		// Issues
		if len(r.Analysis.Issues) > 0 {
			fmt.Fprintln(stdout, "Issues:")
			for _, issue := range r.Analysis.Issues {
				fmt.Fprintf(stdout, "  - %s\n", issue)
			}
		}

		// Recommendations
		if len(r.Analysis.Recommendations) > 0 {
			fmt.Fprintln(stdout, "Recommendations:")
			for _, rec := range r.Analysis.Recommendations {
				fmt.Fprintf(stdout, "  - %s\n", rec)
			}
		}

		fmt.Fprintln(stdout)
	}

	// Summary
	fmt.Fprintln(stdout, "Summary")
	fmt.Fprintln(stdout, "-------")
	fmt.Fprintf(stdout, "Full enforcement:    %d role(s)\n", fullCount)
	fmt.Fprintf(stdout, "Partial enforcement: %d role(s)\n", partialCount)
	fmt.Fprintf(stdout, "No enforcement:      %d role(s)\n", noneCount)
	if errorCount > 0 {
		fmt.Fprintf(stdout, "Errors:              %d role(s)\n", errorCount)
	}
}
