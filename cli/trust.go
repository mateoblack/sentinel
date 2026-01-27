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

// TrustValidateCommandInput contains the input for the trust validate command.
type TrustValidateCommandInput struct {
	RoleARNs   []string
	Prefix     string
	Region     string
	JSONOutput bool
	AWSProfile string // Optional AWS profile for credentials
	MinRisk    string // Minimum risk level to show (default: "low")

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

// ConfigureTrustValidateCommand sets up the trust validate command.
func ConfigureTrustValidateCommand(app *kingpin.Application, s *Sentinel) {
	input := TrustValidateCommandInput{}

	// Create trust command group
	trustCmd := app.Command("trust", "Trust policy operations")

	// Create validate subcommand
	cmd := trustCmd.Command("validate", "Validate IAM role trust policies for Sentinel security requirements")

	cmd.Flag("role", "Role ARN to validate (repeatable)").
		StringsVar(&input.RoleARNs)

	cmd.Flag("prefix", "Role name prefix for discovery (e.g., 'sentinel-')").
		StringVar(&input.Prefix)

	cmd.Flag("region", "AWS region for IAM operations").
		StringVar(&input.Region)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Flag("min-risk", "Minimum risk level to show: high, medium, low (default: low)").
		Default("low").
		StringVar(&input.MinRisk)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode := TrustValidateCommand(context.Background(), input)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// TrustValidateCommand executes the trust validate command logic.
// It validates IAM role trust policies and outputs findings with risk levels.
// Returns exit code: 0=compliant, 1=HIGH findings, 2=MEDIUM but no HIGH.
func TrustValidateCommand(ctx context.Context, input TrustValidateCommandInput) int {
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
	if len(input.RoleARNs) == 0 && input.Prefix == "" {
		fmt.Fprintln(stderr, "Error: at least one --role or --prefix is required")
		return 1
	}

	// Validate min-risk
	minRisk := enforce.RiskLevelLow
	switch input.MinRisk {
	case "high":
		minRisk = enforce.RiskLevelHigh
	case "medium":
		minRisk = enforce.RiskLevelMedium
	case "low":
		minRisk = enforce.RiskLevelLow
	default:
		fmt.Fprintf(stderr, "Error: invalid --min-risk value %q (must be high, medium, or low)\n", input.MinRisk)
		return 1
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
			return 1
		}
		advisor = enforce.NewAdvisor(awsCfg)
	}

	// Collect role ARNs
	roleARNs := append([]string{}, input.RoleARNs...)

	// Discover roles by prefix if specified
	if input.Prefix != "" {
		discovered, err := advisor.ListRolesByPrefix(ctx, input.Prefix)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to list roles by prefix: %v\n", err)
			return 1
		}
		roleARNs = append(roleARNs, discovered...)
	}

	if len(roleARNs) == 0 {
		fmt.Fprintln(stderr, "No roles found to validate")
		return 0
	}

	// Remove duplicates
	roleARNs = uniqueStrings(roleARNs)

	// Validate roles
	results, err := advisor.ValidateRoles(ctx, roleARNs)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to validate roles: %v\n", err)
		return 1
	}

	// Output results
	if input.JSONOutput {
		return outputValidationJSON(stdout, stderr, results, minRisk)
	}
	return outputValidationHuman(stdout, results, minRisk)
}

// outputValidationJSON outputs validation results in JSON format.
func outputValidationJSON(stdout, stderr *os.File, results []*enforce.RoleValidation, minRisk enforce.RiskLevel) int {
	// Filter findings by min risk
	filteredResults := filterResultsByRisk(results, minRisk)

	jsonBytes, err := json.MarshalIndent(filteredResults, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "Failed to format results as JSON: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(jsonBytes))

	return calculateExitCode(results)
}

// outputValidationHuman outputs validation results in human-readable format.
func outputValidationHuman(stdout *os.File, results []*enforce.RoleValidation, minRisk enforce.RiskLevel) int {
	fmt.Fprintln(stdout, "Trust Policy Validation")
	fmt.Fprintln(stdout, "=======================")
	fmt.Fprintln(stdout)

	var compliantCount, nonCompliantCount, errorCount int
	var totalHigh, totalMedium, totalLow int

	for _, r := range results {
		fmt.Fprintf(stdout, "Role: %s\n", r.RoleARN)

		if r.Error != "" {
			fmt.Fprintf(stdout, "Status: ERROR\n")
			fmt.Fprintf(stdout, "Error: %s\n", r.Error)
			fmt.Fprintln(stdout)
			errorCount++
			continue
		}

		if r.Validation == nil {
			fmt.Fprintf(stdout, "Status: ERROR\n")
			fmt.Fprintf(stdout, "Error: validation result is nil\n")
			fmt.Fprintln(stdout)
			errorCount++
			continue
		}

		// Count findings at or above min risk
		highCount := r.Validation.RiskSummary[enforce.RiskLevelHigh]
		mediumCount := r.Validation.RiskSummary[enforce.RiskLevelMedium]
		lowCount := r.Validation.RiskSummary[enforce.RiskLevelLow]

		totalHigh += highCount
		totalMedium += mediumCount
		totalLow += lowCount

		// Build findings summary based on min-risk filter
		var findingsSummary string
		switch minRisk {
		case enforce.RiskLevelHigh:
			findingsSummary = fmt.Sprintf("%d HIGH", highCount)
		case enforce.RiskLevelMedium:
			findingsSummary = fmt.Sprintf("%d HIGH, %d MEDIUM", highCount, mediumCount)
		default:
			findingsSummary = fmt.Sprintf("%d HIGH, %d MEDIUM, %d LOW", highCount, mediumCount, lowCount)
		}

		filteredFindingsCount := countFilteredFindings(r.Validation, minRisk)
		fmt.Fprintf(stdout, "Findings: %d (%s)\n", filteredFindingsCount, findingsSummary)

		if r.Validation.IsCompliant {
			compliantCount++
		} else {
			nonCompliantCount++
		}

		// Print findings filtered by min risk
		for _, f := range r.Validation.Findings {
			if !isRiskAtOrAbove(f.RiskLevel, minRisk) {
				continue
			}
			fmt.Fprintln(stdout)
			fmt.Fprintf(stdout, "  [%s] %s: %s\n", string(f.RiskLevel), f.RuleID, f.Message)
			fmt.Fprintf(stdout, "    Statement: %s\n", f.AffectedStatement)
			fmt.Fprintf(stdout, "    Recommendation: %s\n", f.Recommendation)
		}

		fmt.Fprintln(stdout)
	}

	// Summary
	fmt.Fprintln(stdout, "Summary")
	fmt.Fprintln(stdout, "-------")
	fmt.Fprintf(stdout, "Roles validated: %d\n", len(results))
	fmt.Fprintf(stdout, "Compliant:       %d role(s)\n", compliantCount)
	fmt.Fprintf(stdout, "Non-compliant:   %d role(s)\n", nonCompliantCount)
	fmt.Fprintf(stdout, "HIGH findings:   %d\n", totalHigh)
	fmt.Fprintf(stdout, "MEDIUM findings: %d\n", totalMedium)
	fmt.Fprintf(stdout, "LOW findings:    %d\n", totalLow)
	if errorCount > 0 {
		fmt.Fprintf(stdout, "Errors:          %d role(s)\n", errorCount)
	}

	return calculateExitCode(results)
}

// calculateExitCode determines the exit code based on findings.
// 0 = all compliant, 1 = any HIGH findings, 2 = MEDIUM but no HIGH.
func calculateExitCode(results []*enforce.RoleValidation) int {
	var hasHigh, hasMedium bool
	for _, r := range results {
		if r.Validation == nil {
			continue
		}
		if r.Validation.RiskSummary[enforce.RiskLevelHigh] > 0 {
			hasHigh = true
		}
		if r.Validation.RiskSummary[enforce.RiskLevelMedium] > 0 {
			hasMedium = true
		}
	}

	if hasHigh {
		return 1
	}
	if hasMedium {
		return 2
	}
	return 0
}

// filterResultsByRisk creates a filtered view of results for JSON output.
func filterResultsByRisk(results []*enforce.RoleValidation, minRisk enforce.RiskLevel) []*enforce.RoleValidation {
	filtered := make([]*enforce.RoleValidation, len(results))
	for i, r := range results {
		if r.Validation == nil {
			filtered[i] = r
			continue
		}

		// Copy the result with filtered findings
		newResult := &enforce.RoleValidation{
			RoleARN:  r.RoleARN,
			RoleName: r.RoleName,
			Error:    r.Error,
		}

		if r.Validation != nil {
			var filteredFindings []enforce.ValidationFinding
			for _, f := range r.Validation.Findings {
				if isRiskAtOrAbove(f.RiskLevel, minRisk) {
					filteredFindings = append(filteredFindings, f)
				}
			}

			newResult.Validation = &enforce.ValidationResult{
				Findings:    filteredFindings,
				RiskSummary: r.Validation.RiskSummary,
				IsCompliant: r.Validation.IsCompliant,
			}
		}

		filtered[i] = newResult
	}
	return filtered
}

// countFilteredFindings counts findings at or above the minimum risk level.
func countFilteredFindings(validation *enforce.ValidationResult, minRisk enforce.RiskLevel) int {
	count := 0
	for _, f := range validation.Findings {
		if isRiskAtOrAbove(f.RiskLevel, minRisk) {
			count++
		}
	}
	return count
}

// isRiskAtOrAbove checks if a risk level is at or above the minimum.
func isRiskAtOrAbove(risk, minimum enforce.RiskLevel) bool {
	riskOrder := map[enforce.RiskLevel]int{
		enforce.RiskLevelHigh:   3,
		enforce.RiskLevelMedium: 2,
		enforce.RiskLevelLow:    1,
	}
	return riskOrder[risk] >= riskOrder[minimum]
}

// uniqueStrings removes duplicate strings while preserving order.
func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
