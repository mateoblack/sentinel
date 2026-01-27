package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/deploy"
)

// DeployValidateCommandInput contains the input for the deploy validate command.
type DeployValidateCommandInput struct {
	Region       string
	PolicyRoot   string
	Tables       []string
	SigningKeyID string
	CheckSCP     bool
	JSONOutput   bool
	AWSProfile   string
	MinRisk      string

	// Auditor is an optional Auditor implementation for testing.
	// If nil, a new Auditor will be created using AWS config.
	Auditor *deploy.Auditor

	// SCPAuditor is an optional SCPAuditor implementation for testing.
	// If nil, a new SCPAuditor will be created using AWS config.
	SCPAuditor *deploy.SCPAuditor

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File
}

// ConfigureDeployValidateCommand sets up the deploy validate command.
func ConfigureDeployValidateCommand(app *kingpin.Application, s *Sentinel) {
	input := DeployValidateCommandInput{}

	// Create deploy command group
	deployCmd := app.Command("deploy", "Deployment operations")

	// Create validate subcommand
	cmd := deployCmd.Command("validate", "Audit Sentinel deployment infrastructure for security misconfigurations")

	cmd.Flag("region", "AWS region for API operations").
		StringVar(&input.Region)

	cmd.Flag("policy-root", "SSM parameter path prefix for policies").
		Default("/sentinel/policies").
		StringVar(&input.PolicyRoot)

	cmd.Flag("table", "DynamoDB table name to audit (repeatable)").
		Default("sentinel-requests", "sentinel-breakglass", "sentinel-sessions").
		StringsVar(&input.Tables)

	cmd.Flag("signing-key", "KMS key ID or alias for policy signing").
		StringVar(&input.SigningKeyID)

	cmd.Flag("no-scp", "Skip SCP enforcement check (requires management account)").
		Default("false").
		BoolVar(&input.CheckSCP)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Flag("min-risk", "Minimum risk level to show: high, medium, low (default: low)").
		Default("low").
		StringVar(&input.MinRisk)

	cmd.Action(func(c *kingpin.ParseContext) error {
		// Invert the no-scp flag for internal use
		input.CheckSCP = !input.CheckSCP
		exitCode := DeployValidateCommand(context.Background(), input)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// DeployValidateCommand executes the deploy validate command logic.
// It audits infrastructure and outputs findings with risk levels.
// Returns exit code: 0=all pass, 1=HIGH findings, 2=MEDIUM but no HIGH.
func DeployValidateCommand(ctx context.Context, input DeployValidateCommandInput) int {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Validate min-risk
	minRisk := deploy.RiskLevelLow
	switch strings.ToLower(input.MinRisk) {
	case "high":
		minRisk = deploy.RiskLevelHigh
	case "medium":
		minRisk = deploy.RiskLevelMedium
	case "low":
		minRisk = deploy.RiskLevelLow
	default:
		fmt.Fprintf(stderr, "Error: invalid --min-risk value %q (must be high, medium, or low)\n", input.MinRisk)
		return 1
	}

	// Load AWS config if needed
	var auditor *deploy.Auditor
	var scpAuditor *deploy.SCPAuditor

	if input.Auditor != nil {
		auditor = input.Auditor
	}
	if input.SCPAuditor != nil {
		scpAuditor = input.SCPAuditor
	}

	if auditor == nil || (input.CheckSCP && scpAuditor == nil) {
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

		if auditor == nil {
			auditor = deploy.NewAuditor(awsCfg)
		}
		if input.CheckSCP && scpAuditor == nil {
			scpAuditor = deploy.NewSCPAuditor(awsCfg)
		}
	}

	// Collect all findings
	var allFindings []deploy.DeploymentFinding
	checkedResources := 0

	// Audit DynamoDB tables
	if len(input.Tables) > 0 {
		ddbFindings := auditor.AuditDynamoDBTables(ctx, input.Tables)
		allFindings = append(allFindings, ddbFindings...)
		checkedResources += len(input.Tables)
	}

	// Audit SSM parameters
	if input.PolicyRoot != "" {
		ssmFindings := auditor.AuditSSMParameters(ctx, input.PolicyRoot)
		allFindings = append(allFindings, ssmFindings...)
		checkedResources++
	}

	// Audit KMS key
	if input.SigningKeyID != "" {
		kmsFindings := auditor.AuditKMSKey(ctx, input.SigningKeyID)
		allFindings = append(allFindings, kmsFindings...)
		checkedResources++
	}

	// Audit SCP enforcement (if not skipped)
	if input.CheckSCP && scpAuditor != nil {
		scpFindings := scpAuditor.AuditSCPEnforcement(ctx)
		allFindings = append(allFindings, scpFindings...)
		checkedResources++
	}

	// Create aggregated result
	result := deploy.NewAuditResult(allFindings, checkedResources)

	// Filter findings by min risk
	filteredFindings := filterFindingsByRisk(allFindings, minRisk)

	// Output results
	if input.JSONOutput {
		return outputDeployJSON(stdout, stderr, result, filteredFindings, input)
	}
	return outputDeployHuman(stdout, result, filteredFindings, input, minRisk)
}

// filterFindingsByRisk filters findings to only include those at or above the minimum risk level.
func filterFindingsByRisk(findings []deploy.DeploymentFinding, minRisk deploy.RiskLevel) []deploy.DeploymentFinding {
	var filtered []deploy.DeploymentFinding
	for _, f := range findings {
		if isDeployRiskAtOrAbove(f.RiskLevel, minRisk) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// isDeployRiskAtOrAbove checks if a risk level is at or above the minimum.
func isDeployRiskAtOrAbove(risk, minimum deploy.RiskLevel) bool {
	riskOrder := map[deploy.RiskLevel]int{
		deploy.RiskLevelHigh:    4,
		deploy.RiskLevelMedium:  3,
		deploy.RiskLevelLow:     2,
		deploy.RiskLevelUnknown: 1,
	}
	return riskOrder[risk] >= riskOrder[minimum]
}

// JSONOutput represents the JSON output structure for deploy validate.
type JSONOutput struct {
	Region            string                     `json:"region,omitempty"`
	PolicyRoot        string                     `json:"policy_root"`
	Findings          []deploy.DeploymentFinding `json:"findings"`
	CheckedResources  int                        `json:"checked_resources"`
	RiskSummary       map[deploy.RiskLevel]int   `json:"risk_summary"`
	HasCriticalIssues bool                       `json:"has_critical_issues"`
}

// outputDeployJSON outputs results in JSON format.
func outputDeployJSON(stdout, stderr *os.File, result *deploy.DeploymentAuditResult, filteredFindings []deploy.DeploymentFinding, input DeployValidateCommandInput) int {
	output := JSONOutput{
		Region:            input.Region,
		PolicyRoot:        input.PolicyRoot,
		Findings:          filteredFindings,
		CheckedResources:  result.CheckedResources,
		RiskSummary:       result.RiskSummary,
		HasCriticalIssues: result.HasCriticalIssues,
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "Failed to format results as JSON: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(jsonBytes))

	return calculateDeployExitCode(result)
}

// outputDeployHuman outputs results in human-readable format.
func outputDeployHuman(stdout *os.File, result *deploy.DeploymentAuditResult, filteredFindings []deploy.DeploymentFinding, input DeployValidateCommandInput, minRisk deploy.RiskLevel) int {
	fmt.Fprintln(stdout, "Deployment Security Audit")
	fmt.Fprintln(stdout, "=========================")
	fmt.Fprintln(stdout)

	if input.Region != "" {
		fmt.Fprintf(stdout, "Region: %s\n", input.Region)
	}
	fmt.Fprintf(stdout, "Policy Root: %s\n", input.PolicyRoot)
	fmt.Fprintln(stdout)

	// Group findings by category
	findingsByCategory := make(map[string][]deploy.DeploymentFinding)
	for _, f := range filteredFindings {
		findingsByCategory[f.Category] = append(findingsByCategory[f.Category], f)
	}

	// Print DynamoDB findings
	if ddbFindings, ok := findingsByCategory["DynamoDB"]; ok && len(ddbFindings) > 0 {
		fmt.Fprintln(stdout, "DynamoDB Tables")
		fmt.Fprintln(stdout, "---------------")
		fmt.Fprintln(stdout)
		for _, f := range ddbFindings {
			fmt.Fprintf(stdout, "  [%s] %s: %s\n", f.RiskLevel, f.CheckID, f.Message)
			fmt.Fprintf(stdout, "    Table: %s\n", f.Resource)
			fmt.Fprintf(stdout, "    Remediation: %s\n", f.Remediation)
			fmt.Fprintln(stdout)
		}
	}

	// Print SSM findings
	if ssmFindings, ok := findingsByCategory["SSM"]; ok && len(ssmFindings) > 0 {
		fmt.Fprintln(stdout, "SSM Parameters")
		fmt.Fprintln(stdout, "--------------")
		fmt.Fprintln(stdout)
		for _, f := range ssmFindings {
			fmt.Fprintf(stdout, "  [%s] %s: %s\n", f.RiskLevel, f.CheckID, f.Message)
			fmt.Fprintf(stdout, "    Parameter: %s\n", f.Resource)
			fmt.Fprintf(stdout, "    Remediation: %s\n", f.Remediation)
			fmt.Fprintln(stdout)
		}
	}

	// Print KMS findings
	if kmsFindings, ok := findingsByCategory["KMS"]; ok && len(kmsFindings) > 0 {
		fmt.Fprintln(stdout, "KMS Keys")
		fmt.Fprintln(stdout, "--------")
		fmt.Fprintln(stdout)
		for _, f := range kmsFindings {
			fmt.Fprintf(stdout, "  [%s] %s: %s\n", f.RiskLevel, f.CheckID, f.Message)
			fmt.Fprintf(stdout, "    Key: %s\n", f.Resource)
			fmt.Fprintf(stdout, "    Remediation: %s\n", f.Remediation)
			fmt.Fprintln(stdout)
		}
	}

	// Print SCP findings
	if scpFindings, ok := findingsByCategory["SCP"]; ok && len(scpFindings) > 0 {
		fmt.Fprintln(stdout, "SCP Enforcement")
		fmt.Fprintln(stdout, "---------------")
		fmt.Fprintln(stdout)
		for _, f := range scpFindings {
			fmt.Fprintf(stdout, "  [%s] %s: %s\n", f.RiskLevel, f.CheckID, f.Message)
			fmt.Fprintf(stdout, "    Remediation: %s\n", f.Remediation)
			fmt.Fprintln(stdout)
		}
	}

	// Print summary
	fmt.Fprintln(stdout, "Summary")
	fmt.Fprintln(stdout, "-------")
	fmt.Fprintf(stdout, "Resources checked: %d\n", result.CheckedResources)

	issueCount := result.RiskSummary[deploy.RiskLevelHigh] + result.RiskSummary[deploy.RiskLevelMedium]
	if minRisk == deploy.RiskLevelLow {
		issueCount += result.RiskSummary[deploy.RiskLevelLow]
	}

	fmt.Fprintf(stdout, "Issues found:      %d", len(filteredFindings))
	if len(filteredFindings) > 0 {
		fmt.Fprintf(stdout, " (%d HIGH, %d MEDIUM",
			result.RiskSummary[deploy.RiskLevelHigh],
			result.RiskSummary[deploy.RiskLevelMedium])
		if minRisk == deploy.RiskLevelLow {
			fmt.Fprintf(stdout, ", %d LOW", result.RiskSummary[deploy.RiskLevelLow])
		}
		fmt.Fprint(stdout, ")")
	}
	fmt.Fprintln(stdout)

	// Print remediation report if there are HIGH or MEDIUM findings
	if result.RiskSummary[deploy.RiskLevelHigh] > 0 || result.RiskSummary[deploy.RiskLevelMedium] > 0 {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Remediation Report")
		fmt.Fprintln(stdout, "------------------")
		fmt.Fprintln(stdout)

		// Group remediations by category
		if ddbFindings, ok := findingsByCategory["DynamoDB"]; ok && len(ddbFindings) > 0 {
			fmt.Fprintln(stdout, "# DynamoDB Hardening")
			for _, f := range ddbFindings {
				if f.RiskLevel == deploy.RiskLevelHigh || f.RiskLevel == deploy.RiskLevelMedium {
					fmt.Fprintln(stdout, f.Remediation)
				}
			}
			fmt.Fprintln(stdout)
		}

		if kmsFindings, ok := findingsByCategory["KMS"]; ok && len(kmsFindings) > 0 {
			fmt.Fprintln(stdout, "# KMS Key Management")
			for _, f := range kmsFindings {
				if f.RiskLevel == deploy.RiskLevelHigh || f.RiskLevel == deploy.RiskLevelMedium {
					fmt.Fprintln(stdout, f.Remediation)
				}
			}
			fmt.Fprintln(stdout)
		}

		if scpFindings, ok := findingsByCategory["SCP"]; ok && len(scpFindings) > 0 {
			fmt.Fprintln(stdout, "# SCP Deployment")
			for _, f := range scpFindings {
				if f.RiskLevel == deploy.RiskLevelHigh || f.RiskLevel == deploy.RiskLevelMedium {
					fmt.Fprintln(stdout, f.Remediation)
				}
			}
			fmt.Fprintln(stdout)
		}
	}

	return calculateDeployExitCode(result)
}

// calculateDeployExitCode determines the exit code based on findings.
// 0 = all pass (no HIGH or MEDIUM), 1 = any HIGH findings, 2 = MEDIUM but no HIGH.
func calculateDeployExitCode(result *deploy.DeploymentAuditResult) int {
	if result.RiskSummary[deploy.RiskLevelHigh] > 0 {
		return 1
	}
	if result.RiskSummary[deploy.RiskLevelMedium] > 0 {
		return 2
	}
	return 0
}
