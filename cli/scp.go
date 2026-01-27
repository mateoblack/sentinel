package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/deploy"
)

// SCPDeployCommandInput contains the input for the scp deploy command.
type SCPDeployCommandInput struct {
	DryRun     bool   // Preview policy without deploying
	TargetOU   string // OU ID to attach policy (empty = root)
	AWSProfile string // AWS profile for credentials
	Region     string // AWS region
	// NOTE: Force flag removed - SCP-T-01 threat model requires mandatory confirmation
	// to prevent organization-wide lockout from misconfigured SCPs

	// For testing
	Deployer *deploy.SCPDeployer
	Stdout   *os.File
	Stderr   *os.File
	Stdin    *os.File
}

// ConfigureSCPDeployCommand sets up the scp deploy command.
func ConfigureSCPDeployCommand(app *kingpin.Application, s *Sentinel) {
	input := SCPDeployCommandInput{}

	// Create scp command group
	scpCmd := app.Command("scp", "Service Control Policy operations")

	// Create deploy subcommand
	cmd := scpCmd.Command("deploy", "Deploy Sentinel SCP to enforce SourceIdentity on AssumeRole operations")

	cmd.Flag("dry-run", "Preview SCP policy document without deploying").
		BoolVar(&input.DryRun)

	cmd.Flag("target-ou", "OU ID to attach SCP to (default: organization root)").
		StringVar(&input.TargetOU)

	// NOTE: --force flag intentionally removed due to SCP-T-01 threat model.
	// SCP misconfiguration can lock out entire AWS organization including root.
	// Mandatory confirmation required for all SCP deployments.

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Flag("region", "AWS region for API operations").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode := SCPDeployCommand(context.Background(), input)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// SCPDeployCommand executes the scp deploy command logic.
// It creates or updates the Sentinel SCP and attaches it to the specified target.
// Returns exit code: 0=success, 1=failure, 2=user cancelled.
func SCPDeployCommand(ctx context.Context, input SCPDeployCommandInput) int {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	stdin := input.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}

	// Create deployer if not provided (for testing)
	deployer := input.Deployer
	if deployer == nil {
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
		deployer = deploy.NewSCPDeployer(awsCfg)
	}

	// Determine target
	targetID := input.TargetOU
	targetLabel := "Organization Root"
	if targetID != "" {
		targetLabel = targetID
	} else {
		// Need to look up root ID for display
		rootID, err := deployer.GetOrganizationRoot(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "AccessDenied") || strings.Contains(err.Error(), "not authorized") {
				fmt.Fprintf(stderr, "Error: Permission denied. Ensure you are running from the management account.\n")
				return 1
			}
			if strings.Contains(err.Error(), "AWSOrganizationsNotInUseException") || strings.Contains(err.Error(), "not a member") {
				fmt.Fprintf(stderr, "Error: This account is not part of an AWS Organization.\n")
				return 1
			}
			fmt.Fprintf(stderr, "Error getting organization root: %v\n", err)
			return 1
		}
		targetLabel = fmt.Sprintf("Organization Root (%s)", rootID)
	}

	// Check if SCP already exists
	existingID, err := deployer.FindExistingSentinelSCP(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "AccessDenied") {
			fmt.Fprintf(stderr, "Error: Permission denied when listing SCPs.\n")
			return 1
		}
		fmt.Fprintf(stderr, "Error checking for existing SCP: %v\n", err)
		return 1
	}
	action := "Create new policy"
	if existingID != "" {
		action = fmt.Sprintf("Update existing policy (%s)", existingID)
	}

	// Dry-run: just print info and exit
	if input.DryRun {
		fmt.Fprintln(stdout, "Sentinel SCP Deployment (Dry Run)")
		fmt.Fprintln(stdout, "==================================")
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Policy Name: %s\n", deploy.SentinelSCPName)
		fmt.Fprintf(stdout, "Target:      %s\n", targetLabel)
		fmt.Fprintf(stdout, "Action:      Would %s\n", strings.ToLower(action[:1])+action[1:])
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Policy Content:")
		fmt.Fprintln(stdout, deploy.SentinelSCPPolicy)
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Run without --dry-run to deploy this SCP.")
		return 0
	}

	// Validate permissions before deployment
	if err := deployer.ValidatePermissions(ctx); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	// Print deployment info
	fmt.Fprintln(stdout, "Sentinel SCP Deployment")
	fmt.Fprintln(stdout, "=======================")
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "Policy Name: %s\n", deploy.SentinelSCPName)
	fmt.Fprintf(stdout, "Target:      %s\n", targetLabel)
	fmt.Fprintf(stdout, "Action:      %s\n", action)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Policy Content:")
	fmt.Fprintln(stdout, deploy.SentinelSCPPolicy)
	fmt.Fprintln(stdout)

	// Mandatory confirmation - SCP-T-01: No force bypass due to organization lockout risk
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "⚠️  WARNING: SCP deployment affects the ENTIRE AWS Organization")
	fmt.Fprintln(stdout, "   Misconfiguration can lock out all accounts including root.")
	fmt.Fprintln(stdout, "   Review the policy content above carefully.")
	fmt.Fprintln(stdout, "")
	fmt.Fprintf(stdout, "Deploy SCP to %s? [y/N] ", targetLabel)

	reader := bufio.NewReader(stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(stderr, "Error reading input: %v\n", err)
		return 1
	}

	response = strings.TrimSpace(strings.ToLower(response))
	if response != "y" && response != "yes" {
		fmt.Fprintln(stdout, "Cancelled.")
		return 2
	}

	// Deploy the SCP
	result, err := deployer.DeploySCP(ctx, input.TargetOU)
	if err != nil {
		fmt.Fprintf(stderr, "\nError deploying SCP: %v\n", err)
		return 1
	}

	// Print success
	fmt.Fprintln(stdout)
	if result.Created {
		fmt.Fprintln(stdout, "SCP deployed successfully (created new policy)")
	} else {
		fmt.Fprintln(stdout, "SCP deployed successfully (updated existing policy)")
	}
	fmt.Fprintf(stdout, "  Policy ID:   %s\n", result.PolicyID)
	fmt.Fprintf(stdout, "  Policy ARN:  %s\n", result.PolicyARN)
	if len(result.Targets) > 0 {
		fmt.Fprintf(stdout, "  Attached to: %s\n", strings.Join(result.Targets, ", "))
	}

	return 0
}
