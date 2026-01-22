package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/bootstrap"
	"github.com/byteness/aws-vault/v7/infrastructure"
)

// BootstrapCommandInput contains the input for the bootstrap command.
type BootstrapCommandInput struct {
	PolicyRoot          string
	Profiles            []string
	Region              string
	AWSProfile          string // AWS profile for credentials (optional)
	PlanOnly            bool
	AutoApprove         bool
	GenerateIAMPolicies bool
	JSONOutput          bool
	Description         string

	// DynamoDB table provisioning flags
	WithApprovals       bool   // Creates sentinel-requests table
	WithBreakGlass      bool   // Creates sentinel-breakglass table
	WithSessions        bool   // Creates sentinel-sessions table
	WithAll             bool   // Shorthand for enabling all three
	ApprovalTableName   string // Custom name for approval requests table
	BreakGlassTableName string // Custom name for break-glass events table
	SessionTableName    string // Custom name for server sessions table

	// Planner is an optional Planner implementation for testing.
	// If nil, a new Planner will be created using AWS config.
	Planner *bootstrap.Planner

	// Executor is an optional Executor implementation for testing.
	// If nil, a new Executor will be created using AWS config.
	Executor *bootstrap.Executor

	// Provisioner is an optional TableProvisioner for testing.
	// If nil, a new TableProvisioner will be created using AWS config.
	Provisioner TableProvisionerInterface

	// Stdin is an optional reader for confirmation prompts (for testing).
	// If nil, os.Stdin will be used.
	Stdin *bufio.Scanner

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File
}

// TableProvisionerInterface defines the table provisioning interface for testing.
type TableProvisionerInterface interface {
	Plan(ctx context.Context, schema infrastructure.TableSchema) (*infrastructure.ProvisionPlan, error)
	Create(ctx context.Context, schema infrastructure.TableSchema) (*infrastructure.ProvisionResult, error)
}

// ConfigureBootstrapCommand sets up the bootstrap command as a subcommand of init.
func ConfigureBootstrapCommand(app *kingpin.Application, s *Sentinel) {
	input := BootstrapCommandInput{}

	// Create init command group if it doesn't exist
	initCmd := app.Command("init", "Initialize Sentinel infrastructure")

	// Create bootstrap subcommand under init
	cmd := initCmd.Command("bootstrap", "Bootstrap SSM policy parameters")

	cmd.Flag("policy-root", "SSM parameter path prefix for policies").
		Default(bootstrap.DefaultPolicyRoot).
		StringVar(&input.PolicyRoot)

	cmd.Flag("profile", "AWS profile to bootstrap (repeatable)").
		Required().
		StringsVar(&input.Profiles)

	cmd.Flag("region", "AWS region for SSM operations").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Flag("plan", "Show plan without applying").
		BoolVar(&input.PlanOnly)

	cmd.Flag("yes", "Auto-approve, skip confirmation prompt").
		Short('y').
		BoolVar(&input.AutoApprove)

	cmd.Flag("generate-iam-policies", "Include IAM policy documents in output").
		BoolVar(&input.GenerateIAMPolicies)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Flag("description", "Description for generated policies").
		StringVar(&input.Description)

	cmd.Flag("with-approvals", "Also create DynamoDB approval requests table").
		BoolVar(&input.WithApprovals)

	cmd.Flag("with-breakglass", "Also create DynamoDB break-glass events table").
		BoolVar(&input.WithBreakGlass)

	cmd.Flag("with-sessions", "Also create DynamoDB server sessions table").
		BoolVar(&input.WithSessions)

	cmd.Flag("all", "Create all optional DynamoDB tables (approvals, breakglass, sessions)").
		BoolVar(&input.WithAll)

	cmd.Flag("approval-table", "Name for approval requests table").
		Default(DefaultApprovalTableName).
		StringVar(&input.ApprovalTableName)

	cmd.Flag("breakglass-table", "Name for break-glass events table").
		Default(DefaultBreakGlassTableName).
		StringVar(&input.BreakGlassTableName)

	cmd.Flag("session-table", "Name for server sessions table").
		Default(DefaultSessionTableName).
		StringVar(&input.SessionTableName)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := BootstrapCommand(context.Background(), input)
		app.FatalIfError(err, "bootstrap")
		return nil
	})
}

// BootstrapCommand executes the bootstrap command logic.
// It creates or updates SSM parameters for Sentinel policies.
// On success, outputs plan or apply result. On failure, outputs error to stderr and returns error.
func BootstrapCommand(ctx context.Context, input BootstrapCommandInput) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Validate profiles
	if len(input.Profiles) == 0 {
		fmt.Fprintln(stderr, "Error: at least one --profile is required")
		return fmt.Errorf("at least one --profile is required")
	}

	// Build BootstrapConfig from input
	cfg := &bootstrap.BootstrapConfig{
		PolicyRoot:          input.PolicyRoot,
		Region:              input.Region,
		GenerateIAMPolicies: input.GenerateIAMPolicies,
	}

	// Convert profile names to ProfileConfig structs
	for _, profileName := range input.Profiles {
		cfg.Profiles = append(cfg.Profiles, bootstrap.ProfileConfig{
			Name:        profileName,
			Description: input.Description,
		})
	}

	// Get or create Planner
	planner := input.Planner
	if planner == nil {
		// Load AWS config
		// If --aws-profile not specified, use first --profile for credential loading (SSO support)
		credentialProfile := input.AWSProfile
		if credentialProfile == "" && len(input.Profiles) > 0 {
			credentialProfile = input.Profiles[0]
		}
		awsCfgOpts := []func(*config.LoadOptions) error{}
		if credentialProfile != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(credentialProfile))
		}
		if input.Region != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to load AWS config: %v\n", err)
			return err
		}
		planner = bootstrap.NewPlanner(awsCfg)
	}

	// Generate plan
	plan, err := planner.Plan(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to generate plan: %v\n", err)
		return err
	}

	// Output plan
	if input.JSONOutput {
		planJSON, err := bootstrap.FormatPlanJSON(plan)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to format plan as JSON: %v\n", err)
			return err
		}
		fmt.Fprintln(stdout, string(planJSON))
	} else {
		fmt.Fprint(stdout, bootstrap.FormatPlan(plan))
	}

	// If plan-only mode, output IAM policies if requested and return
	if input.PlanOnly {
		if input.GenerateIAMPolicies && !input.JSONOutput {
			outputIAMPolicies(stdout, cfg.PolicyRoot)
		}
		return nil
	}

	// If no changes needed, return early
	if plan.Summary.ToCreate == 0 && plan.Summary.ToUpdate == 0 {
		if !input.JSONOutput {
			fmt.Fprintln(stdout, "\nNo changes needed.")
		}
		return nil
	}

	// Prompt for confirmation if not auto-approved and not JSON mode
	if !input.AutoApprove && !input.JSONOutput {
		fmt.Fprint(stdout, "\nDo you want to apply these changes? [y/N]: ")

		scanner := input.Stdin
		if scanner == nil {
			scanner = bufio.NewScanner(os.Stdin)
		}

		if !scanner.Scan() {
			fmt.Fprintln(stderr, "Error reading input")
			return fmt.Errorf("error reading input")
		}

		response := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if response != "y" && response != "yes" {
			fmt.Fprintln(stdout, "Cancelled.")
			return nil
		}
	}

	// Get or create Executor
	executor := input.Executor
	if executor == nil {
		// Load AWS config
		// If --aws-profile not specified, use first --profile for credential loading (SSO support)
		credentialProfile := input.AWSProfile
		if credentialProfile == "" && len(input.Profiles) > 0 {
			credentialProfile = input.Profiles[0]
		}
		awsCfgOpts := []func(*config.LoadOptions) error{}
		if credentialProfile != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(credentialProfile))
		}
		if input.Region != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to load AWS config: %v\n", err)
			return err
		}
		executor = bootstrap.NewExecutor(awsCfg)
	}

	// Apply plan
	result, err := executor.Apply(ctx, plan)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to apply plan: %v\n", err)
		return err
	}

	// Output apply result
	if input.JSONOutput {
		resultJSON, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Failed to format result as JSON: %v\n", err)
			return err
		}
		fmt.Fprintln(stdout, string(resultJSON))
	} else {
		fmt.Fprintln(stdout, "\nApply complete:")
		fmt.Fprintf(stdout, "  Created: %d\n", len(result.Created))
		for _, name := range result.Created {
			fmt.Fprintf(stdout, "    + %s\n", name)
		}
		fmt.Fprintf(stdout, "  Updated: %d\n", len(result.Updated))
		for _, name := range result.Updated {
			fmt.Fprintf(stdout, "    ~ %s\n", name)
		}
		fmt.Fprintf(stdout, "  Skipped: %d\n", len(result.Skipped))
		fmt.Fprintf(stdout, "  Failed:  %d\n", len(result.Failed))
		for _, f := range result.Failed {
			fmt.Fprintf(stdout, "    ! %s: %s\n", f.Name, f.Error)
		}

		// Output IAM policies if requested
		if input.GenerateIAMPolicies {
			outputIAMPolicies(stdout, cfg.PolicyRoot)
		}
	}

	// Return error if any failures occurred
	if len(result.Failed) > 0 {
		return fmt.Errorf("%d parameter(s) failed to create/update", len(result.Failed))
	}

	return nil
}

// outputIAMPolicies prints IAM policy documents to stdout.
func outputIAMPolicies(stdout *os.File, policyRoot string) {
	fmt.Fprintln(stdout, "\n"+strings.Repeat("=", 60))
	fmt.Fprintln(stdout, "IAM Policy Documents")
	fmt.Fprintln(stdout, strings.Repeat("=", 60))

	// Reader policy
	fmt.Fprintln(stdout, "\n--- SentinelPolicyReader ---")
	fmt.Fprintln(stdout, "Attach to: Roles that need to read Sentinel policies (e.g., Sentinel CLI)")
	readerPolicy := bootstrap.GenerateReaderPolicy(policyRoot)
	readerJSON, _ := bootstrap.FormatIAMPolicy(readerPolicy)
	fmt.Fprintln(stdout, readerJSON)

	// Admin policy
	fmt.Fprintln(stdout, "\n--- SentinelPolicyAdmin ---")
	fmt.Fprintln(stdout, "Attach to: Roles that manage Sentinel policies (e.g., CI/CD pipelines)")
	adminPolicy := bootstrap.GenerateAdminPolicy(policyRoot)
	adminJSON, _ := bootstrap.FormatIAMPolicy(adminPolicy)
	fmt.Fprintln(stdout, adminJSON)
}
