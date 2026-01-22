package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/bootstrap"
)

// StatusCommandInput contains the input for the status command.
type StatusCommandInput struct {
	PolicyRoot string
	Region     string
	AWSProfile string // Optional AWS profile for credentials
	JSONOutput bool

	// CheckTables enables checking DynamoDB table status.
	// Defaults to true when region is provided, false otherwise.
	CheckTables bool

	// Table names (use defaults if empty)
	ApprovalTableName   string
	BreakGlassTableName string
	SessionTableName    string

	// StatusChecker is an optional StatusChecker implementation for testing.
	// If nil, a new StatusChecker will be created using AWS config.
	StatusChecker *bootstrap.StatusChecker

	// InfrastructureChecker is an optional InfrastructureChecker implementation for testing.
	// If nil, a new InfrastructureChecker will be created using AWS config.
	InfrastructureChecker *bootstrap.InfrastructureChecker

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File
}

// ConfigureStatusCommand sets up the status command as a subcommand of init.
func ConfigureStatusCommand(app *kingpin.Application, s *Sentinel) {
	input := StatusCommandInput{}

	// Get or create init command group
	// Note: ConfigureBootstrapCommand creates "init" command, we add "status" as sibling subcommand
	initCmd := app.GetCommand("init")
	if initCmd == nil {
		initCmd = app.Command("init", "Initialize Sentinel infrastructure")
	}

	// Create status subcommand under init
	cmd := initCmd.Command("status", "Show current Sentinel policy status")

	cmd.Flag("policy-root", "SSM parameter path prefix for policies").
		Default(bootstrap.DefaultPolicyRoot).
		StringVar(&input.PolicyRoot)

	cmd.Flag("region", "AWS region for SSM and DynamoDB operations").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Flag("check-tables", "Check DynamoDB table status (requires --region)").
		BoolVar(&input.CheckTables)

	cmd.Flag("approval-table", "Name of the approval table").
		Default(bootstrap.DefaultApprovalTableName).
		StringVar(&input.ApprovalTableName)

	cmd.Flag("breakglass-table", "Name of the break-glass table").
		Default(bootstrap.DefaultBreakGlassTableName).
		StringVar(&input.BreakGlassTableName)

	cmd.Flag("session-table", "Name of the session table").
		Default(bootstrap.DefaultSessionTableName).
		StringVar(&input.SessionTableName)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := StatusCommand(context.Background(), input)
		app.FatalIfError(err, "status")
		return nil
	})
}

// CombinedStatusResult holds both policy and infrastructure status for JSON output.
type CombinedStatusResult struct {
	*bootstrap.StatusResult
	Infrastructure *bootstrap.InfrastructureStatus `json:"infrastructure,omitempty"`
	Suggestions    []bootstrap.Suggestion          `json:"suggestions,omitempty"`
}

// StatusCommand executes the status command logic.
// It queries SSM for existing Sentinel policy parameters and optionally DynamoDB tables.
// On success, outputs status to stdout. On failure, outputs error to stderr and returns error.
func StatusCommand(ctx context.Context, input StatusCommandInput) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Validate: --check-tables requires --region
	if input.CheckTables && input.Region == "" && input.InfrastructureChecker == nil {
		fmt.Fprintln(stderr, "Error: --check-tables requires --region to be specified")
		return fmt.Errorf("--check-tables requires --region")
	}

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

	// Get or create StatusChecker
	checker := input.StatusChecker
	if checker == nil {
		checker = bootstrap.NewStatusChecker(awsCfg)
	}

	// Get policy status
	result, err := checker.GetStatus(ctx, input.PolicyRoot)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to get status: %v\n", err)
		return err
	}

	// Get infrastructure status if requested
	var infraStatus *bootstrap.InfrastructureStatus
	if input.CheckTables {
		infraChecker := input.InfrastructureChecker
		if infraChecker == nil {
			infraChecker = bootstrap.NewInfrastructureChecker(awsCfg, input.Region)
		}
		infraStatus, err = infraChecker.GetInfrastructureStatus(ctx,
			input.ApprovalTableName,
			input.BreakGlassTableName,
			input.SessionTableName)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to get infrastructure status: %v\n", err)
			return err
		}
	}

	// Generate suggestions based on status
	sg := bootstrap.NewSuggestionGenerator()
	var suggestions []bootstrap.Suggestion

	// Generate infrastructure suggestions for missing tables
	if infraStatus != nil && input.Region != "" {
		suggestions = append(suggestions, sg.GenerateInfrastructureSuggestions(infraStatus.Tables, input.Region)...)
	}

	// Output results
	if input.JSONOutput {
		combined := &CombinedStatusResult{
			StatusResult:   result,
			Infrastructure: infraStatus,
			Suggestions:    suggestions,
		}
		jsonBytes, err := json.MarshalIndent(combined, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Failed to format status as JSON: %v\n", err)
			return err
		}
		fmt.Fprintln(stdout, string(jsonBytes))
	} else {
		fmt.Fprintln(stdout, "Sentinel Status")
		fmt.Fprintln(stdout, "===============")
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Policy Parameters (%s):\n", result.PolicyRoot)

		if len(result.Parameters) == 0 {
			fmt.Fprintln(stdout, "  (none)")
		} else {
			// Find max name length for alignment
			maxNameLen := 0
			for _, p := range result.Parameters {
				if len(p.Name) > maxNameLen {
					maxNameLen = len(p.Name)
				}
			}

			for _, p := range result.Parameters {
				// Format: name (padded) vN (last modified: timestamp)
				padding := strings.Repeat(" ", maxNameLen-len(p.Name))
				timeStr := p.LastModified.Format("2006-01-02 15:04:05")
				fmt.Fprintf(stdout, "  %s%s    v%d  (last modified: %s)\n",
					p.Name, padding, p.Version, timeStr)
			}
		}

		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Total: %d policy parameter", result.Count)
		if result.Count != 1 {
			fmt.Fprint(stdout, "s")
		}
		fmt.Fprintln(stdout)

		// Output infrastructure status if available
		if infraStatus != nil {
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Infrastructure:")

			// Find max table name length for alignment
			maxTableLen := 0
			maxPurposeLen := 0
			for _, t := range infraStatus.Tables {
				if len(t.TableName) > maxTableLen {
					maxTableLen = len(t.TableName)
				}
				if len(t.Purpose) > maxPurposeLen {
					maxPurposeLen = len(t.Purpose)
				}
			}

			for _, t := range infraStatus.Tables {
				tablePadding := strings.Repeat(" ", maxTableLen-len(t.TableName))
				purposePadding := strings.Repeat(" ", maxPurposeLen-len(t.Purpose))
				fmt.Fprintf(stdout, "  %s%s    %s%s    %s\n",
					t.TableName, tablePadding, t.Purpose, purposePadding, t.Status)
			}
		}

		// Output suggestions if any
		if len(suggestions) > 0 {
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Suggestions:")
			for _, s := range suggestions {
				if s.Type == "command" {
					fmt.Fprintf(stdout, "  Run: %s\n", s.Command)
				} else {
					fmt.Fprintf(stdout, "  %s\n", s.Message)
				}
			}
		}

		// Show shell integration hint if --aws-profile was provided
		if input.AWSProfile != "" {
			shellHint := sg.GenerateShellSuggestion(input.AWSProfile)
			rcFile := bootstrap.GetShellRCFile()
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "Shell Integration:")
			fmt.Fprintf(stdout, "  Add to %s: %s\n", rcFile, shellHint.Command)
		}
	}

	return nil
}
