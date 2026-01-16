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
	JSONOutput bool

	// StatusChecker is an optional StatusChecker implementation for testing.
	// If nil, a new StatusChecker will be created using AWS config.
	StatusChecker *bootstrap.StatusChecker

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

	cmd.Flag("region", "AWS region for SSM operations").
		StringVar(&input.Region)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := StatusCommand(context.Background(), input)
		app.FatalIfError(err, "status")
		return nil
	})
}

// StatusCommand executes the status command logic.
// It queries SSM for existing Sentinel policy parameters and displays their status.
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

	// Get or create StatusChecker
	checker := input.StatusChecker
	if checker == nil {
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
		checker = bootstrap.NewStatusChecker(awsCfg)
	}

	// Get status
	result, err := checker.GetStatus(ctx, input.PolicyRoot)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to get status: %v\n", err)
		return err
	}

	// Output results
	if input.JSONOutput {
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Failed to format status as JSON: %v\n", err)
			return err
		}
		fmt.Fprintln(stdout, string(jsonBytes))
	} else {
		fmt.Fprintln(stdout, "Sentinel Policy Status")
		fmt.Fprintln(stdout, "======================")
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Policy Root: %s\n", result.PolicyRoot)
		fmt.Fprintln(stdout)

		if len(result.Parameters) == 0 {
			fmt.Fprintln(stdout, "Profiles:")
			fmt.Fprintln(stdout, "  (none)")
		} else {
			fmt.Fprintln(stdout, "Profiles:")

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
	}

	return nil
}
