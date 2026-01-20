package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/bootstrap"
	"github.com/byteness/aws-vault/v7/shell"
)

// ShellInitCommandInput contains the input for the shell init command.
type ShellInitCommandInput struct {
	PolicyRoot    string
	Region        string
	AWSProfile    string
	Format        string // "bash", "zsh", or empty for auto-detect
	IncludeServer bool   // Generate -server variants for real-time revocation mode

	// ShellGenerator is an optional ShellGenerator implementation for testing.
	// If nil, a new ShellGenerator will be created using AWS config.
	ShellGenerator *shell.ShellGenerator

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors and status (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File
}

// ConfigureShellInitCommand sets up the shell init command.
func ConfigureShellInitCommand(app *kingpin.Application, s *Sentinel) {
	input := ShellInitCommandInput{}

	// Create "shell" parent command if it doesn't exist
	shellCmd := app.GetCommand("shell")
	if shellCmd == nil {
		shellCmd = app.Command("shell", "Shell integration commands")
	}

	// Create "init" subcommand under shell
	cmd := shellCmd.Command("init", "Generate shell functions for Sentinel profiles")

	cmd.Flag("policy-root", "SSM parameter path prefix for policies").
		Default(bootstrap.DefaultPolicyRoot).
		StringVar(&input.PolicyRoot)

	cmd.Flag("region", "AWS region for SSM operations").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for credentials").
		StringVar(&input.AWSProfile)

	cmd.Flag("format", "Output format: bash, zsh (default: auto-detect from $SHELL)").
		StringVar(&input.Format)

	cmd.Flag("include-server", "Also generate -server variants for real-time revocation mode").
		Default("false").
		BoolVar(&input.IncludeServer)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := ShellInitCommand(context.Background(), input)
		app.FatalIfError(err, "shell init")
		return nil
	})
}

// ShellInitCommand executes the shell init command logic.
// It discovers Sentinel profiles and generates shell wrapper functions.
// The generated script is printed to stdout (for eval), and status messages go to stderr.
func ShellInitCommand(ctx context.Context, input ShellInitCommandInput) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Get or create ShellGenerator
	generator := input.ShellGenerator
	if generator == nil {
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
		generator = shell.NewShellGenerator(awsCfg)
	}

	// Get profiles from SSM
	profiles, err := generator.GetProfiles(ctx, input.PolicyRoot)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to discover profiles: %v\n", err)
		return err
	}

	// Detect shell format
	format := detectShellFormat(input.Format)

	// Generate script with options
	opts := shell.GenerateOptions{IncludeServer: input.IncludeServer}
	script := shell.GenerateScriptWithOptions(profiles, input.PolicyRoot, format, opts)

	// Print script to stdout (for eval)
	fmt.Fprint(stdout, script)

	// Print summary to stderr (not captured by eval)
	if len(profiles) == 0 {
		fmt.Fprintf(stderr, "# No profiles found under %s\n", input.PolicyRoot)
		fmt.Fprintf(stderr, "# Run 'sentinel init' to create your first policy\n")
	} else {
		if input.IncludeServer {
			fmt.Fprintf(stderr, "# Generated %d shell function(s) (%d with server mode) for format: %s\n", len(profiles), len(profiles), format)
		} else {
			fmt.Fprintf(stderr, "# Generated %d shell function(s) for format: %s\n", len(profiles), format)
		}
		fmt.Fprintf(stderr, "# Usage: Add to your shell profile: eval \"$(sentinel shell init)\"\n")
	}

	return nil
}

// detectShellFormat determines the shell format from user input or environment.
// If format is specified, it validates and returns it.
// Otherwise, it auto-detects from the SHELL environment variable.
func detectShellFormat(userFormat string) shell.ShellFormat {
	// If user specified a format, use it
	if userFormat != "" {
		switch strings.ToLower(userFormat) {
		case "zsh":
			return shell.FormatZsh
		case "bash":
			return shell.FormatBash
		default:
			// Unknown format, default to bash
			return shell.FormatBash
		}
	}

	// Auto-detect from SHELL environment variable
	shellEnv := os.Getenv("SHELL")
	if strings.Contains(shellEnv, "zsh") {
		return shell.FormatZsh
	}

	// Default to bash
	return shell.FormatBash
}
