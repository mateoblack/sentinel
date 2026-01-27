package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/deploy"
)

// SCPTemplateCommandInput contains the input for the scp template command.
type SCPTemplateCommandInput struct {
	Format     string   // json, yaml, terraform, cloudformation
	OutputFile string   // "" means stdout
	Stdout     *os.File
	Stderr     *os.File
}

// ConfigureSCPTemplateCommand sets up the scp template command.
func ConfigureSCPTemplateCommand(app *kingpin.Application, s *Sentinel) {
	input := SCPTemplateCommandInput{}

	// Create scp command group
	scpCmd := app.Command("scp", "Service Control Policy operations")

	// Create template subcommand
	cmd := scpCmd.Command("template", "Output Sentinel SCP policy template for manual deployment")

	cmd.Flag("format", "Output format: json, yaml, terraform, cloudformation").
		Default("json").
		EnumVar(&input.Format, "json", "yaml", "terraform", "cloudformation")

	cmd.Flag("output", "Output file (default: stdout)").
		Short('o').
		StringVar(&input.OutputFile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode := SCPTemplateCommand(context.Background(), input)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})

	// Hidden deploy command that shows deprecation error
	deployCmd := scpCmd.Command("deploy", "DEPRECATED: Use 'scp template' instead").Hidden()
	deployCmd.Action(func(c *kingpin.ParseContext) error {
		fmt.Fprintln(os.Stderr, "Error: The 'sentinel scp deploy' command has been removed for security reasons (SCP-T-01).")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "SCPs can lock out entire AWS Organizations including management accounts.")
		fmt.Fprintln(os.Stderr, "Use 'sentinel scp template' to generate the SCP policy, then deploy through")
		fmt.Fprintln(os.Stderr, "your organization's change management process.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Example: sentinel scp template --format terraform > sentinel-scp.tf")
		os.Exit(1)
		return nil
	})
}

// SCPTemplateCommand executes the scp template command logic.
// It outputs the Sentinel SCP policy in the requested format.
// Returns exit code: 0=success, 1=failure.
func SCPTemplateCommand(ctx context.Context, input SCPTemplateCommandInput) int {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Generate output based on format
	var output string
	var err error

	switch input.Format {
	case "json":
		output = deploy.GetSCPPolicyJSON()
	case "yaml":
		output, err = deploy.GetSCPPolicyYAML()
		if err != nil {
			fmt.Fprintf(stderr, "Error generating YAML output: %v\n", err)
			return 1
		}
	case "terraform":
		output = deploy.GetSCPTerraform()
	case "cloudformation":
		output = deploy.GetSCPCloudFormation()
	default:
		fmt.Fprintf(stderr, "Error: unknown format %q\n", input.Format)
		return 1
	}

	// Write output
	if input.OutputFile != "" {
		// Write to file
		err := os.WriteFile(input.OutputFile, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(stderr, "Error writing to file %s: %v\n", input.OutputFile, err)
			return 1
		}
		fmt.Fprintf(stdout, "SCP template written to %s\n", input.OutputFile)
	} else {
		// Write to stdout
		fmt.Fprint(stdout, output)
	}

	return 0
}
