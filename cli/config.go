package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/byteness/aws-vault/v7/config"
)

// ConfigValidateCommandInput contains the input for config validate.
type ConfigValidateCommandInput struct {
	Paths      []string // Local file paths to validate
	SSMPaths   []string // SSM paths to load and validate
	ConfigType string   // Override detected type (policy, approval, breakglass, ratelimit, bootstrap)
	Output     string   // human, json
	Region     string   // AWS region for SSM
	AWSProfile string   // Optional AWS profile for SSM credentials

	// For testing
	Stdout   *os.File
	Stderr   *os.File
	SSMFetch func(ctx context.Context, path string) ([]byte, error) // Override for testing
}

// ConfigGenerateCommandInput contains the input for config generate.
type ConfigGenerateCommandInput struct {
	Template   string   // basic, approvals, full
	Profiles   []string // AWS profiles to include
	Users      []string // Users for approvers/break-glass
	OutputDir  string   // Directory to write files (empty = stdout)
	JSONOutput bool     // Output as JSON instead of YAML files

	// For testing
	Stdout *os.File
	Stderr *os.File
}

// configCmd holds the config command reference for subcommand registration.
var configCmd *kingpin.CmdClause

// ConfigureConfigCommand sets up the config command with its subcommands.
func ConfigureConfigCommand(app *kingpin.Application, s *Sentinel) {
	configCmd = app.Command("config", "Configuration management commands")

	input := ConfigValidateCommandInput{}

	cmd := configCmd.Command("validate", "Validate configuration files")

	cmd.Arg("paths", "Local files to validate").
		StringsVar(&input.Paths)

	cmd.Flag("path", "Local file to validate (repeatable)").
		Short('p').
		StringsVar(&input.Paths)

	cmd.Flag("ssm", "SSM parameter to load and validate (repeatable)").
		StringsVar(&input.SSMPaths)

	cmd.Flag("type", "Config type: policy, approval, breakglass, ratelimit, bootstrap (auto-detect if not specified)").
		EnumVar(&input.ConfigType, "policy", "approval", "breakglass", "ratelimit", "bootstrap", "")

	cmd.Flag("output", "Output format: human (default), json").
		Default("human").
		EnumVar(&input.Output, "human", "json")

	cmd.Flag("region", "AWS region for SSM operations").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for SSM credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := ConfigValidateCommand(context.Background(), input)
		if err != nil {
			app.FatalIfError(err, "config validate")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})

	// Configure generate subcommand
	configureConfigGenerateCommand(configCmd, app)
}

// configureConfigGenerateCommand sets up the generate subcommand.
func configureConfigGenerateCommand(parent *kingpin.CmdClause, app *kingpin.Application) {
	genInput := ConfigGenerateCommandInput{}

	cmd := parent.Command("generate", "Generate configuration templates")

	cmd.Flag("template", "Template type: basic, approvals, full").
		Short('t').
		Required().
		EnumVar(&genInput.Template, "basic", "approvals", "full")

	cmd.Flag("profile", "AWS profile to include (repeatable)").
		Short('p').
		Required().
		StringsVar(&genInput.Profiles)

	cmd.Flag("user", "User for approvers/break-glass (repeatable, required for approvals/full)").
		Short('u').
		StringsVar(&genInput.Users)

	cmd.Flag("output-dir", "Directory to write config files (omit for stdout)").
		Short('o').
		StringVar(&genInput.OutputDir)

	cmd.Flag("json", "Output as JSON instead of YAML").
		BoolVar(&genInput.JSONOutput)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := ConfigGenerateCommand(genInput)
		if err != nil {
			app.FatalIfError(err, "config generate")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// ConfigValidateCommand executes the config validate command logic.
// It returns exit code (0=all valid, 1=errors) and any fatal error.
func ConfigValidateCommand(ctx context.Context, input ConfigValidateCommandInput) (int, error) {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Validate at least one path is specified
	if len(input.Paths) == 0 && len(input.SSMPaths) == 0 {
		err := fmt.Errorf("no paths specified; use positional arguments, --path, or --ssm")
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1, err
	}

	// Determine config type (if explicitly specified)
	var configType config.ConfigType
	if input.ConfigType != "" {
		configType = config.ConfigType(input.ConfigType)
		if !configType.IsValid() {
			err := fmt.Errorf("invalid config type: %s", input.ConfigType)
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1, err
		}
	}

	// Collect all results
	var results []config.ValidationResult

	// Validate local files
	for _, path := range input.Paths {
		// Skip empty paths (from combining args and flags)
		if path == "" {
			continue
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			results = append(results, config.ValidationResult{
				ConfigType: configType,
				Source:     path,
				Valid:      false,
				Issues: []config.ValidationIssue{{
					Severity:   config.SeverityError,
					Message:    fmt.Sprintf("failed to read file: %v", err),
					Suggestion: "verify the file path exists and is readable",
				}},
			})
			continue
		}

		// Detect or use specified type
		ct := configType
		if ct == "" {
			ct = config.DetectConfigType(content)
		}

		// Validate
		result := config.Validate(ct, content, path)
		results = append(results, result)
	}

	// Validate SSM parameters
	if len(input.SSMPaths) > 0 {
		// Create SSM fetcher
		ssmFetch := input.SSMFetch
		if ssmFetch == nil {
			// Load AWS config
			var opts []func(*awsconfig.LoadOptions) error
			if input.AWSProfile != "" {
				opts = append(opts, awsconfig.WithSharedConfigProfile(input.AWSProfile))
			}
			if input.Region != "" {
				opts = append(opts, awsconfig.WithRegion(input.Region))
			}
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
			if err != nil {
				formatErrorForConfig(stderr, fmt.Sprintf("failed to load AWS config: %v", err),
					"check AWS credentials and region configuration")
				return 1, err
			}
			ssmClient := ssm.NewFromConfig(awsCfg)
			ssmFetch = func(ctx context.Context, path string) ([]byte, error) {
				out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
					Name:           aws.String(path),
					WithDecryption: aws.Bool(true),
				})
				if err != nil {
					return nil, err
				}
				if out.Parameter == nil || out.Parameter.Value == nil {
					return nil, fmt.Errorf("parameter value is nil")
				}
				return []byte(*out.Parameter.Value), nil
			}
		}

		// Fetch and validate each SSM parameter
		for _, ssmPath := range input.SSMPaths {
			content, err := ssmFetch(ctx, ssmPath)
			if err != nil {
				results = append(results, config.ValidationResult{
					ConfigType: configType,
					Source:     ssmPath,
					Valid:      false,
					Issues: []config.ValidationIssue{{
						Severity:   config.SeverityError,
						Message:    fmt.Sprintf("failed to load SSM parameter: %v", err),
						Suggestion: "verify the SSM path exists and you have ssm:GetParameter permission",
					}},
				})
				continue
			}

			// Detect or use specified type
			ct := configType
			if ct == "" {
				ct = config.DetectConfigType(content)
			}

			// Validate
			result := config.Validate(ct, content, ssmPath)
			results = append(results, result)
		}
	}

	// Compute summary
	var summary config.ResultSummary
	summary.Compute(results)

	// Create aggregated results
	allResults := config.AllResults{
		Results: results,
		Summary: summary,
	}

	// Output results
	if strings.ToLower(input.Output) == "json" {
		outputJSON(stdout, allResults)
	} else {
		outputHuman(stdout, allResults)
	}

	// Return exit code
	if summary.Errors > 0 {
		return 1, nil
	}
	return 0, nil
}

// outputHuman outputs validation results in human-readable format.
func outputHuman(w *os.File, all config.AllResults) {
	total := len(all.Results)
	if total == 0 {
		fmt.Fprintln(w, "No configurations to validate.")
		return
	}

	fmt.Fprintf(w, "Validating %d configuration%s...\n\n", total, pluralize(total))

	for _, result := range all.Results {
		typeStr := ""
		if result.ConfigType != "" {
			typeStr = fmt.Sprintf(" (%s)", result.ConfigType)
		}

		if result.Valid {
			fmt.Fprintf(w, "# %s%s\n", result.Source, typeStr)
			fmt.Fprintln(w, "  Valid")
		} else {
			fmt.Fprintf(w, "X %s%s\n", result.Source, typeStr)

			// Group issues by severity
			var errors, warnings []config.ValidationIssue
			for _, issue := range result.Issues {
				if issue.Severity == config.SeverityError {
					errors = append(errors, issue)
				} else {
					warnings = append(warnings, issue)
				}
			}

			if len(errors) > 0 {
				fmt.Fprintln(w, "  Errors:")
				for _, issue := range errors {
					location := ""
					if issue.Location != "" {
						location = issue.Location + ": "
					}
					fmt.Fprintf(w, "    - %s%s\n", location, issue.Message)
				}
			}

			if len(warnings) > 0 {
				fmt.Fprintln(w, "  Warnings:")
				for _, issue := range warnings {
					location := ""
					if issue.Location != "" {
						location = issue.Location + ": "
					}
					fmt.Fprintf(w, "    - %s%s\n", location, issue.Message)
				}
			}

			// Show suggestions for errors
			if len(errors) > 0 {
				fmt.Fprintln(w, "  Suggestions:")
				seen := make(map[string]bool)
				for _, issue := range errors {
					if issue.Suggestion != "" && !seen[issue.Suggestion] {
						fmt.Fprintf(w, "    - %s\n", issue.Suggestion)
						seen[issue.Suggestion] = true
					}
				}
			}
		}

		// Show warnings for valid files
		if result.Valid && len(result.Issues) > 0 {
			fmt.Fprintln(w, "  Warnings:")
			for _, issue := range result.Issues {
				if issue.Severity == config.SeverityWarning {
					location := ""
					if issue.Location != "" {
						location = issue.Location + ": "
					}
					fmt.Fprintf(w, "    - %s%s\n", location, issue.Message)
				}
			}
		}

		fmt.Fprintln(w)
	}

	// Summary line
	fmt.Fprintf(w, "Summary: %d valid, %d invalid (%d errors, %d warnings)\n",
		all.Summary.Valid, all.Summary.Invalid, all.Summary.Errors, all.Summary.Warnings)
}

// outputJSON outputs validation results in JSON format.
func outputJSON(w *os.File, all config.AllResults) {
	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		fmt.Fprintf(w, `{"error": "failed to marshal JSON: %v"}`, err)
		return
	}
	fmt.Fprintln(w, string(data))
}

// formatErrorForConfig formats an error with suggestion for config command.
func formatErrorForConfig(w *os.File, msg, suggestion string) {
	fmt.Fprintf(w, "Error: %s\n", msg)
	if suggestion != "" {
		fmt.Fprintf(w, "\nSuggestion: %s\n", suggestion)
	}
}

// pluralize returns "s" if count != 1.
func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

// ConfigGenerateCommand executes the config generate command logic.
// It returns exit code (0=success, 1=error) and any fatal error.
func ConfigGenerateCommand(input ConfigGenerateCommandInput) (int, error) {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Validate template ID
	templateID := config.TemplateID(input.Template)
	if !templateID.IsValid() {
		err := fmt.Errorf("invalid template: %s (valid: basic, approvals, full)", input.Template)
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1, err
	}

	// Generate the template
	output, err := config.GenerateTemplate(templateID, input.Profiles, input.Users)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1, err
	}

	// Handle output mode
	if input.JSONOutput {
		return outputGenerateJSON(stdout, output)
	}

	if input.OutputDir != "" {
		return outputGenerateFiles(stdout, stderr, input.OutputDir, output)
	}

	return outputGenerateHumanReadable(stdout, output)
}

// outputGenerateJSON outputs the template as JSON.
func outputGenerateJSON(stdout *os.File, output *config.TemplateOutput) (int, error) {
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return 1, fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Fprintln(stdout, string(data))
	return 0, nil
}

// outputGenerateFiles writes templates to files in the specified directory.
func outputGenerateFiles(stdout, stderr *os.File, dir string, output *config.TemplateOutput) (int, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(stderr, "Error: failed to create directory %s: %v\n", dir, err)
		return 1, err
	}

	files := []struct {
		name    string
		content string
	}{
		{"policy.yaml", output.Policy},
		{"approval.yaml", output.Approval},
		{"breakglass.yaml", output.BreakGlass},
		{"ratelimit.yaml", output.RateLimit},
	}

	var written []string
	for _, f := range files {
		if f.content == "" {
			continue // Skip empty configs
		}
		path := dir + "/" + f.name
		if err := os.WriteFile(path, []byte(f.content), 0644); err != nil {
			fmt.Fprintf(stderr, "Error: failed to write %s: %v\n", path, err)
			return 1, err
		}
		written = append(written, f.name)
	}

	fmt.Fprintf(stdout, "Generated %d config file%s in %s:\n", len(written), pluralize(len(written)), dir)
	for _, name := range written {
		fmt.Fprintf(stdout, "  + %s\n", name)
	}

	return 0, nil
}

// outputGenerateHumanReadable outputs templates to stdout with section headers.
func outputGenerateHumanReadable(stdout *os.File, output *config.TemplateOutput) (int, error) {
	sections := []struct {
		title   string
		file    string
		content string
	}{
		{"Access Policy", "policy.yaml", output.Policy},
		{"Approval Policy", "approval.yaml", output.Approval},
		{"Break-Glass Policy", "breakglass.yaml", output.BreakGlass},
		{"Rate Limit Policy", "ratelimit.yaml", output.RateLimit},
	}

	first := true
	for _, s := range sections {
		if s.content == "" {
			continue
		}

		if !first {
			fmt.Fprintln(stdout) // Blank line between sections
		}
		first = false

		// Section header
		header := fmt.Sprintf("# %s (%s)", s.title, s.file)
		divider := strings.Repeat("=", len(header))
		fmt.Fprintf(stdout, "%s\n# %s\n", header, divider)
		fmt.Fprintln(stdout, s.content)
	}

	return 0, nil
}
