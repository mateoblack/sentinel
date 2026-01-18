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

	// For testing
	Stdout   *os.File
	Stderr   *os.File
	SSMFetch func(ctx context.Context, path string) ([]byte, error) // Override for testing
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
