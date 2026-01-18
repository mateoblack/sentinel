package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/permissions"
)

// PermissionsCommandInput contains the input for the permissions command.
type PermissionsCommandInput struct {
	// Format is the output format (human, json, terraform, cloudformation, cf).
	Format string
	// Subsystem filters to a specific subsystem.
	Subsystem string
	// Feature filters to a specific feature.
	Feature string
	// RequiredOnly excludes optional features.
	RequiredOnly bool
	// Detect auto-detects configured features and shows only required permissions.
	Detect bool
	// Region specifies the AWS region for detection (only used with --detect).
	Region string

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File

	// Detector is an optional custom detector (for testing).
	// If nil, a new detector will be created using AWS config.
	Detector permissions.DetectorInterface
}

// permissionsCmd holds the permissions command reference for subcommand registration.
var permissionsCmd *kingpin.CmdClause

// ConfigurePermissionsCommand sets up the permissions command.
func ConfigurePermissionsCommand(app *kingpin.Application, s *Sentinel) {
	input := PermissionsCommandInput{}

	permissionsCmd = app.Command("permissions", "Show IAM permissions required by Sentinel features")

	permissionsCmd.Flag("format", "Output format: human, json, terraform, cloudformation (or cf)").
		Default("human").
		EnumVar(&input.Format, "human", "json", "terraform", "cloudformation", "cf")

	permissionsCmd.Flag("subsystem", "Filter by subsystem (core, credentials, approvals, breakglass, notifications, audit, enforce, bootstrap)").
		StringVar(&input.Subsystem)

	permissionsCmd.Flag("feature", "Filter by specific feature").
		StringVar(&input.Feature)

	permissionsCmd.Flag("required-only", "Exclude optional features (notify_sns, notify_webhook)").
		BoolVar(&input.RequiredOnly)

	permissionsCmd.Flag("detect", "Auto-detect configured features and show only required permissions").
		BoolVar(&input.Detect)

	permissionsCmd.Flag("region", "AWS region for detection (only used with --detect)").
		StringVar(&input.Region)

	permissionsCmd.Action(func(c *kingpin.ParseContext) error {
		err := PermissionsCommand(input)
		app.FatalIfError(err, "permissions")
		return nil
	})
}

// PermissionsCommand executes the permissions command logic.
// It outputs Sentinel's IAM permission requirements in the specified format.
func PermissionsCommand(input PermissionsCommandInput) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Check for mutual exclusivity: --detect cannot combine with --subsystem or --feature
	if input.Detect && (input.Subsystem != "" || input.Feature != "") {
		err := fmt.Errorf("--detect cannot be combined with --subsystem or --feature")
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return err
	}

	// Get permissions based on filters
	var perms []permissions.FeaturePermissions
	var err error

	if input.Detect {
		// Auto-detect configured features
		perms, err = detectPermissions(input, stderr)
		if err != nil {
			return err
		}
	} else if input.Feature != "" {
		// Filter by specific feature
		perms, err = getFeaturePermissions(input.Feature)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return err
		}
	} else if input.Subsystem != "" {
		// Filter by subsystem
		perms, err = getSubsystemPermissions(input.Subsystem)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return err
		}
	} else {
		// Get all permissions
		perms = permissions.GetAllPermissions()
	}

	// Apply required-only filter
	if input.RequiredOnly {
		perms = filterRequired(perms)
	}

	// Format and output
	format := strings.ToLower(input.Format)
	switch format {
	case "human":
		fmt.Fprint(stdout, permissions.FormatHuman(perms))
	case "json":
		output, err := permissions.FormatJSON(perms)
		if err != nil {
			fmt.Fprintf(stderr, "Error formatting JSON: %v\n", err)
			return err
		}
		fmt.Fprintln(stdout, output)
	case "terraform":
		fmt.Fprint(stdout, permissions.FormatTerraform(perms))
	case "cloudformation", "cf":
		fmt.Fprint(stdout, permissions.FormatCloudFormation(perms))
	default:
		err := fmt.Errorf("invalid format: %s (valid: human, json, terraform, cloudformation, cf)", input.Format)
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return err
	}

	return nil
}

// detectPermissions runs feature detection and returns permissions for detected features.
func detectPermissions(input PermissionsCommandInput, stderr *os.File) ([]permissions.FeaturePermissions, error) {
	ctx := context.Background()

	// Create or use provided detector
	detector := input.Detector
	if detector == nil {
		// Load AWS config
		var opts []func(*config.LoadOptions) error
		if input.Region != "" {
			opts = append(opts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to load AWS config for detection: %v\n", err)
			return nil, fmt.Errorf("failed to load AWS config for detection: %w", err)
		}
		detector = permissions.NewDetector(awsCfg)
	}

	// Run detection
	result, err := detector.Detect(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "Error: detection failed: %v\n", err)
		return nil, fmt.Errorf("detection failed: %w", err)
	}

	// Show detection summary to stderr (human format only)
	if strings.ToLower(input.Format) == "human" {
		fmt.Fprintf(stderr, "Detected features:\n")
		for _, f := range result.Features {
			fmt.Fprintf(stderr, "  - %s: %s\n", f, result.FeatureDetails[f])
		}
		if len(result.Errors) > 0 {
			fmt.Fprintf(stderr, "\nDetection warnings:\n")
			for _, e := range result.Errors {
				fmt.Fprintf(stderr, "  - %s: %s\n", e.Feature, e.Message)
			}
		}
		fmt.Fprintf(stderr, "\n")
	}

	// Get permissions for detected features
	var perms []permissions.FeaturePermissions
	for _, f := range result.Features {
		if fp, ok := permissions.GetFeaturePermissions(f); ok {
			perms = append(perms, fp)
		}
	}

	return perms, nil
}

// getFeaturePermissions returns permissions for a specific feature.
func getFeaturePermissions(featureName string) ([]permissions.FeaturePermissions, error) {
	feature := permissions.Feature(featureName)
	if !feature.IsValid() {
		validFeatures := make([]string, 0)
		for _, f := range permissions.AllFeatures() {
			validFeatures = append(validFeatures, string(f))
		}
		return nil, fmt.Errorf("invalid feature: %s (valid: %s)", featureName, strings.Join(validFeatures, ", "))
	}

	fp, ok := permissions.GetFeaturePermissions(feature)
	if !ok {
		return nil, fmt.Errorf("feature not found: %s", featureName)
	}

	return []permissions.FeaturePermissions{fp}, nil
}

// getSubsystemPermissions returns permissions for a specific subsystem.
func getSubsystemPermissions(subsystemName string) ([]permissions.FeaturePermissions, error) {
	subsystem := permissions.Subsystem(subsystemName)
	if !subsystem.IsValid() {
		validSubsystems := make([]string, 0)
		for _, s := range permissions.AllSubsystems() {
			validSubsystems = append(validSubsystems, string(s))
		}
		return nil, fmt.Errorf("invalid subsystem: %s (valid: %s)", subsystemName, strings.Join(validSubsystems, ", "))
	}

	return permissions.GetSubsystemPermissions(subsystem), nil
}

// filterRequired returns only non-optional permissions.
func filterRequired(perms []permissions.FeaturePermissions) []permissions.FeaturePermissions {
	result := make([]permissions.FeaturePermissions, 0, len(perms))
	for _, fp := range perms {
		if !fp.Optional {
			result = append(result, fp)
		}
	}
	return result
}

// PermissionsCheckCommandInput contains the input for the permissions check command.
type PermissionsCheckCommandInput struct {
	// Format is the output format (human, json).
	Format string
	// Features specifies features to check (comma-separated).
	Features string
	// Detect auto-detects configured features.
	Detect bool
	// Region specifies the AWS region for API calls.
	Region string

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File

	// Checker is an optional custom checker (for testing).
	// If nil, a new checker will be created using AWS config.
	Checker permissions.CheckerInterface

	// Detector is an optional custom detector (for testing with --detect).
	// If nil, a new detector will be created using AWS config.
	Detector permissions.DetectorInterface
}

// PermissionsCheckOutput represents the JSON output from the permissions check command.
type PermissionsCheckOutput struct {
	Results []PermissionsCheckResultJSON `json:"results"`
	Summary PermissionsCheckSummaryJSON  `json:"summary"`
}

// PermissionsCheckResultJSON represents a single check result in JSON format.
type PermissionsCheckResultJSON struct {
	Feature  string `json:"feature"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
}

// PermissionsCheckSummaryJSON represents the summary in JSON format.
type PermissionsCheckSummaryJSON struct {
	Passed int `json:"passed"`
	Failed int `json:"failed"`
	Errors int `json:"errors"`
}

// ConfigurePermissionsCheckCommand sets up the permissions check subcommand.
// Must be called after ConfigurePermissionsCommand.
func ConfigurePermissionsCheckCommand(app *kingpin.Application, s *Sentinel) {
	if permissionsCmd == nil {
		return // permissions command not configured yet
	}

	input := PermissionsCheckCommandInput{}

	// Add check as subcommand of permissions
	// Note: Subcommand flags are separate from parent flags in kingpin
	checkCmd := permissionsCmd.Command("check", "Validate AWS credentials have required permissions")

	checkCmd.Flag("auto-detect", "Auto-detect configured features and check only those").
		BoolVar(&input.Detect)

	checkCmd.Flag("features", "Check specific feature(s), comma-separated (e.g., policy_load,credential_issue)").
		StringVar(&input.Features)

	checkCmd.Flag("output", "Output format: human (default), json").
		Default("human").
		EnumVar(&input.Format, "human", "json")

	checkCmd.Flag("aws-region", "AWS region for API calls").
		StringVar(&input.Region)

	checkCmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := PermissionsCheckCommand(input)
		if err != nil {
			app.FatalIfError(err, "permissions check")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// PermissionsCheckCommand executes the permissions check command logic.
// It returns an exit code (0 = all passed, 1 = failures or errors) and any fatal error.
func PermissionsCheckCommand(input PermissionsCheckCommandInput) (int, error) {
	ctx := context.Background()

	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Validate flags: --detect and --feature are mutually exclusive
	if input.Detect && input.Features != "" {
		err := fmt.Errorf("--detect and --feature are mutually exclusive")
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1, err
	}

	// Determine features to check
	var features []permissions.Feature
	var err error

	if input.Detect {
		// Auto-detect features
		features, err = detectFeaturesForCheck(ctx, input, stderr)
		if err != nil {
			return 1, err
		}
	} else if input.Features != "" {
		// Parse comma-separated feature list
		features, err = parseFeatureList(input.Features)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1, err
		}
	} else {
		// Check all features
		features = permissions.AllFeatures()
	}

	// Create or use provided checker
	checker := input.Checker
	if checker == nil {
		var opts []func(*config.LoadOptions) error
		if input.Region != "" {
			opts = append(opts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to load AWS config: %v\n", err)
			return 1, fmt.Errorf("failed to load AWS config: %w", err)
		}
		checker = permissions.NewChecker(awsCfg)
	}

	// Run the check
	summary, err := checker.Check(ctx, features)
	if err != nil {
		fmt.Fprintf(stderr, "Error: check failed: %v\n", err)
		return 1, fmt.Errorf("check failed: %w", err)
	}

	// Format output
	format := strings.ToLower(input.Format)
	switch format {
	case "human":
		formatPermissionsCheckHuman(stdout, summary, features)
	case "json":
		if err := formatPermissionsCheckJSON(stdout, summary); err != nil {
			fmt.Fprintf(stderr, "Error formatting JSON: %v\n", err)
			return 1, err
		}
	}

	// Return exit code based on results
	if summary.FailCount > 0 || summary.ErrorCount > 0 {
		return 1, nil
	}
	return 0, nil
}

// detectFeaturesForCheck runs detection and returns the detected features.
func detectFeaturesForCheck(ctx context.Context, input PermissionsCheckCommandInput, stderr *os.File) ([]permissions.Feature, error) {
	detector := input.Detector
	if detector == nil {
		var opts []func(*config.LoadOptions) error
		if input.Region != "" {
			opts = append(opts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to load AWS config for detection: %v\n", err)
			return nil, fmt.Errorf("failed to load AWS config for detection: %w", err)
		}
		detector = permissions.NewDetector(awsCfg)
	}

	result, err := detector.Detect(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "Error: detection failed: %v\n", err)
		return nil, fmt.Errorf("detection failed: %w", err)
	}

	return result.Features, nil
}

// parseFeatureList parses a comma-separated list of features.
func parseFeatureList(featureStr string) ([]permissions.Feature, error) {
	parts := strings.Split(featureStr, ",")
	features := make([]permissions.Feature, 0, len(parts))

	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		feature := permissions.Feature(name)
		if !feature.IsValid() {
			validFeatures := make([]string, 0)
			for _, f := range permissions.AllFeatures() {
				validFeatures = append(validFeatures, string(f))
			}
			return nil, fmt.Errorf("invalid feature: %s (valid: %s)", name, strings.Join(validFeatures, ", "))
		}
		features = append(features, feature)
	}

	if len(features) == 0 {
		return nil, fmt.Errorf("no valid features specified")
	}

	return features, nil
}

// formatPermissionsCheckHuman outputs check results in human-readable format.
func formatPermissionsCheckHuman(w *os.File, summary *permissions.CheckSummary, features []permissions.Feature) {
	fmt.Fprintf(w, "Checking permissions for %d features...\n\n", len(features))

	// Group results by feature
	byFeature := make(map[permissions.Feature][]permissions.CheckResult)
	for _, r := range summary.Results {
		byFeature[r.Feature] = append(byFeature[r.Feature], r)
	}

	// Output results by feature
	for _, feature := range features {
		results, ok := byFeature[feature]
		if !ok {
			continue
		}

		// Determine feature status
		featurePassed := true
		featureError := false
		for _, r := range results {
			if r.Status == permissions.StatusDenied {
				featurePassed = false
			}
			if r.Status == permissions.StatusError {
				featureError = true
			}
		}

		// Feature header with status icon
		if featureError {
			fmt.Fprintf(w, "? %s\n", feature)
		} else if featurePassed {
			fmt.Fprintf(w, "# %s\n", feature)
		} else {
			fmt.Fprintf(w, "X %s\n", feature)
		}

		// Individual permission results
		for _, r := range results {
			switch r.Status {
			case permissions.StatusAllowed:
				fmt.Fprintf(w, "  # %s on %s\n", r.Action, r.Resource)
			case permissions.StatusDenied:
				fmt.Fprintf(w, "  X %s on %s - %s\n", r.Action, r.Resource, r.Message)
			case permissions.StatusError:
				fmt.Fprintf(w, "  ? %s on %s - %s\n", r.Action, r.Resource, r.Message)
			}
		}
		fmt.Fprintln(w)
	}

	// Summary
	fmt.Fprintf(w, "Summary: %d passed, %d failed, %d error\n", summary.PassCount, summary.FailCount, summary.ErrorCount)
}

// formatPermissionsCheckJSON outputs check results in JSON format.
func formatPermissionsCheckJSON(w *os.File, summary *permissions.CheckSummary) error {
	output := PermissionsCheckOutput{
		Results: make([]PermissionsCheckResultJSON, 0, len(summary.Results)),
		Summary: PermissionsCheckSummaryJSON{
			Passed: summary.PassCount,
			Failed: summary.FailCount,
			Errors: summary.ErrorCount,
		},
	}

	for _, r := range summary.Results {
		output.Results = append(output.Results, PermissionsCheckResultJSON{
			Feature:  string(r.Feature),
			Action:   r.Action,
			Resource: r.Resource,
			Status:   string(r.Status),
			Message:  r.Message,
		})
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Fprintln(w, string(data))
	return nil
}
