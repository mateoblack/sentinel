package cli

import (
	"context"
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

// ConfigurePermissionsCommand sets up the permissions command.
func ConfigurePermissionsCommand(app *kingpin.Application, s *Sentinel) {
	input := PermissionsCommandInput{}

	cmd := app.Command("permissions", "Show IAM permissions required by Sentinel features")

	cmd.Flag("format", "Output format: human, json, terraform, cloudformation (or cf)").
		Default("human").
		EnumVar(&input.Format, "human", "json", "terraform", "cloudformation", "cf")

	cmd.Flag("subsystem", "Filter by subsystem (core, credentials, approvals, breakglass, notifications, audit, enforce, bootstrap)").
		StringVar(&input.Subsystem)

	cmd.Flag("feature", "Filter by specific feature").
		StringVar(&input.Feature)

	cmd.Flag("required-only", "Exclude optional features (notify_sns, notify_webhook)").
		BoolVar(&input.RequiredOnly)

	cmd.Flag("detect", "Auto-detect configured features and show only required permissions").
		BoolVar(&input.Detect)

	cmd.Flag("region", "AWS region for detection (only used with --detect)").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
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
