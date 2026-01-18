package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/bootstrap"
	"github.com/byteness/aws-vault/v7/permissions"
	"github.com/byteness/aws-vault/v7/vault"
)

// WizardStep represents the current step in the wizard flow.
type WizardStep int

const (
	StepWelcome WizardStep = iota
	StepProfiles
	StepFeatures
	StepRegion
	StepOutputOptions
	StepSummary
	StepComplete
)

// WizardState holds the state accumulated during wizard execution.
type WizardState struct {
	// User selections
	Profiles       []string            // AWS profiles to configure
	Features       []permissions.Feature // Selected features
	Region         string              // AWS region
	GenerateIAM    bool                // Generate IAM policy
	GenerateSample bool                // Generate sample policies

	// Detection results (optional)
	DetectionResult *permissions.DetectionResult

	// Outputs
	IAMPolicy      string            // Generated IAM policy JSON
	SamplePolicies map[string]string // profile -> sample policy YAML
}

// InitWizardCommandInput contains the input for the init wizard command.
type InitWizardCommandInput struct {
	// Non-interactive mode flags (for scripting)
	Profiles      []string
	Features      []string
	Region        string
	SkipDetection bool
	OutputFormat  string // human, json

	// I/O for testing
	Stdin  *bufio.Scanner
	Stdout *os.File
	Stderr *os.File

	// Detector for testing
	Detector permissions.DetectorInterface
}

// InitWizardJSONOutput represents the JSON output from the wizard.
type InitWizardJSONOutput struct {
	Profiles       []string          `json:"profiles"`
	Features       []string          `json:"features"`
	Region         string            `json:"region"`
	IAMPolicy      json.RawMessage   `json:"iam_policy"`
	SamplePolicies map[string]string `json:"sample_policies"`
	NextSteps      []string          `json:"next_steps"`
}

// discoverProfiles parses ~/.aws/config to find available profiles.
func discoverProfiles() ([]string, error) {
	configFile, err := vault.LoadConfigFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return configFile.ProfileNames(), nil
}

// promptMultiSelect prompts for multiple selection with numbered options.
// Returns the selected items.
func promptMultiSelect(prompt string, options []string, stdin *bufio.Scanner, stdout *os.File) ([]string, error) {
	// Display options
	for i, opt := range options {
		fmt.Fprintf(stdout, "  [%d] %s\n", i+1, opt)
	}
	fmt.Fprintf(stdout, "\n%s (comma-separated, e.g., 1,2,3 or 'all'): ", prompt)

	if !stdin.Scan() {
		return nil, fmt.Errorf("error reading input")
	}

	input := strings.TrimSpace(stdin.Text())
	if input == "" {
		return nil, fmt.Errorf("no selection made")
	}

	// Handle "all" input
	if strings.ToLower(input) == "all" {
		return options, nil
	}

	// Parse comma-separated indices
	parts := strings.Split(input, ",")
	selected := make([]string, 0, len(parts))
	seen := make(map[int]bool)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid selection '%s': must be a number", part)
		}
		if idx < 1 || idx > len(options) {
			return nil, fmt.Errorf("invalid selection %d: must be between 1 and %d", idx, len(options))
		}
		if !seen[idx] {
			seen[idx] = true
			selected = append(selected, options[idx-1])
		}
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("no valid selection made")
	}

	return selected, nil
}

// promptYesNo prompts for a yes/no answer with a default.
func promptYesNo(prompt string, defaultYes bool, stdin *bufio.Scanner, stdout *os.File) (bool, error) {
	defaultHint := "[y/N]"
	if defaultYes {
		defaultHint = "[Y/n]"
	}
	fmt.Fprintf(stdout, "%s %s: ", prompt, defaultHint)

	if !stdin.Scan() {
		return defaultYes, nil
	}

	input := strings.TrimSpace(strings.ToLower(stdin.Text()))
	if input == "" {
		return defaultYes, nil
	}

	switch input {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return defaultYes, nil
	}
}

// promptSingleSelect prompts for a single selection from options.
func promptSingleSelect(prompt string, options []string, defaultValue string, stdin *bufio.Scanner, stdout *os.File) (string, error) {
	// Display options
	for i, opt := range options {
		marker := ""
		if opt == defaultValue {
			marker = " (default)"
		}
		fmt.Fprintf(stdout, "  [%d] %s%s\n", i+1, opt, marker)
	}
	fmt.Fprintf(stdout, "\n%s: ", prompt)

	if !stdin.Scan() {
		if defaultValue != "" {
			return defaultValue, nil
		}
		return "", fmt.Errorf("error reading input")
	}

	input := strings.TrimSpace(stdin.Text())
	if input == "" {
		if defaultValue != "" {
			return defaultValue, nil
		}
		return "", fmt.Errorf("no selection made")
	}

	// Try to parse as index
	idx, err := strconv.Atoi(input)
	if err == nil {
		if idx >= 1 && idx <= len(options) {
			return options[idx-1], nil
		}
		return "", fmt.Errorf("invalid selection %d: must be between 1 and %d", idx, len(options))
	}

	// Try to match as string
	for _, opt := range options {
		if strings.EqualFold(opt, input) {
			return opt, nil
		}
	}

	return input, nil // Return as-is for custom input
}

// promptString prompts for a string with optional default.
func promptString(prompt string, defaultValue string, stdin *bufio.Scanner, stdout *os.File) (string, error) {
	if defaultValue != "" {
		fmt.Fprintf(stdout, "%s (Press Enter for %s): ", prompt, defaultValue)
	} else {
		fmt.Fprintf(stdout, "%s: ", prompt)
	}

	if !stdin.Scan() {
		if defaultValue != "" {
			return defaultValue, nil
		}
		return "", fmt.Errorf("error reading input")
	}

	input := strings.TrimSpace(stdin.Text())
	if input == "" {
		return defaultValue, nil
	}

	return input, nil
}

// getFeatureOptions returns the list of features with descriptions.
func getFeatureOptions() []string {
	return []string{
		"policy_load        - Load policies from SSM (required)",
		"credential_issue   - Issue credentials with SourceIdentity (required)",
		"approval_workflow  - Request/approve access flow",
		"breakglass         - Emergency access bypass",
		"audit_verify       - CloudTrail session verification",
		"enforce_analyze    - IAM trust policy analysis",
		"bootstrap_plan     - Bootstrap planning",
		"bootstrap_apply    - Bootstrap SSM parameter creation",
		"notify_sns         - SNS notifications (optional)",
	}
}

// parseFeatureName extracts the feature name from the display string.
func parseFeatureName(display string) string {
	parts := strings.SplitN(display, " ", 2)
	return strings.TrimSpace(parts[0])
}

// generateWizardOutputs generates the IAM policy and sample policies based on state.
func generateWizardOutputs(state *WizardState) error {
	// Generate IAM policy
	var perms []permissions.FeaturePermissions
	for _, f := range state.Features {
		if fp, ok := permissions.GetFeaturePermissions(f); ok {
			perms = append(perms, fp)
		}
	}

	if state.GenerateIAM && len(perms) > 0 {
		iamPolicy, err := permissions.FormatJSON(perms)
		if err != nil {
			return fmt.Errorf("failed to generate IAM policy: %w", err)
		}
		state.IAMPolicy = iamPolicy
	}

	// Generate sample policies
	if state.GenerateSample && len(state.Profiles) > 0 {
		state.SamplePolicies = make(map[string]string)
		for _, profile := range state.Profiles {
			policyYAML, err := bootstrap.GenerateSamplePolicy(profile, "")
			if err != nil {
				return fmt.Errorf("failed to generate sample policy for %s: %w", profile, err)
			}
			state.SamplePolicies[profile] = policyYAML
		}
	}

	return nil
}

// formatNextSteps generates the next steps text based on state.
func formatNextSteps(state *WizardState) []string {
	steps := make([]string, 0)

	steps = append(steps, "1. Create the IAM policy and attach to your Sentinel user/role")

	if len(state.Profiles) > 0 {
		profilesArg := ""
		for _, p := range state.Profiles {
			profilesArg += fmt.Sprintf(" --profile %s", p)
		}
		regionArg := ""
		if state.Region != "" {
			regionArg = fmt.Sprintf(" --region %s", state.Region)
		}
		steps = append(steps, fmt.Sprintf("2. Save the sample policies to SSM:\n   sentinel init bootstrap%s%s", profilesArg, regionArg))
	}

	steps = append(steps, "3. Verify permissions:\n   sentinel permissions check --auto-detect")

	steps = append(steps, "4. Configure credential_process in ~/.aws/config:\n   [profile production]\n   credential_process = sentinel credentials --profile production")

	return steps
}

// runWizardInteractive runs the wizard in interactive mode.
func runWizardInteractive(ctx context.Context, input InitWizardCommandInput, state *WizardState, stdin *bufio.Scanner, stdout, stderr *os.File) error {
	totalSteps := 6

	// Step 1: Welcome
	fmt.Fprintf(stdout, "\nStep 1/%d: Welcome\n", totalSteps)
	fmt.Fprintln(stdout, strings.Repeat("=", 54))
	fmt.Fprintln(stdout, "Welcome to Sentinel!")
	fmt.Fprintln(stdout, "\nThis wizard will help you configure Sentinel for your AWS environment.")
	fmt.Fprintln(stdout, "")

	// Step 2: Profile Selection
	fmt.Fprintf(stdout, "Step 2/%d: Profile Selection\n", totalSteps)
	fmt.Fprintln(stdout, strings.Repeat("=", 54))

	if len(input.Profiles) > 0 {
		// Pre-selected via flags
		state.Profiles = input.Profiles
		fmt.Fprintf(stdout, "Using pre-selected profiles: %s\n\n", strings.Join(state.Profiles, ", "))
	} else {
		// Discover and prompt
		profiles, err := discoverProfiles()
		if err != nil {
			fmt.Fprintf(stderr, "Warning: Could not discover AWS profiles: %v\n", err)
			profiles = []string{}
		}

		if len(profiles) == 0 {
			fmt.Fprintln(stdout, "No AWS profiles found in ~/.aws/config.")
			fmt.Fprintln(stdout, "You can add profiles later using `sentinel init bootstrap`.")
			fmt.Fprintln(stdout, "")
		} else {
			fmt.Fprintf(stdout, "Found %d AWS profiles in ~/.aws/config:\n\n", len(profiles))
			selected, err := promptMultiSelect("Which profiles should Sentinel manage?", profiles, stdin, stdout)
			if err != nil {
				return fmt.Errorf("profile selection failed: %w", err)
			}
			state.Profiles = selected
			fmt.Fprintf(stdout, "\nSelected: %s\n\n", strings.Join(state.Profiles, ", "))
		}
	}

	// Step 3: Feature Selection
	fmt.Fprintf(stdout, "Step 3/%d: Feature Selection\n", totalSteps)
	fmt.Fprintln(stdout, strings.Repeat("=", 54))
	fmt.Fprintln(stdout, "Which features do you need?")
	fmt.Fprintln(stdout, "")

	if len(input.Features) > 0 {
		// Pre-selected via flags
		for _, f := range input.Features {
			state.Features = append(state.Features, permissions.Feature(f))
		}
		featureNames := make([]string, len(state.Features))
		for i, f := range state.Features {
			featureNames[i] = string(f)
		}
		fmt.Fprintf(stdout, "Using pre-selected features: %s\n\n", strings.Join(featureNames, ", "))
	} else {
		// Prompt for features
		featureOptions := getFeatureOptions()
		selected, err := promptMultiSelect("Select features", featureOptions, stdin, stdout)
		if err != nil {
			return fmt.Errorf("feature selection failed: %w", err)
		}
		for _, s := range selected {
			featureName := parseFeatureName(s)
			state.Features = append(state.Features, permissions.Feature(featureName))
		}
		featureNames := make([]string, len(state.Features))
		for i, f := range state.Features {
			featureNames[i] = string(f)
		}
		fmt.Fprintf(stdout, "\nSelected: %s\n\n", strings.Join(featureNames, ", "))
	}

	// Step 4: AWS Region
	fmt.Fprintf(stdout, "Step 4/%d: AWS Region\n", totalSteps)
	fmt.Fprintln(stdout, strings.Repeat("=", 54))

	if input.Region != "" {
		state.Region = input.Region
		fmt.Fprintf(stdout, "Using pre-selected region: %s\n\n", state.Region)
	} else {
		region, err := promptString("Which AWS region for SSM/DynamoDB resources?", "us-east-1", stdin, stdout)
		if err != nil {
			return fmt.Errorf("region selection failed: %w", err)
		}
		state.Region = region
		fmt.Fprintf(stdout, "\nSelected: %s\n\n", state.Region)
	}

	// Step 5: Output Options
	fmt.Fprintf(stdout, "Step 5/%d: Output Options\n", totalSteps)
	fmt.Fprintln(stdout, strings.Repeat("=", 54))

	genIAM, err := promptYesNo("Generate IAM policy document?", true, stdin, stdout)
	if err != nil {
		return fmt.Errorf("output options failed: %w", err)
	}
	state.GenerateIAM = genIAM

	genSample, err := promptYesNo("Generate sample Sentinel policies?", true, stdin, stdout)
	if err != nil {
		return fmt.Errorf("output options failed: %w", err)
	}
	state.GenerateSample = genSample
	fmt.Fprintln(stdout, "")

	// Step 6: Summary
	fmt.Fprintf(stdout, "Step 6/%d: Summary\n", totalSteps)
	fmt.Fprintln(stdout, strings.Repeat("=", 54))
	fmt.Fprintln(stdout, "Configuration Summary:")
	fmt.Fprintln(stdout, "")
	fmt.Fprintf(stdout, "Profiles: %s\n", strings.Join(state.Profiles, ", "))
	featureNames := make([]string, len(state.Features))
	for i, f := range state.Features {
		featureNames[i] = string(f)
	}
	fmt.Fprintf(stdout, "Features: %s\n", strings.Join(featureNames, ", "))
	fmt.Fprintf(stdout, "Region: %s\n", state.Region)
	fmt.Fprintf(stdout, "IAM Policy: %v\n", state.GenerateIAM)
	fmt.Fprintf(stdout, "Sample Policies: %v\n", state.GenerateSample)
	fmt.Fprintln(stdout, "")

	proceed, err := promptYesNo("Proceed?", true, stdin, stdout)
	if err != nil {
		return fmt.Errorf("confirmation failed: %w", err)
	}
	if !proceed {
		fmt.Fprintln(stdout, "\nCancelled.")
		return nil
	}

	return nil
}

// runWizardNonInteractive runs the wizard with pre-provided values.
func runWizardNonInteractive(input InitWizardCommandInput, state *WizardState) error {
	// Set values from flags
	state.Profiles = input.Profiles
	for _, f := range input.Features {
		state.Features = append(state.Features, permissions.Feature(f))
	}
	state.Region = input.Region
	state.GenerateIAM = true
	state.GenerateSample = len(state.Profiles) > 0

	return nil
}

// outputWizardResults outputs the wizard results based on format.
func outputWizardResults(state *WizardState, format string, stdout *os.File) error {
	if format == "json" {
		return outputWizardJSON(state, stdout)
	}
	return outputWizardHuman(state, stdout)
}

// outputWizardHuman outputs the wizard results in human-readable format.
func outputWizardHuman(state *WizardState, stdout *os.File) error {
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, strings.Repeat("=", 54))
	fmt.Fprintln(stdout, "Output")
	fmt.Fprintln(stdout, strings.Repeat("=", 54))

	if state.GenerateIAM && state.IAMPolicy != "" {
		fmt.Fprintln(stdout, "\n--- IAM Policy ---")
		fmt.Fprintln(stdout, state.IAMPolicy)
	}

	if state.GenerateSample && len(state.SamplePolicies) > 0 {
		for profile, policyYAML := range state.SamplePolicies {
			fmt.Fprintf(stdout, "\n--- Sample Policy: %s ---\n", profile)
			fmt.Fprintln(stdout, policyYAML)
		}
	}

	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, strings.Repeat("=", 54))
	fmt.Fprintln(stdout, "Next Steps")
	fmt.Fprintln(stdout, strings.Repeat("=", 54))

	nextSteps := formatNextSteps(state)
	for _, step := range nextSteps {
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, step)
	}

	return nil
}

// outputWizardJSON outputs the wizard results in JSON format.
func outputWizardJSON(state *WizardState, stdout *os.File) error {
	featureNames := make([]string, len(state.Features))
	for i, f := range state.Features {
		featureNames[i] = string(f)
	}

	// Parse IAM policy as raw JSON
	var iamPolicy json.RawMessage
	if state.IAMPolicy != "" {
		iamPolicy = json.RawMessage(state.IAMPolicy)
	} else {
		iamPolicy = json.RawMessage("{}")
	}

	output := InitWizardJSONOutput{
		Profiles:       state.Profiles,
		Features:       featureNames,
		Region:         state.Region,
		IAMPolicy:      iamPolicy,
		SamplePolicies: state.SamplePolicies,
		NextSteps:      formatNextSteps(state),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Fprintln(stdout, string(data))
	return nil
}

// initWizardCmd holds the init wizard command reference for subcommand registration.
var initWizardCmd *kingpin.CmdClause

// ConfigureInitWizardCommand sets up the init wizard command as a subcommand of init.
// Structure:
//   sentinel init wizard   # Runs the wizard (this command)
//   sentinel init bootstrap # Runs bootstrap (existing)
//   sentinel init status    # Shows status (existing)
func ConfigureInitWizardCommand(app *kingpin.Application, s *Sentinel) {
	input := InitWizardCommandInput{}

	// Get or create the init command
	initCmd := app.GetCommand("init")
	if initCmd == nil {
		initCmd = app.Command("init", "Initialize Sentinel infrastructure")
	}

	// Create wizard as a subcommand of init
	initWizardCmd = initCmd.Command("wizard", "Interactive setup wizard for Sentinel configuration")

	initWizardCmd.Flag("profile", "Pre-select profiles (repeatable)").
		StringsVar(&input.Profiles)

	initWizardCmd.Flag("feature", "Pre-select features (repeatable)").
		StringsVar(&input.Features)

	initWizardCmd.Flag("region", "AWS region").
		StringVar(&input.Region)

	initWizardCmd.Flag("skip-detection", "Skip auto-detection step").
		BoolVar(&input.SkipDetection)

	initWizardCmd.Flag("format", "Output format: human (default), json").
		Default("human").
		EnumVar(&input.OutputFormat, "human", "json")

	initWizardCmd.Action(func(c *kingpin.ParseContext) error {
		err := InitWizardCommand(context.Background(), input)
		app.FatalIfError(err, "init wizard")
		return nil
	})
}

// InitWizardCommand executes the init wizard command logic.
func InitWizardCommand(ctx context.Context, input InitWizardCommandInput) error {
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
		stdin = bufio.NewScanner(os.Stdin)
	}

	state := &WizardState{
		Profiles:       []string{},
		Features:       []permissions.Feature{},
		SamplePolicies: make(map[string]string),
	}

	// Determine mode: interactive or non-interactive
	isNonInteractive := len(input.Profiles) > 0 && len(input.Features) > 0

	if isNonInteractive {
		// Non-interactive mode with pre-provided values
		if err := runWizardNonInteractive(input, state); err != nil {
			return err
		}
	} else {
		// Interactive mode
		if err := runWizardInteractive(ctx, input, state, stdin, stdout, stderr); err != nil {
			return err
		}

		// Check if user cancelled
		if len(state.Features) == 0 && !state.GenerateIAM && !state.GenerateSample {
			return nil
		}
	}

	// Generate outputs
	if err := generateWizardOutputs(state); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return err
	}

	// Output results
	return outputWizardResults(state, input.OutputFormat, stdout)
}
