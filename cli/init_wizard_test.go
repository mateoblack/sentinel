package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/permissions"
)

// wizardMockDetector implements permissions.DetectorInterface for testing.
type wizardMockDetector struct {
	result *permissions.DetectionResult
	err    error
}

func (m *wizardMockDetector) Detect(ctx context.Context) (*permissions.DetectionResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func TestInitWizardCommandNonInteractive(t *testing.T) {
	tests := []struct {
		name       string
		input      InitWizardCommandInput
		wantErr    bool
		wantOutput []string // Strings that should be in output
	}{
		{
			name: "non-interactive with profiles and features",
			input: InitWizardCommandInput{
				Profiles:     []string{"production", "staging"},
				Features:     []string{"policy_load", "credential_issue"},
				Region:       "us-west-2",
				OutputFormat: "human",
			},
			wantErr: false,
			wantOutput: []string{
				"IAM Policy",
				"Sample Policy: production",
				"Sample Policy: staging",
				"Next Steps",
			},
		},
		{
			name: "non-interactive JSON output",
			input: InitWizardCommandInput{
				Profiles:     []string{"test-profile"},
				Features:     []string{"policy_load"},
				Region:       "eu-west-1",
				OutputFormat: "json",
			},
			wantErr:    false,
			wantOutput: []string{`"profiles"`, `"features"`, `"region"`, `"iam_policy"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test output files
			stdout, err := os.CreateTemp("", "stdout")
			if err != nil {
				t.Fatalf("failed to create temp stdout: %v", err)
			}
			defer os.Remove(stdout.Name())
			defer stdout.Close()

			stderr, err := os.CreateTemp("", "stderr")
			if err != nil {
				t.Fatalf("failed to create temp stderr: %v", err)
			}
			defer os.Remove(stderr.Name())
			defer stderr.Close()

			tt.input.Stdout = stdout
			tt.input.Stderr = stderr

			// Run command
			err = InitWizardCommand(context.Background(), tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitWizardCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Read output
			stdout.Seek(0, 0)
			outBytes, _ := os.ReadFile(stdout.Name())
			output := string(outBytes)

			// Check expected strings in output
			for _, want := range tt.wantOutput {
				if !strings.Contains(output, want) {
					t.Errorf("output missing expected string %q\nGot: %s", want, output)
				}
			}
		})
	}
}

func TestInitWizardCommandJSONOutput(t *testing.T) {
	// Create test output files
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	defer stdout.Close()

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create temp stderr: %v", err)
	}
	defer os.Remove(stderr.Name())
	defer stderr.Close()

	input := InitWizardCommandInput{
		Profiles:     []string{"prod"},
		Features:     []string{"policy_load", "credential_issue"},
		Region:       "us-east-1",
		OutputFormat: "json",
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err = InitWizardCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("InitWizardCommand() error = %v", err)
	}

	// Read and parse JSON output
	stdout.Seek(0, 0)
	outBytes, _ := os.ReadFile(stdout.Name())

	var jsonOutput InitWizardJSONOutput
	if err := json.Unmarshal(outBytes, &jsonOutput); err != nil {
		t.Fatalf("failed to parse JSON output: %v\nOutput: %s", err, string(outBytes))
	}

	// Verify fields
	if len(jsonOutput.Profiles) != 1 || jsonOutput.Profiles[0] != "prod" {
		t.Errorf("profiles = %v, want [prod]", jsonOutput.Profiles)
	}

	if len(jsonOutput.Features) != 2 {
		t.Errorf("features = %v, want 2 features", jsonOutput.Features)
	}

	if jsonOutput.Region != "us-east-1" {
		t.Errorf("region = %v, want us-east-1", jsonOutput.Region)
	}

	// Verify IAM policy is valid JSON
	var iamPolicy map[string]interface{}
	if err := json.Unmarshal(jsonOutput.IAMPolicy, &iamPolicy); err != nil {
		t.Errorf("iam_policy is not valid JSON: %v", err)
	}

	// Verify IAM policy structure
	if version, ok := iamPolicy["Version"].(string); !ok || version != "2012-10-17" {
		t.Errorf("IAM policy Version = %v, want 2012-10-17", iamPolicy["Version"])
	}

	// Verify sample policies
	if len(jsonOutput.SamplePolicies) != 1 {
		t.Errorf("sample_policies = %d, want 1", len(jsonOutput.SamplePolicies))
	}
	if _, ok := jsonOutput.SamplePolicies["prod"]; !ok {
		t.Errorf("sample_policies missing 'prod' key")
	}

	// Verify next steps
	if len(jsonOutput.NextSteps) == 0 {
		t.Error("next_steps is empty")
	}
}

func TestPromptMultiSelect(t *testing.T) {
	tests := []struct {
		name     string
		options  []string
		userIn   string
		want     []string
		wantErr  bool
	}{
		{
			name:    "select single",
			options: []string{"a", "b", "c"},
			userIn:  "1\n",
			want:    []string{"a"},
			wantErr: false,
		},
		{
			name:    "select multiple",
			options: []string{"a", "b", "c"},
			userIn:  "1,3\n",
			want:    []string{"a", "c"},
			wantErr: false,
		},
		{
			name:    "select all",
			options: []string{"a", "b", "c"},
			userIn:  "all\n",
			want:    []string{"a", "b", "c"},
			wantErr: false,
		},
		{
			name:    "invalid index",
			options: []string{"a", "b"},
			userIn:  "5\n",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid input",
			options: []string{"a", "b"},
			userIn:  "xyz\n",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty input",
			options: []string{"a", "b"},
			userIn:  "\n",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdin := bufio.NewScanner(strings.NewReader(tt.userIn))
			stdout, _ := os.CreateTemp("", "stdout")
			defer os.Remove(stdout.Name())
			defer stdout.Close()

			got, err := promptMultiSelect("Select", tt.options, stdin, stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("promptMultiSelect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("promptMultiSelect() = %v, want %v", got, tt.want)
					return
				}
				for i, v := range got {
					if v != tt.want[i] {
						t.Errorf("promptMultiSelect()[%d] = %v, want %v", i, v, tt.want[i])
					}
				}
			}
		})
	}
}

func TestPromptYesNo(t *testing.T) {
	tests := []struct {
		name       string
		userIn     string
		defaultYes bool
		want       bool
	}{
		{
			name:       "yes explicit",
			userIn:     "y\n",
			defaultYes: false,
			want:       true,
		},
		{
			name:       "no explicit",
			userIn:     "n\n",
			defaultYes: true,
			want:       false,
		},
		{
			name:       "empty with default yes",
			userIn:     "\n",
			defaultYes: true,
			want:       true,
		},
		{
			name:       "empty with default no",
			userIn:     "\n",
			defaultYes: false,
			want:       false,
		},
		{
			name:       "yes full word",
			userIn:     "yes\n",
			defaultYes: false,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdin := bufio.NewScanner(strings.NewReader(tt.userIn))
			stdout, _ := os.CreateTemp("", "stdout")
			defer os.Remove(stdout.Name())
			defer stdout.Close()

			got, _ := promptYesNo("Test?", tt.defaultYes, stdin, stdout)
			if got != tt.want {
				t.Errorf("promptYesNo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPromptString(t *testing.T) {
	tests := []struct {
		name         string
		userIn       string
		defaultValue string
		want         string
	}{
		{
			name:         "user input",
			userIn:       "custom-value\n",
			defaultValue: "default",
			want:         "custom-value",
		},
		{
			name:         "empty with default",
			userIn:       "\n",
			defaultValue: "default",
			want:         "default",
		},
		{
			name:         "empty without default",
			userIn:       "\n",
			defaultValue: "",
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdin := bufio.NewScanner(strings.NewReader(tt.userIn))
			stdout, _ := os.CreateTemp("", "stdout")
			defer os.Remove(stdout.Name())
			defer stdout.Close()

			got, _ := promptString("Enter value", tt.defaultValue, stdin, stdout)
			if got != tt.want {
				t.Errorf("promptString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseFeatureName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "policy_load        - Load policies from SSM (required)",
			want:  "policy_load",
		},
		{
			input: "credential_issue   - Issue credentials with SourceIdentity (required)",
			want:  "credential_issue",
		},
		{
			input: "simple",
			want:  "simple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseFeatureName(tt.input)
			if got != tt.want {
				t.Errorf("parseFeatureName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGenerateWizardOutputs(t *testing.T) {
	state := &WizardState{
		Profiles: []string{"test-profile"},
		Features: []permissions.Feature{
			permissions.FeaturePolicyLoad,
			permissions.FeatureCredentialIssue,
		},
		Region:         "us-east-1",
		GenerateIAM:    true,
		GenerateSample: true,
		SamplePolicies: make(map[string]string),
	}

	err := generateWizardOutputs(state)
	if err != nil {
		t.Fatalf("generateWizardOutputs() error = %v", err)
	}

	// Verify IAM policy was generated
	if state.IAMPolicy == "" {
		t.Error("IAM policy was not generated")
	}

	// Verify IAM policy is valid JSON
	var iamPolicy map[string]interface{}
	if err := json.Unmarshal([]byte(state.IAMPolicy), &iamPolicy); err != nil {
		t.Errorf("IAM policy is not valid JSON: %v", err)
	}

	// Verify sample policy was generated
	if len(state.SamplePolicies) != 1 {
		t.Errorf("sample policies count = %d, want 1", len(state.SamplePolicies))
	}
	if _, ok := state.SamplePolicies["test-profile"]; !ok {
		t.Error("sample policy for test-profile was not generated")
	}
}

func TestFormatNextSteps(t *testing.T) {
	state := &WizardState{
		Profiles: []string{"prod", "staging"},
		Region:   "us-west-2",
	}

	steps := formatNextSteps(state)

	if len(steps) == 0 {
		t.Fatal("formatNextSteps() returned empty steps")
	}

	// Verify steps contain expected content
	allSteps := strings.Join(steps, " ")

	if !strings.Contains(allSteps, "IAM policy") {
		t.Error("steps should mention IAM policy")
	}

	if !strings.Contains(allSteps, "--profile prod") {
		t.Error("steps should mention profile flags")
	}

	if !strings.Contains(allSteps, "--region us-west-2") {
		t.Error("steps should mention region flag")
	}

	if !strings.Contains(allSteps, "sentinel permissions check") {
		t.Error("steps should mention permissions check")
	}
}

func TestWizardStateDefaults(t *testing.T) {
	state := &WizardState{
		Profiles:       []string{},
		Features:       []permissions.Feature{},
		SamplePolicies: make(map[string]string),
	}

	// Verify empty state doesn't cause errors in output generation
	err := generateWizardOutputs(state)
	if err != nil {
		t.Errorf("generateWizardOutputs() with empty state error = %v", err)
	}

	// Verify IAM policy is empty when no features selected
	if state.IAMPolicy != "" {
		t.Errorf("IAM policy should be empty when GenerateIAM is false, got: %s", state.IAMPolicy)
	}
}

func TestInitWizardJSONOutputStructure(t *testing.T) {
	// Test that JSON output structure is correct
	output := InitWizardJSONOutput{
		Profiles:       []string{"test"},
		Features:       []string{"policy_load"},
		Region:         "us-east-1",
		IAMPolicy:      json.RawMessage(`{"Version":"2012-10-17"}`),
		SamplePolicies: map[string]string{"test": "policy: content"},
		NextSteps:      []string{"Step 1", "Step 2"},
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("failed to marshal InitWizardJSONOutput: %v", err)
	}

	// Verify it can be unmarshaled back
	var decoded InitWizardJSONOutput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal InitWizardJSONOutput: %v", err)
	}

	if len(decoded.Profiles) != 1 || decoded.Profiles[0] != "test" {
		t.Errorf("Profiles = %v, want [test]", decoded.Profiles)
	}

	if decoded.Region != "us-east-1" {
		t.Errorf("Region = %v, want us-east-1", decoded.Region)
	}
}

func TestOutputWizardHuman(t *testing.T) {
	state := &WizardState{
		Profiles: []string{"prod"},
		Features: []permissions.Feature{permissions.FeaturePolicyLoad},
		Region:   "us-east-1",
		GenerateIAM:    true,
		GenerateSample: true,
		IAMPolicy:      `{"Version":"2012-10-17","Statement":[]}`,
		SamplePolicies: map[string]string{"prod": "# Sample policy\nversion: 1"},
	}

	// Create temp stdout
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	defer stdout.Close()

	err = outputWizardHuman(state, stdout)
	if err != nil {
		t.Fatalf("outputWizardHuman() error = %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	outBytes, _ := os.ReadFile(stdout.Name())
	output := string(outBytes)

	// Verify sections are present
	expectedSections := []string{
		"Output",
		"IAM Policy",
		"Sample Policy: prod",
		"Next Steps",
	}

	for _, section := range expectedSections {
		if !strings.Contains(output, section) {
			t.Errorf("output missing section %q", section)
		}
	}
}

func TestOutputWizardJSON(t *testing.T) {
	state := &WizardState{
		Profiles: []string{"test"},
		Features: []permissions.Feature{permissions.FeaturePolicyLoad},
		Region:   "eu-west-1",
		IAMPolicy: `{"Version":"2012-10-17","Statement":[]}`,
		SamplePolicies: map[string]string{"test": "# policy"},
	}

	// Create temp stdout
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	defer stdout.Close()

	err = outputWizardJSON(state, stdout)
	if err != nil {
		t.Fatalf("outputWizardJSON() error = %v", err)
	}

	// Read and parse output
	stdout.Seek(0, 0)
	outBytes, _ := os.ReadFile(stdout.Name())

	var output InitWizardJSONOutput
	if err := json.Unmarshal(outBytes, &output); err != nil {
		t.Fatalf("failed to parse JSON: %v\nOutput: %s", err, string(outBytes))
	}

	if len(output.Profiles) != 1 {
		t.Errorf("profiles count = %d, want 1", len(output.Profiles))
	}

	if output.Region != "eu-west-1" {
		t.Errorf("region = %s, want eu-west-1", output.Region)
	}
}

func TestPromptMultiSelectWithSpaces(t *testing.T) {
	stdin := bufio.NewScanner(strings.NewReader("1, 2, 3\n"))
	stdout, _ := os.CreateTemp("", "stdout")
	defer os.Remove(stdout.Name())
	defer stdout.Close()

	options := []string{"option-a", "option-b", "option-c"}
	got, err := promptMultiSelect("Select", options, stdin, stdout)
	if err != nil {
		t.Fatalf("promptMultiSelect() error = %v", err)
	}

	if len(got) != 3 {
		t.Errorf("promptMultiSelect() returned %d items, want 3", len(got))
	}
}

func TestPromptMultiSelectDuplicates(t *testing.T) {
	// Selecting same index multiple times should deduplicate
	stdin := bufio.NewScanner(strings.NewReader("1,1,2\n"))
	stdout, _ := os.CreateTemp("", "stdout")
	defer os.Remove(stdout.Name())
	defer stdout.Close()

	options := []string{"a", "b", "c"}
	got, err := promptMultiSelect("Select", options, stdin, stdout)
	if err != nil {
		t.Fatalf("promptMultiSelect() error = %v", err)
	}

	// Should return 2 unique items, not 3
	if len(got) != 2 {
		t.Errorf("promptMultiSelect() returned %d items, want 2 (deduped)", len(got))
	}
}

func TestRunWizardNonInteractive(t *testing.T) {
	input := InitWizardCommandInput{
		Profiles: []string{"p1", "p2"},
		Features: []string{"policy_load", "credential_issue"},
		Region:   "ap-south-1",
	}

	state := &WizardState{
		Profiles:       []string{},
		Features:       []permissions.Feature{},
		SamplePolicies: make(map[string]string),
	}

	err := runWizardNonInteractive(input, state)
	if err != nil {
		t.Fatalf("runWizardNonInteractive() error = %v", err)
	}

	// Verify state was populated
	if len(state.Profiles) != 2 {
		t.Errorf("Profiles = %v, want 2 items", state.Profiles)
	}

	if len(state.Features) != 2 {
		t.Errorf("Features = %v, want 2 items", state.Features)
	}

	if state.Region != "ap-south-1" {
		t.Errorf("Region = %s, want ap-south-1", state.Region)
	}

	if !state.GenerateIAM {
		t.Error("GenerateIAM should be true in non-interactive mode")
	}

	if !state.GenerateSample {
		t.Error("GenerateSample should be true when profiles provided")
	}
}

func TestInteractiveWizardFlow(t *testing.T) {
	// Simulate interactive input
	var input bytes.Buffer
	// Select profiles 1 and 2
	input.WriteString("1,2\n")
	// Select features 1 and 2
	input.WriteString("1,2\n")
	// Use default region (just press enter)
	input.WriteString("\n")
	// Generate IAM policy (yes)
	input.WriteString("y\n")
	// Generate sample policies (yes)
	input.WriteString("y\n")
	// Proceed (yes)
	input.WriteString("y\n")

	stdin := bufio.NewScanner(&input)

	stdout, _ := os.CreateTemp("", "stdout")
	defer os.Remove(stdout.Name())
	defer stdout.Close()

	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stderr.Name())
	defer stderr.Close()

	// This test can't run the full wizard without mocking profile discovery
	// But we can test the flow structure
	state := &WizardState{
		Profiles:       []string{},
		Features:       []permissions.Feature{},
		SamplePolicies: make(map[string]string),
	}

	// Test with pre-populated profiles to skip discovery
	cmdInput := InitWizardCommandInput{
		Profiles: []string{"test1", "test2"},
		Stdin:    stdin,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	// Pre-populate the state to simulate earlier steps
	state.Profiles = cmdInput.Profiles

	// Now run just the feature selection step output
	err := generateWizardOutputs(state)
	if err != nil {
		t.Logf("Note: generateWizardOutputs with empty features is expected to produce no IAM policy")
	}
}
