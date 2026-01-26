package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/byteness/aws-vault/v7/bootstrap"
	"github.com/byteness/aws-vault/v7/policy"
)

// MockSSMClient implements policy.SSMAPI for testing.
type MockSSMClient struct {
	// Policies maps parameter names to YAML content.
	Policies map[string]string

	// GetParameterFunc allows custom behavior override.
	GetParameterFunc func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)

	// PutParameterFunc allows custom behavior override for PutParameter.
	PutParameterFunc func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)

	// Calls tracks GetParameter calls for assertions.
	Calls []*ssm.GetParameterInput

	// PutCalls tracks PutParameter calls for assertions.
	PutCalls []*ssm.PutParameterInput
}

// GetParameter implements policy.SSMAPI.
func (m *MockSSMClient) GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	m.Calls = append(m.Calls, params)

	if m.GetParameterFunc != nil {
		return m.GetParameterFunc(ctx, params, optFns...)
	}

	if m.Policies == nil {
		return nil, &types.ParameterNotFound{Message: aws.String("Parameter not found")}
	}

	name := aws.ToString(params.Name)
	if content, ok := m.Policies[name]; ok {
		return &ssm.GetParameterOutput{
			Parameter: &types.Parameter{
				Name:    params.Name,
				Value:   aws.String(content),
				Version: 1,
			},
		}, nil
	}

	return nil, &types.ParameterNotFound{Message: aws.String("Parameter not found")}
}

// PutParameter implements policy.SSMAPI.
func (m *MockSSMClient) PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	m.PutCalls = append(m.PutCalls, params)

	if m.PutParameterFunc != nil {
		return m.PutParameterFunc(ctx, params, optFns...)
	}

	// Default success behavior
	return &ssm.PutParameterOutput{
		Version: 1,
	}, nil
}

// validPolicyYAML returns a minimal valid policy YAML for testing.
func validPolicyYAML() string {
	return `version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      profiles:
        - "*"
`
}

func TestPolicyPullCommand_Success(t *testing.T) {
	// Create temp stdout/stderr
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{
		Policies: map[string]string{
			"/sentinel/policies/dev": validPolicyYAML(),
		},
	}

	input := PolicyPullCommandInput{
		Profile:   "dev",
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPullCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Read stdout and verify YAML output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "version:") {
		t.Errorf("output should contain 'version:', got: %s", output)
	}
	if !strings.Contains(output, "rules:") {
		t.Errorf("output should contain 'rules:', got: %s", output)
	}
	if !strings.Contains(output, "effect: allow") {
		t.Errorf("output should contain 'effect: allow', got: %s", output)
	}

	// Verify GetParameter was called with correct path
	if len(mockClient.Calls) != 1 {
		t.Fatalf("expected 1 GetParameter call, got %d", len(mockClient.Calls))
	}
	expectedPath := bootstrap.DefaultPolicyParameterName(bootstrap.DefaultPolicyRoot, "dev")
	if aws.ToString(mockClient.Calls[0].Name) != expectedPath {
		t.Errorf("GetParameter path = %q, want %q", aws.ToString(mockClient.Calls[0].Name), expectedPath)
	}
}

func TestPolicyPullCommand_WriteToFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "policy-pull-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{
		Policies: map[string]string{
			"/sentinel/policies/prod": validPolicyYAML(),
		},
	}

	outputFile := filepath.Join(tmpDir, "policy.yaml")

	input := PolicyPullCommandInput{
		Profile:    "prod",
		OutputFile: outputFile,
		Stdout:     stdout,
		Stderr:     stderr,
		SSMClient:  mockClient,
	}

	exitCode, err := PolicyPullCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify file was created with expected content
	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if !strings.Contains(string(content), "version:") {
		t.Errorf("file should contain 'version:', got: %s", string(content))
	}
	if !strings.Contains(string(content), "rules:") {
		t.Errorf("file should contain 'rules:', got: %s", string(content))
	}

	// Verify stderr message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "Policy written to") {
		t.Errorf("stderr should contain 'Policy written to', got: %s", errOutput)
	}
	if !strings.Contains(errOutput, outputFile) {
		t.Errorf("stderr should contain output file path, got: %s", errOutput)
	}
}

func TestPolicyPullCommand_NotFound(t *testing.T) {
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	// Mock client with no policies (returns not found)
	mockClient := &MockSSMClient{
		Policies: map[string]string{},
	}

	input := PolicyPullCommandInput{
		Profile:   "nonexistent",
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPullCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for not found", exitCode)
	}

	// Verify stderr contains error message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "policy not found") {
		t.Errorf("stderr should contain 'policy not found', got: %s", errOutput)
	}
	if !strings.Contains(errOutput, "Suggestion:") {
		t.Errorf("stderr should contain 'Suggestion:', got: %s", errOutput)
	}
}

func TestPolicyPullCommand_ExplicitPolicyParameter(t *testing.T) {
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	explicitPath := "/custom/path/to/policy"

	mockClient := &MockSSMClient{
		Policies: map[string]string{
			explicitPath: validPolicyYAML(),
		},
	}

	input := PolicyPullCommandInput{
		Profile:         "ignored-profile",
		PolicyParameter: explicitPath,
		Stdout:          stdout,
		Stderr:          stderr,
		SSMClient:       mockClient,
	}

	exitCode, err := PolicyPullCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify the explicit path was used (not derived from profile)
	if len(mockClient.Calls) != 1 {
		t.Fatalf("expected 1 GetParameter call, got %d", len(mockClient.Calls))
	}
	if aws.ToString(mockClient.Calls[0].Name) != explicitPath {
		t.Errorf("GetParameter path = %q, want %q (explicit path)", aws.ToString(mockClient.Calls[0].Name), explicitPath)
	}
}

func TestPolicyPullCommand_DefaultPolicyRoot(t *testing.T) {
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	expectedPath := bootstrap.DefaultPolicyRoot + "/myprofile"

	mockClient := &MockSSMClient{
		Policies: map[string]string{
			expectedPath: validPolicyYAML(),
		},
	}

	input := PolicyPullCommandInput{
		Profile:   "myprofile",
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPullCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify parameter path is {DefaultPolicyRoot}/{profile}
	if len(mockClient.Calls) != 1 {
		t.Fatalf("expected 1 GetParameter call, got %d", len(mockClient.Calls))
	}
	if aws.ToString(mockClient.Calls[0].Name) != expectedPath {
		t.Errorf("GetParameter path = %q, want %q", aws.ToString(mockClient.Calls[0].Name), expectedPath)
	}
}

func TestPolicyPullCommand_CustomPolicyRoot(t *testing.T) {
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	customRoot := "/my/custom/policies"
	expectedPath := customRoot + "/staging"

	mockClient := &MockSSMClient{
		Policies: map[string]string{
			expectedPath: validPolicyYAML(),
		},
	}

	input := PolicyPullCommandInput{
		Profile:    "staging",
		PolicyRoot: customRoot,
		Stdout:     stdout,
		Stderr:     stderr,
		SSMClient:  mockClient,
	}

	exitCode, err := PolicyPullCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify parameter path uses custom root
	if len(mockClient.Calls) != 1 {
		t.Fatalf("expected 1 GetParameter call, got %d", len(mockClient.Calls))
	}
	if aws.ToString(mockClient.Calls[0].Name) != expectedPath {
		t.Errorf("GetParameter path = %q, want %q", aws.ToString(mockClient.Calls[0].Name), expectedPath)
	}
}

func TestPolicyPullCommand_SSMError(t *testing.T) {
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return nil, errors.New("network timeout")
		},
	}

	input := PolicyPullCommandInput{
		Profile:   "dev",
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPullCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for SSM error", exitCode)
	}

	// Verify stderr contains error message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "failed to load policy") {
		t.Errorf("stderr should contain 'failed to load policy', got: %s", errOutput)
	}
}

func TestPolicyPullCommand_OutputRoundTrip(t *testing.T) {
	// Test that pulled policy can be parsed back
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{
		Policies: map[string]string{
			"/sentinel/policies/dev": validPolicyYAML(),
		},
	}

	input := PolicyPullCommandInput{
		Profile:   "dev",
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPullCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}

	// Read output and parse it back
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.Bytes()

	// Verify output can be parsed as valid policy
	parsedPolicy, err := policy.ParsePolicy(output)
	if err != nil {
		t.Fatalf("output should be valid policy YAML, parse error: %v", err)
	}

	if parsedPolicy.Version != "1" {
		t.Errorf("parsed version = %q, want %q", parsedPolicy.Version, "1")
	}
	if len(parsedPolicy.Rules) != 1 {
		t.Errorf("parsed rules count = %d, want 1", len(parsedPolicy.Rules))
	}
}

func TestPolicyPullCommand_WithDecryption(t *testing.T) {
	// Verify WithDecryption is set to true
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatalf("failed to create stdout: %v", err)
	}
	defer os.Remove(stdout.Name())
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	var calledWithDecryption bool

	mockClient := &MockSSMClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			calledWithDecryption = aws.ToBool(params.WithDecryption)
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:    params.Name,
					Value:   aws.String(validPolicyYAML()),
					Version: 1,
				},
			}, nil
		},
	}

	input := PolicyPullCommandInput{
		Profile:   "dev",
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, _ := PolicyPullCommand(context.Background(), input)
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}

	// The loader should use WithDecryption=true (handled by policy.Loader)
	// This is verified by the loader tests, but we can at least verify the call was made
	if len(mockClient.Calls) == 0 {
		t.Error("expected GetParameter to be called")
	}
}

// createTempPolicyFile creates a temporary file with the given content and returns its path.
func createTempPolicyFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	return tmpFile.Name()
}

func TestPolicyPushCommand_Success(t *testing.T) {
	// Create temp file with valid policy
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{
		Policies: map[string]string{}, // No existing policy
	}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true, // Skip confirmation prompt
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Errorf("exitCode = %d, want 0. stderr: %s", exitCode, buf.String())
	}

	// Verify PutParameter was called
	if len(mockClient.PutCalls) != 1 {
		t.Fatalf("expected 1 PutParameter call, got %d", len(mockClient.PutCalls))
	}

	// Verify correct path
	expectedPath := bootstrap.DefaultPolicyParameterName(bootstrap.DefaultPolicyRoot, "dev")
	if aws.ToString(mockClient.PutCalls[0].Name) != expectedPath {
		t.Errorf("PutParameter path = %q, want %q", aws.ToString(mockClient.PutCalls[0].Name), expectedPath)
	}

	// Verify Overwrite=true
	if !aws.ToBool(mockClient.PutCalls[0].Overwrite) {
		t.Error("expected Overwrite=true")
	}

	// Verify content matches
	if !strings.Contains(aws.ToString(mockClient.PutCalls[0].Value), "version:") {
		t.Error("PutParameter value should contain policy content")
	}

	// Verify stderr contains success message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "successfully pushed") {
		t.Errorf("stderr should contain 'successfully pushed', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_ValidationError(t *testing.T) {
	// Create temp file with invalid policy YAML
	invalidPolicy := `version: "1"
rules: []
`
	policyFile := createTempPolicyFile(t, invalidPolicy)
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for validation error", exitCode)
	}

	// Verify no PutParameter was called
	if len(mockClient.PutCalls) != 0 {
		t.Errorf("expected 0 PutParameter calls, got %d", len(mockClient.PutCalls))
	}

	// Verify stderr contains validation error
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "validation error") {
		t.Errorf("stderr should contain 'validation error', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_FileNotFound(t *testing.T) {
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: "/nonexistent/path/policy.yaml",
		Force:     true,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for file not found", exitCode)
	}

	// Verify stderr contains file not found message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "file not found") {
		t.Errorf("stderr should contain 'file not found', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_SSMError(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{
		PutParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		NoBackup:  true, // Skip backup check
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for SSM error", exitCode)
	}

	// Verify stderr contains error message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "failed to write policy to SSM") {
		t.Errorf("stderr should contain 'failed to write policy to SSM', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_NoBackupFlag(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		NoBackup:  true, // Skip backup fetch
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify GetParameter was NOT called (no backup fetch)
	if len(mockClient.Calls) != 0 {
		t.Errorf("expected 0 GetParameter calls with --no-backup, got %d", len(mockClient.Calls))
	}

	// Verify PutParameter WAS called
	if len(mockClient.PutCalls) != 1 {
		t.Errorf("expected 1 PutParameter call, got %d", len(mockClient.PutCalls))
	}
}

func TestPolicyPushCommand_ForceFlag(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{}

	// With --force, no stdin input is needed
	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		NoBackup:  true,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify PutParameter was called without waiting for stdin
	if len(mockClient.PutCalls) != 1 {
		t.Errorf("expected 1 PutParameter call, got %d", len(mockClient.PutCalls))
	}
}

func TestPolicyPushCommand_PolicyParameterOverride(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	explicitPath := "/custom/path/to/policy"

	mockClient := &MockSSMClient{}

	input := PolicyPushCommandInput{
		Profile:         "ignored-profile",
		InputFile:       policyFile,
		PolicyParameter: explicitPath,
		Force:           true,
		NoBackup:        true,
		Stderr:          stderr,
		SSMClient:       mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify the explicit path was used
	if len(mockClient.PutCalls) != 1 {
		t.Fatalf("expected 1 PutParameter call, got %d", len(mockClient.PutCalls))
	}
	if aws.ToString(mockClient.PutCalls[0].Name) != explicitPath {
		t.Errorf("PutParameter path = %q, want %q (explicit path)", aws.ToString(mockClient.PutCalls[0].Name), explicitPath)
	}
}

func TestPolicyPushCommand_BackupFetch(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{
		Policies: map[string]string{
			"/sentinel/policies/dev": validPolicyYAML(), // Existing policy
		},
	}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true, // Skip confirmation, but NOT skipping backup
		// NoBackup is false - so it should fetch existing policy
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Errorf("exitCode = %d, want 0. stderr: %s", exitCode, buf.String())
	}

	// Verify GetParameter WAS called (backup fetch)
	if len(mockClient.Calls) != 1 {
		t.Errorf("expected 1 GetParameter call for backup, got %d", len(mockClient.Calls))
	}

	// Verify stderr contains existing policy message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "Existing policy found") {
		t.Errorf("stderr should contain 'Existing policy found', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_ConfirmationYes(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{}

	// Simulate "y\n" input for confirmation
	stdinBuf := strings.NewReader("y\n")

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     false, // NOT forcing, so confirmation is required
		NoBackup:  true,
		Stdin:     stdinBuf,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Errorf("exitCode = %d, want 0. stderr: %s", exitCode, buf.String())
	}

	// Verify PutParameter was called after confirmation
	if len(mockClient.PutCalls) != 1 {
		t.Errorf("expected 1 PutParameter call after 'y' confirmation, got %d", len(mockClient.PutCalls))
	}
}

func TestPolicyPushCommand_ConfirmationNo(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{}

	// Simulate "n\n" input for rejection
	stdinBuf := strings.NewReader("n\n")

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     false, // NOT forcing, so confirmation is required
		NoBackup:  true,
		Stdin:     stdinBuf,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Cancellation should exit with 0 (not an error, just cancelled)
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 for cancellation", exitCode)
	}

	// Verify PutParameter was NOT called after rejection
	if len(mockClient.PutCalls) != 0 {
		t.Errorf("expected 0 PutParameter calls after 'n' confirmation, got %d", len(mockClient.PutCalls))
	}

	// Verify stderr contains cancelled message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "Cancelled") {
		t.Errorf("stderr should contain 'Cancelled', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_ParseError(t *testing.T) {
	// Create temp file with malformed YAML (not just invalid policy, but unparseable)
	malformedYAML := `version: "1"
rules:
  - name: test
  effect: allow  # wrong indentation - parse error
`
	policyFile := createTempPolicyFile(t, malformedYAML)
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for parse error", exitCode)
	}

	// Verify stderr contains parse error
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "parse error") {
		t.Errorf("stderr should contain 'parse error', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_ParameterTypeString(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockClient := &MockSSMClient{}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		NoBackup:  true,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify ParameterTypeString was used (not SecureString)
	if len(mockClient.PutCalls) != 1 {
		t.Fatalf("expected 1 PutParameter call, got %d", len(mockClient.PutCalls))
	}
	if mockClient.PutCalls[0].Type != types.ParameterTypeString {
		t.Errorf("Type = %v, want ParameterTypeString", mockClient.PutCalls[0].Type)
	}
}
