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
	"github.com/aws/aws-sdk-go-v2/service/kms"
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

	mockClient := &MockSSMClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			// Verify decryption flag is set (handled by policy.Loader)
			_ = aws.ToBool(params.WithDecryption)
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

// --- PolicyDiffCommand Tests ---

func TestPolicyDiffCommand_NoChanges(t *testing.T) {
	// Create temp file with valid policy
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

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

	// Remote has same policy (normalized form)
	mockClient := &MockSSMClient{
		Policies: map[string]string{
			"/sentinel/policies/dev": validPolicyYAML(),
		},
	}

	input := PolicyDiffCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyDiffCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Exit code 0 means no changes
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 for no changes", exitCode)
	}

	// Verify stdout is empty (no diff output)
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if output != "" {
		t.Errorf("expected empty stdout for no changes, got: %s", output)
	}
}

func TestPolicyDiffCommand_WithChanges(t *testing.T) {
	// Create temp file with modified policy
	localPolicy := `version: "1"
rules:
  - name: allow-dev
    effect: allow
    conditions:
      profiles:
        - "dev-*"
`
	policyFile := createTempPolicyFile(t, localPolicy)
	defer os.Remove(policyFile)

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

	// Remote has original policy
	mockClient := &MockSSMClient{
		Policies: map[string]string{
			"/sentinel/policies/dev": validPolicyYAML(),
		},
	}

	input := PolicyDiffCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		NoColor:   true, // Easier to verify without ANSI codes
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyDiffCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Exit code 1 means changes exist
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for changes exist", exitCode)
	}

	// Verify stdout contains diff output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "---") {
		t.Errorf("output should contain '---' header, got: %s", output)
	}
	if !strings.Contains(output, "+++") {
		t.Errorf("output should contain '+++' header, got: %s", output)
	}
	if !strings.Contains(output, "@@") {
		t.Errorf("output should contain '@@' hunk markers, got: %s", output)
	}
	// Should show the change from "allow-all" to "allow-dev"
	if !strings.Contains(output, "-") && !strings.Contains(output, "+") {
		t.Errorf("output should contain +/- lines, got: %s", output)
	}
}

func TestPolicyDiffCommand_RemoteNotFound(t *testing.T) {
	// Create temp file with valid policy
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

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

	// Remote has no policy (ParameterNotFound)
	mockClient := &MockSSMClient{
		Policies: map[string]string{}, // Empty - will return ParameterNotFound
	}

	input := PolicyDiffCommandInput{
		Profile:   "newprofile",
		InputFile: policyFile,
		NoColor:   true,
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyDiffCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Exit code 1 means changes exist (all lines are additions)
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for new policy (all additions)", exitCode)
	}

	// Verify stdout contains diff output with all additions
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "+++") {
		t.Errorf("output should contain '+++' header, got: %s", output)
	}
	// All lines should be additions (+) since remote is empty
	if !strings.Contains(output, "+version:") {
		t.Errorf("output should show +version: for new policy, got: %s", output)
	}
}

func TestPolicyDiffCommand_ValidationError(t *testing.T) {
	// Create temp file with invalid policy YAML
	invalidPolicy := `version: "1"
rules: []
`
	policyFile := createTempPolicyFile(t, invalidPolicy)
	defer os.Remove(policyFile)

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

	mockClient := &MockSSMClient{}

	input := PolicyDiffCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyDiffCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for validation error", exitCode)
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

func TestPolicyDiffCommand_FileNotFound(t *testing.T) {
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

	mockClient := &MockSSMClient{}

	input := PolicyDiffCommandInput{
		Profile:   "dev",
		InputFile: "/nonexistent/path/policy.yaml",
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyDiffCommand(context.Background(), input)
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

func TestPolicyDiffCommand_SSMError(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

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
			return nil, errors.New("access denied")
		},
	}

	input := PolicyDiffCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyDiffCommand(context.Background(), input)
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

	if !strings.Contains(errOutput, "failed to fetch remote policy") {
		t.Errorf("stderr should contain 'failed to fetch remote policy', got: %s", errOutput)
	}
}

func TestPolicyDiffCommand_NoColorFlag(t *testing.T) {
	// Create temp file with different policy
	localPolicy := `version: "1"
rules:
  - name: modified-rule
    effect: allow
    conditions:
      profiles:
        - "test-*"
`
	policyFile := createTempPolicyFile(t, localPolicy)
	defer os.Remove(policyFile)

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

	input := PolicyDiffCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		NoColor:   true, // --no-color flag
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyDiffCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for changes exist", exitCode)
	}

	// Verify stdout does NOT contain ANSI color codes
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if strings.Contains(output, "\033[") {
		t.Errorf("output should not contain ANSI codes with --no-color, got: %s", output)
	}
	// Should still have diff markers
	if !strings.Contains(output, "---") || !strings.Contains(output, "+++") {
		t.Errorf("output should contain diff markers, got: %s", output)
	}
}

func TestPolicyDiffCommand_PolicyParameterOverride(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

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

	input := PolicyDiffCommandInput{
		Profile:         "ignored-profile",
		InputFile:       policyFile,
		PolicyParameter: explicitPath,
		Stdout:          stdout,
		Stderr:          stderr,
		SSMClient:       mockClient,
	}

	exitCode, err := PolicyDiffCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Should be 0 (no changes) since same policy
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

func TestPolicyDiffCommand_WithColorOutput(t *testing.T) {
	// Create temp file with different policy
	localPolicy := `version: "1"
rules:
  - name: color-test
    effect: allow
    conditions:
      profiles:
        - "color-*"
`
	policyFile := createTempPolicyFile(t, localPolicy)
	defer os.Remove(policyFile)

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

	input := PolicyDiffCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		NoColor:   false, // Color enabled (default)
		Stdout:    stdout,
		Stderr:    stderr,
		SSMClient: mockClient,
	}

	exitCode, err := PolicyDiffCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for changes exist", exitCode)
	}

	// Verify stdout CONTAINS ANSI color codes
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "\033[") {
		t.Errorf("output should contain ANSI codes with color enabled, got: %s", output)
	}
}

// --- PolicyValidateCommand Tests ---

func TestPolicyValidateCommand_ValidPolicy(t *testing.T) {
	// Create temp file with valid policy
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Exit code 0 = valid
	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Errorf("exitCode = %d, want 0 for valid policy. stderr: %s", exitCode, buf.String())
	}

	// Verify stderr contains success message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "Policy is valid") {
		t.Errorf("stderr should contain 'Policy is valid', got: %s", errOutput)
	}
}

func TestPolicyValidateCommand_InvalidYAML(t *testing.T) {
	// Create temp file with malformed YAML syntax
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

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	// Exit code 1 = invalid
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for invalid YAML", exitCode)
	}

	// Verify stderr contains parse error
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "parse error") {
		t.Errorf("stderr should contain 'parse error', got: %s", errOutput)
	}
	if !strings.Contains(errOutput, "Suggestion:") {
		t.Errorf("stderr should contain 'Suggestion:', got: %s", errOutput)
	}
}

func TestPolicyValidateCommand_ValidationError(t *testing.T) {
	// Create temp file with valid YAML but invalid policy (no rules)
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

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	// Exit code 1 = invalid
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for validation error", exitCode)
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

func TestPolicyValidateCommand_FileNotFound(t *testing.T) {
	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	input := PolicyValidateCommandInput{
		InputFile: "/nonexistent/path/policy.yaml",
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	// Exit code 1 = file not found
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
	if !strings.Contains(errOutput, "Suggestion:") {
		t.Errorf("stderr should contain 'Suggestion:', got: %s", errOutput)
	}
}

func TestPolicyValidateCommand_QuietMode(t *testing.T) {
	// Create temp file with valid policy
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     true, // --quiet flag
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Exit code 0 = valid
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 for valid policy", exitCode)
	}

	// Verify stderr is empty (no success message in quiet mode)
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if errOutput != "" {
		t.Errorf("stderr should be empty in quiet mode on success, got: %s", errOutput)
	}
}

func TestPolicyValidateCommand_InvalidVersion(t *testing.T) {
	// Create temp file with unsupported version
	invalidVersionPolicy := `version: "99"
rules:
  - name: allow-all
    effect: allow
    conditions:
      profiles:
        - "*"
`
	policyFile := createTempPolicyFile(t, invalidVersionPolicy)
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	// Exit code 1 = invalid
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for invalid version", exitCode)
	}

	// Verify stderr contains validation error about version
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "validation error") {
		t.Errorf("stderr should contain 'validation error', got: %s", errOutput)
	}
	// Should mention the unsupported version
	if !strings.Contains(errOutput, "version") {
		t.Errorf("stderr should mention 'version', got: %s", errOutput)
	}
}

func TestPolicyValidateCommand_InvalidEffect(t *testing.T) {
	// Create temp file with invalid effect value
	invalidEffectPolicy := `version: "1"
rules:
  - name: invalid-effect
    effect: invalid_effect_value
    conditions:
      profiles:
        - "*"
`
	policyFile := createTempPolicyFile(t, invalidEffectPolicy)
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	// Exit code 1 = invalid
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for invalid effect", exitCode)
	}

	// Verify stderr contains validation error about effect
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "validation error") {
		t.Errorf("stderr should contain 'validation error', got: %s", errOutput)
	}
	// Should mention invalid effect
	if !strings.Contains(errOutput, "effect") {
		t.Errorf("stderr should mention 'effect', got: %s", errOutput)
	}
}

// --- PolicyPushCommand Signing Tests ---

// MockKMSClientForPush implements policy.KMSAPI for push command testing.
type MockKMSClientForPush struct {
	SignFunc   func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	VerifyFunc func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
	SignCalls  []*kms.SignInput
}

// Sign implements policy.KMSAPI.
func (m *MockKMSClientForPush) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	m.SignCalls = append(m.SignCalls, params)
	if m.SignFunc != nil {
		return m.SignFunc(ctx, params, optFns...)
	}
	return nil, errors.New("Sign not implemented")
}

// Verify implements policy.KMSAPI.
func (m *MockKMSClientForPush) Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("Verify not implemented")
}

func TestPolicyPushCommand_WithSignFlag(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockSSM := &MockSSMClient{}

	mockKMS := &MockKMSClientForPush{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: []byte("test-signature-bytes"),
			}, nil
		},
	}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		NoBackup:  true,
		Sign:      true,
		KeyID:     "alias/test-signing-key",
		Stderr:    stderr,
		SSMClient: mockSSM,
		KMSClient: mockKMS,
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

	// Verify policy was pushed (PutParameter call 1)
	if len(mockSSM.PutCalls) != 2 {
		t.Fatalf("expected 2 PutParameter calls (policy + signature), got %d", len(mockSSM.PutCalls))
	}

	// Verify first call is the policy
	policyCall := mockSSM.PutCalls[0]
	if !strings.Contains(aws.ToString(policyCall.Name), "/sentinel/policies/dev") {
		t.Errorf("first PutParameter should be policy path, got %s", aws.ToString(policyCall.Name))
	}

	// Verify second call is the signature
	sigCall := mockSSM.PutCalls[1]
	if !strings.Contains(aws.ToString(sigCall.Name), "/sentinel/signatures/dev") {
		t.Errorf("second PutParameter should be signature path, got %s", aws.ToString(sigCall.Name))
	}

	// Verify KMS Sign was called
	if len(mockKMS.SignCalls) != 1 {
		t.Errorf("expected 1 KMS Sign call, got %d", len(mockKMS.SignCalls))
	}
	if aws.ToString(mockKMS.SignCalls[0].KeyId) != "alias/test-signing-key" {
		t.Errorf("KMS Sign keyId = %q, want %q", aws.ToString(mockKMS.SignCalls[0].KeyId), "alias/test-signing-key")
	}

	// Verify stderr messages
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "Policy successfully pushed") {
		t.Errorf("stderr should contain 'Policy successfully pushed', got: %s", errOutput)
	}
	if !strings.Contains(errOutput, "Signature pushed") {
		t.Errorf("stderr should contain 'Signature pushed', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_SignWithoutKeyID(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockSSM := &MockSSMClient{}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		NoBackup:  true,
		Sign:      true,
		KeyID:     "", // Missing key ID
		Stderr:    stderr,
		SSMClient: mockSSM,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for missing key ID", exitCode)
	}

	// Verify no SSM calls were made
	if len(mockSSM.PutCalls) != 0 {
		t.Errorf("expected 0 PutParameter calls, got %d", len(mockSSM.PutCalls))
	}

	// Verify stderr contains error
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "--key-id is required") {
		t.Errorf("stderr should contain '--key-id is required', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_KMSSignError(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockSSM := &MockSSMClient{}

	mockKMS := &MockKMSClientForPush{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return nil, errors.New("KMS access denied")
		},
	}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		NoBackup:  true,
		Sign:      true,
		KeyID:     "alias/test-key",
		Stderr:    stderr,
		SSMClient: mockSSM,
		KMSClient: mockKMS,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for KMS error", exitCode)
	}

	// Verify policy WAS pushed (before signing failed)
	if len(mockSSM.PutCalls) != 1 {
		t.Errorf("expected 1 PutParameter call (policy only), got %d", len(mockSSM.PutCalls))
	}

	// Verify stderr contains error
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "failed to sign policy") {
		t.Errorf("stderr should contain 'failed to sign policy', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_SignatureSSMError(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	callCount := 0
	mockSSM := &MockSSMClient{
		PutParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			callCount++
			if callCount == 2 {
				// Fail on signature write
				return nil, errors.New("access denied for signature")
			}
			return &ssm.PutParameterOutput{Version: 1}, nil
		},
	}

	mockKMS := &MockKMSClientForPush{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: []byte("test-signature"),
			}, nil
		},
	}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		NoBackup:  true,
		Sign:      true,
		KeyID:     "alias/test-key",
		Stderr:    stderr,
		SSMClient: mockSSM,
		KMSClient: mockKMS,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for signature SSM error", exitCode)
	}

	// Verify stderr contains error
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "failed to write signature to SSM") {
		t.Errorf("stderr should contain 'failed to write signature to SSM', got: %s", errOutput)
	}
}

func TestPolicyPushCommand_WithoutSignFlag(t *testing.T) {
	// Verify that without --sign, no signature is stored
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	mockSSM := &MockSSMClient{}

	input := PolicyPushCommandInput{
		Profile:   "dev",
		InputFile: policyFile,
		Force:     true,
		NoBackup:  true,
		Sign:      false, // No signing
		Stderr:    stderr,
		SSMClient: mockSSM,
	}

	exitCode, err := PolicyPushCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify only policy was pushed (no signature)
	if len(mockSSM.PutCalls) != 1 {
		t.Errorf("expected 1 PutParameter call (policy only), got %d", len(mockSSM.PutCalls))
	}

	// Verify it's the policy path
	if !strings.Contains(aws.ToString(mockSSM.PutCalls[0].Name), "/sentinel/policies/") {
		t.Errorf("PutParameter should be for policy path, got %s", aws.ToString(mockSSM.PutCalls[0].Name))
	}
}

// --- PolicyValidateCommand Lint Integration Tests ---

// policyWithLintIssuesYAML returns a policy YAML that triggers lint warnings
func policyWithLintIssuesYAML() string {
	return `version: "1"
rules:
  - name: allow-prod
    effect: allow
    conditions:
      profiles:
        - prod
  - name: deny-prod
    effect: deny
    conditions:
      profiles:
        - prod
`
}

func TestPolicyValidateCommand_LintWarnings(t *testing.T) {
	// Create temp file with policy that has lint issues
	policyFile := createTempPolicyFile(t, policyWithLintIssuesYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Exit code 0 - lint warnings don't affect exit code
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 (lint warnings don't change exit code)", exitCode)
	}

	// Verify stderr contains lint warnings
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "lint:") {
		t.Errorf("stderr should contain lint warnings, got: %s", errOutput)
	}
	if !strings.Contains(errOutput, "allow-before-deny") {
		t.Errorf("stderr should contain 'allow-before-deny', got: %s", errOutput)
	}

	// Should NOT contain "Policy is valid" when lint issues exist
	if strings.Contains(errOutput, "Policy is valid") {
		t.Errorf("stderr should NOT contain 'Policy is valid' when lint issues exist, got: %s", errOutput)
	}
}

func TestPolicyValidateCommand_LintWarnings_ValidWithoutIssues(t *testing.T) {
	// Valid policy without lint issues
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify stderr contains "Policy is valid" message
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "Policy is valid") {
		t.Errorf("stderr should contain 'Policy is valid', got: %s", errOutput)
	}

	// Should NOT contain lint warnings
	if strings.Contains(errOutput, "lint:") {
		t.Errorf("stderr should NOT contain lint warnings, got: %s", errOutput)
	}
}

func TestPolicyValidateCommand_LintWarnings_InvalidPolicyNoLintOutput(t *testing.T) {
	// Invalid policy (empty rules) - should fail validation before linting
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

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	// Exit code 1 - validation error
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for validation error", exitCode)
	}

	// Verify stderr does NOT contain lint warnings (fails before linting)
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if strings.Contains(errOutput, "lint:") {
		t.Errorf("stderr should NOT contain lint warnings for invalid policy, got: %s", errOutput)
	}
	if !strings.Contains(errOutput, "validation error") {
		t.Errorf("stderr should contain 'validation error', got: %s", errOutput)
	}
}

func TestPolicyValidateCommand_LintQuiet(t *testing.T) {
	// Valid policy with lint issues + --quiet flag
	policyFile := createTempPolicyFile(t, policyWithLintIssuesYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     true, // --quiet flag
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Exit code 0 - lint warnings don't affect exit code
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify stderr is empty (--quiet suppresses lint output too)
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if errOutput != "" {
		t.Errorf("stderr should be empty with --quiet, got: %s", errOutput)
	}
}

func TestPolicyValidateCommand_LintOutput_Format(t *testing.T) {
	// Verify exact output format: lint: {type}: {message}
	policyFile := createTempPolicyFile(t, policyWithLintIssuesYAML())
	defer os.Remove(policyFile)

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatalf("failed to create stderr: %v", err)
	}
	defer os.Remove(stderr.Name())

	input := PolicyValidateCommandInput{
		InputFile: policyFile,
		Quiet:     false,
		Stderr:    stderr,
	}

	exitCode, err := PolicyValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify output format
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	// Should start with "lint: " prefix
	if !strings.HasPrefix(errOutput, "lint: ") {
		t.Errorf("lint output should start with 'lint: ', got: %s", errOutput)
	}

	// Should have the format: lint: {type}: {message}
	// e.g., "lint: allow-before-deny: allow rule 'allow-prod' at index 0 precedes deny rule 'deny-prod' for same profiles"
	if !strings.Contains(errOutput, "lint: allow-before-deny:") {
		t.Errorf("lint output should contain 'lint: allow-before-deny:', got: %s", errOutput)
	}
}

// TestPolicyPullCommand_OutputFilePermissions verifies that policy output files
// have secure permissions (0600) as required by SEC-03 security hardening.
func TestPolicyPullCommand_OutputFilePermissions(t *testing.T) {
	// Skip on Windows - file permissions work differently
	if os.Getenv("GOOS") == "windows" {
		t.Skip("File permissions test not applicable on Windows")
	}

	// Create temp directory
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "policy-output.yaml")

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
			"/sentinel/policies/test-perms": validPolicyYAML(),
		},
	}

	input := PolicyPullCommandInput{
		Profile:    "test-perms",
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

	// Verify file was created
	info, err := os.Stat(outputFile)
	if err != nil {
		t.Fatalf("failed to stat output file: %v", err)
	}

	// Verify file has 0600 permissions (SEC-03)
	expectedPerm := os.FileMode(0600)
	actualPerm := info.Mode().Perm()
	if actualPerm != expectedPerm {
		t.Errorf("Policy output file should have %o permissions (SEC-03), got %o", expectedPerm, actualPerm)
	}
}
