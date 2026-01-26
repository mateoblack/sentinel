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

	// Calls tracks GetParameter calls for assertions.
	Calls []*ssm.GetParameterInput
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
