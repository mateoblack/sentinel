package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigValidateCommand_ValidFile(t *testing.T) {
	// Create temp file with valid policy
	tmpDir, err := os.MkdirTemp("", "config-cli-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	validPolicy := `
version: "1"
rules:
  - name: allow-dev
    effect: allow
    conditions:
      profiles:
        - dev
`
	validPath := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte(validPolicy), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

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

	input := ConfigValidateCommandInput{
		Paths:  []string{validPath},
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Read stdout and verify output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Valid") {
		t.Errorf("output should contain 'Valid', got: %s", output)
	}
	if !strings.Contains(output, "1 valid, 0 invalid") {
		t.Errorf("output should contain summary, got: %s", output)
	}
}

func TestConfigValidateCommand_InvalidFile(t *testing.T) {
	// Create temp file with invalid policy
	tmpDir, err := os.MkdirTemp("", "config-cli-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	invalidPolicy := `
version: "1"
rules: []
`
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte(invalidPolicy), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

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

	input := ConfigValidateCommandInput{
		Paths:  []string{invalidPath},
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for invalid config", exitCode)
	}

	// Read stdout
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Errors:") {
		t.Errorf("output should contain 'Errors:', got: %s", output)
	}
	if !strings.Contains(output, "0 valid, 1 invalid") {
		t.Errorf("output should contain summary, got: %s", output)
	}
}

func TestConfigValidateCommand_MixedFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-cli-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create valid file
	validPolicy := `
version: "1"
rules:
  - name: allow-dev
    effect: allow
    conditions:
      profiles:
        - dev
`
	validPath := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte(validPolicy), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Create invalid file
	invalidPolicy := `
version: "1"
rules:
  - effect: allow
    conditions:
      profiles:
        - dev
`
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte(invalidPolicy), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

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

	input := ConfigValidateCommandInput{
		Paths:  []string{validPath, invalidPath},
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 (some invalid)", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "1 valid, 1 invalid") {
		t.Errorf("output should contain '1 valid, 1 invalid', got: %s", output)
	}
}

func TestConfigValidateCommand_JSONOutput(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-cli-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	validPolicy := `
version: "1"
rules:
  - name: allow-dev
    effect: allow
    conditions:
      profiles:
        - dev
`
	validPath := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte(validPolicy), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

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

	input := ConfigValidateCommandInput{
		Paths:  []string{validPath},
		Output: "json",
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify JSON output
	if !strings.Contains(output, `"valid": true`) {
		t.Errorf("JSON output should contain '\"valid\": true', got: %s", output)
	}
	if !strings.Contains(output, `"config_type": "policy"`) {
		t.Errorf("JSON output should contain config_type, got: %s", output)
	}
	if !strings.Contains(output, `"summary"`) {
		t.Errorf("JSON output should contain summary, got: %s", output)
	}
}

func TestConfigValidateCommand_ExplicitType(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-cli-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create approval policy
	approvalPolicy := `
version: "1"
rules:
  - name: prod-approval
    profiles:
      - prod
    approvers:
      - admin
`
	path := filepath.Join(tmpDir, "approval.yaml")
	if err := os.WriteFile(path, []byte(approvalPolicy), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

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

	input := ConfigValidateCommandInput{
		Paths:      []string{path},
		ConfigType: "approval",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "(approval)") {
		t.Errorf("output should show type as (approval), got: %s", output)
	}
}

func TestConfigValidateCommand_AutoDetectType(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-cli-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create bootstrap config
	bootstrapConfig := `
policy_root: /sentinel/policies
profiles:
  - name: dev
`
	path := filepath.Join(tmpDir, "bootstrap.yaml")
	if err := os.WriteFile(path, []byte(bootstrapConfig), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

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

	input := ConfigValidateCommandInput{
		Paths:  []string{path},
		Stdout: stdout,
		Stderr: stderr,
		// No ConfigType specified - should auto-detect
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "(bootstrap)") {
		t.Errorf("should auto-detect as bootstrap, got: %s", output)
	}
}

func TestConfigValidateCommand_NonexistentFile(t *testing.T) {
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

	input := ConfigValidateCommandInput{
		Paths:  []string{"/nonexistent/path.yaml"},
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for nonexistent file", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "failed to read file") {
		t.Errorf("output should mention file read failure, got: %s", output)
	}
}

func TestConfigValidateCommand_NoPathsError(t *testing.T) {
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

	input := ConfigValidateCommandInput{
		Paths:  []string{},
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error for no paths")
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "no paths specified") {
		t.Errorf("stderr should mention no paths, got: %s", errOutput)
	}
}

func TestConfigValidateCommand_SSMPath(t *testing.T) {
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

	// Mock SSM fetcher
	validPolicy := `
version: "1"
rules:
  - name: allow-dev
    effect: allow
    conditions:
      profiles:
        - dev
`
	mockSSMFetch := func(ctx context.Context, path string) ([]byte, error) {
		if path == "/sentinel/policies/dev" {
			return []byte(validPolicy), nil
		}
		return nil, errors.New("parameter not found")
	}

	input := ConfigValidateCommandInput{
		SSMPaths: []string{"/sentinel/policies/dev"},
		Stdout:   stdout,
		Stderr:   stderr,
		SSMFetch: mockSSMFetch,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "/sentinel/policies/dev") {
		t.Errorf("output should contain SSM path, got: %s", output)
	}
	if !strings.Contains(output, "1 valid") {
		t.Errorf("output should show valid result, got: %s", output)
	}
}

func TestConfigValidateCommand_SSMPathError(t *testing.T) {
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

	// Mock SSM fetcher that returns error
	mockSSMFetch := func(ctx context.Context, path string) ([]byte, error) {
		return nil, errors.New("parameter not found")
	}

	input := ConfigValidateCommandInput{
		SSMPaths: []string{"/sentinel/policies/nonexistent"},
		Stdout:   stdout,
		Stderr:   stderr,
		SSMFetch: mockSSMFetch,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for SSM error", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "failed to load SSM parameter") {
		t.Errorf("output should mention SSM error, got: %s", output)
	}
}

func TestConfigValidateCommand_WarningsDoNotAffectExitCode(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-cli-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Policy with warnings (empty profiles) but valid
	policyWithWarnings := `
version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      time:
        days:
          - monday
`
	path := filepath.Join(tmpDir, "warnings.yaml")
	if err := os.WriteFile(path, []byte(policyWithWarnings), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

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

	input := ConfigValidateCommandInput{
		Paths:  []string{path},
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode, err := ConfigValidateCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Warnings should not cause exit code 1
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 (warnings don't affect exit code)", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Should show as valid with warnings
	if !strings.Contains(output, "1 valid") {
		t.Errorf("should show valid count, got: %s", output)
	}
}

func TestPluralize(t *testing.T) {
	tests := []struct {
		count    int
		expected string
	}{
		{0, "s"},
		{1, ""},
		{2, "s"},
		{10, "s"},
	}

	for _, tt := range tests {
		got := pluralize(tt.count)
		if got != tt.expected {
			t.Errorf("pluralize(%d) = %q, want %q", tt.count, got, tt.expected)
		}
	}
}

// Tests for ConfigGenerateCommand

func TestConfigGenerateCommand_BasicTemplate(t *testing.T) {
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

	input := ConfigGenerateCommandInput{
		Template: "basic",
		Profiles: []string{"dev", "staging"},
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode, err := ConfigGenerateCommand(input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify policy output
	if !strings.Contains(output, "Access Policy") {
		t.Errorf("output should contain 'Access Policy', got: %s", output)
	}
	if !strings.Contains(output, "allow-configured-profiles") {
		t.Errorf("output should contain rule name, got: %s", output)
	}
	if !strings.Contains(output, "dev") {
		t.Errorf("output should contain profile 'dev', got: %s", output)
	}

	// Basic template should NOT have approval, breakglass, ratelimit
	if strings.Contains(output, "Approval Policy") {
		t.Errorf("basic template should not have Approval Policy")
	}
}

func TestConfigGenerateCommand_ApprovalsTemplate(t *testing.T) {
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

	input := ConfigGenerateCommandInput{
		Template: "approvals",
		Profiles: []string{"prod"},
		Users:    []string{"alice", "bob"},
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode, err := ConfigGenerateCommand(input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify both policy and approval
	if !strings.Contains(output, "Access Policy") {
		t.Errorf("output should contain 'Access Policy'")
	}
	if !strings.Contains(output, "Approval Policy") {
		t.Errorf("output should contain 'Approval Policy'")
	}
	if !strings.Contains(output, "require_approval") {
		t.Errorf("output should contain 'require_approval' effect")
	}
	if !strings.Contains(output, "alice") {
		t.Errorf("output should contain approver 'alice'")
	}

	// Approvals should NOT have breakglass or ratelimit
	if strings.Contains(output, "Break-Glass Policy") {
		t.Errorf("approvals template should not have Break-Glass Policy")
	}
}

func TestConfigGenerateCommand_FullTemplate(t *testing.T) {
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

	input := ConfigGenerateCommandInput{
		Template: "full",
		Profiles: []string{"prod"},
		Users:    []string{"oncall"},
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode, err := ConfigGenerateCommand(input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify all four configs are present
	if !strings.Contains(output, "Access Policy") {
		t.Errorf("output should contain 'Access Policy'")
	}
	if !strings.Contains(output, "Approval Policy") {
		t.Errorf("output should contain 'Approval Policy'")
	}
	if !strings.Contains(output, "Break-Glass Policy") {
		t.Errorf("output should contain 'Break-Glass Policy'")
	}
	if !strings.Contains(output, "Rate Limit Policy") {
		t.Errorf("output should contain 'Rate Limit Policy'")
	}
}

func TestConfigGenerateCommand_ApprovalsWithoutUsers(t *testing.T) {
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

	input := ConfigGenerateCommandInput{
		Template: "approvals",
		Profiles: []string{"prod"},
		// No users - should error
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode, err := ConfigGenerateCommand(input)
	if err == nil {
		t.Error("expected error for approvals without users")
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "at least one user") {
		t.Errorf("stderr should mention users required, got: %s", errOutput)
	}
}

func TestConfigGenerateCommand_InvalidTemplate(t *testing.T) {
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

	input := ConfigGenerateCommandInput{
		Template: "invalid-template",
		Profiles: []string{"dev"},
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode, err := ConfigGenerateCommand(input)
	if err == nil {
		t.Error("expected error for invalid template")
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "invalid template") {
		t.Errorf("stderr should mention invalid template, got: %s", errOutput)
	}
}

func TestConfigGenerateCommand_JSONOutput(t *testing.T) {
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

	input := ConfigGenerateCommandInput{
		Template:   "basic",
		Profiles:   []string{"dev"},
		JSONOutput: true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode, err := ConfigGenerateCommand(input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify JSON structure
	if !strings.Contains(output, `"Policy":`) {
		t.Errorf("JSON output should contain 'Policy' field, got: %s", output)
	}
	if !strings.Contains(output, `"Approval":`) {
		t.Errorf("JSON output should contain 'Approval' field, got: %s", output)
	}
}

func TestConfigGenerateCommand_FileOutput(t *testing.T) {
	// Create temp dir for output
	tmpDir, err := os.MkdirTemp("", "config-generate-test")
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

	outputDir := filepath.Join(tmpDir, "policies")

	input := ConfigGenerateCommandInput{
		Template:  "full",
		Profiles:  []string{"prod"},
		Users:     []string{"admin"},
		OutputDir: outputDir,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	exitCode, err := ConfigGenerateCommand(input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Verify files were created
	expectedFiles := []string{"policy.yaml", "approval.yaml", "breakglass.yaml", "ratelimit.yaml"}
	for _, name := range expectedFiles {
		path := filepath.Join(outputDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s was not created", name)
		}
	}

	// Verify stdout message
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Generated 4 config files") {
		t.Errorf("stdout should contain file count, got: %s", output)
	}
	for _, name := range expectedFiles {
		if !strings.Contains(output, name) {
			t.Errorf("stdout should list file %s, got: %s", name, output)
		}
	}
}

func TestConfigGenerateCommand_BasicFileOutput(t *testing.T) {
	// Create temp dir for output
	tmpDir, err := os.MkdirTemp("", "config-generate-test")
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

	outputDir := filepath.Join(tmpDir, "policies")

	input := ConfigGenerateCommandInput{
		Template:  "basic",
		Profiles:  []string{"dev"},
		OutputDir: outputDir,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	exitCode, err := ConfigGenerateCommand(input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Basic should only create policy.yaml
	if _, err := os.Stat(filepath.Join(outputDir, "policy.yaml")); os.IsNotExist(err) {
		t.Error("expected policy.yaml to be created")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "approval.yaml")); !os.IsNotExist(err) {
		t.Error("approval.yaml should not be created for basic template")
	}

	// Verify stdout
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Generated 1 config file") {
		t.Errorf("stdout should say 1 config file, got: %s", output)
	}
}
