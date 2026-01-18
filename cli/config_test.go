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
