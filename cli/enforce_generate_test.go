package cli

import (
	"context"
	"os"
	"strings"
	"testing"
)

// ============================================================================
// Test Helper Functions (reuse patterns from enforce_test.go)
// ============================================================================

// createGenerateTestFiles creates temp files for test I/O.
func createGenerateTestFiles(t *testing.T) (*os.File, *os.File, func()) {
	t.Helper()

	stdout, err := os.CreateTemp("", "generate-stdout-*")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}

	stderr, err := os.CreateTemp("", "generate-stderr-*")
	if err != nil {
		stdout.Close()
		os.Remove(stdout.Name())
		t.Fatalf("failed to create temp stderr: %v", err)
	}

	cleanup := func() {
		stdout.Close()
		stderr.Close()
		os.Remove(stdout.Name())
		os.Remove(stderr.Name())
	}

	return stdout, stderr, cleanup
}

// readGenerateFile reads content from a temp file.
func readGenerateFile(t *testing.T, f *os.File) string {
	t.Helper()
	f.Seek(0, 0)
	content, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	return string(content)
}

// ============================================================================
// Pattern A Tests
// ============================================================================

func TestEnforceGenerateTrustPolicyCommand_PatternA(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern:      "any-sentinel",
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readGenerateFile(t, stdout)

	// Verify JSON structure
	if !strings.Contains(output, `"Version": "2012-10-17"`) {
		t.Error("expected output to contain Version")
	}
	if !strings.Contains(output, `"Sid": "AllowSentinelAccess"`) {
		t.Error("expected output to contain AllowSentinelAccess Sid")
	}
	if !strings.Contains(output, `"Effect": "Allow"`) {
		t.Error("expected output to contain Allow effect")
	}
	if !strings.Contains(output, `"arn:aws:iam::123456789012:root"`) {
		t.Error("expected output to contain principal ARN")
	}
	if !strings.Contains(output, `"sts:AssumeRole"`) {
		t.Error("expected output to contain sts:AssumeRole action")
	}
	if !strings.Contains(output, `"StringLike"`) {
		t.Error("expected output to contain StringLike condition")
	}
	if !strings.Contains(output, `"sts:SourceIdentity"`) {
		t.Error("expected output to contain sts:SourceIdentity key")
	}
	if !strings.Contains(output, `"sentinel:*"`) {
		t.Error("expected output to contain sentinel:* pattern")
	}
}

// ============================================================================
// Pattern B Tests
// ============================================================================

func TestEnforceGenerateTrustPolicyCommand_PatternB_SingleUser(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern:      "specific-users",
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Users:        []string{"alice"},
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readGenerateFile(t, stdout)

	if !strings.Contains(output, `"Sid": "AllowSentinelUsers"`) {
		t.Error("expected output to contain AllowSentinelUsers Sid")
	}
	if !strings.Contains(output, `"sentinel:alice:*"`) {
		t.Error("expected output to contain sentinel:alice:* pattern")
	}
}

func TestEnforceGenerateTrustPolicyCommand_PatternB_MultipleUsers(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern:      "specific-users",
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Users:        []string{"alice", "bob"},
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readGenerateFile(t, stdout)

	if !strings.Contains(output, `"sentinel:alice:*"`) {
		t.Error("expected output to contain sentinel:alice:* pattern")
	}
	if !strings.Contains(output, `"sentinel:bob:*"`) {
		t.Error("expected output to contain sentinel:bob:* pattern")
	}
}

// ============================================================================
// Pattern C Tests
// ============================================================================

func TestEnforceGenerateTrustPolicyCommand_PatternC(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern:         "migration",
		PrincipalARN:    "arn:aws:iam::123456789012:root",
		LegacyPrincipal: "arn:aws:iam::123456789012:role/LegacyServiceRole",
		Stdout:          stdout,
		Stderr:          stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readGenerateFile(t, stdout)

	// Verify two statements
	if !strings.Contains(output, `"Sid": "AllowSentinelAccess"`) {
		t.Error("expected output to contain AllowSentinelAccess Sid")
	}
	if !strings.Contains(output, `"Sid": "AllowLegacyAccess"`) {
		t.Error("expected output to contain AllowLegacyAccess Sid")
	}
	if !strings.Contains(output, `"sentinel:*"`) {
		t.Error("expected output to contain sentinel:* pattern")
	}
	if !strings.Contains(output, `"arn:aws:iam::123456789012:role/LegacyServiceRole"`) {
		t.Error("expected output to contain legacy principal ARN")
	}
}

// ============================================================================
// Error Cases
// ============================================================================

func TestEnforceGenerateTrustPolicyCommand_MissingPattern(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern:      "",
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error for missing pattern")
	}

	errOutput := readGenerateFile(t, stderr)
	if !strings.Contains(errOutput, "invalid pattern") {
		t.Errorf("expected stderr to contain invalid pattern error, got: %s", errOutput)
	}
}

func TestEnforceGenerateTrustPolicyCommand_InvalidPattern(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern:      "invalid-pattern",
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error for invalid pattern")
	}

	errOutput := readGenerateFile(t, stderr)
	if !strings.Contains(errOutput, "invalid pattern") {
		t.Errorf("expected stderr to contain invalid pattern error, got: %s", errOutput)
	}
}

func TestEnforceGenerateTrustPolicyCommand_MissingPrincipal(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern: "any-sentinel",
		Stdout:  stdout,
		Stderr:  stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error for missing principal")
	}

	errOutput := readGenerateFile(t, stderr)
	if !strings.Contains(errOutput, "--principal is required") {
		t.Errorf("expected stderr to contain principal required error, got: %s", errOutput)
	}
}

func TestEnforceGenerateTrustPolicyCommand_PatternBWithoutUsers(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern:      "specific-users",
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error for pattern B without users")
	}

	errOutput := readGenerateFile(t, stderr)
	if !strings.Contains(errOutput, "--users is required") {
		t.Errorf("expected stderr to contain users required error, got: %s", errOutput)
	}
}

func TestEnforceGenerateTrustPolicyCommand_PatternCWithoutLegacyPrincipal(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern:      "migration",
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error for pattern C without legacy principal")
	}

	errOutput := readGenerateFile(t, stderr)
	if !strings.Contains(errOutput, "--legacy-principal is required") {
		t.Errorf("expected stderr to contain legacy-principal required error, got: %s", errOutput)
	}
}

// ============================================================================
// JSON Format Validation
// ============================================================================

func TestEnforceGenerateTrustPolicyCommand_ValidJSON(t *testing.T) {
	stdout, stderr, cleanup := createGenerateTestFiles(t)
	defer cleanup()

	input := EnforceGenerateTrustPolicyCommandInput{
		Pattern:      "any-sentinel",
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readGenerateFile(t, stdout)

	// Verify it's valid JSON by checking basic structure
	if !strings.HasPrefix(strings.TrimSpace(output), "{") {
		t.Error("expected output to start with {")
	}
	if !strings.HasSuffix(strings.TrimSpace(output), "}") {
		t.Error("expected output to end with }")
	}

	// Verify indentation (pretty printed)
	if !strings.Contains(output, "  ") {
		t.Error("expected output to be indented")
	}
}
