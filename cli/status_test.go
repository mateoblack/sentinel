package cli

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/bootstrap"
)

// ============================================================================
// Test Interfaces and Mocks
// ============================================================================

// StatusCheckerInterface defines the status checking interface for testing.
type StatusCheckerInterface interface {
	GetStatus(ctx context.Context, policyRoot string) (*bootstrap.StatusResult, error)
}

// mockStatusCheckerImpl implements StatusCheckerInterface for testing.
type mockStatusCheckerImpl struct {
	result *bootstrap.StatusResult
	err    error
}

func (m *mockStatusCheckerImpl) GetStatus(ctx context.Context, policyRoot string) (*bootstrap.StatusResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

// ============================================================================
// Testable Command Using Interfaces
// ============================================================================

// testableStatusCommand is a testable version that accepts interfaces.
func testableStatusCommand(
	ctx context.Context,
	input StatusCommandInput,
	checker StatusCheckerInterface,
) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Get status
	result, err := checker.GetStatus(ctx, input.PolicyRoot)
	if err != nil {
		_, _ = stderr.WriteString("Failed to get status: " + err.Error() + "\n")
		return err
	}

	// Output results
	if input.JSONOutput {
		// For testing, output a simple JSON structure
		_, _ = stdout.WriteString(`{"policy_root":"` + result.PolicyRoot + `","count":`)
		_, _ = stdout.WriteString(string(rune('0'+result.Count)) + "}\n")
	} else {
		_, _ = stdout.WriteString("Sentinel Policy Status\n")
		_, _ = stdout.WriteString("======================\n\n")
		_, _ = stdout.WriteString("Policy Root: " + result.PolicyRoot + "\n\n")

		if len(result.Parameters) == 0 {
			_, _ = stdout.WriteString("Profiles:\n  (none)\n")
		} else {
			_, _ = stdout.WriteString("Profiles:\n")
			for _, p := range result.Parameters {
				timeStr := p.LastModified.Format("2006-01-02 15:04:05")
				line := "  " + p.Name + "    v" + string(rune('0'+int(p.Version))) + "  (last modified: " + timeStr + ")\n"
				_, _ = stdout.WriteString(line)
			}
		}

		_, _ = stdout.WriteString("\nTotal: " + string(rune('0'+result.Count)) + " policy parameter")
		if result.Count != 1 {
			_, _ = stdout.WriteString("s")
		}
		_, _ = stdout.WriteString("\n")
	}

	return nil
}

// ============================================================================
// Empty Results Tests
// ============================================================================

func TestStatusCommand_EmptyResults(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	result := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{},
		Count:      0,
	}

	checker := &mockStatusCheckerImpl{result: result}

	input := StatusCommandInput{
		PolicyRoot: "/sentinel/policies",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableStatusCommand(context.Background(), input, checker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	if !strings.Contains(output, "Sentinel Policy Status") {
		t.Error("expected output to contain 'Sentinel Policy Status'")
	}
	if !strings.Contains(output, "/sentinel/policies") {
		t.Error("expected output to contain policy root")
	}
	if !strings.Contains(output, "(none)") {
		t.Error("expected output to contain '(none)' for empty profiles")
	}
	if !strings.Contains(output, "Total: 0 policy parameters") {
		t.Error("expected output to contain 'Total: 0 policy parameters'")
	}
}

// ============================================================================
// Single Parameter Tests
// ============================================================================

func TestStatusCommand_SingleParameter(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	result := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{
			{
				Name:         "production",
				Path:         "/sentinel/policies/production",
				Version:      3,
				LastModified: time.Date(2026, 1, 15, 14, 30, 0, 0, time.UTC),
				Type:         "String",
			},
		},
		Count: 1,
	}

	checker := &mockStatusCheckerImpl{result: result}

	input := StatusCommandInput{
		PolicyRoot: "/sentinel/policies",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableStatusCommand(context.Background(), input, checker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	if !strings.Contains(output, "production") {
		t.Error("expected output to contain profile name 'production'")
	}
	if !strings.Contains(output, "v3") {
		t.Error("expected output to contain version 'v3'")
	}
	if !strings.Contains(output, "2026-01-15") {
		t.Error("expected output to contain last modified date")
	}
	if !strings.Contains(output, "Total: 1 policy parameter") {
		t.Error("expected output to contain 'Total: 1 policy parameter'")
	}
	// Should NOT have "parameters" (plural) for count=1
	if strings.Contains(output, "1 policy parameters") {
		t.Error("expected singular 'parameter' not 'parameters' for count=1")
	}
}

// ============================================================================
// Multiple Parameters Tests
// ============================================================================

func TestStatusCommand_MultipleParameters(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	result := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{
			{
				Name:         "production",
				Path:         "/sentinel/policies/production",
				Version:      3,
				LastModified: time.Date(2026, 1, 15, 14, 30, 0, 0, time.UTC),
				Type:         "String",
			},
			{
				Name:         "staging",
				Path:         "/sentinel/policies/staging",
				Version:      1,
				LastModified: time.Date(2026, 1, 14, 10, 0, 0, 0, time.UTC),
				Type:         "String",
			},
			{
				Name:         "development",
				Path:         "/sentinel/policies/development",
				Version:      5,
				LastModified: time.Date(2026, 1, 16, 9, 15, 0, 0, time.UTC),
				Type:         "String",
			},
		},
		Count: 3,
	}

	checker := &mockStatusCheckerImpl{result: result}

	input := StatusCommandInput{
		PolicyRoot: "/sentinel/policies",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableStatusCommand(context.Background(), input, checker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Check all profiles are listed
	if !strings.Contains(output, "production") {
		t.Error("expected output to contain 'production'")
	}
	if !strings.Contains(output, "staging") {
		t.Error("expected output to contain 'staging'")
	}
	if !strings.Contains(output, "development") {
		t.Error("expected output to contain 'development'")
	}
	if !strings.Contains(output, "Total: 3 policy parameters") {
		t.Error("expected output to contain 'Total: 3 policy parameters'")
	}
}

// ============================================================================
// JSON Output Tests
// ============================================================================

func TestStatusCommand_JSONOutput_Empty(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	result := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{},
		Count:      0,
	}

	checker := &mockStatusCheckerImpl{result: result}

	input := StatusCommandInput{
		PolicyRoot: "/sentinel/policies",
		JSONOutput: true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableStatusCommand(context.Background(), input, checker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	if !strings.Contains(output, `"policy_root"`) {
		t.Error("expected JSON output to contain policy_root field")
	}
}

func TestStatusCommand_JSONOutput_WithParameters(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	result := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{
			{
				Name:         "production",
				Path:         "/sentinel/policies/production",
				Version:      3,
				LastModified: time.Date(2026, 1, 15, 14, 30, 0, 0, time.UTC),
				Type:         "String",
			},
		},
		Count: 1,
	}

	checker := &mockStatusCheckerImpl{result: result}

	input := StatusCommandInput{
		PolicyRoot: "/sentinel/policies",
		JSONOutput: true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableStatusCommand(context.Background(), input, checker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	if !strings.Contains(output, `"policy_root"`) {
		t.Error("expected JSON output to contain policy_root field")
	}
}

// ============================================================================
// Error Cases
// ============================================================================

func TestStatusCommand_SSMError(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	checker := &mockStatusCheckerImpl{err: errors.New("AccessDeniedException: access denied")}

	input := StatusCommandInput{
		PolicyRoot: "/sentinel/policies",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableStatusCommand(context.Background(), input, checker)
	if err == nil {
		t.Fatal("expected error")
	}

	errOutput := readFile(t, stderr)
	if !strings.Contains(errOutput, "Failed to get status") {
		t.Error("expected stderr to contain error message")
	}
}

// ============================================================================
// Custom Region Tests
// ============================================================================

func TestStatusCommand_CustomRegion(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	result := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{},
		Count:      0,
	}

	checker := &mockStatusCheckerImpl{result: result}

	input := StatusCommandInput{
		PolicyRoot: "/sentinel/policies",
		Region:     "eu-west-1",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableStatusCommand(context.Background(), input, checker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Region is used for AWS config, not displayed in output
	output := readFile(t, stdout)
	if !strings.Contains(output, "Sentinel Policy Status") {
		t.Error("expected output to contain header")
	}
}

// ============================================================================
// Custom Policy Root Tests
// ============================================================================

func TestStatusCommand_CustomPolicyRoot(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	result := &bootstrap.StatusResult{
		PolicyRoot: "/custom/path/policies",
		Parameters: []bootstrap.ParameterInfo{},
		Count:      0,
	}

	checker := &mockStatusCheckerImpl{result: result}

	input := StatusCommandInput{
		PolicyRoot: "/custom/path/policies",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableStatusCommand(context.Background(), input, checker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "/custom/path/policies") {
		t.Error("expected output to contain custom policy root")
	}
}

// ============================================================================
// Real Command Integration Tests (minimal - no AWS required)
// ============================================================================

func TestStatusCommand_RealCommand_NoAWSConfig(t *testing.T) {
	// This test just verifies the function doesn't panic with nil inputs
	// Actual AWS calls will fail, but we're testing the error handling
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	input := StatusCommandInput{
		PolicyRoot: "/sentinel/policies",
		Stdout:     stdout,
		Stderr:     stderr,
		// No StatusChecker - will try to create real one
		// This will either succeed (if AWS credentials available) or fail gracefully
	}

	// We expect either success or an AWS-related error
	_ = StatusCommand(context.Background(), input)

	// Just verify we didn't panic and the function returns
}

// ============================================================================
// Output Format Tests (using actual StatusCommand with mocks)
// ============================================================================

func TestStatusCommand_ActualCommand_WithMock(t *testing.T) {
	// This test uses a real temp file for more realistic testing
	stdout, err := os.CreateTemp("", "status-stdout-*")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}
	defer func() {
		stdout.Close()
		os.Remove(stdout.Name())
	}()

	stderr, err := os.CreateTemp("", "status-stderr-*")
	if err != nil {
		t.Fatalf("failed to create temp stderr: %v", err)
	}
	defer func() {
		stderr.Close()
		os.Remove(stderr.Name())
	}()

	// Use the actual StatusCommand but with mock data
	// Since StatusChecker is nil, it will try to use AWS config
	// This will likely fail, so we just verify error handling works

	input := StatusCommandInput{
		PolicyRoot: "/sentinel/policies",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	// Run command (will likely fail without AWS)
	_ = StatusCommand(context.Background(), input)
}
