package cli

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/audit"
)

// ============================================================================
// Test Helper Functions
// ============================================================================

// createAuditTestFiles creates temp files for test I/O.
func createAuditTestFiles(t *testing.T) (*os.File, *os.File, func()) {
	t.Helper()

	stdout, err := os.CreateTemp("", "audit-stdout-*")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}

	stderr, err := os.CreateTemp("", "audit-stderr-*")
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

// readAuditFile reads content from a temp file.
func readAuditFile(t *testing.T, f *os.File) string {
	t.Helper()
	f.Seek(0, 0)
	content, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	return string(content)
}

// createMockVerificationResult creates a test VerificationResult.
func createMockVerificationResult(total, sentinel, nonSentinel int, issues []audit.SessionIssue) *audit.VerificationResult {
	return &audit.VerificationResult{
		StartTime:           time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		EndTime:             time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		TotalSessions:       total,
		SentinelSessions:    sentinel,
		NonSentinelSessions: nonSentinel,
		Issues:              issues,
	}
}

// ============================================================================
// Mock Verifier
// ============================================================================

// mockVerifier implements a mock Verifier for testing.
type mockVerifier struct {
	result *audit.VerificationResult
	err    error
}

// We need to create a wrapper that allows us to inject the mock
// Since we can't easily mock the Verifier struct, we'll use the input.Verifier field

// ============================================================================
// Test: All Sentinel Sessions (No Issues)
// ============================================================================

func TestAuditVerifyCommand_AllSentinelSessions(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	// Create a mock verifier with all Sentinel sessions
	verifier := audit.NewVerifierForTest(func(ctx context.Context, input *audit.VerifyInput) (*audit.VerificationResult, error) {
		return createMockVerificationResult(42, 42, 0, nil), nil
	})

	input := AuditVerifyCommandInput{
		StartTime: time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		Verifier:  verifier,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readAuditFile(t, stdout)

	if !strings.Contains(output, "CloudTrail Session Verification") {
		t.Error("expected output to contain header")
	}
	if !strings.Contains(output, "Total sessions:       42") {
		t.Error("expected output to contain total sessions")
	}
	if !strings.Contains(output, "Sentinel sessions:    42 (100.0%)") {
		t.Error("expected output to contain 100% Sentinel sessions")
	}
	if !strings.Contains(output, "Non-Sentinel:         0") {
		t.Error("expected output to contain 0 non-Sentinel sessions")
	}
	if !strings.Contains(output, "All sessions verified with Sentinel SourceIdentity") {
		t.Error("expected output to contain success message")
	}
}

// ============================================================================
// Test: Mixed Sessions (Has Issues)
// ============================================================================

func TestAuditVerifyCommand_MixedSessions(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	// Create issues for non-Sentinel sessions
	issues := []audit.SessionIssue{
		{
			Severity: audit.SeverityWarning,
			Type:     audit.IssueTypeMissingSourceIdentity,
			SessionInfo: &audit.SessionInfo{
				EventID:   "abc123",
				EventTime: time.Date(2026, 1, 16, 8, 30, 0, 0, time.UTC),
				EventName: "AssumeRole",
				Username:  "alice",
			},
			Message: "Session without Sentinel SourceIdentity: alice (event: AssumeRole)",
		},
		{
			Severity: audit.SeverityWarning,
			Type:     audit.IssueTypeMissingSourceIdentity,
			SessionInfo: &audit.SessionInfo{
				EventID:   "def456",
				EventTime: time.Date(2026, 1, 16, 10, 15, 0, 0, time.UTC),
				EventName: "AssumeRole",
				Username:  "bob",
			},
			Message: "Session without Sentinel SourceIdentity: bob (event: AssumeRole)",
		},
	}

	verifier := audit.NewVerifierForTest(func(ctx context.Context, input *audit.VerifyInput) (*audit.VerificationResult, error) {
		return createMockVerificationResult(42, 40, 2, issues), nil
	})

	input := AuditVerifyCommandInput{
		StartTime: time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		Verifier:  verifier,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error when issues found")
	}
	if !strings.Contains(err.Error(), "2 issue(s) found") {
		t.Errorf("expected error message to contain issue count, got: %v", err)
	}

	output := readAuditFile(t, stdout)

	if !strings.Contains(output, "Total sessions:       42") {
		t.Error("expected output to contain total sessions")
	}
	if !strings.Contains(output, "Sentinel sessions:    40 (95.2%)") {
		t.Error("expected output to contain 95.2% Sentinel sessions")
	}
	if !strings.Contains(output, "Non-Sentinel:         2") {
		t.Error("expected output to contain 2 non-Sentinel sessions")
	}
	if !strings.Contains(output, "Issues (2)") {
		t.Error("expected output to contain issues header")
	}
	if !strings.Contains(output, "[WARNING] Session without Sentinel SourceIdentity: alice") {
		t.Error("expected output to contain alice issue")
	}
	if !strings.Contains(output, "[WARNING] Session without Sentinel SourceIdentity: bob") {
		t.Error("expected output to contain bob issue")
	}
	if !strings.Contains(output, "Event ID: abc123") {
		t.Error("expected output to contain alice event ID")
	}
	if !strings.Contains(output, "Event ID: def456") {
		t.Error("expected output to contain bob event ID")
	}
	if !strings.Contains(output, "Result: 2 issue(s) found") {
		t.Error("expected output to contain result message")
	}
}

// ============================================================================
// Test: Human Output Format
// ============================================================================

func TestAuditVerifyCommand_HumanOutputFormat(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	verifier := audit.NewVerifierForTest(func(ctx context.Context, input *audit.VerifyInput) (*audit.VerificationResult, error) {
		return createMockVerificationResult(10, 10, 0, nil), nil
	})

	input := AuditVerifyCommandInput{
		StartTime: time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		Verifier:  verifier,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readAuditFile(t, stdout)

	// Check structure
	if !strings.Contains(output, "CloudTrail Session Verification") {
		t.Error("expected header")
	}
	if !strings.Contains(output, "================================") {
		t.Error("expected header separator")
	}
	if !strings.Contains(output, "Time Window:") {
		t.Error("expected time window")
	}
	if !strings.Contains(output, "2026-01-16T00:00:00Z to 2026-01-16T12:00:00Z") {
		t.Error("expected time window values")
	}
	if !strings.Contains(output, "Summary") {
		t.Error("expected summary section")
	}
	if !strings.Contains(output, "-------") {
		t.Error("expected summary separator")
	}
}

// ============================================================================
// Test: JSON Output Format
// ============================================================================

func TestAuditVerifyCommand_JSONOutput(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	verifier := audit.NewVerifierForTest(func(ctx context.Context, input *audit.VerifyInput) (*audit.VerificationResult, error) {
		return createMockVerificationResult(42, 40, 2, []audit.SessionIssue{
			{
				Severity: audit.SeverityWarning,
				Type:     audit.IssueTypeMissingSourceIdentity,
				Message:  "Session without Sentinel SourceIdentity: alice (event: AssumeRole)",
			},
		}), nil
	})

	input := AuditVerifyCommandInput{
		StartTime:  time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		EndTime:    time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		JSONOutput: true,
		Verifier:   verifier,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	// Error expected because of issues
	if err == nil {
		t.Error("expected error when issues found")
	}

	output := readAuditFile(t, stdout)

	// Check JSON structure
	if !strings.Contains(output, `"start_time"`) {
		t.Error("expected JSON to contain start_time")
	}
	if !strings.Contains(output, `"end_time"`) {
		t.Error("expected JSON to contain end_time")
	}
	if !strings.Contains(output, `"total_sessions": 42`) {
		t.Error("expected JSON to contain total_sessions")
	}
	if !strings.Contains(output, `"sentinel_sessions": 40`) {
		t.Error("expected JSON to contain sentinel_sessions")
	}
	if !strings.Contains(output, `"non_sentinel_sessions": 2`) {
		t.Error("expected JSON to contain non_sentinel_sessions")
	}
	if !strings.Contains(output, `"issues"`) {
		t.Error("expected JSON to contain issues")
	}
	if !strings.Contains(output, `"severity": "warning"`) {
		t.Error("expected JSON to contain severity")
	}
}

// ============================================================================
// Test: Time Validation (End Before Start)
// ============================================================================

func TestAuditVerifyCommand_TimeValidation(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	input := AuditVerifyCommandInput{
		StartTime: time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC), // Before start
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error when end time is before start time")
	}
	if !strings.Contains(err.Error(), "--end must be after --start") {
		t.Errorf("expected error message about time validation, got: %v", err)
	}

	errOutput := readAuditFile(t, stderr)
	if !strings.Contains(errOutput, "Error: --end must be after --start") {
		t.Error("expected stderr to contain error message")
	}
}

func TestAuditVerifyCommand_TimeValidation_EqualTimes(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	sameTime := time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC)
	input := AuditVerifyCommandInput{
		StartTime: sameTime,
		EndTime:   sameTime, // Same as start
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error when end time equals start time")
	}
	if !strings.Contains(err.Error(), "--end must be after --start") {
		t.Errorf("expected error message about time validation, got: %v", err)
	}
}

// ============================================================================
// Test: With Role Filter
// ============================================================================

func TestAuditVerifyCommand_WithRoleFilter(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	var capturedInput *audit.VerifyInput
	verifier := audit.NewVerifierForTest(func(ctx context.Context, input *audit.VerifyInput) (*audit.VerificationResult, error) {
		capturedInput = input
		return createMockVerificationResult(5, 5, 0, nil), nil
	})

	input := AuditVerifyCommandInput{
		StartTime: time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		RoleARN:   "arn:aws:iam::123456789012:role/MyRole",
		Verifier:  verifier,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedInput == nil {
		t.Fatal("expected verify input to be captured")
	}
	if capturedInput.RoleARN != "arn:aws:iam::123456789012:role/MyRole" {
		t.Errorf("expected role filter to be passed, got: %s", capturedInput.RoleARN)
	}
}

// ============================================================================
// Test: With User Filter
// ============================================================================

func TestAuditVerifyCommand_WithUserFilter(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	var capturedInput *audit.VerifyInput
	verifier := audit.NewVerifierForTest(func(ctx context.Context, input *audit.VerifyInput) (*audit.VerificationResult, error) {
		capturedInput = input
		return createMockVerificationResult(3, 3, 0, nil), nil
	})

	input := AuditVerifyCommandInput{
		StartTime: time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		Username:  "alice",
		Verifier:  verifier,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedInput == nil {
		t.Fatal("expected verify input to be captured")
	}
	if capturedInput.Username != "alice" {
		t.Errorf("expected username filter to be passed, got: %s", capturedInput.Username)
	}
}

// ============================================================================
// Test: With Both Filters
// ============================================================================

func TestAuditVerifyCommand_WithBothFilters(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	var capturedInput *audit.VerifyInput
	verifier := audit.NewVerifierForTest(func(ctx context.Context, input *audit.VerifyInput) (*audit.VerificationResult, error) {
		capturedInput = input
		return createMockVerificationResult(1, 1, 0, nil), nil
	})

	input := AuditVerifyCommandInput{
		StartTime: time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		RoleARN:   "arn:aws:iam::123456789012:role/AdminRole",
		Username:  "bob",
		Verifier:  verifier,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedInput == nil {
		t.Fatal("expected verify input to be captured")
	}
	if capturedInput.RoleARN != "arn:aws:iam::123456789012:role/AdminRole" {
		t.Errorf("expected role filter to be passed, got: %s", capturedInput.RoleARN)
	}
	if capturedInput.Username != "bob" {
		t.Errorf("expected username filter to be passed, got: %s", capturedInput.Username)
	}
}

// ============================================================================
// Test: Zero Sessions
// ============================================================================

func TestAuditVerifyCommand_ZeroSessions(t *testing.T) {
	stdout, stderr, cleanup := createAuditTestFiles(t)
	defer cleanup()

	verifier := audit.NewVerifierForTest(func(ctx context.Context, input *audit.VerifyInput) (*audit.VerificationResult, error) {
		return createMockVerificationResult(0, 0, 0, nil), nil
	})

	input := AuditVerifyCommandInput{
		StartTime: time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC),
		EndTime:   time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
		Verifier:  verifier,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := AuditVerifyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readAuditFile(t, stdout)

	if !strings.Contains(output, "Total sessions:       0") {
		t.Error("expected output to contain 0 total sessions")
	}
	if !strings.Contains(output, "Sentinel sessions:    0 (100.0%)") {
		t.Error("expected output to contain 100% (no sessions = no issues)")
	}
	if !strings.Contains(output, "All sessions verified with Sentinel SourceIdentity") {
		t.Error("expected success message for zero sessions")
	}
}
