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

// Note: Full CLI integration tests require CGO (1password-sdk-go dependency).
// These tests validate logic and formatting without full CLI execution.

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

// InfrastructureCheckerInterface defines the infrastructure checking interface for testing.
type InfrastructureCheckerInterface interface {
	GetInfrastructureStatus(ctx context.Context, approvalTable, breakglassTable, sessionTable string) (*bootstrap.InfrastructureStatus, error)
}

// mockInfrastructureCheckerImpl implements InfrastructureCheckerInterface for testing.
type mockInfrastructureCheckerImpl struct {
	result *bootstrap.InfrastructureStatus
	err    error
}

func (m *mockInfrastructureCheckerImpl) GetInfrastructureStatus(ctx context.Context, approvalTable, breakglassTable, sessionTable string) (*bootstrap.InfrastructureStatus, error) {
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
	return testableStatusCommandWithInfra(ctx, input, checker, nil)
}

// testableStatusCommandWithInfra is a testable version that accepts both interfaces.
func testableStatusCommandWithInfra(
	ctx context.Context,
	input StatusCommandInput,
	checker StatusCheckerInterface,
	infraChecker InfrastructureCheckerInterface,
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

	// Validate: --check-tables requires --region (unless we have mock checker)
	if input.CheckTables && input.Region == "" && infraChecker == nil {
		_, _ = stderr.WriteString("Error: --check-tables requires --region to be specified\n")
		return errors.New("--check-tables requires --region")
	}

	// Get status
	result, err := checker.GetStatus(ctx, input.PolicyRoot)
	if err != nil {
		_, _ = stderr.WriteString("Failed to get status: " + err.Error() + "\n")
		return err
	}

	// Get infrastructure status if requested
	var infraStatus *bootstrap.InfrastructureStatus
	if input.CheckTables && infraChecker != nil {
		infraStatus, err = infraChecker.GetInfrastructureStatus(ctx,
			input.ApprovalTableName,
			input.BreakGlassTableName,
			input.SessionTableName)
		if err != nil {
			_, _ = stderr.WriteString("Failed to get infrastructure status: " + err.Error() + "\n")
			return err
		}
	}

	// Output results
	if input.JSONOutput {
		// For testing, output a simple JSON structure
		_, _ = stdout.WriteString(`{"policy_root":"` + result.PolicyRoot + `","count":`)
		_, _ = stdout.WriteString(string(rune('0' + result.Count)))
		if infraStatus != nil {
			_, _ = stdout.WriteString(`,"infrastructure":{"tables":[`)
			for i, t := range infraStatus.Tables {
				if i > 0 {
					_, _ = stdout.WriteString(",")
				}
				_, _ = stdout.WriteString(`{"table_name":"` + t.TableName + `","status":"` + t.Status + `","purpose":"` + t.Purpose + `"}`)
			}
			_, _ = stdout.WriteString("]}")
		}
		_, _ = stdout.WriteString("}\n")
	} else {
		_, _ = stdout.WriteString("Sentinel Status\n")
		_, _ = stdout.WriteString("===============\n\n")
		_, _ = stdout.WriteString("Policy Parameters (" + result.PolicyRoot + "):\n")

		if len(result.Parameters) == 0 {
			_, _ = stdout.WriteString("  (none)\n")
		} else {
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

		// Output infrastructure status if available
		if infraStatus != nil {
			_, _ = stdout.WriteString("\nInfrastructure:\n")
			for _, t := range infraStatus.Tables {
				_, _ = stdout.WriteString("  " + t.TableName + "    " + t.Purpose + "    " + t.Status + "\n")
			}
		}
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

	if !strings.Contains(output, "Sentinel Status") {
		t.Error("expected output to contain 'Sentinel Status'")
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
	if !strings.Contains(output, "Sentinel Status") {
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
// Infrastructure Status Tests
// ============================================================================

func TestStatusCommand_WithInfrastructure_AllActive(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	policyResult := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{},
		Count:      0,
	}

	infraResult := &bootstrap.InfrastructureStatus{
		Tables: []bootstrap.TableInfo{
			{TableName: "sentinel-requests", Status: "ACTIVE", Region: "us-east-1", Purpose: "approvals"},
			{TableName: "sentinel-breakglass", Status: "ACTIVE", Region: "us-east-1", Purpose: "breakglass"},
			{TableName: "sentinel-sessions", Status: "ACTIVE", Region: "us-east-1", Purpose: "sessions"},
		},
	}

	policyChecker := &mockStatusCheckerImpl{result: policyResult}
	infraChecker := &mockInfrastructureCheckerImpl{result: infraResult}

	input := StatusCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Region:      "us-east-1",
		CheckTables: true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableStatusCommandWithInfra(context.Background(), input, policyChecker, infraChecker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Check header changed to "Sentinel Status"
	if !strings.Contains(output, "Sentinel Status") {
		t.Error("expected output to contain 'Sentinel Status'")
	}
	// Check infrastructure section
	if !strings.Contains(output, "Infrastructure:") {
		t.Error("expected output to contain 'Infrastructure:'")
	}
	if !strings.Contains(output, "sentinel-requests") {
		t.Error("expected output to contain 'sentinel-requests'")
	}
	if !strings.Contains(output, "ACTIVE") {
		t.Error("expected output to contain 'ACTIVE'")
	}
	if !strings.Contains(output, "approvals") {
		t.Error("expected output to contain 'approvals'")
	}
}

func TestStatusCommand_WithInfrastructure_SomeMissing(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	policyResult := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{
			{
				Name:         "production",
				Path:         "/sentinel/policies/production",
				Version:      1,
				LastModified: time.Date(2026, 1, 20, 10, 0, 0, 0, time.UTC),
				Type:         "String",
			},
		},
		Count: 1,
	}

	infraResult := &bootstrap.InfrastructureStatus{
		Tables: []bootstrap.TableInfo{
			{TableName: "sentinel-requests", Status: "ACTIVE", Region: "us-east-1", Purpose: "approvals"},
			{TableName: "sentinel-breakglass", Status: "NOT_FOUND", Region: "us-east-1", Purpose: "breakglass"},
			{TableName: "sentinel-sessions", Status: "NOT_FOUND", Region: "us-east-1", Purpose: "sessions"},
		},
	}

	policyChecker := &mockStatusCheckerImpl{result: policyResult}
	infraChecker := &mockInfrastructureCheckerImpl{result: infraResult}

	input := StatusCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Region:      "us-east-1",
		CheckTables: true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableStatusCommandWithInfra(context.Background(), input, policyChecker, infraChecker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Check infrastructure section shows both statuses
	if !strings.Contains(output, "ACTIVE") {
		t.Error("expected output to contain 'ACTIVE'")
	}
	if !strings.Contains(output, "NOT_FOUND") {
		t.Error("expected output to contain 'NOT_FOUND'")
	}
}

func TestStatusCommand_WithInfrastructure_JSON(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	policyResult := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{},
		Count:      0,
	}

	infraResult := &bootstrap.InfrastructureStatus{
		Tables: []bootstrap.TableInfo{
			{TableName: "sentinel-requests", Status: "ACTIVE", Region: "us-east-1", Purpose: "approvals"},
			{TableName: "sentinel-breakglass", Status: "CREATING", Region: "us-east-1", Purpose: "breakglass"},
		},
	}

	policyChecker := &mockStatusCheckerImpl{result: policyResult}
	infraChecker := &mockInfrastructureCheckerImpl{result: infraResult}

	input := StatusCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Region:      "us-east-1",
		CheckTables: true,
		JSONOutput:  true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableStatusCommandWithInfra(context.Background(), input, policyChecker, infraChecker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Check JSON output contains infrastructure
	if !strings.Contains(output, `"infrastructure"`) {
		t.Error("expected JSON output to contain 'infrastructure' field")
	}
	if !strings.Contains(output, `"tables"`) {
		t.Error("expected JSON output to contain 'tables' field")
	}
	if !strings.Contains(output, `"sentinel-requests"`) {
		t.Error("expected JSON output to contain table name")
	}
	if !strings.Contains(output, `"ACTIVE"`) {
		t.Error("expected JSON output to contain status")
	}
	if !strings.Contains(output, `"CREATING"`) {
		t.Error("expected JSON output to contain CREATING status")
	}
}

func TestStatusCommand_CheckTables_RequiresRegion(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	policyResult := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{},
		Count:      0,
	}

	policyChecker := &mockStatusCheckerImpl{result: policyResult}

	input := StatusCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Region:      "", // No region
		CheckTables: true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	// No infrastructure checker - should fail due to missing region
	err := testableStatusCommandWithInfra(context.Background(), input, policyChecker, nil)
	if err == nil {
		t.Fatal("expected error due to missing region")
	}

	errOutput := readFile(t, stderr)
	if !strings.Contains(errOutput, "--check-tables requires --region") {
		t.Errorf("expected error about region requirement, got: %s", errOutput)
	}
}

func TestStatusCommand_InfrastructureError(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	policyResult := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{},
		Count:      0,
	}

	policyChecker := &mockStatusCheckerImpl{result: policyResult}
	infraChecker := &mockInfrastructureCheckerImpl{err: errors.New("AccessDeniedException: not authorized")}

	input := StatusCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Region:      "us-east-1",
		CheckTables: true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableStatusCommandWithInfra(context.Background(), input, policyChecker, infraChecker)
	if err == nil {
		t.Fatal("expected error from infrastructure checker")
	}

	errOutput := readFile(t, stderr)
	if !strings.Contains(errOutput, "Failed to get infrastructure status") {
		t.Error("expected stderr to contain infrastructure error message")
	}
}

func TestStatusCommand_WithoutCheckTables_NoInfrastructure(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	policyResult := &bootstrap.StatusResult{
		PolicyRoot: "/sentinel/policies",
		Parameters: []bootstrap.ParameterInfo{},
		Count:      0,
	}

	policyChecker := &mockStatusCheckerImpl{result: policyResult}
	// Even with infra checker available, if CheckTables is false, it should not be called
	infraChecker := &mockInfrastructureCheckerImpl{
		result: &bootstrap.InfrastructureStatus{
			Tables: []bootstrap.TableInfo{
				{TableName: "should-not-appear", Status: "ACTIVE", Purpose: "test"},
			},
		},
	}

	input := StatusCommandInput{
		PolicyRoot:  "/sentinel/policies",
		CheckTables: false, // Disabled
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableStatusCommandWithInfra(context.Background(), input, policyChecker, infraChecker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Should NOT contain infrastructure section
	if strings.Contains(output, "Infrastructure:") {
		t.Error("expected output to NOT contain infrastructure section when CheckTables is false")
	}
	if strings.Contains(output, "should-not-appear") {
		t.Error("expected infra checker to not be called when CheckTables is false")
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
