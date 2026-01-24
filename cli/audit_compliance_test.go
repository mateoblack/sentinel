package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/audit"
)

func TestAuditSessionComplianceCommand_AllCompliant(t *testing.T) {
	// Create a mock reporter that returns all compliant
	mockReporter := audit.NewReporterForTest(func(ctx context.Context, input *audit.SessionComplianceInput) (*audit.SessionComplianceResult, error) {
		return &audit.SessionComplianceResult{
			StartTime:              input.StartTime,
			EndTime:                input.EndTime,
			RequiredProfiles:       2,
			FullyCompliantProfiles: 2,
			ProfilesWithGaps:       0,
			Profiles: []audit.ProfileCompliance{
				{
					Profile:        "prod",
					PolicyRequired: true,
					TrackedCount:   145,
					UntrackedCount: 0,
					ComplianceRate: 100.0,
					HasGap:         false,
				},
				{
					Profile:        "staging",
					PolicyRequired: true,
					TrackedCount:   89,
					UntrackedCount: 0,
					ComplianceRate: 100.0,
					HasGap:         false,
				},
			},
		}, nil
	})

	// Create temp files for output
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stdout.Name())

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stderr.Name())

	input := AuditSessionComplianceCommandInput{
		Since:     "7d",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Reporter:  mockReporter,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditSessionComplianceCommand(context.Background(), input)
	if err != nil {
		t.Errorf("Expected no error when all compliant, got: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "All required profiles fully compliant") {
		t.Errorf("Expected 'All required profiles fully compliant' in output, got: %s", output)
	}
	if !strings.Contains(output, "Fully compliant profiles: 2") {
		t.Errorf("Expected 'Fully compliant profiles: 2' in output, got: %s", output)
	}
}

func TestAuditSessionComplianceCommand_ComplianceGaps(t *testing.T) {
	// Create a mock reporter that returns compliance gaps
	mockReporter := audit.NewReporterForTest(func(ctx context.Context, input *audit.SessionComplianceInput) (*audit.SessionComplianceResult, error) {
		return &audit.SessionComplianceResult{
			StartTime:              input.StartTime,
			EndTime:                input.EndTime,
			RequiredProfiles:       2,
			FullyCompliantProfiles: 1,
			ProfilesWithGaps:       1,
			Profiles: []audit.ProfileCompliance{
				{
					Profile:        "prod",
					PolicyRequired: true,
					TrackedCount:   145,
					UntrackedCount: 0,
					ComplianceRate: 100.0,
					HasGap:         false,
				},
				{
					Profile:        "staging",
					PolicyRequired: true,
					TrackedCount:   89,
					UntrackedCount: 3,
					ComplianceRate: 96.7,
					HasGap:         true,
				},
			},
		}, nil
	})

	// Create temp files for output
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stdout.Name())

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stderr.Name())

	input := AuditSessionComplianceCommandInput{
		Since:     "7d",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Reporter:  mockReporter,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditSessionComplianceCommand(context.Background(), input)
	if err == nil {
		t.Error("Expected error when compliance gaps found, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "compliance gap") {
		t.Errorf("Expected 'compliance gap' in error, got: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "1 profile(s) with compliance gaps") {
		t.Errorf("Expected '1 profile(s) with compliance gaps' in output, got: %s", output)
	}
	if !strings.Contains(output, "Profiles with gaps: 1") {
		t.Errorf("Expected 'Profiles with gaps: 1' in output, got: %s", output)
	}
}

func TestAuditSessionComplianceCommand_JSONOutput(t *testing.T) {
	// Create a mock reporter
	mockReporter := audit.NewReporterForTest(func(ctx context.Context, input *audit.SessionComplianceInput) (*audit.SessionComplianceResult, error) {
		return &audit.SessionComplianceResult{
			StartTime:              input.StartTime,
			EndTime:                input.EndTime,
			RequiredProfiles:       1,
			FullyCompliantProfiles: 1,
			ProfilesWithGaps:       0,
			Profiles: []audit.ProfileCompliance{
				{
					Profile:        "prod",
					PolicyRequired: true,
					TrackedCount:   100,
					UntrackedCount: 0,
					ComplianceRate: 100.0,
					HasGap:         false,
				},
			},
		}, nil
	})

	// Create temp files for output
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stdout.Name())

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stderr.Name())

	input := AuditSessionComplianceCommandInput{
		Since:      "7d",
		Region:     "us-east-1",
		TableName:  "test-sessions",
		JSONOutput: true,
		Reporter:   mockReporter,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err = AuditSessionComplianceCommand(context.Background(), input)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "\"required_profiles\": 1") {
		t.Errorf("Expected JSON with required_profiles, got: %s", output)
	}
	if !strings.Contains(output, "\"fully_compliant_profiles\": 1") {
		t.Errorf("Expected JSON with fully_compliant_profiles, got: %s", output)
	}
	if !strings.Contains(output, "\"profiles_with_gaps\": 0") {
		t.Errorf("Expected JSON with profiles_with_gaps, got: %s", output)
	}
}

func TestAuditSessionComplianceCommand_InvalidDuration(t *testing.T) {
	// Create temp files for output
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stdout.Name())

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stderr.Name())

	input := AuditSessionComplianceCommandInput{
		Since:     "invalid",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditSessionComplianceCommand(context.Background(), input)
	if err == nil {
		t.Error("Expected error for invalid duration, got nil")
	}

	// Read stderr
	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	errOutput := buf.String()

	if !strings.Contains(errOutput, "Invalid --since duration") {
		t.Errorf("Expected 'Invalid --since duration' in stderr, got: %s", errOutput)
	}
}

func TestAuditSessionComplianceCommand_WithUntilDuration(t *testing.T) {
	var capturedInput *audit.SessionComplianceInput

	// Create a mock reporter that captures the input
	mockReporter := audit.NewReporterForTest(func(ctx context.Context, input *audit.SessionComplianceInput) (*audit.SessionComplianceResult, error) {
		capturedInput = input
		return &audit.SessionComplianceResult{
			StartTime:              input.StartTime,
			EndTime:                input.EndTime,
			RequiredProfiles:       0,
			FullyCompliantProfiles: 0,
			ProfilesWithGaps:       0,
			Profiles:               []audit.ProfileCompliance{},
		}, nil
	})

	// Create temp files for output
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stdout.Name())

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stderr.Name())

	input := AuditSessionComplianceCommandInput{
		Since:     "7d",
		Until:     "1d",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Reporter:  mockReporter,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditSessionComplianceCommand(context.Background(), input)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify the time window was calculated correctly
	// EndTime should be ~1 day ago, StartTime should be ~8 days ago
	if capturedInput == nil {
		t.Fatal("Input was not captured")
	}

	now := time.Now()
	expectedEndTime := now.Add(-24 * time.Hour)
	expectedStartTime := expectedEndTime.Add(-7 * 24 * time.Hour)

	// Allow 5 second tolerance for test execution time
	if capturedInput.EndTime.Sub(expectedEndTime).Abs() > 5*time.Second {
		t.Errorf("EndTime mismatch: expected ~%v, got %v", expectedEndTime, capturedInput.EndTime)
	}
	if capturedInput.StartTime.Sub(expectedStartTime).Abs() > 5*time.Second {
		t.Errorf("StartTime mismatch: expected ~%v, got %v", expectedStartTime, capturedInput.StartTime)
	}
}

func TestAuditSessionComplianceCommand_ProfileFilter(t *testing.T) {
	var capturedInput *audit.SessionComplianceInput

	// Create a mock reporter that captures the input
	mockReporter := audit.NewReporterForTest(func(ctx context.Context, input *audit.SessionComplianceInput) (*audit.SessionComplianceResult, error) {
		capturedInput = input
		return &audit.SessionComplianceResult{
			StartTime:              input.StartTime,
			EndTime:                input.EndTime,
			RequiredProfiles:       0,
			FullyCompliantProfiles: 0,
			ProfilesWithGaps:       0,
			Profiles:               []audit.ProfileCompliance{},
		}, nil
	})

	// Create temp files for output
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stdout.Name())

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stderr.Name())

	input := AuditSessionComplianceCommandInput{
		Since:     "7d",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Profile:   "prod",
		Reporter:  mockReporter,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditSessionComplianceCommand(context.Background(), input)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify the profile filter was passed
	if capturedInput == nil {
		t.Fatal("Input was not captured")
	}

	if capturedInput.ProfileName != "prod" {
		t.Errorf("ProfileName mismatch: expected 'prod', got %q", capturedInput.ProfileName)
	}
}

func TestAuditSessionComplianceCommand_NoRequiredProfiles(t *testing.T) {
	// Create a mock reporter that returns no required profiles
	mockReporter := audit.NewReporterForTest(func(ctx context.Context, input *audit.SessionComplianceInput) (*audit.SessionComplianceResult, error) {
		return &audit.SessionComplianceResult{
			StartTime:              input.StartTime,
			EndTime:                input.EndTime,
			RequiredProfiles:       0,
			FullyCompliantProfiles: 0,
			ProfilesWithGaps:       0,
			Profiles: []audit.ProfileCompliance{
				{
					Profile:        "dev",
					PolicyRequired: false,
					TrackedCount:   12,
					UntrackedCount: 45,
					ComplianceRate: 21.1,
					HasGap:         false,
				},
			},
		}, nil
	})

	// Create temp files for output
	stdout, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stdout.Name())

	stderr, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stderr.Name())

	input := AuditSessionComplianceCommandInput{
		Since:     "7d",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Reporter:  mockReporter,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditSessionComplianceCommand(context.Background(), input)
	if err != nil {
		t.Errorf("Expected no error when no required profiles, got: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "All required profiles fully compliant") {
		t.Errorf("Expected 'All required profiles fully compliant' in output, got: %s", output)
	}
	if !strings.Contains(output, "Profiles with require_server_session: 0") {
		t.Errorf("Expected 'Profiles with require_server_session: 0' in output, got: %s", output)
	}
}
