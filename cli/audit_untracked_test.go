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

func TestAuditUntrackedSessionsCommand_AllTracked(t *testing.T) {
	// Create a mock detector that returns all tracked
	mockDetector := audit.NewDetectorForTest(func(ctx context.Context, input *audit.UntrackedSessionsInput) (*audit.UntrackedSessionsResult, error) {
		return &audit.UntrackedSessionsResult{
			StartTime:         input.StartTime,
			EndTime:           input.EndTime,
			TotalEvents:       10,
			TrackedEvents:     10,
			UntrackedEvents:   0,
			OrphanedEvents:    0,
			UntrackedSessions: []audit.UntrackedSession{},
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

	input := AuditUntrackedSessionsCommandInput{
		Since:     "7d",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Detector:  mockDetector,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditUntrackedSessionsCommand(context.Background(), input)
	if err != nil {
		t.Errorf("Expected no error when all tracked, got: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "All sessions properly tracked") {
		t.Errorf("Expected 'All sessions properly tracked' in output, got: %s", output)
	}
	if !strings.Contains(output, "Tracked:          10") {
		t.Errorf("Expected 'Tracked:          10' in output, got: %s", output)
	}
}

func TestAuditUntrackedSessionsCommand_UntrackedFound(t *testing.T) {
	// Create a mock detector that returns untracked sessions
	mockDetector := audit.NewDetectorForTest(func(ctx context.Context, input *audit.UntrackedSessionsInput) (*audit.UntrackedSessionsResult, error) {
		return &audit.UntrackedSessionsResult{
			StartTime:       input.StartTime,
			EndTime:         input.EndTime,
			TotalEvents:     10,
			TrackedEvents:   7,
			UntrackedEvents: 3,
			OrphanedEvents:  0,
			UntrackedSessions: []audit.UntrackedSession{
				{
					EventID:   "event-001",
					EventTime: time.Now(),
					RoleARN:   "arn:aws:iam::123456789012:role/TestRole",
					SourceIP:  "1.2.3.4",
					Category:  audit.CategoryNoSourceIdentity,
					Reason:    "No SourceIdentity set on AssumeRole call",
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

	input := AuditUntrackedSessionsCommandInput{
		Since:     "7d",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Detector:  mockDetector,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditUntrackedSessionsCommand(context.Background(), input)
	if err == nil {
		t.Error("Expected error when untracked sessions found, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "untracked session") {
		t.Errorf("Expected 'untracked session' in error, got: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "compliance gap") {
		t.Errorf("Expected 'compliance gap' in output, got: %s", output)
	}
	if !strings.Contains(output, "Untracked:        3") {
		t.Errorf("Expected 'Untracked:        3' in output, got: %s", output)
	}
}

func TestAuditUntrackedSessionsCommand_JSONOutput(t *testing.T) {
	// Create a mock detector
	mockDetector := audit.NewDetectorForTest(func(ctx context.Context, input *audit.UntrackedSessionsInput) (*audit.UntrackedSessionsResult, error) {
		return &audit.UntrackedSessionsResult{
			StartTime:         input.StartTime,
			EndTime:           input.EndTime,
			TotalEvents:       5,
			TrackedEvents:     5,
			UntrackedEvents:   0,
			OrphanedEvents:    0,
			UntrackedSessions: []audit.UntrackedSession{},
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

	input := AuditUntrackedSessionsCommandInput{
		Since:      "7d",
		Region:     "us-east-1",
		TableName:  "test-sessions",
		JSONOutput: true,
		Detector:   mockDetector,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err = AuditUntrackedSessionsCommand(context.Background(), input)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "\"total_events\": 5") {
		t.Errorf("Expected JSON with total_events, got: %s", output)
	}
	if !strings.Contains(output, "\"tracked_events\": 5") {
		t.Errorf("Expected JSON with tracked_events, got: %s", output)
	}
}

func TestAuditUntrackedSessionsCommand_InvalidDuration(t *testing.T) {
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

	input := AuditUntrackedSessionsCommandInput{
		Since:     "invalid",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditUntrackedSessionsCommand(context.Background(), input)
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

func TestAuditUntrackedSessionsCommand_WithUntilDuration(t *testing.T) {
	var capturedInput *audit.UntrackedSessionsInput

	// Create a mock detector that captures the input
	mockDetector := audit.NewDetectorForTest(func(ctx context.Context, input *audit.UntrackedSessionsInput) (*audit.UntrackedSessionsResult, error) {
		capturedInput = input
		return &audit.UntrackedSessionsResult{
			StartTime:         input.StartTime,
			EndTime:           input.EndTime,
			TotalEvents:       0,
			TrackedEvents:     0,
			UntrackedEvents:   0,
			OrphanedEvents:    0,
			UntrackedSessions: []audit.UntrackedSession{},
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

	input := AuditUntrackedSessionsCommandInput{
		Since:     "7d",
		Until:     "1d",
		Region:    "us-east-1",
		TableName: "test-sessions",
		Detector:  mockDetector,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err = AuditUntrackedSessionsCommand(context.Background(), input)
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
