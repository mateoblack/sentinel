package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/permissions"
)

// mockDetector implements permissions.DetectorInterface for testing.
type mockDetector struct {
	DetectFunc func(ctx context.Context) (*permissions.DetectionResult, error)
}

func (m *mockDetector) Detect(ctx context.Context) (*permissions.DetectionResult, error) {
	if m.DetectFunc != nil {
		return m.DetectFunc(ctx)
	}
	return &permissions.DetectionResult{
		Features:       []permissions.Feature{permissions.FeatureCredentialIssue},
		FeatureDetails: map[permissions.Feature]string{permissions.FeatureCredentialIssue: "test"},
		Errors:         []permissions.DetectionError{},
	}, nil
}

func TestPermissionsCommand_DefaultFormat(t *testing.T) {
	// Create temp files for output capture
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format: "human",
		Stdout: stdout,
		Stderr: stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	output, _ := os.ReadFile(stdout.Name())
	result := string(output)

	// Should contain header
	if !strings.Contains(result, "Sentinel IAM Permissions") {
		t.Error("expected human-readable header")
	}

	// Should include all features
	for _, f := range permissions.AllFeatures() {
		if !strings.Contains(result, string(f)) {
			t.Errorf("expected feature %s in output", f)
		}
	}
}

func TestPermissionsCommand_JSONFormat(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format: "json",
		Stdout: stdout,
		Stderr: stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	output, _ := os.ReadFile(stdout.Name())

	// Should be valid JSON
	var doc permissions.IAMPolicyDocument
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Should have statements
	if len(doc.Statement) == 0 {
		t.Error("expected statements in JSON output")
	}

	// Should have correct version
	if doc.Version != "2012-10-17" {
		t.Errorf("expected Version 2012-10-17, got %s", doc.Version)
	}
}

func TestPermissionsCommand_TerraformFormat(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format: "terraform",
		Stdout: stdout,
		Stderr: stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	output, _ := os.ReadFile(stdout.Name())
	result := string(output)

	// Should be HCL
	if !strings.Contains(result, `data "aws_iam_policy_document" "sentinel"`) {
		t.Error("expected Terraform data source declaration")
	}
	if !strings.Contains(result, "statement {") {
		t.Error("expected statement block")
	}
}

func TestPermissionsCommand_CloudFormationFormat(t *testing.T) {
	testCases := []struct {
		name   string
		format string
	}{
		{"cloudformation", "cloudformation"},
		{"cf alias", "cf"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _ := os.CreateTemp("", "stdout")
			stderr, _ := os.CreateTemp("", "stderr")
			defer os.Remove(stdout.Name())
			defer os.Remove(stderr.Name())

			input := PermissionsCommandInput{
				Format: tc.format,
				Stdout: stdout,
				Stderr: stderr,
			}

			err := PermissionsCommand(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Read output
			stdout.Seek(0, 0)
			output, _ := os.ReadFile(stdout.Name())
			result := string(output)

			// Should be YAML
			if !strings.Contains(result, "Type: AWS::IAM::ManagedPolicy") {
				t.Error("expected CloudFormation type")
			}
			if !strings.Contains(result, "PolicyDocument:") {
				t.Error("expected PolicyDocument")
			}
		})
	}
}

func TestPermissionsCommand_SubsystemFilter(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format:    "human",
		Subsystem: "core",
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	output, _ := os.ReadFile(stdout.Name())
	result := string(output)

	// Should contain core subsystem features
	if !strings.Contains(result, "policy_load") {
		t.Error("expected policy_load feature for core subsystem")
	}

	// Should NOT contain other subsystem features
	if strings.Contains(result, "credential_issue") {
		t.Error("should not contain credential_issue (credentials subsystem)")
	}
	if strings.Contains(result, "approval_workflow") {
		t.Error("should not contain approval_workflow (approvals subsystem)")
	}
}

func TestPermissionsCommand_FeatureFilter(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format:  "human",
		Feature: "policy_load",
		Stdout:  stdout,
		Stderr:  stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	output, _ := os.ReadFile(stdout.Name())
	result := string(output)

	// Should contain policy_load
	if !strings.Contains(result, "policy_load") {
		t.Error("expected policy_load feature")
	}

	// Should NOT contain other features
	if strings.Contains(result, "credential_issue") {
		t.Error("should not contain credential_issue")
	}
	if strings.Contains(result, "notify_sns") {
		t.Error("should not contain notify_sns")
	}
}

func TestPermissionsCommand_RequiredOnly(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format:       "human",
		RequiredOnly: true,
		Stdout:       stdout,
		Stderr:       stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read output
	stdout.Seek(0, 0)
	output, _ := os.ReadFile(stdout.Name())
	result := string(output)

	// Should NOT contain optional features
	if strings.Contains(result, "notify_sns") {
		t.Error("should not contain notify_sns (optional)")
	}
	if strings.Contains(result, "notify_webhook") {
		t.Error("should not contain notify_webhook (optional)")
	}

	// Should contain required features
	if !strings.Contains(result, "policy_load") {
		t.Error("expected policy_load (required)")
	}
	if !strings.Contains(result, "credential_issue") {
		t.Error("expected credential_issue (required)")
	}
}

func TestPermissionsCommand_InvalidFormat(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format: "invalid",
		Stdout: stdout,
		Stderr: stderr,
	}

	err := PermissionsCommand(input)
	if err == nil {
		t.Error("expected error for invalid format")
	}

	if !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("expected 'invalid format' error, got: %v", err)
	}
}

func TestPermissionsCommand_InvalidSubsystem(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format:    "human",
		Subsystem: "invalid-subsystem",
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := PermissionsCommand(input)
	if err == nil {
		t.Error("expected error for invalid subsystem")
	}

	if !strings.Contains(err.Error(), "invalid subsystem") {
		t.Errorf("expected 'invalid subsystem' error, got: %v", err)
	}
}

func TestPermissionsCommand_InvalidFeature(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format:  "human",
		Feature: "invalid-feature",
		Stdout:  stdout,
		Stderr:  stderr,
	}

	err := PermissionsCommand(input)
	if err == nil {
		t.Error("expected error for invalid feature")
	}

	if !strings.Contains(err.Error(), "invalid feature") {
		t.Errorf("expected 'invalid feature' error, got: %v", err)
	}
}

func TestPermissionsCommand_AllSubsystems(t *testing.T) {
	// Test each valid subsystem
	for _, subsystem := range permissions.AllSubsystems() {
		t.Run(string(subsystem), func(t *testing.T) {
			stdout, _ := os.CreateTemp("", "stdout")
			stderr, _ := os.CreateTemp("", "stderr")
			defer os.Remove(stdout.Name())
			defer os.Remove(stderr.Name())

			input := PermissionsCommandInput{
				Format:    "human",
				Subsystem: string(subsystem),
				Stdout:    stdout,
				Stderr:    stderr,
			}

			err := PermissionsCommand(input)
			if err != nil {
				t.Fatalf("unexpected error for subsystem %s: %v", subsystem, err)
			}
		})
	}
}

func TestPermissionsCommand_AllFeatures(t *testing.T) {
	// Test each valid feature
	for _, feature := range permissions.AllFeatures() {
		t.Run(string(feature), func(t *testing.T) {
			stdout, _ := os.CreateTemp("", "stdout")
			stderr, _ := os.CreateTemp("", "stderr")
			defer os.Remove(stdout.Name())
			defer os.Remove(stderr.Name())

			input := PermissionsCommandInput{
				Format:  "human",
				Feature: string(feature),
				Stdout:  stdout,
				Stderr:  stderr,
			}

			err := PermissionsCommand(input)
			if err != nil {
				t.Fatalf("unexpected error for feature %s: %v", feature, err)
			}
		})
	}
}

func TestFilterRequired(t *testing.T) {
	perms := []permissions.FeaturePermissions{
		{Feature: permissions.FeaturePolicyLoad, Optional: false},
		{Feature: permissions.FeatureNotifySNS, Optional: true},
		{Feature: permissions.FeatureNotifyWebhook, Optional: true},
		{Feature: permissions.FeatureCredentialIssue, Optional: false},
	}

	result := filterRequired(perms)

	// Should have 2 required features
	if len(result) != 2 {
		t.Errorf("expected 2 required features, got %d", len(result))
	}

	// Verify all results are non-optional
	for _, fp := range result {
		if fp.Optional {
			t.Errorf("expected non-optional, got optional: %s", fp.Feature)
		}
	}
}

func TestGetFeaturePermissions(t *testing.T) {
	t.Run("valid feature", func(t *testing.T) {
		result, err := getFeaturePermissions("policy_load")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 1 {
			t.Errorf("expected 1 result, got %d", len(result))
		}
		if result[0].Feature != permissions.FeaturePolicyLoad {
			t.Errorf("expected policy_load, got %s", result[0].Feature)
		}
	})

	t.Run("invalid feature", func(t *testing.T) {
		_, err := getFeaturePermissions("not_a_feature")
		if err == nil {
			t.Error("expected error for invalid feature")
		}
	})
}

func TestGetSubsystemPermissions(t *testing.T) {
	t.Run("valid subsystem", func(t *testing.T) {
		result, err := getSubsystemPermissions("core")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) == 0 {
			t.Error("expected at least 1 result for core subsystem")
		}
		// Core subsystem should have policy_load
		found := false
		for _, fp := range result {
			if fp.Feature == permissions.FeaturePolicyLoad {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected policy_load in core subsystem")
		}
	})

	t.Run("invalid subsystem", func(t *testing.T) {
		_, err := getSubsystemPermissions("not_a_subsystem")
		if err == nil {
			t.Error("expected error for invalid subsystem")
		}
	})
}

func TestPermissionsCommand_Detect_HumanFormat(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	detector := &mockDetector{
		DetectFunc: func(ctx context.Context) (*permissions.DetectionResult, error) {
			return &permissions.DetectionResult{
				Features: []permissions.Feature{
					permissions.FeatureCredentialIssue,
					permissions.FeaturePolicyLoad,
				},
				FeatureDetails: map[permissions.Feature]string{
					permissions.FeatureCredentialIssue: "base feature",
					permissions.FeaturePolicyLoad:      "SSM parameter exists",
				},
				Errors: []permissions.DetectionError{},
			}, nil
		},
	}

	input := PermissionsCommandInput{
		Format:   "human",
		Detect:   true,
		Detector: detector,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read stdout (permissions output)
	stdout.Seek(0, 0)
	output, _ := os.ReadFile(stdout.Name())
	result := string(output)

	// Should contain detected features
	if !strings.Contains(result, "credential_issue") {
		t.Error("expected credential_issue in output")
	}
	if !strings.Contains(result, "policy_load") {
		t.Error("expected policy_load in output")
	}

	// Read stderr (detection summary)
	stderr.Seek(0, 0)
	stderrOutput, _ := os.ReadFile(stderr.Name())
	stderrResult := string(stderrOutput)

	// Should show detection summary on stderr
	if !strings.Contains(stderrResult, "Detected features:") {
		t.Error("expected detection summary on stderr")
	}
	if !strings.Contains(stderrResult, "base feature") {
		t.Error("expected feature detail in detection summary")
	}
}

func TestPermissionsCommand_Detect_JSONFormat(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	detector := &mockDetector{
		DetectFunc: func(ctx context.Context) (*permissions.DetectionResult, error) {
			return &permissions.DetectionResult{
				Features: []permissions.Feature{
					permissions.FeatureCredentialIssue,
				},
				FeatureDetails: map[permissions.Feature]string{
					permissions.FeatureCredentialIssue: "base feature",
				},
				Errors: []permissions.DetectionError{},
			}, nil
		},
	}

	input := PermissionsCommandInput{
		Format:   "json",
		Detect:   true,
		Detector: detector,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read stdout (JSON output)
	stdout.Seek(0, 0)
	output, _ := os.ReadFile(stdout.Name())

	// Should be valid JSON
	var doc permissions.IAMPolicyDocument
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Read stderr - should NOT have detection summary for non-human formats
	stderr.Seek(0, 0)
	stderrOutput, _ := os.ReadFile(stderr.Name())

	if strings.Contains(string(stderrOutput), "Detected features:") {
		t.Error("did not expect detection summary on stderr for JSON format")
	}
}

func TestPermissionsCommand_Detect_WithWarnings(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	detector := &mockDetector{
		DetectFunc: func(ctx context.Context) (*permissions.DetectionResult, error) {
			return &permissions.DetectionResult{
				Features: []permissions.Feature{
					permissions.FeatureCredentialIssue,
				},
				FeatureDetails: map[permissions.Feature]string{
					permissions.FeatureCredentialIssue: "base feature",
				},
				Errors: []permissions.DetectionError{
					{Feature: permissions.FeaturePolicyLoad, Message: "access denied"},
					{Feature: permissions.FeatureApprovalWorkflow, Message: "network error"},
				},
			}, nil
		},
	}

	input := PermissionsCommandInput{
		Format:   "human",
		Detect:   true,
		Detector: detector,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read stderr (should show warnings)
	stderr.Seek(0, 0)
	stderrOutput, _ := os.ReadFile(stderr.Name())
	stderrResult := string(stderrOutput)

	if !strings.Contains(stderrResult, "Detection warnings:") {
		t.Error("expected detection warnings on stderr")
	}
	if !strings.Contains(stderrResult, "access denied") {
		t.Error("expected warning message in output")
	}
}

func TestPermissionsCommand_Detect_Error(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	detector := &mockDetector{
		DetectFunc: func(ctx context.Context) (*permissions.DetectionResult, error) {
			return nil, errors.New("fatal detection error")
		},
	}

	input := PermissionsCommandInput{
		Format:   "human",
		Detect:   true,
		Detector: detector,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := PermissionsCommand(input)
	if err == nil {
		t.Error("expected error when detection fails")
	}

	if !strings.Contains(err.Error(), "detection failed") {
		t.Errorf("expected 'detection failed' error, got: %v", err)
	}
}

func TestPermissionsCommand_Detect_MutualExclusivity_Subsystem(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format:    "human",
		Detect:    true,
		Subsystem: "core",
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := PermissionsCommand(input)
	if err == nil {
		t.Error("expected error when --detect combined with --subsystem")
	}

	if !strings.Contains(err.Error(), "--detect cannot be combined") {
		t.Errorf("expected mutual exclusivity error, got: %v", err)
	}
}

func TestPermissionsCommand_Detect_MutualExclusivity_Feature(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := PermissionsCommandInput{
		Format:  "human",
		Detect:  true,
		Feature: "policy_load",
		Stdout:  stdout,
		Stderr:  stderr,
	}

	err := PermissionsCommand(input)
	if err == nil {
		t.Error("expected error when --detect combined with --feature")
	}

	if !strings.Contains(err.Error(), "--detect cannot be combined") {
		t.Errorf("expected mutual exclusivity error, got: %v", err)
	}
}

func TestPermissionsCommand_Detect_AllFormats(t *testing.T) {
	formats := []string{"human", "json", "terraform", "cloudformation", "cf"}

	detector := &mockDetector{
		DetectFunc: func(ctx context.Context) (*permissions.DetectionResult, error) {
			return &permissions.DetectionResult{
				Features: []permissions.Feature{
					permissions.FeatureCredentialIssue,
					permissions.FeaturePolicyLoad,
				},
				FeatureDetails: map[permissions.Feature]string{
					permissions.FeatureCredentialIssue: "base feature",
					permissions.FeaturePolicyLoad:      "SSM parameter exists",
				},
				Errors: []permissions.DetectionError{},
			}, nil
		},
	}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			stdout, _ := os.CreateTemp("", "stdout")
			stderr, _ := os.CreateTemp("", "stderr")
			defer os.Remove(stdout.Name())
			defer os.Remove(stderr.Name())

			input := PermissionsCommandInput{
				Format:   format,
				Detect:   true,
				Detector: detector,
				Stdout:   stdout,
				Stderr:   stderr,
			}

			err := PermissionsCommand(input)
			if err != nil {
				t.Fatalf("unexpected error for format %s: %v", format, err)
			}

			// Read stdout
			stdout.Seek(0, 0)
			output, _ := os.ReadFile(stdout.Name())

			if len(output) == 0 {
				t.Errorf("expected non-empty output for format %s", format)
			}
		})
	}
}

func TestPermissionsCommand_Detect_MultipleFeatures(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	detector := &mockDetector{
		DetectFunc: func(ctx context.Context) (*permissions.DetectionResult, error) {
			return &permissions.DetectionResult{
				Features: []permissions.Feature{
					permissions.FeatureCredentialIssue,
					permissions.FeaturePolicyLoad,
					permissions.FeatureAuditVerify,
					permissions.FeatureEnforceAnalyze,
					permissions.FeatureApprovalWorkflow,
				},
				FeatureDetails: map[permissions.Feature]string{
					permissions.FeatureCredentialIssue:  "base feature",
					permissions.FeaturePolicyLoad:       "SSM parameter exists",
					permissions.FeatureAuditVerify:      "CloudTrail available",
					permissions.FeatureEnforceAnalyze:   "IAM available",
					permissions.FeatureApprovalWorkflow: "DynamoDB table exists",
				},
				Errors: []permissions.DetectionError{},
			}, nil
		},
	}

	input := PermissionsCommandInput{
		Format:   "human",
		Detect:   true,
		Detector: detector,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := PermissionsCommand(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read stdout
	stdout.Seek(0, 0)
	output, _ := os.ReadFile(stdout.Name())
	result := string(output)

	// Should contain all detected features
	expectedFeatures := []string{"credential_issue", "policy_load", "audit_verify", "enforce_analyze", "approval_workflow"}
	for _, feature := range expectedFeatures {
		if !strings.Contains(result, feature) {
			t.Errorf("expected feature %s in output", feature)
		}
	}
}
