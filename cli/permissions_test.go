package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/permissions"
)

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
