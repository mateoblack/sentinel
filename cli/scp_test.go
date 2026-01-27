package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/deploy"
)

// ============================================================================
// SCP Template CLI Tests
// ============================================================================

func TestSCPTemplateCommand_JSONFormat(t *testing.T) {
	ctx := context.Background()

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPTemplateCommandInput{
		Format: "json",
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode := SCPTemplateCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify JSON structure
	if !strings.Contains(output, "Version") {
		t.Error("expected JSON output to contain Version")
	}
	if !strings.Contains(output, "sts:SourceIdentity") {
		t.Error("expected JSON output to contain sts:SourceIdentity")
	}
	if !strings.Contains(output, "sts:AssumeRole") {
		t.Error("expected JSON output to contain sts:AssumeRole")
	}
	if !strings.Contains(output, "DenyAssumeRoleWithoutSourceIdentity") {
		t.Error("expected JSON output to contain Sid")
	}
}

func TestSCPTemplateCommand_YAMLFormat(t *testing.T) {
	ctx := context.Background()

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPTemplateCommandInput{
		Format: "yaml",
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode := SCPTemplateCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify YAML structure
	if !strings.Contains(output, "Version:") {
		t.Error("expected YAML output to contain Version:")
	}
	if !strings.Contains(output, "sts:SourceIdentity") {
		t.Error("expected YAML output to contain sts:SourceIdentity")
	}
	if !strings.Contains(output, "Statement:") {
		t.Error("expected YAML output to contain Statement:")
	}
	// Verify YAML has comment with warning
	if !strings.Contains(output, "WARNING") {
		t.Error("expected YAML output to contain WARNING comment")
	}
}

func TestSCPTemplateCommand_TerraformFormat(t *testing.T) {
	ctx := context.Background()

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPTemplateCommandInput{
		Format: "terraform",
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode := SCPTemplateCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify Terraform structure
	if !strings.Contains(output, "resource \"aws_organizations_policy\"") {
		t.Error("expected Terraform output to contain aws_organizations_policy resource")
	}
	if !strings.Contains(output, "SERVICE_CONTROL_POLICY") {
		t.Error("expected Terraform output to contain SERVICE_CONTROL_POLICY type")
	}
	if !strings.Contains(output, "aws_organizations_policy_attachment") {
		t.Error("expected Terraform output to contain policy attachment resource")
	}
	if !strings.Contains(output, deploy.SentinelSCPName) {
		t.Error("expected Terraform output to contain policy name")
	}
	// Verify Terraform has warning comment
	if !strings.Contains(output, "WARNING") {
		t.Error("expected Terraform output to contain WARNING comment")
	}
}

func TestSCPTemplateCommand_CloudFormationFormat(t *testing.T) {
	ctx := context.Background()

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPTemplateCommandInput{
		Format: "cloudformation",
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode := SCPTemplateCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify CloudFormation structure
	if !strings.Contains(output, "AWSTemplateFormatVersion:") {
		t.Error("expected CloudFormation output to contain AWSTemplateFormatVersion")
	}
	if !strings.Contains(output, "AWS::Organizations::Policy") {
		t.Error("expected CloudFormation output to contain AWS::Organizations::Policy resource type")
	}
	if !strings.Contains(output, "SERVICE_CONTROL_POLICY") {
		t.Error("expected CloudFormation output to contain SERVICE_CONTROL_POLICY type")
	}
	if !strings.Contains(output, "Parameters:") {
		t.Error("expected CloudFormation output to contain Parameters section")
	}
	if !strings.Contains(output, "TargetId") {
		t.Error("expected CloudFormation output to contain TargetId parameter")
	}
	if !strings.Contains(output, "Outputs:") {
		t.Error("expected CloudFormation output to contain Outputs section")
	}
	// Verify CloudFormation has warning in description
	if !strings.Contains(output, "WARNING") {
		t.Error("expected CloudFormation output to contain WARNING in description")
	}
}

func TestSCPTemplateCommand_OutputToFile(t *testing.T) {
	ctx := context.Background()

	// Create a temp file for output
	outputFile, _ := os.CreateTemp("", "scp-output-*.json")
	outputPath := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputPath)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPTemplateCommandInput{
		Format:     "json",
		OutputFile: outputPath,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := SCPTemplateCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Verify stdout shows confirmation message
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	stdoutContent := buf.String()

	if !strings.Contains(stdoutContent, "SCP template written to") {
		t.Error("expected stdout to show file written message")
	}

	// Verify file contents
	fileContent, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if !strings.Contains(string(fileContent), "sts:SourceIdentity") {
		t.Error("expected output file to contain policy content")
	}
}

func TestSCPTemplateCommand_DefaultFormat(t *testing.T) {
	// When format is empty, it should default to json
	ctx := context.Background()

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPTemplateCommandInput{
		Format: "", // Empty should work like json
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode := SCPTemplateCommand(ctx, input)

	// Empty format should fail with error (unknown format)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for unknown format, got %d", exitCode)
	}
}

func TestSCPTemplateCommand_InvalidFormat(t *testing.T) {
	ctx := context.Background()

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPTemplateCommandInput{
		Format: "invalid",
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode := SCPTemplateCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid format, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	output := buf.String()

	if !strings.Contains(output, "unknown format") {
		t.Error("expected error message about unknown format")
	}
}

func TestSCPTemplateCommand_OutputFileWriteError(t *testing.T) {
	ctx := context.Background()

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	// Use a path that should fail (directory doesn't exist)
	input := SCPTemplateCommandInput{
		Format:     "json",
		OutputFile: "/nonexistent/path/file.json",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := SCPTemplateCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for file write error, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	output := buf.String()

	if !strings.Contains(output, "Error writing to file") {
		t.Error("expected error message about file write failure")
	}
}

// ============================================================================
// Template Generation Function Tests
// ============================================================================

func TestGetSCPPolicyJSON(t *testing.T) {
	output := deploy.GetSCPPolicyJSON()

	// Verify it's valid JSON-like content
	if !strings.Contains(output, "Version") {
		t.Error("expected JSON to contain Version")
	}
	if !strings.Contains(output, "Statement") {
		t.Error("expected JSON to contain Statement")
	}
	if !strings.Contains(output, "sts:SourceIdentity") {
		t.Error("expected JSON to contain sts:SourceIdentity")
	}
}

func TestGetSCPPolicyYAML(t *testing.T) {
	output, err := deploy.GetSCPPolicyYAML()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "Version:") {
		t.Error("expected YAML to contain Version:")
	}
	if !strings.Contains(output, "Statement:") {
		t.Error("expected YAML to contain Statement:")
	}
}

func TestGetSCPTerraform(t *testing.T) {
	output := deploy.GetSCPTerraform()

	if !strings.Contains(output, "resource") {
		t.Error("expected Terraform to contain resource")
	}
	if !strings.Contains(output, "aws_organizations_policy") {
		t.Error("expected Terraform to contain aws_organizations_policy")
	}
}

func TestGetSCPCloudFormation(t *testing.T) {
	output := deploy.GetSCPCloudFormation()

	if !strings.Contains(output, "AWSTemplateFormatVersion") {
		t.Error("expected CloudFormation to contain AWSTemplateFormatVersion")
	}
	if !strings.Contains(output, "Resources:") {
		t.Error("expected CloudFormation to contain Resources:")
	}
}

// ============================================================================
// Sentinel SCP Constants Tests
// ============================================================================

func TestSentinelSCPPolicy_ContainsRequiredElements(t *testing.T) {
	// Verify the SCP policy contains all required security elements
	policy := deploy.SentinelSCPPolicy

	if !strings.Contains(policy, "Deny") {
		t.Error("policy must contain Deny effect")
	}
	if !strings.Contains(policy, "sts:AssumeRole") {
		t.Error("policy must restrict sts:AssumeRole")
	}
	if !strings.Contains(policy, "sts:SourceIdentity") {
		t.Error("policy must use sts:SourceIdentity condition")
	}
	if !strings.Contains(policy, "Null") {
		t.Error("policy must use Null condition operator")
	}
}

func TestSentinelSCPName(t *testing.T) {
	if deploy.SentinelSCPName == "" {
		t.Error("SentinelSCPName must not be empty")
	}
	if !strings.Contains(deploy.SentinelSCPName, "Sentinel") {
		t.Error("SentinelSCPName should contain 'Sentinel'")
	}
}

func TestSentinelSCPDescription(t *testing.T) {
	if deploy.SentinelSCPDescription == "" {
		t.Error("SentinelSCPDescription must not be empty")
	}
	if !strings.Contains(deploy.SentinelSCPDescription, "SourceIdentity") {
		t.Error("SentinelSCPDescription should mention SourceIdentity")
	}
}
