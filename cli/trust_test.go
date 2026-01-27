package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/byteness/aws-vault/v7/enforce"
)

// mockTrustIAMClient implements the iamAPI interface for testing trust commands.
type mockTrustIAMClient struct {
	getRoleFunc   func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	listRolesFunc func(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
}

func (m *mockTrustIAMClient) GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	if m.getRoleFunc != nil {
		return m.getRoleFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetRole not implemented")
}

func (m *mockTrustIAMClient) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if m.listRolesFunc != nil {
		return m.listRolesFunc(ctx, params, optFns...)
	}
	return &iam.ListRolesOutput{}, nil
}

// newMockAdvisor creates an Advisor with a mock client for testing.
// This uses reflection-safe approach by calling the exported constructor.
func newMockAdvisor(client *mockTrustIAMClient) *enforce.Advisor {
	return enforce.NewAdvisorWithClient(client)
}

// ============================================================================
// TrustValidateCommand Tests
// ============================================================================

func TestTrustValidateCommand_SingleRole_Compliant(t *testing.T) {
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "AllowSentinelAccess",
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole",
			"Condition": {
				"StringLike": {
					"sts:SourceIdentity": "sentinel:*"
				}
			}
		}]
	}`

	client := &mockTrustIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/CompliantRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
				},
			}, nil
		},
	}

	stdout, _ := os.CreateTemp("", "stdout")
	defer os.Remove(stdout.Name())
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stderr.Name())

	input := TrustValidateCommandInput{
		RoleARNs: []string{"arn:aws:iam::123456789012:role/CompliantRole"},
		Advisor:  newMockAdvisor(client),
		Stdout:   stdout,
		Stderr:   stderr,
		MinRisk:  "low",
	}

	exitCode := TrustValidateCommand(context.Background(), input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Read output
	stdout.Seek(0, 0)
	outputBytes := make([]byte, 4096)
	n, _ := stdout.Read(outputBytes)
	output := string(outputBytes[:n])

	if !strings.Contains(output, "Compliant:       1 role(s)") {
		t.Errorf("expected compliant count in output, got: %s", output)
	}
}

func TestTrustValidateCommand_SingleRole_NonCompliant(t *testing.T) {
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	client := &mockTrustIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/NonCompliantRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
				},
			}, nil
		},
	}

	stdout, _ := os.CreateTemp("", "stdout")
	defer os.Remove(stdout.Name())
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stderr.Name())

	input := TrustValidateCommandInput{
		RoleARNs: []string{"arn:aws:iam::123456789012:role/NonCompliantRole"},
		Advisor:  newMockAdvisor(client),
		Stdout:   stdout,
		Stderr:   stderr,
		MinRisk:  "low",
	}

	exitCode := TrustValidateCommand(context.Background(), input)

	// Should return 1 for HIGH findings
	if exitCode != 1 {
		t.Errorf("expected exit code 1 (HIGH findings), got %d", exitCode)
	}

	// Read output
	stdout.Seek(0, 0)
	outputBytes := make([]byte, 4096)
	n, _ := stdout.Read(outputBytes)
	output := string(outputBytes[:n])

	if !strings.Contains(output, "Non-compliant:   1 role(s)") {
		t.Errorf("expected non-compliant count in output, got: %s", output)
	}
	if !strings.Contains(output, "TRUST-02") {
		t.Errorf("expected TRUST-02 finding in output, got: %s", output)
	}
}

func TestTrustValidateCommand_BatchWithPrefix(t *testing.T) {
	trustPolicyCompliant := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole",
			"Condition": {"StringLike": {"sts:SourceIdentity": "sentinel:*"}}
		}]
	}`

	trustPolicyNonCompliant := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	client := &mockTrustIAMClient{
		listRolesFunc: func(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{
				Roles: []types.Role{
					{RoleName: aws.String("sentinel-admin"), Arn: aws.String("arn:aws:iam::123456789012:role/sentinel-admin")},
					{RoleName: aws.String("sentinel-user"), Arn: aws.String("arn:aws:iam::123456789012:role/sentinel-user")},
					{RoleName: aws.String("other-role"), Arn: aws.String("arn:aws:iam::123456789012:role/other-role")},
				},
				IsTruncated: false,
			}, nil
		},
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			policy := trustPolicyNonCompliant
			if *params.RoleName == "sentinel-admin" {
				policy = trustPolicyCompliant
			}
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/" + *params.RoleName),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(policy)),
				},
			}, nil
		},
	}

	stdout, _ := os.CreateTemp("", "stdout")
	defer os.Remove(stdout.Name())
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stderr.Name())

	input := TrustValidateCommandInput{
		Prefix:  "sentinel-",
		Advisor: newMockAdvisor(client),
		Stdout:  stdout,
		Stderr:  stderr,
		MinRisk: "low",
	}

	exitCode := TrustValidateCommand(context.Background(), input)

	// Should return 1 for HIGH findings in sentinel-user
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}

	// Read output
	stdout.Seek(0, 0)
	outputBytes := make([]byte, 8192)
	n, _ := stdout.Read(outputBytes)
	output := string(outputBytes[:n])

	if !strings.Contains(output, "Roles validated: 2") {
		t.Errorf("expected 2 roles validated, got: %s", output)
	}
	if !strings.Contains(output, "Compliant:       1 role(s)") {
		t.Errorf("expected 1 compliant, got: %s", output)
	}
	if !strings.Contains(output, "Non-compliant:   1 role(s)") {
		t.Errorf("expected 1 non-compliant, got: %s", output)
	}
}

func TestTrustValidateCommand_JSONOutput(t *testing.T) {
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	client := &mockTrustIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/TestRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
				},
			}, nil
		},
	}

	stdout, _ := os.CreateTemp("", "stdout")
	defer os.Remove(stdout.Name())
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stderr.Name())

	input := TrustValidateCommandInput{
		RoleARNs:   []string{"arn:aws:iam::123456789012:role/TestRole"},
		JSONOutput: true,
		Advisor:    newMockAdvisor(client),
		Stdout:     stdout,
		Stderr:     stderr,
		MinRisk:    "low",
	}

	exitCode := TrustValidateCommand(context.Background(), input)
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}

	// Read output
	stdout.Seek(0, 0)
	outputBytes := make([]byte, 8192)
	n, _ := stdout.Read(outputBytes)
	output := bytes.TrimSpace(outputBytes[:n])

	// Should be valid JSON
	var results []enforce.RoleValidation
	if err := json.Unmarshal(output, &results); err != nil {
		t.Errorf("expected valid JSON output, got error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result in JSON, got %d", len(results))
	}
}

func TestTrustValidateCommand_ExitCodes(t *testing.T) {
	tests := []struct {
		name         string
		trustPolicy  string
		expectedCode int
	}{
		{
			name: "compliant - exit 0",
			trustPolicy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/SomeRole"},
					"Action": "sts:AssumeRole",
					"Condition": {"StringLike": {"sts:SourceIdentity": "sentinel:*"}}
				}]
			}`,
			expectedCode: 0,
		},
		{
			name: "HIGH findings - exit 1",
			trustPolicy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "sts:AssumeRole"
				}]
			}`,
			expectedCode: 1,
		},
		{
			name: "MEDIUM only - exit 2",
			trustPolicy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:role/SomeRole"},
					"Action": "sts:AssumeRole",
					"Condition": {"StringLike": {"sts:SourceIdentity": "custom-prefix:*"}}
				}]
			}`,
			expectedCode: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockTrustIAMClient{
				getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
					return &iam.GetRoleOutput{
						Role: &types.Role{
							RoleName:                 params.RoleName,
							Arn:                      aws.String("arn:aws:iam::123456789012:role/TestRole"),
							AssumeRolePolicyDocument: aws.String(url.QueryEscape(tt.trustPolicy)),
						},
					}, nil
				},
			}

			stdout, _ := os.CreateTemp("", "stdout")
			defer os.Remove(stdout.Name())
			stderr, _ := os.CreateTemp("", "stderr")
			defer os.Remove(stderr.Name())

			input := TrustValidateCommandInput{
				RoleARNs: []string{"arn:aws:iam::123456789012:role/TestRole"},
				Advisor:  newMockAdvisor(client),
				Stdout:   stdout,
				Stderr:   stderr,
				MinRisk:  "low",
			}

			exitCode := TrustValidateCommand(context.Background(), input)
			if exitCode != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, exitCode)
			}
		})
	}
}

func TestTrustValidateCommand_MinRiskFiltering(t *testing.T) {
	// Policy with findings at all risk levels
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "sts:AssumeRole",
			"Condition": {"StringEquals": {"sts:SourceIdentity": "sentinel:*"}}
		}]
	}`

	client := &mockTrustIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/TestRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
				},
			}, nil
		},
	}

	tests := []struct {
		minRisk      string
		expectHigh   bool
		expectMedium bool
		expectLow    bool
	}{
		{"high", true, false, false},
		{"medium", true, true, false},
		{"low", true, true, true},
	}

	for _, tt := range tests {
		t.Run("min-risk="+tt.minRisk, func(t *testing.T) {
			stdout, _ := os.CreateTemp("", "stdout")
			defer os.Remove(stdout.Name())
			stderr, _ := os.CreateTemp("", "stderr")
			defer os.Remove(stderr.Name())

			input := TrustValidateCommandInput{
				RoleARNs: []string{"arn:aws:iam::123456789012:role/TestRole"},
				Advisor:  newMockAdvisor(client),
				Stdout:   stdout,
				Stderr:   stderr,
				MinRisk:  tt.minRisk,
			}

			TrustValidateCommand(context.Background(), input)

			stdout.Seek(0, 0)
			outputBytes := make([]byte, 8192)
			n, _ := stdout.Read(outputBytes)
			output := string(outputBytes[:n])

			// Check that findings at appropriate levels are shown/hidden
			hasHigh := strings.Contains(output, "[high]")
			hasLow := strings.Contains(output, "[low]")

			if tt.expectHigh && !hasHigh {
				t.Errorf("expected HIGH findings in output with min-risk=%s", tt.minRisk)
			}
			if tt.expectLow && !hasLow {
				t.Errorf("expected LOW findings in output with min-risk=%s", tt.minRisk)
			}
			if !tt.expectLow && hasLow {
				t.Errorf("unexpected LOW findings in output with min-risk=%s", tt.minRisk)
			}
		})
	}
}

func TestTrustValidateCommand_NoRolesOrPrefix(t *testing.T) {
	stdout, _ := os.CreateTemp("", "stdout")
	defer os.Remove(stdout.Name())
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stderr.Name())

	input := TrustValidateCommandInput{
		Stdout: stdout,
		Stderr: stderr,
	}

	exitCode := TrustValidateCommand(context.Background(), input)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing input, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	stderrBytes := make([]byte, 4096)
	n, _ := stderr.Read(stderrBytes)
	errOutput := string(stderrBytes[:n])

	if !strings.Contains(errOutput, "at least one --role or --prefix is required") {
		t.Errorf("expected error message about missing input, got: %s", errOutput)
	}
}

func TestTrustValidateCommand_InvalidMinRisk(t *testing.T) {
	client := &mockTrustIAMClient{}

	stdout, _ := os.CreateTemp("", "stdout")
	defer os.Remove(stdout.Name())
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stderr.Name())

	input := TrustValidateCommandInput{
		RoleARNs: []string{"arn:aws:iam::123456789012:role/TestRole"},
		Advisor:  newMockAdvisor(client),
		Stdout:   stdout,
		Stderr:   stderr,
		MinRisk:  "invalid",
	}

	exitCode := TrustValidateCommand(context.Background(), input)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid min-risk, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	stderrBytes := make([]byte, 4096)
	n, _ := stderr.Read(stderrBytes)
	errOutput := string(stderrBytes[:n])

	if !strings.Contains(errOutput, "invalid --min-risk value") {
		t.Errorf("expected error message about invalid min-risk, got: %s", errOutput)
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestUniqueStrings(t *testing.T) {
	tests := []struct {
		input    []string
		expected []string
	}{
		{[]string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{[]string{"a", "a", "b"}, []string{"a", "b"}},
		{[]string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{[]string{}, []string{}},
		{nil, []string{}},
	}

	for _, tt := range tests {
		result := uniqueStrings(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("uniqueStrings(%v) = %v, want %v", tt.input, result, tt.expected)
			continue
		}
		for i, v := range result {
			if v != tt.expected[i] {
				t.Errorf("uniqueStrings(%v)[%d] = %v, want %v", tt.input, i, v, tt.expected[i])
			}
		}
	}
}

func TestIsRiskAtOrAbove(t *testing.T) {
	tests := []struct {
		risk    enforce.RiskLevel
		min     enforce.RiskLevel
		atAbove bool
	}{
		{enforce.RiskLevelHigh, enforce.RiskLevelHigh, true},
		{enforce.RiskLevelHigh, enforce.RiskLevelMedium, true},
		{enforce.RiskLevelHigh, enforce.RiskLevelLow, true},
		{enforce.RiskLevelMedium, enforce.RiskLevelHigh, false},
		{enforce.RiskLevelMedium, enforce.RiskLevelMedium, true},
		{enforce.RiskLevelMedium, enforce.RiskLevelLow, true},
		{enforce.RiskLevelLow, enforce.RiskLevelHigh, false},
		{enforce.RiskLevelLow, enforce.RiskLevelMedium, false},
		{enforce.RiskLevelLow, enforce.RiskLevelLow, true},
	}

	for _, tt := range tests {
		result := isRiskAtOrAbove(tt.risk, tt.min)
		if result != tt.atAbove {
			t.Errorf("isRiskAtOrAbove(%s, %s) = %v, want %v", tt.risk, tt.min, result, tt.atAbove)
		}
	}
}
