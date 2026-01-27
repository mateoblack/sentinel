package cli

import (
	"context"
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

// ============================================================================
// Test Interfaces and Mocks
// ============================================================================

// mockIAMClient implements iamAPI interface for testing.
type mockIAMClient struct {
	getRoleFunc   func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	listRolesFunc func(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
}

func (m *mockIAMClient) GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	if m.getRoleFunc != nil {
		return m.getRoleFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetRole not implemented")
}

func (m *mockIAMClient) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if m.listRolesFunc != nil {
		return m.listRolesFunc(ctx, params, optFns...)
	}
	return &iam.ListRolesOutput{Roles: []types.Role{}}, nil
}

// createEnforceTestFiles creates temp files for test I/O.
func createEnforceTestFiles(t *testing.T) (*os.File, *os.File, func()) {
	t.Helper()

	stdout, err := os.CreateTemp("", "enforce-stdout-*")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}

	stderr, err := os.CreateTemp("", "enforce-stderr-*")
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

// readEnforceFile reads content from a temp file.
func readEnforceFile(t *testing.T, f *os.File) string {
	t.Helper()
	f.Seek(0, 0)
	content, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	return string(content)
}

// ============================================================================
// Test Helper to Create Advisor with Mock
// ============================================================================

// createMockAdvisor creates an Advisor with a mock IAM client.
func createMockAdvisor(getRoleFunc func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)) *enforce.Advisor {
	return enforce.NewAdvisorWithClient(&mockIAMClient{getRoleFunc: getRoleFunc})
}

// ============================================================================
// Human Output Tests
// ============================================================================

func TestEnforcePlanCommand_HumanOutput_FullEnforcement(t *testing.T) {
	stdout, stderr, cleanup := createEnforceTestFiles(t)
	defer cleanup()

	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
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

	advisor := createMockAdvisor(func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
		return &iam.GetRoleOutput{
			Role: &types.Role{
				RoleName:                 params.RoleName,
				Arn:                      aws.String("arn:aws:iam::123456789012:role/ProductionAdmin"),
				AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
			},
		}, nil
	})

	input := EnforcePlanCommandInput{
		RoleARNs: []string{"arn:aws:iam::123456789012:role/ProductionAdmin"},
		Advisor:  advisor,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := EnforcePlanCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readEnforceFile(t, stdout)

	if !strings.Contains(output, "Sentinel Enforcement Analysis") {
		t.Error("expected output to contain header")
	}
	if !strings.Contains(output, "arn:aws:iam::123456789012:role/ProductionAdmin") {
		t.Error("expected output to contain role ARN")
	}
	if !strings.Contains(output, "FULL") {
		t.Error("expected output to contain FULL status")
	}
	if !strings.Contains(output, "trust_policy") {
		t.Error("expected output to contain trust_policy level")
	}
	if !strings.Contains(output, "Full enforcement:    1 role(s)") {
		t.Error("expected output to contain summary")
	}
}

func TestEnforcePlanCommand_HumanOutput_PartialEnforcement(t *testing.T) {
	stdout, stderr, cleanup := createEnforceTestFiles(t)
	defer cleanup()

	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
				"Action": "sts:AssumeRole",
				"Condition": {
					"StringLike": {
						"sts:SourceIdentity": "sentinel:*"
					}
				}
			},
			{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:role/Legacy"},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	advisor := createMockAdvisor(func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
		return &iam.GetRoleOutput{
			Role: &types.Role{
				RoleName:                 params.RoleName,
				Arn:                      aws.String("arn:aws:iam::123456789012:role/MigrationRole"),
				AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
			},
		}, nil
	})

	input := EnforcePlanCommandInput{
		RoleARNs: []string{"arn:aws:iam::123456789012:role/MigrationRole"},
		Advisor:  advisor,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := EnforcePlanCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readEnforceFile(t, stdout)

	if !strings.Contains(output, "PARTIAL") {
		t.Error("expected output to contain PARTIAL status")
	}
	if !strings.Contains(output, "Issues:") {
		t.Error("expected output to contain issues")
	}
	if !strings.Contains(output, "Recommendations:") {
		t.Error("expected output to contain recommendations")
	}
	if !strings.Contains(output, "Partial enforcement: 1 role(s)") {
		t.Error("expected output to contain summary")
	}
}

func TestEnforcePlanCommand_HumanOutput_NoEnforcement(t *testing.T) {
	stdout, stderr, cleanup := createEnforceTestFiles(t)
	defer cleanup()

	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	advisor := createMockAdvisor(func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
		return &iam.GetRoleOutput{
			Role: &types.Role{
				RoleName:                 params.RoleName,
				Arn:                      aws.String("arn:aws:iam::123456789012:role/LegacyRole"),
				AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
			},
		}, nil
	})

	input := EnforcePlanCommandInput{
		RoleARNs: []string{"arn:aws:iam::123456789012:role/LegacyRole"},
		Advisor:  advisor,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := EnforcePlanCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readEnforceFile(t, stdout)

	if !strings.Contains(output, "NONE") {
		t.Error("expected output to contain NONE status")
	}
	if !strings.Contains(output, "advisory") {
		t.Error("expected output to contain advisory level")
	}
	if !strings.Contains(output, "No enforcement:      1 role(s)") {
		t.Error("expected output to contain summary")
	}
}

func TestEnforcePlanCommand_HumanOutput_MultipleRoles(t *testing.T) {
	stdout, stderr, cleanup := createEnforceTestFiles(t)
	defer cleanup()

	trustPolicyFull := `{
		"Version": "2012-10-17",
		"Statement": [{
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

	trustPolicyNone := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	advisor := createMockAdvisor(func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
		switch *params.RoleName {
		case "FullRole":
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/FullRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicyFull)),
				},
			}, nil
		case "NoneRole":
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/NoneRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicyNone)),
				},
			}, nil
		default:
			return nil, errors.New("role not found")
		}
	})

	input := EnforcePlanCommandInput{
		RoleARNs: []string{
			"arn:aws:iam::123456789012:role/FullRole",
			"arn:aws:iam::123456789012:role/NoneRole",
		},
		Advisor: advisor,
		Stdout:  stdout,
		Stderr:  stderr,
	}

	err := EnforcePlanCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readEnforceFile(t, stdout)

	if !strings.Contains(output, "Full enforcement:    1 role(s)") {
		t.Error("expected output to show 1 full enforcement")
	}
	if !strings.Contains(output, "No enforcement:      1 role(s)") {
		t.Error("expected output to show 1 no enforcement")
	}
}

// ============================================================================
// JSON Output Tests
// ============================================================================

func TestEnforcePlanCommand_JSONOutput(t *testing.T) {
	stdout, stderr, cleanup := createEnforceTestFiles(t)
	defer cleanup()

	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
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

	advisor := createMockAdvisor(func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
		return &iam.GetRoleOutput{
			Role: &types.Role{
				RoleName:                 params.RoleName,
				Arn:                      aws.String("arn:aws:iam::123456789012:role/ProductionAdmin"),
				AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
			},
		}, nil
	})

	input := EnforcePlanCommandInput{
		RoleARNs:   []string{"arn:aws:iam::123456789012:role/ProductionAdmin"},
		JSONOutput: true,
		Advisor:    advisor,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := EnforcePlanCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readEnforceFile(t, stdout)

	if !strings.Contains(output, `"role_arn"`) {
		t.Error("expected JSON output to contain role_arn field")
	}
	if !strings.Contains(output, `"role_name"`) {
		t.Error("expected JSON output to contain role_name field")
	}
	if !strings.Contains(output, `"analysis"`) {
		t.Error("expected JSON output to contain analysis field")
	}
	if !strings.Contains(output, `"status"`) {
		t.Error("expected JSON output to contain status field")
	}
	if !strings.Contains(output, `"full"`) {
		t.Error("expected JSON output to contain full status value")
	}
}

// ============================================================================
// Error Cases
// ============================================================================

func TestEnforcePlanCommand_NoRoles(t *testing.T) {
	stdout, stderr, cleanup := createEnforceTestFiles(t)
	defer cleanup()

	input := EnforcePlanCommandInput{
		RoleARNs: []string{},
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := EnforcePlanCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error for no roles")
	}

	errOutput := readEnforceFile(t, stderr)
	if !strings.Contains(errOutput, "at least one --role is required") {
		t.Error("expected stderr to contain error message")
	}
}

func TestEnforcePlanCommand_RoleError(t *testing.T) {
	stdout, stderr, cleanup := createEnforceTestFiles(t)
	defer cleanup()

	advisor := createMockAdvisor(func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
		return nil, errors.New("AccessDeniedException: Access denied")
	})

	input := EnforcePlanCommandInput{
		RoleARNs: []string{"arn:aws:iam::123456789012:role/Inaccessible"},
		Advisor:  advisor,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	err := EnforcePlanCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error when role analysis fails")
	}

	output := readEnforceFile(t, stdout)
	if !strings.Contains(output, "ERROR") {
		t.Error("expected output to contain ERROR status")
	}
	if !strings.Contains(output, "Errors:") {
		t.Error("expected output to contain Errors summary")
	}
}

func TestEnforcePlanCommand_MixedResults(t *testing.T) {
	stdout, stderr, cleanup := createEnforceTestFiles(t)
	defer cleanup()

	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
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

	advisor := createMockAdvisor(func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
		switch *params.RoleName {
		case "GoodRole":
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/GoodRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
				},
			}, nil
		case "BadRole":
			return nil, errors.New("NoSuchEntity: Role not found")
		default:
			return nil, errors.New("Role not found")
		}
	})

	input := EnforcePlanCommandInput{
		RoleARNs: []string{
			"arn:aws:iam::123456789012:role/GoodRole",
			"arn:aws:iam::123456789012:role/BadRole",
		},
		Advisor: advisor,
		Stdout:  stdout,
		Stderr:  stderr,
	}

	err := EnforcePlanCommand(context.Background(), input)
	if err == nil {
		t.Error("expected error when any role fails")
	}

	output := readEnforceFile(t, stdout)

	// Should still output all results
	if !strings.Contains(output, "GoodRole") {
		t.Error("expected output to contain GoodRole")
	}
	if !strings.Contains(output, "BadRole") {
		t.Error("expected output to contain BadRole")
	}
	if !strings.Contains(output, "Full enforcement:    1") {
		t.Error("expected output to show full enforcement count")
	}
	if !strings.Contains(output, "Errors:              1") {
		t.Error("expected output to show error count")
	}
}

// ============================================================================
// Output Format Symbol Tests
// ============================================================================

func TestEnforcePlanCommand_Symbols(t *testing.T) {
	stdout, stderr, cleanup := createEnforceTestFiles(t)
	defer cleanup()

	trustPolicyFull := `{
		"Version": "2012-10-17",
		"Statement": [{
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

	trustPolicyPartial := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
				"Action": "sts:AssumeRole",
				"Condition": {
					"StringLike": {
						"sts:SourceIdentity": "sentinel:*"
					}
				}
			},
			{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:role/Legacy"},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	trustPolicyNone := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	advisor := createMockAdvisor(func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
		switch *params.RoleName {
		case "FullRole":
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/FullRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicyFull)),
				},
			}, nil
		case "PartialRole":
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/PartialRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicyPartial)),
				},
			}, nil
		case "NoneRole":
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/NoneRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicyNone)),
				},
			}, nil
		default:
			return nil, errors.New("Role not found")
		}
	})

	input := EnforcePlanCommandInput{
		RoleARNs: []string{
			"arn:aws:iam::123456789012:role/FullRole",
			"arn:aws:iam::123456789012:role/PartialRole",
			"arn:aws:iam::123456789012:role/NoneRole",
		},
		Advisor: advisor,
		Stdout:  stdout,
		Stderr:  stderr,
	}

	err := EnforcePlanCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readEnforceFile(t, stdout)

	// Check for symbols
	if !strings.Contains(output, "\u2713") { // checkmark
		t.Error("expected output to contain checkmark for FULL")
	}
	if !strings.Contains(output, "\u26A0") { // warning
		t.Error("expected output to contain warning for PARTIAL")
	}
	if !strings.Contains(output, "\u2717") { // X mark
		t.Error("expected output to contain X for NONE")
	}
}
