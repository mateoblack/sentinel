package enforce

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// mockIAMClient implements iamAPI for testing.
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
	return &iam.ListRolesOutput{}, nil
}

// ============================================================================
// extractRoleName Tests
// ============================================================================

func TestExtractRoleName(t *testing.T) {
	tests := []struct {
		name    string
		arn     string
		want    string
		wantErr bool
	}{
		{
			name: "simple role ARN",
			arn:  "arn:aws:iam::123456789012:role/ProductionAdmin",
			want: "ProductionAdmin",
		},
		{
			name: "role ARN with path",
			arn:  "arn:aws:iam::123456789012:role/application/ProductionAdmin",
			want: "ProductionAdmin",
		},
		{
			name: "role ARN with deep path",
			arn:  "arn:aws:iam::123456789012:role/team/service/component/RoleName",
			want: "RoleName",
		},
		{
			name:    "empty ARN",
			arn:     "",
			wantErr: true,
		},
		{
			name:    "not a role ARN",
			arn:     "arn:aws:iam::123456789012:user/UserName",
			wantErr: true,
		},
		{
			name:    "missing role name",
			arn:     "arn:aws:iam::123456789012:role/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractRoleName(tt.arn)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractRoleName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractRoleName() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// AnalyzeRole Tests
// ============================================================================

func TestAdvisor_AnalyzeRole_PatternA(t *testing.T) {
	// Pattern A: Require ANY Sentinel-Issued Credentials
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

	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/ProductionAdmin"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
				},
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.AnalyzeRole(context.Background(), "arn:aws:iam::123456789012:role/ProductionAdmin")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected result error: %v", result.Error)
	}
	if result.RoleName != "ProductionAdmin" {
		t.Errorf("RoleName = %v, want ProductionAdmin", result.RoleName)
	}
	if result.Analysis == nil {
		t.Fatal("Analysis is nil")
	}
	if result.Analysis.Status != EnforcementStatusFull {
		t.Errorf("Status = %v, want %v", result.Analysis.Status, EnforcementStatusFull)
	}
	if result.Analysis.Level != EnforcementLevelTrustPolicy {
		t.Errorf("Level = %v, want %v", result.Analysis.Level, EnforcementLevelTrustPolicy)
	}
}

func TestAdvisor_AnalyzeRole_PatternB(t *testing.T) {
	// Pattern B: Require Sentinel AND Specific Users
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole",
			"Condition": {
				"StringLike": {
					"sts:SourceIdentity": ["sentinel:alice:*", "sentinel:bob:*"]
				}
			}
		}]
	}`

	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/SensitiveRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
				},
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.AnalyzeRole(context.Background(), "arn:aws:iam::123456789012:role/SensitiveRole")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected result error: %v", result.Error)
	}
	if result.Analysis == nil {
		t.Fatal("Analysis is nil")
	}
	if result.Analysis.Status != EnforcementStatusFull {
		t.Errorf("Status = %v, want %v", result.Analysis.Status, EnforcementStatusFull)
	}
}

func TestAdvisor_AnalyzeRole_PatternC(t *testing.T) {
	// Pattern C: Allow Sentinel OR Legacy (Migration Period)
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowSentinelAccess",
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
				"Sid": "AllowLegacyAccess",
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:role/LegacyServiceRole"},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/MigrationRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
				},
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.AnalyzeRole(context.Background(), "arn:aws:iam::123456789012:role/MigrationRole")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected result error: %v", result.Error)
	}
	if result.Analysis == nil {
		t.Fatal("Analysis is nil")
	}
	if result.Analysis.Status != EnforcementStatusPartial {
		t.Errorf("Status = %v, want %v", result.Analysis.Status, EnforcementStatusPartial)
	}
	if len(result.Analysis.Issues) == 0 {
		t.Error("expected issues for partial enforcement")
	}
	if len(result.Analysis.Recommendations) == 0 {
		t.Error("expected recommendations for partial enforcement")
	}
}

func TestAdvisor_AnalyzeRole_NoEnforcement(t *testing.T) {
	// No Sentinel enforcement
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/LegacyRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicy)),
				},
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.AnalyzeRole(context.Background(), "arn:aws:iam::123456789012:role/LegacyRole")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected result error: %v", result.Error)
	}
	if result.Analysis == nil {
		t.Fatal("Analysis is nil")
	}
	if result.Analysis.Status != EnforcementStatusNone {
		t.Errorf("Status = %v, want %v", result.Analysis.Status, EnforcementStatusNone)
	}
	if result.Analysis.Level != EnforcementLevelAdvisory {
		t.Errorf("Level = %v, want %v", result.Analysis.Level, EnforcementLevelAdvisory)
	}
	if len(result.Analysis.Issues) == 0 {
		t.Error("expected issues for no enforcement")
	}
	if len(result.Analysis.Recommendations) == 0 {
		t.Error("expected recommendations for no enforcement")
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestAdvisor_AnalyzeRole_RoleNotFound(t *testing.T) {
	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return nil, errors.New("NoSuchEntityException: Role not found")
		},
	}

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.AnalyzeRole(context.Background(), "arn:aws:iam::123456789012:role/NonExistent")

	// Should not return error - error captured in result
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error in result")
	}
	if result.Analysis != nil {
		t.Error("expected nil Analysis when error occurs")
	}
}

func TestAdvisor_AnalyzeRole_InvalidARN(t *testing.T) {
	advisor := NewAdvisorWithClient(&mockIAMClient{})
	result, err := advisor.AnalyzeRole(context.Background(), "invalid-arn")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error in result for invalid ARN")
	}
}

func TestAdvisor_AnalyzeRole_InvalidJSON(t *testing.T) {
	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/BadRole"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape("not valid json")),
				},
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.AnalyzeRole(context.Background(), "arn:aws:iam::123456789012:role/BadRole")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error in result for invalid JSON")
	}
	if result.Analysis != nil {
		t.Error("expected nil Analysis when parse error occurs")
	}
}

func TestAdvisor_AnalyzeRole_NilTrustPolicy(t *testing.T) {
	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return &iam.GetRoleOutput{
				Role: &types.Role{
					RoleName:                 params.RoleName,
					Arn:                      aws.String("arn:aws:iam::123456789012:role/NoPolicy"),
					AssumeRolePolicyDocument: nil,
				},
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.AnalyzeRole(context.Background(), "arn:aws:iam::123456789012:role/NoPolicy")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error in result for nil trust policy")
	}
}

// ============================================================================
// AnalyzeRoles (Batch) Tests
// ============================================================================

func TestAdvisor_AnalyzeRoles(t *testing.T) {
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

	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
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
			case "ErrorRole":
				return nil, errors.New("AccessDeniedException")
			default:
				return nil, errors.New("Role not found")
			}
		},
	}

	advisor := NewAdvisorWithClient(client)
	results, err := advisor.AnalyzeRoles(context.Background(), []string{
		"arn:aws:iam::123456789012:role/FullRole",
		"arn:aws:iam::123456789012:role/NoneRole",
		"arn:aws:iam::123456789012:role/ErrorRole",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Check first result (Full)
	if results[0].RoleName != "FullRole" {
		t.Errorf("result[0].RoleName = %v, want FullRole", results[0].RoleName)
	}
	if results[0].Error != "" {
		t.Errorf("result[0] unexpected error: %v", results[0].Error)
	}
	if results[0].Analysis == nil || results[0].Analysis.Status != EnforcementStatusFull {
		t.Error("result[0] should have Full status")
	}

	// Check second result (None)
	if results[1].RoleName != "NoneRole" {
		t.Errorf("result[1].RoleName = %v, want NoneRole", results[1].RoleName)
	}
	if results[1].Error != "" {
		t.Errorf("result[1] unexpected error: %v", results[1].Error)
	}
	if results[1].Analysis == nil || results[1].Analysis.Status != EnforcementStatusNone {
		t.Error("result[1] should have None status")
	}

	// Check third result (Error)
	if results[2].RoleName != "ErrorRole" {
		t.Errorf("result[2].RoleName = %v, want ErrorRole", results[2].RoleName)
	}
	if results[2].Error == "" {
		t.Error("result[2] should have error")
	}
	if results[2].Analysis != nil {
		t.Error("result[2] should have nil Analysis")
	}
}

func TestAdvisor_AnalyzeRoles_Empty(t *testing.T) {
	advisor := NewAdvisorWithClient(&mockIAMClient{})
	results, err := advisor.AnalyzeRoles(context.Background(), []string{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// ============================================================================
// ValidateRole Tests
// ============================================================================

func TestAdvisor_ValidateRole_Compliant(t *testing.T) {
	// Compliant policy with sentinel:* pattern
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

	client := &mockIAMClient{
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

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.ValidateRole(context.Background(), "arn:aws:iam::123456789012:role/CompliantRole")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected result error: %v", result.Error)
	}
	if result.RoleName != "CompliantRole" {
		t.Errorf("RoleName = %v, want CompliantRole", result.RoleName)
	}
	if result.Validation == nil {
		t.Fatal("Validation is nil")
	}
	if !result.Validation.IsCompliant {
		t.Error("expected compliant validation result")
	}
	if len(result.Validation.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Validation.Findings))
	}
}

func TestAdvisor_ValidateRole_NonCompliant(t *testing.T) {
	// Non-compliant policy without SourceIdentity
	trustPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	client := &mockIAMClient{
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

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.ValidateRole(context.Background(), "arn:aws:iam::123456789012:role/NonCompliantRole")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected result error: %v", result.Error)
	}
	if result.Validation == nil {
		t.Fatal("Validation is nil")
	}
	if result.Validation.IsCompliant {
		t.Error("expected non-compliant validation result")
	}
	if len(result.Validation.Findings) == 0 {
		t.Error("expected findings for non-compliant policy")
	}
	// Should have at least TRUST-02 (missing SourceIdentity) and TRUST-04 (root without protection)
	var hasTrust02, hasTrust04 bool
	for _, f := range result.Validation.Findings {
		if f.RuleID == "TRUST-02" {
			hasTrust02 = true
		}
		if f.RuleID == "TRUST-04" {
			hasTrust04 = true
		}
	}
	if !hasTrust02 {
		t.Error("expected TRUST-02 finding")
	}
	if !hasTrust04 {
		t.Error("expected TRUST-04 finding")
	}
}

func TestAdvisor_ValidateRole_Error(t *testing.T) {
	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return nil, errors.New("AccessDeniedException")
		},
	}

	advisor := NewAdvisorWithClient(client)
	result, err := advisor.ValidateRole(context.Background(), "arn:aws:iam::123456789012:role/TestRole")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected error in result")
	}
	if result.Validation != nil {
		t.Error("expected nil Validation when error occurs")
	}
}

// ============================================================================
// ValidateRoles (Batch) Tests
// ============================================================================

func TestAdvisor_ValidateRoles(t *testing.T) {
	trustPolicyCompliant := `{
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

	trustPolicyNonCompliant := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "sts:AssumeRole"
		}]
	}`

	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			switch *params.RoleName {
			case "CompliantRole":
				return &iam.GetRoleOutput{
					Role: &types.Role{
						RoleName:                 params.RoleName,
						Arn:                      aws.String("arn:aws:iam::123456789012:role/CompliantRole"),
						AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicyCompliant)),
					},
				}, nil
			case "NonCompliantRole":
				return &iam.GetRoleOutput{
					Role: &types.Role{
						RoleName:                 params.RoleName,
						Arn:                      aws.String("arn:aws:iam::123456789012:role/NonCompliantRole"),
						AssumeRolePolicyDocument: aws.String(url.QueryEscape(trustPolicyNonCompliant)),
					},
				}, nil
			default:
				return nil, errors.New("Role not found")
			}
		},
	}

	advisor := NewAdvisorWithClient(client)
	results, err := advisor.ValidateRoles(context.Background(), []string{
		"arn:aws:iam::123456789012:role/CompliantRole",
		"arn:aws:iam::123456789012:role/NonCompliantRole",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Check first result (Compliant)
	if results[0].RoleName != "CompliantRole" {
		t.Errorf("result[0].RoleName = %v, want CompliantRole", results[0].RoleName)
	}
	if results[0].Error != "" {
		t.Errorf("result[0] unexpected error: %v", results[0].Error)
	}
	if results[0].Validation == nil || !results[0].Validation.IsCompliant {
		t.Error("result[0] should be compliant")
	}

	// Check second result (NonCompliant)
	if results[1].RoleName != "NonCompliantRole" {
		t.Errorf("result[1].RoleName = %v, want NonCompliantRole", results[1].RoleName)
	}
	if results[1].Error != "" {
		t.Errorf("result[1] unexpected error: %v", results[1].Error)
	}
	if results[1].Validation == nil || results[1].Validation.IsCompliant {
		t.Error("result[1] should be non-compliant")
	}
}

func TestAdvisor_ValidateRoles_Empty(t *testing.T) {
	advisor := NewAdvisorWithClient(&mockIAMClient{})
	results, err := advisor.ValidateRoles(context.Background(), []string{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// ============================================================================
// ListRolesByPrefix Tests
// ============================================================================

func TestAdvisor_ListRolesByPrefix(t *testing.T) {
	client := &mockIAMClient{
		listRolesFunc: func(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{
				Roles: []types.Role{
					{
						RoleName: aws.String("sentinel-admin"),
						Arn:      aws.String("arn:aws:iam::123456789012:role/sentinel-admin"),
					},
					{
						RoleName: aws.String("sentinel-user"),
						Arn:      aws.String("arn:aws:iam::123456789012:role/sentinel-user"),
					},
					{
						RoleName: aws.String("other-role"),
						Arn:      aws.String("arn:aws:iam::123456789012:role/other-role"),
					},
				},
				IsTruncated: false,
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	roles, err := advisor.ListRolesByPrefix(context.Background(), "sentinel-")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
	if roles[0] != "arn:aws:iam::123456789012:role/sentinel-admin" {
		t.Errorf("roles[0] = %v, want sentinel-admin ARN", roles[0])
	}
	if roles[1] != "arn:aws:iam::123456789012:role/sentinel-user" {
		t.Errorf("roles[1] = %v, want sentinel-user ARN", roles[1])
	}
}

func TestAdvisor_ListRolesByPrefix_Pagination(t *testing.T) {
	callCount := 0
	client := &mockIAMClient{
		listRolesFunc: func(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
			callCount++
			if callCount == 1 {
				return &iam.ListRolesOutput{
					Roles: []types.Role{
						{
							RoleName: aws.String("sentinel-role1"),
							Arn:      aws.String("arn:aws:iam::123456789012:role/sentinel-role1"),
						},
					},
					IsTruncated: true,
					Marker:      aws.String("page2"),
				}, nil
			}
			return &iam.ListRolesOutput{
				Roles: []types.Role{
					{
						RoleName: aws.String("sentinel-role2"),
						Arn:      aws.String("arn:aws:iam::123456789012:role/sentinel-role2"),
					},
				},
				IsTruncated: false,
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	roles, err := advisor.ListRolesByPrefix(context.Background(), "sentinel-")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles across pages, got %d", len(roles))
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls for pagination, got %d", callCount)
	}
}

func TestAdvisor_ListRolesByPrefix_NoMatches(t *testing.T) {
	client := &mockIAMClient{
		listRolesFunc: func(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{
				Roles: []types.Role{
					{
						RoleName: aws.String("other-role"),
						Arn:      aws.String("arn:aws:iam::123456789012:role/other-role"),
					},
				},
				IsTruncated: false,
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	roles, err := advisor.ListRolesByPrefix(context.Background(), "sentinel-")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("expected 0 roles, got %d", len(roles))
	}
}

func TestAdvisor_ListRolesByPrefix_Error(t *testing.T) {
	client := &mockIAMClient{
		listRolesFunc: func(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
			return nil, errors.New("AccessDeniedException")
		},
	}

	advisor := NewAdvisorWithClient(client)
	_, err := advisor.ListRolesByPrefix(context.Background(), "sentinel-")

	if err == nil {
		t.Error("expected error for ListRoles failure")
	}
}
