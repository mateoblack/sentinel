package enforce

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestDriftStatus_String(t *testing.T) {
	tests := []struct {
		status   DriftStatus
		expected string
	}{
		{DriftStatusOK, "ok"},
		{DriftStatusPartial, "partial"},
		{DriftStatusNone, "none"},
		{DriftStatusUnknown, "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if got := tc.status.String(); got != tc.expected {
				t.Errorf("DriftStatus.String() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestDriftChecker_CheckRole_FullEnforcement(t *testing.T) {
	// Create mock IAM client that returns a role with full Sentinel enforcement
	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			// Trust policy with StringLike condition for sentinel:*
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
			return &iam.GetRoleOutput{
				Role: &types.Role{
					Arn:                      aws.String("arn:aws:iam::123456789012:role/TestRole"),
					RoleName:                 aws.String("TestRole"),
					AssumeRolePolicyDocument: aws.String(trustPolicy),
				},
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	checker := NewDriftCheckerWithAdvisor(advisor)

	result, err := checker.CheckRole(context.Background(), "arn:aws:iam::123456789012:role/TestRole")
	if err != nil {
		t.Fatalf("CheckRole returned error: %v", err)
	}

	if result.Status != DriftStatusOK {
		t.Errorf("expected status %q, got %q", DriftStatusOK, result.Status)
	}
	if result.RoleARN != "arn:aws:iam::123456789012:role/TestRole" {
		t.Errorf("expected role ARN in result, got %q", result.RoleARN)
	}
	if result.Message == "" {
		t.Error("expected non-empty message")
	}
	if result.Error != "" {
		t.Errorf("expected no error, got %q", result.Error)
	}
}

func TestDriftChecker_CheckRole_PartialEnforcement(t *testing.T) {
	// Create mock IAM client that returns a role with partial enforcement
	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			// Trust policy with mixed enforcement (one statement with Sentinel, one without)
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
						"Principal": {"Service": "ec2.amazonaws.com"},
						"Action": "sts:AssumeRole"
					}
				]
			}`
			return &iam.GetRoleOutput{
				Role: &types.Role{
					Arn:                      aws.String("arn:aws:iam::123456789012:role/MixedRole"),
					RoleName:                 aws.String("MixedRole"),
					AssumeRolePolicyDocument: aws.String(trustPolicy),
				},
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	checker := NewDriftCheckerWithAdvisor(advisor)

	result, err := checker.CheckRole(context.Background(), "arn:aws:iam::123456789012:role/MixedRole")
	if err != nil {
		t.Fatalf("CheckRole returned error: %v", err)
	}

	if result.Status != DriftStatusPartial {
		t.Errorf("expected status %q, got %q", DriftStatusPartial, result.Status)
	}
}

func TestDriftChecker_CheckRole_NoEnforcement(t *testing.T) {
	// Create mock IAM client that returns a role with no Sentinel enforcement
	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			// Trust policy without any SourceIdentity condition
			trustPolicy := `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "sts:AssumeRole"
				}]
			}`
			return &iam.GetRoleOutput{
				Role: &types.Role{
					Arn:                      aws.String("arn:aws:iam::123456789012:role/NoEnforcementRole"),
					RoleName:                 aws.String("NoEnforcementRole"),
					AssumeRolePolicyDocument: aws.String(trustPolicy),
				},
			}, nil
		},
	}

	advisor := NewAdvisorWithClient(client)
	checker := NewDriftCheckerWithAdvisor(advisor)

	result, err := checker.CheckRole(context.Background(), "arn:aws:iam::123456789012:role/NoEnforcementRole")
	if err != nil {
		t.Fatalf("CheckRole returned error: %v", err)
	}

	if result.Status != DriftStatusNone {
		t.Errorf("expected status %q, got %q", DriftStatusNone, result.Status)
	}
}

func TestDriftChecker_CheckRole_IAMError(t *testing.T) {
	// Create mock IAM client that returns an error
	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return nil, errors.New("AccessDenied: User does not have permission to get role")
		},
	}

	advisor := NewAdvisorWithClient(client)
	checker := NewDriftCheckerWithAdvisor(advisor)

	result, err := checker.CheckRole(context.Background(), "arn:aws:iam::123456789012:role/TestRole")
	if err != nil {
		t.Fatalf("CheckRole should not return error, got: %v", err)
	}

	if result.Status != DriftStatusUnknown {
		t.Errorf("expected status %q for IAM error, got %q", DriftStatusUnknown, result.Status)
	}
	if result.Error == "" {
		t.Error("expected error message for IAM error")
	}
}

func TestDriftChecker_CheckRole_InvalidRoleARN(t *testing.T) {
	// Empty ARN should result in unknown status
	client := &mockIAMClient{
		getRoleFunc: func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
			return nil, errors.New("invalid role name")
		},
	}

	advisor := NewAdvisorWithClient(client)
	checker := NewDriftCheckerWithAdvisor(advisor)

	result, err := checker.CheckRole(context.Background(), "invalid-arn")
	if err != nil {
		t.Fatalf("CheckRole should not return error, got: %v", err)
	}

	if result.Status != DriftStatusUnknown {
		t.Errorf("expected status %q for invalid ARN, got %q", DriftStatusUnknown, result.Status)
	}
}

func TestTestDriftChecker_DefaultBehavior(t *testing.T) {
	// TestDriftChecker with no CheckFunc should return DriftStatusOK
	checker := &TestDriftChecker{}

	result, err := checker.CheckRole(context.Background(), "arn:aws:iam::123456789012:role/TestRole")
	if err != nil {
		t.Fatalf("CheckRole returned error: %v", err)
	}

	if result.Status != DriftStatusOK {
		t.Errorf("expected default status %q, got %q", DriftStatusOK, result.Status)
	}
	if result.RoleARN != "arn:aws:iam::123456789012:role/TestRole" {
		t.Errorf("expected role ARN in result, got %q", result.RoleARN)
	}
}

func TestTestDriftChecker_CustomCheckFunc(t *testing.T) {
	tests := []struct {
		name           string
		checkFunc      func(ctx context.Context, roleARN string) (*DriftCheckResult, error)
		expectedStatus DriftStatus
		expectedError  bool
	}{
		{
			name: "returns partial status",
			checkFunc: func(ctx context.Context, roleARN string) (*DriftCheckResult, error) {
				return &DriftCheckResult{
					Status:  DriftStatusPartial,
					RoleARN: roleARN,
					Message: "Mixed enforcement detected",
				}, nil
			},
			expectedStatus: DriftStatusPartial,
			expectedError:  false,
		},
		{
			name: "returns none status",
			checkFunc: func(ctx context.Context, roleARN string) (*DriftCheckResult, error) {
				return &DriftCheckResult{
					Status:  DriftStatusNone,
					RoleARN: roleARN,
					Message: "No Sentinel enforcement",
				}, nil
			},
			expectedStatus: DriftStatusNone,
			expectedError:  false,
		},
		{
			name: "returns unknown with error",
			checkFunc: func(ctx context.Context, roleARN string) (*DriftCheckResult, error) {
				return &DriftCheckResult{
					Status:  DriftStatusUnknown,
					RoleARN: roleARN,
					Message: "Check failed",
					Error:   "API error",
				}, nil
			},
			expectedStatus: DriftStatusUnknown,
			expectedError:  false,
		},
		{
			name: "returns error from function",
			checkFunc: func(ctx context.Context, roleARN string) (*DriftCheckResult, error) {
				return nil, errors.New("context canceled")
			},
			expectedStatus: "",
			expectedError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker := &TestDriftChecker{CheckFunc: tc.checkFunc}

			result, err := checker.CheckRole(context.Background(), "arn:aws:iam::123456789012:role/TestRole")

			if tc.expectedError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Status != tc.expectedStatus {
				t.Errorf("expected status %q, got %q", tc.expectedStatus, result.Status)
			}
		})
	}
}

func TestDriftCheckResult_Fields(t *testing.T) {
	result := DriftCheckResult{
		Status:  DriftStatusPartial,
		RoleARN: "arn:aws:iam::123456789012:role/TestRole",
		Message: "Some statements lack enforcement",
		Error:   "",
	}

	if result.Status != DriftStatusPartial {
		t.Errorf("expected Status %q, got %q", DriftStatusPartial, result.Status)
	}
	if result.RoleARN != "arn:aws:iam::123456789012:role/TestRole" {
		t.Errorf("expected RoleARN, got %q", result.RoleARN)
	}
	if result.Message == "" {
		t.Error("expected non-empty Message")
	}
	if result.Error != "" {
		t.Errorf("expected empty Error, got %q", result.Error)
	}
}
