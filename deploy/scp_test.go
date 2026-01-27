package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// ============================================================================
// Mock Client for Audit
// ============================================================================

// mockOrganizationsAuditClient implements organizationsAuditAPI for testing.
type mockOrganizationsAuditClient struct {
	ListPoliciesFunc         func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicyFunc       func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicyFunc func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
}

// ============================================================================
// Mock Client for Deploy
// ============================================================================

// mockOrganizationsDeployClient implements organizationsDeployAPI for testing.
type mockOrganizationsDeployClient struct {
	ListPoliciesFunc                     func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicyFunc                   func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicyFunc             func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
	CreatePolicyFunc                     func(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error)
	AttachPolicyFunc                     func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error)
	UpdatePolicyFunc                     func(ctx context.Context, params *organizations.UpdatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error)
	ListRootsFunc                        func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParentFunc func(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
}

func (m *mockOrganizationsDeployClient) ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if m.ListPoliciesFunc != nil {
		return m.ListPoliciesFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListPolicies not implemented")
}

func (m *mockOrganizationsDeployClient) DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if m.DescribePolicyFunc != nil {
		return m.DescribePolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribePolicy not implemented")
}

func (m *mockOrganizationsDeployClient) ListTargetsForPolicy(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	if m.ListTargetsForPolicyFunc != nil {
		return m.ListTargetsForPolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListTargetsForPolicy not implemented")
}

func (m *mockOrganizationsDeployClient) CreatePolicy(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error) {
	if m.CreatePolicyFunc != nil {
		return m.CreatePolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("CreatePolicy not implemented")
}

func (m *mockOrganizationsDeployClient) AttachPolicy(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
	if m.AttachPolicyFunc != nil {
		return m.AttachPolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("AttachPolicy not implemented")
}

func (m *mockOrganizationsDeployClient) UpdatePolicy(ctx context.Context, params *organizations.UpdatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error) {
	if m.UpdatePolicyFunc != nil {
		return m.UpdatePolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("UpdatePolicy not implemented")
}

func (m *mockOrganizationsDeployClient) ListRoots(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	if m.ListRootsFunc != nil {
		return m.ListRootsFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListRoots not implemented")
}

func (m *mockOrganizationsDeployClient) ListOrganizationalUnitsForParent(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	if m.ListOrganizationalUnitsForParentFunc != nil {
		return m.ListOrganizationalUnitsForParentFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListOrganizationalUnitsForParent not implemented")
}

func (m *mockOrganizationsAuditClient) ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if m.ListPoliciesFunc != nil {
		return m.ListPoliciesFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListPolicies not implemented")
}

func (m *mockOrganizationsAuditClient) DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if m.DescribePolicyFunc != nil {
		return m.DescribePolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribePolicy not implemented")
}

func (m *mockOrganizationsAuditClient) ListTargetsForPolicy(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	if m.ListTargetsForPolicyFunc != nil {
		return m.ListTargetsForPolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListTargetsForPolicy not implemented")
}

// ============================================================================
// SCP Audit Tests
// ============================================================================

func TestAuditSCPEnforcement_WithSentinelSCP(t *testing.T) {
	ctx := context.Background()

	// SCP that enforces SourceIdentity
	sentinelSCPContent := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "DenyWithoutSourceIdentity",
				"Effect": "Deny",
				"Action": "sts:AssumeRole",
				"Resource": "*",
				"Condition": {
					"Null": {
						"sts:SourceIdentity": "true"
					}
				}
			}
		]
	}`

	orgClient := &mockOrganizationsAuditClient{
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{
						Id:   aws.String("p-abc123"),
						Name: aws.String("SentinelEnforcement"),
					},
				},
			}, nil
		},
		DescribePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return &organizations.DescribePolicyOutput{
				Policy: &orgtypes.Policy{
					Content: aws.String(sentinelSCPContent),
				},
			}, nil
		},
	}

	auditor := NewSCPAuditorWithClient(orgClient)
	findings := auditor.AuditSCPEnforcement(ctx)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when Sentinel SCP exists, got %d", len(findings))
		for _, f := range findings {
			t.Logf("Finding: %s - %s", f.CheckID, f.Message)
		}
	}
}

func TestAuditSCPEnforcement_NoSourceIdentitySCP(t *testing.T) {
	ctx := context.Background()

	// SCP without SourceIdentity (just a regular policy)
	regularSCPContent := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Deny",
				"Action": "ec2:*",
				"Resource": "*"
			}
		]
	}`

	orgClient := &mockOrganizationsAuditClient{
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{
						Id:   aws.String("p-xyz789"),
						Name: aws.String("EC2Restrictions"),
					},
				},
			}, nil
		},
		DescribePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return &organizations.DescribePolicyOutput{
				Policy: &orgtypes.Policy{
					Content: aws.String(regularSCPContent),
				},
			}, nil
		},
	}

	auditor := NewSCPAuditorWithClient(orgClient)
	findings := auditor.AuditSCPEnforcement(ctx)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when no Sentinel SCP, got %d", len(findings))
	}

	finding := findings[0]
	if finding.CheckID != "DEPLOY-01" {
		t.Errorf("expected CheckID DEPLOY-01, got %s", finding.CheckID)
	}
	if finding.RiskLevel != RiskLevelHigh {
		t.Errorf("expected HIGH risk level, got %s", finding.RiskLevel)
	}
	if finding.Category != "SCP" {
		t.Errorf("expected category SCP, got %s", finding.Category)
	}
}

func TestAuditSCPEnforcement_NoCustomSCPs(t *testing.T) {
	ctx := context.Background()

	orgClient := &mockOrganizationsAuditClient{
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			// Only the default FullAWSAccess policy
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{
						Id:   aws.String("p-FullAWSAccess"),
						Name: aws.String("FullAWSAccess"),
					},
				},
			}, nil
		},
	}

	auditor := NewSCPAuditorWithClient(orgClient)
	findings := auditor.AuditSCPEnforcement(ctx)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when no custom SCPs, got %d", len(findings))
	}

	finding := findings[0]
	if finding.CheckID != "DEPLOY-01" {
		t.Errorf("expected CheckID DEPLOY-01, got %s", finding.CheckID)
	}
	if finding.RiskLevel != RiskLevelHigh {
		t.Errorf("expected HIGH risk level, got %s", finding.RiskLevel)
	}
}

func TestAuditSCPEnforcement_AccessDenied(t *testing.T) {
	ctx := context.Background()

	orgClient := &mockOrganizationsAuditClient{
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return nil, errors.New("AccessDeniedException: User not authorized")
		},
	}

	auditor := NewSCPAuditorWithClient(orgClient)
	findings := auditor.AuditSCPEnforcement(ctx)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for access denied, got %d", len(findings))
	}

	finding := findings[0]
	if finding.RiskLevel != RiskLevelUnknown {
		t.Errorf("expected UNKNOWN risk level for access denied, got %s", finding.RiskLevel)
	}
}

func TestAuditSCPEnforcement_NotInOrganization(t *testing.T) {
	ctx := context.Background()

	orgClient := &mockOrganizationsAuditClient{
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return nil, errors.New("AWSOrganizationsNotInUseException: Account is not a member of an organization")
		},
	}

	auditor := NewSCPAuditorWithClient(orgClient)
	findings := auditor.AuditSCPEnforcement(ctx)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for not in organization, got %d", len(findings))
	}

	finding := findings[0]
	if finding.RiskLevel != RiskLevelUnknown {
		t.Errorf("expected UNKNOWN risk level for not in org, got %s", finding.RiskLevel)
	}
}

func TestAuditSCPEnforcement_WrongPattern(t *testing.T) {
	ctx := context.Background()

	// SCP has SourceIdentity but not for AssumeRole
	wrongPatternSCP := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Deny",
				"Action": "s3:*",
				"Resource": "*",
				"Condition": {
					"Null": {
						"sts:SourceIdentity": "true"
					}
				}
			}
		]
	}`

	orgClient := &mockOrganizationsAuditClient{
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{
						Id:   aws.String("p-wrong123"),
						Name: aws.String("WrongPattern"),
					},
				},
			}, nil
		},
		DescribePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return &organizations.DescribePolicyOutput{
				Policy: &orgtypes.Policy{
					Content: aws.String(wrongPatternSCP),
				},
			}, nil
		},
	}

	auditor := NewSCPAuditorWithClient(orgClient)
	findings := auditor.AuditSCPEnforcement(ctx)

	// Should detect missing proper SCP because it doesn't have sts:AssumeRole
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for wrong pattern, got %d", len(findings))
	}

	finding := findings[0]
	if finding.CheckID != "DEPLOY-01" {
		t.Errorf("expected CheckID DEPLOY-01, got %s", finding.CheckID)
	}
	if finding.RiskLevel != RiskLevelHigh {
		t.Errorf("expected HIGH risk level, got %s", finding.RiskLevel)
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestIsSentinelSCP(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "valid_sentinel_scp",
			content: `{
				"Statement": [{
					"Effect": "Deny",
					"Action": "sts:AssumeRole",
					"Condition": {"Null": {"sts:SourceIdentity": "true"}}
				}]
			}`,
			want: true,
		},
		{
			name: "missing_source_identity",
			content: `{
				"Statement": [{
					"Effect": "Deny",
					"Action": "sts:AssumeRole"
				}]
			}`,
			want: false,
		},
		{
			name: "missing_assume_role",
			content: `{
				"Statement": [{
					"Effect": "Deny",
					"Action": "s3:*",
					"Condition": {"Null": {"sts:SourceIdentity": "true"}}
				}]
			}`,
			want: false,
		},
		{
			name:    "empty_content",
			content: "",
			want:    false,
		},
		{
			name:    "unrelated_policy",
			content: `{"Statement": [{"Effect": "Deny", "Action": "ec2:*"}]}`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSentinelSCP(tt.content)
			if got != tt.want {
				t.Errorf("isSentinelSCP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNotInOrganization(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "organizations_not_in_use",
			err:  errors.New("AWSOrganizationsNotInUseException: Account is not a member"),
			want: true,
		},
		{
			name: "not_member_of_org",
			err:  errors.New("not a member of an organization"),
			want: true,
		},
		{
			name: "access_denied",
			err:  errors.New("AccessDeniedException: User not authorized"),
			want: false,
		},
		{
			name: "nil_error",
			err:  nil,
			want: false,
		},
		{
			name: "generic_error",
			err:  errors.New("something went wrong"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNotInOrganization(tt.err)
			if got != tt.want {
				t.Errorf("isNotInOrganization() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// SCP Deployment Tests
// ============================================================================

func TestSCPDeployer_DeploySCP_CreateNew(t *testing.T) {
	ctx := context.Background()

	client := &mockOrganizationsDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-abcd")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			// No existing Sentinel SCP
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{
						Id:   aws.String("p-FullAWSAccess"),
						Name: aws.String("FullAWSAccess"),
					},
				},
			}, nil
		},
		CreatePolicyFunc: func(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error) {
			// Verify correct parameters
			if *params.Name != SentinelSCPName {
				t.Errorf("expected policy name %q, got %q", SentinelSCPName, *params.Name)
			}
			if params.Type != orgtypes.PolicyTypeServiceControlPolicy {
				t.Errorf("expected policy type SERVICE_CONTROL_POLICY, got %v", params.Type)
			}
			return &organizations.CreatePolicyOutput{
				Policy: &orgtypes.Policy{
					PolicySummary: &orgtypes.PolicySummary{
						Id:  aws.String("p-new123"),
						Arn: aws.String("arn:aws:organizations::123456789012:policy/o-xxxxx/service_control_policy/p-new123"),
					},
				},
			}, nil
		},
		AttachPolicyFunc: func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
			if *params.TargetId != "r-abcd" {
				t.Errorf("expected target r-abcd, got %s", *params.TargetId)
			}
			return &organizations.AttachPolicyOutput{}, nil
		},
	}

	deployer := NewSCPDeployerWithClient(client)
	result, err := deployer.DeploySCP(ctx, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Created {
		t.Error("expected Created=true for new policy")
	}
	if result.PolicyID != "p-new123" {
		t.Errorf("expected PolicyID p-new123, got %s", result.PolicyID)
	}
	if len(result.Targets) != 1 || result.Targets[0] != "r-abcd" {
		t.Errorf("expected targets [r-abcd], got %v", result.Targets)
	}
}

func TestSCPDeployer_DeploySCP_UpdateExisting(t *testing.T) {
	ctx := context.Background()

	client := &mockOrganizationsDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-abcd")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			// Existing Sentinel SCP
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{
						Id:   aws.String("p-existing456"),
						Name: aws.String(SentinelSCPName),
					},
				},
			}, nil
		},
		UpdatePolicyFunc: func(ctx context.Context, params *organizations.UpdatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error) {
			if *params.PolicyId != "p-existing456" {
				t.Errorf("expected policy ID p-existing456, got %s", *params.PolicyId)
			}
			return &organizations.UpdatePolicyOutput{
				Policy: &orgtypes.Policy{
					PolicySummary: &orgtypes.PolicySummary{
						Id:  aws.String("p-existing456"),
						Arn: aws.String("arn:aws:organizations::123456789012:policy/o-xxxxx/service_control_policy/p-existing456"),
					},
				},
			}, nil
		},
		AttachPolicyFunc: func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
			return &organizations.AttachPolicyOutput{}, nil
		},
	}

	deployer := NewSCPDeployerWithClient(client)
	result, err := deployer.DeploySCP(ctx, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Created {
		t.Error("expected Created=false for existing policy update")
	}
	if result.PolicyID != "p-existing456" {
		t.Errorf("expected PolicyID p-existing456, got %s", result.PolicyID)
	}
}

func TestSCPDeployer_DeploySCP_WithSpecificOU(t *testing.T) {
	ctx := context.Background()

	attachedTarget := ""
	client := &mockOrganizationsDeployClient{
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{},
			}, nil
		},
		CreatePolicyFunc: func(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error) {
			return &organizations.CreatePolicyOutput{
				Policy: &orgtypes.Policy{
					PolicySummary: &orgtypes.PolicySummary{
						Id:  aws.String("p-new789"),
						Arn: aws.String("arn:aws:organizations::123456789012:policy/o-xxxxx/service_control_policy/p-new789"),
					},
				},
			}, nil
		},
		AttachPolicyFunc: func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
			attachedTarget = *params.TargetId
			return &organizations.AttachPolicyOutput{}, nil
		},
	}

	deployer := NewSCPDeployerWithClient(client)
	result, err := deployer.DeploySCP(ctx, "ou-abc123")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if attachedTarget != "ou-abc123" {
		t.Errorf("expected attachment to ou-abc123, got %s", attachedTarget)
	}
	if len(result.Targets) != 1 || result.Targets[0] != "ou-abc123" {
		t.Errorf("expected targets [ou-abc123], got %v", result.Targets)
	}
}

func TestSCPDeployer_DeploySCP_DuplicateAttachment(t *testing.T) {
	ctx := context.Background()

	client := &mockOrganizationsDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-abcd")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{
						Id:   aws.String("p-existing"),
						Name: aws.String(SentinelSCPName),
					},
				},
			}, nil
		},
		UpdatePolicyFunc: func(ctx context.Context, params *organizations.UpdatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error) {
			return &organizations.UpdatePolicyOutput{
				Policy: &orgtypes.Policy{
					PolicySummary: &orgtypes.PolicySummary{
						Id:  aws.String("p-existing"),
						Arn: aws.String("arn:aws:organizations::123456789012:policy/o-xxxxx/service_control_policy/p-existing"),
					},
				},
			}, nil
		},
		AttachPolicyFunc: func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
			// Policy already attached
			return nil, errors.New("DuplicatePolicyAttachmentException: The policy is already attached to target")
		},
	}

	deployer := NewSCPDeployerWithClient(client)
	result, err := deployer.DeploySCP(ctx, "")

	// Should succeed despite duplicate attachment error
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PolicyID != "p-existing" {
		t.Errorf("expected PolicyID p-existing, got %s", result.PolicyID)
	}
}

func TestSCPDeployer_ValidatePermissions_AccessDenied(t *testing.T) {
	ctx := context.Background()

	client := &mockOrganizationsDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return nil, errors.New("AccessDeniedException: User not authorized to perform organizations:ListRoots")
		},
	}

	deployer := NewSCPDeployerWithClient(client)
	err := deployer.ValidatePermissions(ctx)

	if err == nil {
		t.Fatal("expected error for access denied")
	}
	if !errors.Is(err, err) {
		t.Logf("error: %v", err)
	}
}

func TestSCPDeployer_ValidatePermissions_NotInOrganization(t *testing.T) {
	ctx := context.Background()

	client := &mockOrganizationsDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return nil, errors.New("AWSOrganizationsNotInUseException: Account is not a member of an organization")
		},
	}

	deployer := NewSCPDeployerWithClient(client)
	err := deployer.ValidatePermissions(ctx)

	if err == nil {
		t.Fatal("expected error for not in organization")
	}
	if !errors.Is(err, err) {
		t.Logf("error: %v", err)
	}
}

func TestSCPDeployer_ValidatePermissions_Success(t *testing.T) {
	ctx := context.Background()

	client := &mockOrganizationsDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-abcd")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{},
			}, nil
		},
	}

	deployer := NewSCPDeployerWithClient(client)
	err := deployer.ValidatePermissions(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSCPDeployer_GetOrganizationRoot(t *testing.T) {
	ctx := context.Background()

	client := &mockOrganizationsDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-xyz789")},
				},
			}, nil
		},
	}

	deployer := NewSCPDeployerWithClient(client)
	rootID, err := deployer.GetOrganizationRoot(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rootID != "r-xyz789" {
		t.Errorf("expected root ID r-xyz789, got %s", rootID)
	}
}

func TestSCPDeployer_GetOrganizationRoot_NoRoots(t *testing.T) {
	ctx := context.Background()

	client := &mockOrganizationsDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{},
			}, nil
		},
	}

	deployer := NewSCPDeployerWithClient(client)
	_, err := deployer.GetOrganizationRoot(ctx)

	if err == nil {
		t.Fatal("expected error for no roots")
	}
}

func TestIsDuplicateAttachment(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "duplicate_exception",
			err:  errors.New("DuplicatePolicyAttachmentException: The policy is already attached"),
			want: true,
		},
		{
			name: "already_attached",
			err:  errors.New("policy is already attached to target"),
			want: true,
		},
		{
			name: "access_denied",
			err:  errors.New("AccessDeniedException: User not authorized"),
			want: false,
		},
		{
			name: "nil_error",
			err:  nil,
			want: false,
		},
		{
			name: "generic_error",
			err:  errors.New("something went wrong"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDuplicateAttachment(tt.err)
			if got != tt.want {
				t.Errorf("isDuplicateAttachment() = %v, want %v", got, tt.want)
			}
		})
	}
}
