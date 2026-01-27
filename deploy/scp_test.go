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
// Mock Client
// ============================================================================

// mockOrganizationsAuditClient implements organizationsAuditAPI for testing.
type mockOrganizationsAuditClient struct {
	ListPoliciesFunc         func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicyFunc       func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicyFunc func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
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
