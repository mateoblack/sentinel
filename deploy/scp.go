package deploy

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

// organizationsAuditAPI defines Organizations operations used for SCP audits.
type organizationsAuditAPI interface {
	ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicy(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
}

// SCPAuditor performs security audits on Service Control Policies.
type SCPAuditor struct {
	orgs organizationsAuditAPI
}

// NewSCPAuditor creates a new SCPAuditor using the provided AWS configuration.
func NewSCPAuditor(cfg aws.Config) *SCPAuditor {
	return &SCPAuditor{
		orgs: organizations.NewFromConfig(cfg),
	}
}

// NewSCPAuditorWithClient creates an SCPAuditor with a custom client for testing.
func NewSCPAuditorWithClient(client organizationsAuditAPI) *SCPAuditor {
	return &SCPAuditor{
		orgs: client,
	}
}

// AuditSCPEnforcement checks if any SCP enforces SourceIdentity for AssumeRole.
// DEPLOY-01: HIGH if no SCP enforces SourceIdentity on protected roles.
// Returns UNKNOWN if access is denied (common when running outside management account).
func (a *SCPAuditor) AuditSCPEnforcement(ctx context.Context) []DeploymentFinding {
	var findings []DeploymentFinding

	// List all SCPs in the organization
	policies, err := a.listAllSCPs(ctx)
	if err != nil {
		if isAccessDenied(err) || isNotInOrganization(err) {
			findings = append(findings, DeploymentFinding{
				CheckID:     "DEPLOY-01",
				Category:    "SCP",
				RiskLevel:   RiskLevelUnknown,
				Resource:    "AWS Organizations",
				Message:     "Unable to check SCP enforcement (access denied or not in management account)",
				Remediation: "Run from management account with organizations:ListPolicies permission, or use --no-scp to skip this check",
			})
			return findings
		}
		// Other errors - treat as unknown
		findings = append(findings, DeploymentFinding{
			CheckID:     "DEPLOY-01",
			Category:    "SCP",
			RiskLevel:   RiskLevelUnknown,
			Resource:    "AWS Organizations",
			Message:     "Unable to check SCP enforcement: " + err.Error(),
			Remediation: "Ensure AWS Organizations permissions are configured",
		})
		return findings
	}

	// Check if any SCP enforces SourceIdentity
	hasSentinelSCP := false
	for _, policyID := range policies {
		content, err := a.getPolicyContent(ctx, policyID)
		if err != nil {
			continue // Skip policies we can't read
		}

		if isSentinelSCP(content) {
			hasSentinelSCP = true
			break
		}
	}

	if !hasSentinelSCP && len(policies) > 0 {
		findings = append(findings, DeploymentFinding{
			CheckID:     "DEPLOY-01",
			Category:    "SCP",
			RiskLevel:   RiskLevelHigh,
			Resource:    "AWS Organizations",
			Message:     "No SCP enforces sts:SourceIdentity for AssumeRole - non-Sentinel credentials can bypass policy controls",
			Remediation: "sentinel scp deploy --dry-run",
		})
	} else if len(policies) == 0 {
		// No SCPs at all (besides FullAWSAccess default)
		findings = append(findings, DeploymentFinding{
			CheckID:     "DEPLOY-01",
			Category:    "SCP",
			RiskLevel:   RiskLevelHigh,
			Resource:    "AWS Organizations",
			Message:     "No custom SCPs found - organization-wide policy controls not configured",
			Remediation: "sentinel scp deploy --dry-run",
		})
	}

	return findings
}

// listAllSCPs retrieves all SCP policy IDs in the organization.
func (a *SCPAuditor) listAllSCPs(ctx context.Context) ([]string, error) {
	var policyIDs []string
	var nextToken *string

	for {
		input := &organizations.ListPoliciesInput{
			Filter:    "SERVICE_CONTROL_POLICY",
			NextToken: nextToken,
		}

		output, err := a.orgs.ListPolicies(ctx, input)
		if err != nil {
			return nil, err
		}

		for _, policy := range output.Policies {
			if policy.Id != nil {
				// Skip the default FullAWSAccess policy
				if policy.Name != nil && *policy.Name == "FullAWSAccess" {
					continue
				}
				policyIDs = append(policyIDs, *policy.Id)
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return policyIDs, nil
}

// getPolicyContent retrieves the content of an SCP by ID.
func (a *SCPAuditor) getPolicyContent(ctx context.Context, policyID string) (string, error) {
	output, err := a.orgs.DescribePolicy(ctx, &organizations.DescribePolicyInput{
		PolicyId: aws.String(policyID),
	})
	if err != nil {
		return "", err
	}

	if output.Policy != nil && output.Policy.Content != nil {
		return *output.Policy.Content, nil
	}

	return "", nil
}

// isSentinelSCP checks if an SCP enforces SourceIdentity for AssumeRole.
// A valid Sentinel SCP should contain:
// 1. A reference to sts:SourceIdentity condition key
// 2. A reference to sts:AssumeRole action
// This ensures credentials without SourceIdentity are blocked.
func isSentinelSCP(policyContent string) bool {
	// Check for both required elements
	hasSourceIdentity := strings.Contains(policyContent, "sts:SourceIdentity")
	hasAssumeRole := strings.Contains(policyContent, "sts:AssumeRole")

	return hasSourceIdentity && hasAssumeRole
}

// isNotInOrganization checks if an error indicates the account is not in an organization.
func isNotInOrganization(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "AWSOrganizationsNotInUseException") ||
		strings.Contains(errMsg, "not a member of an organization")
}
