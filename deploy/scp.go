package deploy

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// organizationsAuditAPI defines Organizations operations used for SCP audits.
type organizationsAuditAPI interface {
	ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicy(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
}

// organizationsDeployAPI extends audit operations with deployment capabilities.
type organizationsDeployAPI interface {
	// Audit operations (existing)
	ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicy(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)

	// Deployment operations (new)
	CreatePolicy(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error)
	AttachPolicy(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error)
	UpdatePolicy(ctx context.Context, params *organizations.UpdatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error)
	ListRoots(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
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

// ============================================================================
// SCP Deployment
// ============================================================================

// SentinelSCPPolicy is the recommended SCP JSON that enforces SourceIdentity for AssumeRole.
const SentinelSCPPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAssumeRoleWithoutSourceIdentity",
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

// SentinelSCPName is the name of the Sentinel SCP policy.
const SentinelSCPName = "SentinelSourceIdentityEnforcement"

// SentinelSCPDescription is the description of the Sentinel SCP policy.
const SentinelSCPDescription = "Enforces SourceIdentity for all AssumeRole operations to enable Sentinel credential tracking"

// DeployResult contains the result of an SCP deployment.
type DeployResult struct {
	PolicyID  string   // AWS policy ID
	PolicyARN string   // AWS policy ARN
	Created   bool     // true if new policy created, false if updated
	Targets   []string // IDs of targets the policy is attached to
}

// SCPDeployer handles SCP deployment operations.
type SCPDeployer struct {
	orgs organizationsDeployAPI
}

// NewSCPDeployer creates a new SCPDeployer using the provided AWS configuration.
func NewSCPDeployer(cfg aws.Config) *SCPDeployer {
	return &SCPDeployer{
		orgs: organizations.NewFromConfig(cfg),
	}
}

// NewSCPDeployerWithClient creates an SCPDeployer with a custom client for testing.
func NewSCPDeployerWithClient(client organizationsDeployAPI) *SCPDeployer {
	return &SCPDeployer{
		orgs: client,
	}
}

// DeploySCP creates or updates the Sentinel SCP and attaches it to the specified target.
// If targetID is empty, attaches to the organization root.
func (d *SCPDeployer) DeploySCP(ctx context.Context, targetID string) (*DeployResult, error) {
	result := &DeployResult{}

	// If no target specified, use organization root
	if targetID == "" {
		rootID, err := d.GetOrganizationRoot(ctx)
		if err != nil {
			return nil, err
		}
		targetID = rootID
	}

	// Check if Sentinel SCP already exists
	existingPolicyID, err := d.FindExistingSentinelSCP(ctx)
	if err != nil {
		return nil, err
	}

	if existingPolicyID != "" {
		// Update existing policy
		updateOutput, err := d.orgs.UpdatePolicy(ctx, &organizations.UpdatePolicyInput{
			PolicyId:    aws.String(existingPolicyID),
			Content:     aws.String(SentinelSCPPolicy),
			Description: aws.String(SentinelSCPDescription),
		})
		if err != nil {
			return nil, err
		}

		result.PolicyID = existingPolicyID
		if updateOutput.Policy != nil && updateOutput.Policy.PolicySummary != nil && updateOutput.Policy.PolicySummary.Arn != nil {
			result.PolicyARN = *updateOutput.Policy.PolicySummary.Arn
		}
		result.Created = false
	} else {
		// Create new policy
		createOutput, err := d.orgs.CreatePolicy(ctx, &organizations.CreatePolicyInput{
			Content:     aws.String(SentinelSCPPolicy),
			Description: aws.String(SentinelSCPDescription),
			Name:        aws.String(SentinelSCPName),
			Type:        orgtypes.PolicyTypeServiceControlPolicy,
		})
		if err != nil {
			return nil, err
		}

		if createOutput.Policy != nil && createOutput.Policy.PolicySummary != nil {
			if createOutput.Policy.PolicySummary.Id != nil {
				result.PolicyID = *createOutput.Policy.PolicySummary.Id
			}
			if createOutput.Policy.PolicySummary.Arn != nil {
				result.PolicyARN = *createOutput.Policy.PolicySummary.Arn
			}
		}
		result.Created = true
	}

	// Attach policy to target
	_, err = d.orgs.AttachPolicy(ctx, &organizations.AttachPolicyInput{
		PolicyId: aws.String(result.PolicyID),
		TargetId: aws.String(targetID),
	})
	if err != nil {
		// Check if already attached (not an error)
		if !isDuplicateAttachment(err) {
			return nil, err
		}
	}

	result.Targets = []string{targetID}
	return result, nil
}

// GetOrganizationRoot returns the root ID of the organization.
func (d *SCPDeployer) GetOrganizationRoot(ctx context.Context) (string, error) {
	output, err := d.orgs.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return "", err
	}

	if len(output.Roots) == 0 {
		return "", errors.New("no organization root found")
	}

	if output.Roots[0].Id == nil {
		return "", errors.New("organization root has no ID")
	}

	return *output.Roots[0].Id, nil
}

// FindExistingSentinelSCP returns the policy ID if a Sentinel SCP already exists, empty string if not.
func (d *SCPDeployer) FindExistingSentinelSCP(ctx context.Context) (string, error) {
	var nextToken *string

	for {
		input := &organizations.ListPoliciesInput{
			Filter:    "SERVICE_CONTROL_POLICY",
			NextToken: nextToken,
		}

		output, err := d.orgs.ListPolicies(ctx, input)
		if err != nil {
			return "", err
		}

		for _, policy := range output.Policies {
			if policy.Name != nil && *policy.Name == SentinelSCPName {
				if policy.Id != nil {
					return *policy.Id, nil
				}
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return "", nil
}

// ValidatePermissions validates that the caller has required IAM permissions for SCP deployment.
// Returns nil if all permissions are available, error describing missing permissions otherwise.
func (d *SCPDeployer) ValidatePermissions(ctx context.Context) error {
	// Try to list roots to check basic Organizations access
	_, err := d.orgs.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		if isAccessDenied(err) {
			return errors.New("missing permission: organizations:ListRoots - ensure you are running from the management account")
		}
		if isNotInOrganization(err) {
			return errors.New("this account is not part of an AWS Organization")
		}
		return err
	}

	// Try to list policies to check policy read access
	_, err = d.orgs.ListPolicies(ctx, &organizations.ListPoliciesInput{
		Filter: "SERVICE_CONTROL_POLICY",
	})
	if err != nil {
		if isAccessDenied(err) {
			return errors.New("missing permission: organizations:ListPolicies")
		}
		return err
	}

	// Note: We can't easily test CreatePolicy/AttachPolicy/UpdatePolicy permissions
	// without actually creating/modifying resources. The dry-run will catch these
	// during actual deployment if there are permission issues.

	return nil
}

// isDuplicateAttachment checks if an error indicates the policy is already attached.
func isDuplicateAttachment(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "DuplicatePolicyAttachmentException") ||
		strings.Contains(errMsg, "already attached")
}
