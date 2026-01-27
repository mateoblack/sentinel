package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
)

// NOTE: SCP deployment functionality was removed in v2.0 (SEC-02/SCP-T-01).
// SCPs can lock out entire AWS Organizations. Users should deploy SCPs
// through their organization's change management process.
// Use sentinel scp template to generate the policy.

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
			Remediation: "sentinel scp template --format terraform",
		})
	} else if len(policies) == 0 {
		// No SCPs at all (besides FullAWSAccess default)
		findings = append(findings, DeploymentFinding{
			CheckID:     "DEPLOY-01",
			Category:    "SCP",
			RiskLevel:   RiskLevelHigh,
			Resource:    "AWS Organizations",
			Message:     "No custom SCPs found - organization-wide policy controls not configured",
			Remediation: "sentinel scp template --format terraform",
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
// SCP Template Generation
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

// GetSCPPolicyJSON returns the SCP policy as formatted JSON.
func GetSCPPolicyJSON() string {
	// Pretty-print the JSON for readability
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(SentinelSCPPolicy), "", "  "); err != nil {
		// If indentation fails (shouldn't happen), return as-is
		return SentinelSCPPolicy
	}
	return buf.String() + "\n"
}

// GetSCPPolicyYAML returns the SCP policy as YAML.
func GetSCPPolicyYAML() (string, error) {
	// Convert JSON to YAML-like format manually (simple conversion)
	// This avoids adding a YAML dependency
	yaml := `# Sentinel SCP Policy
# Enforces SourceIdentity for all AssumeRole operations
#
# WARNING: This SCP affects the ENTIRE AWS Organization.
# Test thoroughly before deploying to production.

Version: "2012-10-17"
Statement:
  - Sid: DenyAssumeRoleWithoutSourceIdentity
    Effect: Deny
    Action: "sts:AssumeRole"
    Resource: "*"
    Condition:
      "Null":
        "sts:SourceIdentity": "true"
`
	return yaml, nil
}

// GetSCPTerraform returns a Terraform resource definition for the SCP.
func GetSCPTerraform() string {
	return `# Sentinel SCP - Terraform Configuration
#
# This SCP enforces SourceIdentity for all AssumeRole operations,
# ensuring that only Sentinel-approved credentials can access AWS resources.
#
# WARNING: This SCP affects the ENTIRE AWS Organization.
# Test thoroughly before deploying to production.
#
# Usage:
#   1. Replace "r-xxxx" with your organization root ID or OU ID
#   2. Run: terraform plan
#   3. Review the plan carefully
#   4. Run: terraform apply

resource "aws_organizations_policy" "sentinel_source_identity" {
  name        = "SentinelSourceIdentityEnforcement"
  description = "Enforces SourceIdentity for all AssumeRole operations to enable Sentinel credential tracking"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyAssumeRoleWithoutSourceIdentity"
        Effect    = "Deny"
        Action    = "sts:AssumeRole"
        Resource  = "*"
        Condition = {
          "Null" = {
            "sts:SourceIdentity" = "true"
          }
        }
      }
    ]
  })
}

# Attach the SCP to your organization root or specific OUs
# Replace "r-xxxx" with your actual organization root ID
resource "aws_organizations_policy_attachment" "sentinel_root" {
  policy_id = aws_organizations_policy.sentinel_source_identity.id
  target_id = "r-xxxx"  # Replace with your organization root ID or OU ID
}
`
}

// GetSCPCloudFormation returns a CloudFormation template for the SCP.
func GetSCPCloudFormation() string {
	return `AWSTemplateFormatVersion: '2010-09-09'
Description: >
  Sentinel SCP - CloudFormation Template

  This SCP enforces SourceIdentity for all AssumeRole operations,
  ensuring that only Sentinel-approved credentials can access AWS resources.

  WARNING: This SCP affects the ENTIRE AWS Organization.
  Test thoroughly before deploying to production.

Parameters:
  TargetId:
    Type: String
    Description: Organization root ID (r-xxxx) or OU ID (ou-xxxx-xxxxxxxx) to attach the SCP
    AllowedPattern: "^(r-[a-z0-9]{4,32}|ou-[a-z0-9]{4,32}-[a-z0-9]{8,32})$"
    ConstraintDescription: Must be a valid organization root ID (r-xxxx) or OU ID (ou-xxxx-xxxxxxxx)

Resources:
  SentinelSCP:
    Type: AWS::Organizations::Policy
    Properties:
      Name: SentinelSourceIdentityEnforcement
      Description: Enforces SourceIdentity for all AssumeRole operations to enable Sentinel credential tracking
      Type: SERVICE_CONTROL_POLICY
      TargetIds:
        - !Ref TargetId
      Content:
        Version: "2012-10-17"
        Statement:
          - Sid: DenyAssumeRoleWithoutSourceIdentity
            Effect: Deny
            Action: "sts:AssumeRole"
            Resource: "*"
            Condition:
              "Null":
                "sts:SourceIdentity": "true"

Outputs:
  PolicyId:
    Description: The ID of the created SCP
    Value: !Ref SentinelSCP
  PolicyArn:
    Description: The ARN of the created SCP
    Value: !GetAtt SentinelSCP.Arn
`
}
