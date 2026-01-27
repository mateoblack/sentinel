package enforce

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// iamAPI defines the IAM operations used by the Advisor.
// This interface enables testing with mock implementations.
type iamAPI interface {
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
}

// Advisor provides trust policy analysis for IAM roles.
// It fetches trust policies from IAM and analyzes them for Sentinel enforcement.
type Advisor struct {
	client iamAPI
}

// NewAdvisor creates a new Advisor with the given AWS config.
func NewAdvisor(cfg aws.Config) *Advisor {
	return &Advisor{
		client: iam.NewFromConfig(cfg),
	}
}

// NewAdvisorWithClient creates a new Advisor with a custom IAM client.
// This is useful for testing with mock implementations.
func NewAdvisorWithClient(client iamAPI) *Advisor {
	return &Advisor{
		client: client,
	}
}

// RoleAnalysis contains the result of analyzing an IAM role's trust policy.
type RoleAnalysis struct {
	// RoleARN is the full ARN of the analyzed role.
	RoleARN string `json:"role_arn"`
	// RoleName is the name portion of the role ARN.
	RoleName string `json:"role_name"`
	// Analysis contains the enforcement analysis result.
	Analysis *AnalysisResult `json:"analysis,omitempty"`
	// Error contains any error message if analysis failed.
	Error string `json:"error,omitempty"`
}

// AnalyzeRole fetches and analyzes a single IAM role's trust policy.
// The roleARN should be a full IAM role ARN (arn:aws:iam::ACCOUNT:role/NAME).
func (a *Advisor) AnalyzeRole(ctx context.Context, roleARN string) (*RoleAnalysis, error) {
	result := &RoleAnalysis{
		RoleARN: roleARN,
	}

	// Extract role name from ARN
	// ARN format: arn:aws:iam::ACCOUNT:role/PATH/NAME or arn:aws:iam::ACCOUNT:role/NAME
	roleName, err := extractRoleName(roleARN)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	result.RoleName = roleName

	// Fetch role from IAM
	output, err := a.client.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		result.Error = fmt.Sprintf("failed to get role: %v", err)
		return result, nil
	}

	if output.Role == nil || output.Role.AssumeRolePolicyDocument == nil {
		result.Error = "role has no trust policy"
		return result, nil
	}

	// IAM returns URL-encoded JSON for trust policy
	policyJSON, err := url.QueryUnescape(*output.Role.AssumeRolePolicyDocument)
	if err != nil {
		result.Error = fmt.Sprintf("failed to decode trust policy: %v", err)
		return result, nil
	}

	// Parse trust policy
	policy, err := ParseTrustPolicy([]byte(policyJSON))
	if err != nil {
		result.Error = fmt.Sprintf("failed to parse trust policy: %v", err)
		return result, nil
	}

	// Analyze trust policy
	result.Analysis = AnalyzeTrustPolicy(policy)

	return result, nil
}

// AnalyzeRoles analyzes multiple IAM roles' trust policies.
// It processes all roles and collects results, continuing even if some fail.
// Returns results for all roles, with errors captured in each RoleAnalysis.Error.
func (a *Advisor) AnalyzeRoles(ctx context.Context, roleARNs []string) ([]*RoleAnalysis, error) {
	results := make([]*RoleAnalysis, 0, len(roleARNs))

	for _, arn := range roleARNs {
		result, _ := a.AnalyzeRole(ctx, arn)
		results = append(results, result)
	}

	return results, nil
}

// RoleValidation contains the result of validating an IAM role's trust policy.
type RoleValidation struct {
	// RoleARN is the full ARN of the validated role.
	RoleARN string `json:"role_arn"`
	// RoleName is the name portion of the role ARN.
	RoleName string `json:"role_name"`
	// Validation contains the validation result.
	Validation *ValidationResult `json:"validation,omitempty"`
	// Error contains any error message if validation failed.
	Error string `json:"error,omitempty"`
}

// ValidateRole fetches and validates a single IAM role's trust policy.
// The roleARN should be a full IAM role ARN (arn:aws:iam::ACCOUNT:role/NAME).
func (a *Advisor) ValidateRole(ctx context.Context, roleARN string) (*RoleValidation, error) {
	result := &RoleValidation{
		RoleARN: roleARN,
	}

	// Extract role name from ARN
	roleName, err := extractRoleName(roleARN)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	result.RoleName = roleName

	// Fetch role from IAM
	output, err := a.client.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		result.Error = fmt.Sprintf("failed to get role: %v", err)
		return result, nil
	}

	if output.Role == nil || output.Role.AssumeRolePolicyDocument == nil {
		result.Error = "role has no trust policy"
		return result, nil
	}

	// IAM returns URL-encoded JSON for trust policy
	policyJSON, err := url.QueryUnescape(*output.Role.AssumeRolePolicyDocument)
	if err != nil {
		result.Error = fmt.Sprintf("failed to decode trust policy: %v", err)
		return result, nil
	}

	// Parse trust policy
	policy, err := ParseTrustPolicy([]byte(policyJSON))
	if err != nil {
		result.Error = fmt.Sprintf("failed to parse trust policy: %v", err)
		return result, nil
	}

	// Validate trust policy
	result.Validation = ValidateTrustPolicy(policy)

	return result, nil
}

// ValidateRoles validates multiple IAM roles' trust policies.
// It processes all roles and collects results, continuing even if some fail.
// Returns results for all roles, with errors captured in each RoleValidation.Error.
func (a *Advisor) ValidateRoles(ctx context.Context, roleARNs []string) ([]*RoleValidation, error) {
	results := make([]*RoleValidation, 0, len(roleARNs))

	for _, arn := range roleARNs {
		result, _ := a.ValidateRole(ctx, arn)
		results = append(results, result)
	}

	return results, nil
}

// ListRolesByPrefix lists IAM role ARNs that match a given prefix.
// The prefix can match either the role path or role name.
// For example, prefix "sentinel-" will match roles like "sentinel-admin", "sentinel-user".
func (a *Advisor) ListRolesByPrefix(ctx context.Context, prefix string) ([]string, error) {
	var roleARNs []string
	var marker *string

	for {
		input := &iam.ListRolesInput{
			Marker: marker,
		}

		output, err := a.client.ListRoles(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list roles: %w", err)
		}

		for _, role := range output.Roles {
			if role.RoleName != nil && strings.HasPrefix(*role.RoleName, prefix) {
				if role.Arn != nil {
					roleARNs = append(roleARNs, *role.Arn)
				}
			}
		}

		if !output.IsTruncated {
			break
		}
		marker = output.Marker
	}

	return roleARNs, nil
}

// extractRoleName extracts the role name from an IAM role ARN.
// ARN formats:
//   - arn:aws:iam::123456789012:role/RoleName
//   - arn:aws:iam::123456789012:role/path/to/RoleName
func extractRoleName(arn string) (string, error) {
	if arn == "" {
		return "", fmt.Errorf("empty role ARN")
	}

	// Check for role ARN format
	if !strings.Contains(arn, ":role/") {
		return "", fmt.Errorf("invalid role ARN format: must contain :role/")
	}

	// Extract everything after :role/
	parts := strings.SplitN(arn, ":role/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("invalid role ARN format: missing role name")
	}

	// The role name is the last segment (handles paths like role/path/to/name)
	rolePath := parts[1]
	segments := strings.Split(rolePath, "/")
	return segments[len(segments)-1], nil
}
