package bootstrap

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// ssmStatusAPI defines the SSM operations used by StatusChecker.
// This interface enables testing with mock implementations.
// Note: This is separate from ssmAPI in planner.go as they have different method needs.
type ssmStatusAPI interface {
	GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
}

// ParameterInfo holds status information about a single SSM parameter.
type ParameterInfo struct {
	// Name is the parameter name (extracted from path, e.g., "production").
	Name string `json:"name"`

	// Path is the full SSM path (e.g., "/sentinel/policies/production").
	Path string `json:"path"`

	// Version is the SSM version number.
	Version int64 `json:"version"`

	// LastModified is when the parameter was last modified.
	LastModified time.Time `json:"last_modified"`

	// Type is the parameter type (String or SecureString).
	Type string `json:"type"`
}

// StatusResult contains the results of a status query.
type StatusResult struct {
	// PolicyRoot is the root path that was queried.
	PolicyRoot string `json:"policy_root"`

	// Parameters contains information about found parameters.
	Parameters []ParameterInfo `json:"parameters"`

	// Count is the total number of parameters found.
	Count int `json:"count"`
}

// StatusChecker queries SSM for existing policy parameters.
type StatusChecker struct {
	ssm ssmStatusAPI
}

// NewStatusChecker creates a new StatusChecker using the provided AWS configuration.
func NewStatusChecker(cfg aws.Config) *StatusChecker {
	return &StatusChecker{
		ssm: ssm.NewFromConfig(cfg),
	}
}

// newStatusCheckerWithClient creates a StatusChecker with a custom SSM client.
// This is primarily used for testing with mock clients.
func newStatusCheckerWithClient(client ssmStatusAPI) *StatusChecker {
	return &StatusChecker{
		ssm: client,
	}
}

// GetStatus queries SSM for parameters under the given policy root.
// It returns a StatusResult with information about all found parameters.
func (s *StatusChecker) GetStatus(ctx context.Context, policyRoot string) (*StatusResult, error) {
	result := &StatusResult{
		PolicyRoot: policyRoot,
		Parameters: []ParameterInfo{},
	}

	var nextToken *string

	for {
		input := &ssm.GetParametersByPathInput{
			Path:      aws.String(policyRoot),
			Recursive: aws.Bool(false),
			NextToken: nextToken,
		}

		output, err := s.ssm.GetParametersByPath(ctx, input)
		if err != nil {
			return nil, err
		}

		// Process parameters from this page
		for _, param := range output.Parameters {
			path := aws.ToString(param.Name)
			name := extractProfileName(policyRoot, path)

			info := ParameterInfo{
				Name:         name,
				Path:         path,
				Version:      param.Version,
				Type:         string(param.Type),
				LastModified: aws.ToTime(param.LastModifiedDate),
			}
			result.Parameters = append(result.Parameters, info)
		}

		// Check for more pages
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	result.Count = len(result.Parameters)
	return result, nil
}

// extractProfileName extracts the profile name from a full parameter path.
// For example, "/sentinel/policies/production" -> "production".
func extractProfileName(policyRoot, paramPath string) string {
	// Remove trailing slash from policyRoot if present
	policyRoot = strings.TrimSuffix(policyRoot, "/")

	// Remove the policy root prefix and leading slash
	name := strings.TrimPrefix(paramPath, policyRoot)
	name = strings.TrimPrefix(name, "/")

	return name
}
