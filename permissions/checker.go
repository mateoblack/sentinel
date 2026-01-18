package permissions

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	sentinelerrors "github.com/byteness/aws-vault/v7/errors"
)

// CheckStatus represents the result of a permission check.
type CheckStatus string

const (
	// StatusAllowed indicates the permission is allowed.
	StatusAllowed CheckStatus = "allowed"
	// StatusDenied indicates the permission is denied.
	StatusDenied CheckStatus = "denied"
	// StatusError indicates an error occurred during the check.
	StatusError CheckStatus = "error"
	// StatusNotChecked indicates the permission was not checked.
	StatusNotChecked CheckStatus = "not_checked"
)

// CheckResult represents the result of checking a single permission.
type CheckResult struct {
	// Feature is the feature this permission belongs to.
	Feature Feature
	// Action is the IAM action that was checked.
	Action string
	// Resource is the resource ARN that was checked.
	Resource string
	// Status is the result of the check.
	Status CheckStatus
	// Message provides additional context about the result.
	Message string
}

// CheckSummary contains the aggregated results of permission checks.
type CheckSummary struct {
	// Results contains all individual check results.
	Results []CheckResult
	// PassCount is the number of checks that passed.
	PassCount int
	// FailCount is the number of checks that failed (denied).
	FailCount int
	// ErrorCount is the number of checks that errored.
	ErrorCount int
}

// iamCheckerAPI defines the IAM operations used by Checker.
// This interface enables testing with mock implementations.
type iamCheckerAPI interface {
	SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

// stsCheckerAPI defines the STS operations used by Checker.
// This interface enables testing with mock implementations.
type stsCheckerAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// CheckerInterface defines the interface for permission checking.
// This enables testing with mock checkers in the CLI.
type CheckerInterface interface {
	Check(ctx context.Context, features []Feature) (*CheckSummary, error)
}

// Checker validates AWS IAM permissions using SimulatePrincipalPolicy.
type Checker struct {
	iamClient stsCheckerAPI
	simClient iamCheckerAPI
	callerArn string // cached caller ARN
}

// NewChecker creates a Checker using the provided AWS configuration.
func NewChecker(cfg aws.Config) *Checker {
	return &Checker{
		iamClient: sts.NewFromConfig(cfg),
		simClient: iam.NewFromConfig(cfg),
	}
}

// newCheckerWithClients creates a Checker with custom clients (for testing).
func newCheckerWithClients(stsClient stsCheckerAPI, iamClient iamCheckerAPI) *Checker {
	return &Checker{
		iamClient: stsClient,
		simClient: iamClient,
	}
}

// Check validates permissions for the given features using IAM SimulatePrincipalPolicy.
// It returns a summary of all check results, even if some checks fail.
func (c *Checker) Check(ctx context.Context, features []Feature) (*CheckSummary, error) {
	// Get caller identity if not cached
	if c.callerArn == "" {
		identity, err := c.iamClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return nil, sentinelerrors.WrapSTSError(err, "GetCallerIdentity")
		}
		c.callerArn = aws.ToString(identity.Arn)
	}

	summary := &CheckSummary{
		Results: []CheckResult{},
	}

	// Check each feature's permissions
	for _, feature := range features {
		fp, ok := GetFeaturePermissions(feature)
		if !ok {
			// Feature not found in registry - skip
			continue
		}

		// Check each permission for this feature
		for _, perm := range fp.Permissions {
			for _, action := range perm.Actions {
				result := c.checkPermission(ctx, feature, action, perm.Resource)
				summary.Results = append(summary.Results, result)

				// Update counts
				switch result.Status {
				case StatusAllowed:
					summary.PassCount++
				case StatusDenied:
					summary.FailCount++
				case StatusError:
					summary.ErrorCount++
				}
			}
		}
	}

	return summary, nil
}

// checkPermission checks a single permission using SimulatePrincipalPolicy.
func (c *Checker) checkPermission(ctx context.Context, feature Feature, action, resource string) CheckResult {
	result := CheckResult{
		Feature:  feature,
		Action:   action,
		Resource: resource,
	}

	// Call SimulatePrincipalPolicy
	output, err := c.simClient.SimulatePrincipalPolicy(ctx, &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(c.callerArn),
		ActionNames:     []string{action},
		ResourceArns:    []string{resource},
	})
	if err != nil {
		// Check if it's an access denied error for SimulatePrincipalPolicy itself
		if isAccessDeniedError(err) {
			result.Status = StatusError
			result.Message = sentinelerrors.GetSuggestion(sentinelerrors.ErrCodeIAMSimulateAccessDenied)
			return result
		}
		result.Status = StatusError
		result.Message = err.Error()
		return result
	}

	// Check the evaluation results
	if len(output.EvaluationResults) == 0 {
		result.Status = StatusError
		result.Message = "no evaluation results returned"
		return result
	}

	evalResult := output.EvaluationResults[0]
	switch evalResult.EvalDecision {
	case iamtypes.PolicyEvaluationDecisionTypeAllowed:
		result.Status = StatusAllowed
		result.Message = "allowed"
	case iamtypes.PolicyEvaluationDecisionTypeExplicitDeny:
		result.Status = StatusDenied
		result.Message = "explicitly denied"
	case iamtypes.PolicyEvaluationDecisionTypeImplicitDeny:
		result.Status = StatusDenied
		result.Message = "implicitly denied (no matching allow)"
	default:
		result.Status = StatusDenied
		result.Message = string(evalResult.EvalDecision)
	}

	return result
}

// isAccessDeniedError checks if an error indicates access was denied.
func isAccessDeniedError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "accessdenied") ||
		strings.Contains(errMsg, "access denied") ||
		strings.Contains(errMsg, "unauthorized") ||
		strings.Contains(errMsg, "not authorized")
}

// ErrCallerIdentityFailed is returned when GetCallerIdentity fails.
var ErrCallerIdentityFailed = errors.New("failed to get caller identity")
