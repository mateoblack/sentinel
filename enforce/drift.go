package enforce

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// DriftStatus indicates the Sentinel enforcement state of a role.
type DriftStatus string

const (
	// DriftStatusOK means the role has full Sentinel enforcement.
	DriftStatusOK DriftStatus = "ok"
	// DriftStatusPartial means the role has partial enforcement (some statements missing).
	DriftStatusPartial DriftStatus = "partial"
	// DriftStatusNone means the role has no Sentinel enforcement.
	DriftStatusNone DriftStatus = "none"
	// DriftStatusUnknown means the check failed (e.g., IAM API error).
	DriftStatusUnknown DriftStatus = "unknown"
)

// String returns the string representation of the DriftStatus.
func (s DriftStatus) String() string {
	return string(s)
}

// DriftCheckResult contains the outcome of checking a role for Sentinel enforcement drift.
type DriftCheckResult struct {
	// Status is the drift status determined by the check.
	Status DriftStatus `json:"status"`
	// RoleARN is the ARN of the role that was checked.
	RoleARN string `json:"role_arn"`
	// Message is a human-readable explanation of the status.
	Message string `json:"message"`
	// Error is the error message if the check failed (Status=DriftStatusUnknown).
	Error string `json:"error,omitempty"`
}

// DriftChecker checks IAM roles for Sentinel enforcement drift.
type DriftChecker interface {
	// CheckRole analyzes a role's trust policy for Sentinel enforcement.
	// Returns DriftCheckResult with the enforcement status.
	CheckRole(ctx context.Context, roleARN string) (*DriftCheckResult, error)
}

// driftChecker implements DriftChecker using the Advisor for IAM analysis.
type driftChecker struct {
	advisor *Advisor
}

// NewDriftChecker creates a new DriftChecker with the given AWS config.
func NewDriftChecker(cfg aws.Config) DriftChecker {
	return &driftChecker{
		advisor: NewAdvisor(cfg),
	}
}

// NewDriftCheckerWithAdvisor creates a DriftChecker with a custom Advisor.
// This is useful for testing.
func NewDriftCheckerWithAdvisor(advisor *Advisor) DriftChecker {
	return &driftChecker{
		advisor: advisor,
	}
}

// CheckRole analyzes a role's trust policy for Sentinel enforcement.
func (c *driftChecker) CheckRole(ctx context.Context, roleARN string) (*DriftCheckResult, error) {
	result := &DriftCheckResult{
		RoleARN: roleARN,
	}

	// Use Advisor to analyze the role
	analysis, err := c.advisor.AnalyzeRole(ctx, roleARN)
	if err != nil {
		result.Status = DriftStatusUnknown
		result.Error = err.Error()
		result.Message = "Failed to analyze role"
		return result, nil
	}

	// Check if analysis itself had an error
	if analysis.Error != "" {
		result.Status = DriftStatusUnknown
		result.Error = analysis.Error
		result.Message = "Failed to analyze role trust policy"
		return result, nil
	}

	// Map AnalysisResult.Status to DriftStatus
	switch analysis.Analysis.Status {
	case EnforcementStatusFull:
		result.Status = DriftStatusOK
		result.Message = "Role has full Sentinel enforcement"
	case EnforcementStatusPartial:
		result.Status = DriftStatusPartial
		result.Message = "Role has partial Sentinel enforcement"
		if len(analysis.Analysis.Issues) > 0 {
			result.Message = analysis.Analysis.Issues[0]
		}
	case EnforcementStatusNone:
		result.Status = DriftStatusNone
		result.Message = "Role has no Sentinel enforcement"
		if len(analysis.Analysis.Recommendations) > 0 {
			result.Message = analysis.Analysis.Recommendations[0]
		}
	default:
		result.Status = DriftStatusUnknown
		result.Message = "Unknown enforcement status"
	}

	return result, nil
}

// TestDriftChecker is a DriftChecker implementation for testing.
// It allows tests to control the drift check results.
type TestDriftChecker struct {
	// CheckFunc is called by CheckRole. If nil, returns DriftStatusOK.
	CheckFunc func(ctx context.Context, roleARN string) (*DriftCheckResult, error)
}

// CheckRole calls the configured CheckFunc or returns DriftStatusOK by default.
func (t *TestDriftChecker) CheckRole(ctx context.Context, roleARN string) (*DriftCheckResult, error) {
	if t.CheckFunc != nil {
		return t.CheckFunc(ctx, roleARN)
	}
	return &DriftCheckResult{
		Status:  DriftStatusOK,
		RoleARN: roleARN,
		Message: "Role has full Sentinel enforcement",
	}, nil
}
