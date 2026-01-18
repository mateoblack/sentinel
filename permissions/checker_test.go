package permissions

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// mockSTSCheckerClient implements stsCheckerAPI for testing.
type mockSTSCheckerClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockSTSCheckerClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return &sts.GetCallerIdentityOutput{
		Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
		Account: aws.String("123456789012"),
		UserId:  aws.String("AIDAEXAMPLE"),
	}, nil
}

// mockIAMCheckerClient implements iamCheckerAPI for testing.
type mockIAMCheckerClient struct {
	SimulatePrincipalPolicyFunc func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

func (m *mockIAMCheckerClient) SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	if m.SimulatePrincipalPolicyFunc != nil {
		return m.SimulatePrincipalPolicyFunc(ctx, params, optFns...)
	}
	return &iam.SimulatePrincipalPolicyOutput{}, nil
}

func TestChecker_Check_AllAllowed(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{
					{
						EvalActionName: aws.String(params.ActionNames[0]),
						EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeAllowed,
					},
				},
			}, nil
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)
	summary, err := checker.Check(context.Background(), []Feature{FeaturePolicyLoad})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.FailCount != 0 {
		t.Errorf("expected 0 failures, got %d", summary.FailCount)
	}
	if summary.ErrorCount != 0 {
		t.Errorf("expected 0 errors, got %d", summary.ErrorCount)
	}
	if summary.PassCount == 0 {
		t.Error("expected at least one pass")
	}

	// All results should be allowed
	for _, result := range summary.Results {
		if result.Status != StatusAllowed {
			t.Errorf("expected StatusAllowed, got %s for action %s", result.Status, result.Action)
		}
	}
}

func TestChecker_Check_AllDenied(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{
					{
						EvalActionName: aws.String(params.ActionNames[0]),
						EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeImplicitDeny,
					},
				},
			}, nil
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)
	summary, err := checker.Check(context.Background(), []Feature{FeaturePolicyLoad})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.PassCount != 0 {
		t.Errorf("expected 0 passes, got %d", summary.PassCount)
	}
	if summary.FailCount == 0 {
		t.Error("expected at least one failure")
	}

	// All results should be denied
	for _, result := range summary.Results {
		if result.Status != StatusDenied {
			t.Errorf("expected StatusDenied, got %s for action %s", result.Status, result.Action)
		}
	}
}

func TestChecker_Check_ExplicitDeny(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{
					{
						EvalActionName: aws.String(params.ActionNames[0]),
						EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeExplicitDeny,
					},
				},
			}, nil
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)
	summary, err := checker.Check(context.Background(), []Feature{FeatureCredentialIssue})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.FailCount == 0 {
		t.Error("expected at least one failure for explicit deny")
	}

	// Check that explicit deny is captured
	for _, result := range summary.Results {
		if result.Status == StatusDenied && result.Message != "explicitly denied" {
			t.Errorf("expected 'explicitly denied' message, got %s", result.Message)
		}
	}
}

func TestChecker_Check_MixedResults(t *testing.T) {
	callCount := 0
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			callCount++
			decision := iamtypes.PolicyEvaluationDecisionTypeAllowed
			if callCount%2 == 0 {
				decision = iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
			}
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{
					{
						EvalActionName: aws.String(params.ActionNames[0]),
						EvalDecision:   decision,
					},
				},
			}, nil
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)
	summary, err := checker.Check(context.Background(), []Feature{FeaturePolicyLoad, FeatureCredentialIssue})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have both passes and failures
	if summary.PassCount == 0 {
		t.Error("expected at least one pass in mixed results")
	}
	if summary.FailCount == 0 {
		t.Error("expected at least one failure in mixed results")
	}
}

func TestChecker_Check_SimulateAccessDenied(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			return nil, errors.New("AccessDenied: User is not authorized to perform iam:SimulatePrincipalPolicy")
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)
	summary, err := checker.Check(context.Background(), []Feature{FeaturePolicyLoad})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have errors, not failures
	if summary.ErrorCount == 0 {
		t.Error("expected at least one error")
	}

	// Check error message - should contain SimulatePrincipalPolicy suggestion
	for _, result := range summary.Results {
		if result.Status == StatusError {
			if !strings.Contains(result.Message, "SimulatePrincipalPolicy") {
				t.Errorf("expected SimulatePrincipalPolicy permission error message, got: %s", result.Message)
			}
		}
	}
}

func TestChecker_Check_OtherAPIError(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			return nil, errors.New("network timeout")
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)
	summary, err := checker.Check(context.Background(), []Feature{FeaturePolicyLoad})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have errors
	if summary.ErrorCount == 0 {
		t.Error("expected at least one error for API failure")
	}

	// Check error contains original message
	for _, result := range summary.Results {
		if result.Status == StatusError {
			if result.Message != "network timeout" {
				t.Errorf("expected 'network timeout' error message, got: %s", result.Message)
			}
		}
	}
}

func TestChecker_Check_GetCallerIdentityFails(t *testing.T) {
	stsClient := &mockSTSCheckerClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return nil, errors.New("failed to get identity")
		},
	}
	iamClient := &mockIAMCheckerClient{}

	checker := newCheckerWithClients(stsClient, iamClient)
	_, err := checker.Check(context.Background(), []Feature{FeaturePolicyLoad})

	if err == nil {
		t.Error("expected error when GetCallerIdentity fails")
	}
	// Error should be wrapped as SentinelError with STS error context
	if !strings.Contains(err.Error(), "GetCallerIdentity") {
		t.Errorf("expected GetCallerIdentity in error, got: %v", err)
	}
}

func TestChecker_Check_NoEvaluationResults(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{}, // Empty
			}, nil
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)
	summary, err := checker.Check(context.Background(), []Feature{FeaturePolicyLoad})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have errors for missing evaluation results
	if summary.ErrorCount == 0 {
		t.Error("expected at least one error for missing evaluation results")
	}

	for _, result := range summary.Results {
		if result.Status == StatusError && result.Message != "no evaluation results returned" {
			t.Errorf("expected 'no evaluation results' error, got: %s", result.Message)
		}
	}
}

func TestChecker_Check_UnknownFeature(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{}

	checker := newCheckerWithClients(stsClient, iamClient)
	summary, err := checker.Check(context.Background(), []Feature{Feature("unknown_feature")})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have no results for unknown feature
	if len(summary.Results) != 0 {
		t.Errorf("expected 0 results for unknown feature, got %d", len(summary.Results))
	}
}

func TestChecker_Check_EmptyFeatures(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{}

	checker := newCheckerWithClients(stsClient, iamClient)
	summary, err := checker.Check(context.Background(), []Feature{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have no results
	if len(summary.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(summary.Results))
	}
	if summary.PassCount != 0 || summary.FailCount != 0 || summary.ErrorCount != 0 {
		t.Error("expected all counts to be 0")
	}
}

func TestChecker_Check_MultipleFeatures(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{
					{
						EvalActionName: aws.String(params.ActionNames[0]),
						EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeAllowed,
					},
				},
			}, nil
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)
	features := []Feature{
		FeaturePolicyLoad,
		FeatureCredentialIssue,
		FeatureApprovalWorkflow,
		FeatureAuditVerify,
	}
	summary, err := checker.Check(context.Background(), features)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have results for all features
	if len(summary.Results) == 0 {
		t.Error("expected results for multiple features")
	}

	// Check that multiple features are represented
	featuresSeen := make(map[Feature]bool)
	for _, result := range summary.Results {
		featuresSeen[result.Feature] = true
	}

	if len(featuresSeen) < 2 {
		t.Errorf("expected results from multiple features, got %d unique features", len(featuresSeen))
	}
}

func TestChecker_Check_CachesCallerArn(t *testing.T) {
	callCount := 0
	stsClient := &mockSTSCheckerClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			callCount++
			return &sts.GetCallerIdentityOutput{
				Arn: aws.String("arn:aws:iam::123456789012:user/testuser"),
			}, nil
		},
	}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{
					{EvalDecision: iamtypes.PolicyEvaluationDecisionTypeAllowed},
				},
			}, nil
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)

	// First call
	_, err := checker.Check(context.Background(), []Feature{FeaturePolicyLoad})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second call
	_, err = checker.Check(context.Background(), []Feature{FeatureCredentialIssue})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// GetCallerIdentity should only be called once (cached)
	if callCount != 1 {
		t.Errorf("expected GetCallerIdentity to be called once (cached), got %d calls", callCount)
	}
}

func TestChecker_Check_PassesCorrectParameters(t *testing.T) {
	var capturedParams *iam.SimulatePrincipalPolicyInput
	stsClient := &mockSTSCheckerClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn: aws.String("arn:aws:iam::123456789012:user/testuser"),
			}, nil
		},
	}
	iamClient := &mockIAMCheckerClient{
		SimulatePrincipalPolicyFunc: func(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
			capturedParams = params
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: []iamtypes.EvaluationResult{
					{EvalDecision: iamtypes.PolicyEvaluationDecisionTypeAllowed},
				},
			}, nil
		},
	}

	checker := newCheckerWithClients(stsClient, iamClient)
	_, err := checker.Check(context.Background(), []Feature{FeatureCredentialIssue})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify parameters
	if capturedParams == nil {
		t.Fatal("expected SimulatePrincipalPolicy to be called")
	}

	if aws.ToString(capturedParams.PolicySourceArn) != "arn:aws:iam::123456789012:user/testuser" {
		t.Errorf("unexpected PolicySourceArn: %s", aws.ToString(capturedParams.PolicySourceArn))
	}

	// Should have action from credential_issue feature
	if len(capturedParams.ActionNames) == 0 {
		t.Error("expected at least one action name")
	}
	if capturedParams.ActionNames[0] != "sts:AssumeRole" {
		t.Errorf("expected sts:AssumeRole action, got: %s", capturedParams.ActionNames[0])
	}

	// Should have resource
	if len(capturedParams.ResourceArns) == 0 {
		t.Error("expected at least one resource ARN")
	}
}

func TestIsAccessDeniedError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "AccessDenied",
			err:      errors.New("AccessDenied: User is not authorized"),
			expected: true,
		},
		{
			name:     "access denied lowercase",
			err:      errors.New("access denied to resource"),
			expected: true,
		},
		{
			name:     "unauthorized",
			err:      errors.New("User is not authorized to perform this action"),
			expected: true,
		},
		{
			name:     "Unauthorized capitalized",
			err:      errors.New("Unauthorized"),
			expected: true,
		},
		{
			name:     "network error",
			err:      errors.New("network timeout"),
			expected: false,
		},
		{
			name:     "validation error",
			err:      errors.New("validation error: invalid parameter"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAccessDeniedError(tt.err)
			if result != tt.expected {
				t.Errorf("isAccessDeniedError(%v) = %v, expected %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestCheckerInterface(t *testing.T) {
	// Verify Checker implements CheckerInterface
	var _ CheckerInterface = (*Checker)(nil)
}

func TestNewCheckerWithClients(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{}

	checker := newCheckerWithClients(stsClient, iamClient)

	if checker.iamClient != stsClient {
		t.Error("STS client not set correctly")
	}
	if checker.simClient != iamClient {
		t.Error("IAM client not set correctly")
	}
}

func TestCheckStatus_Constants(t *testing.T) {
	// Verify status constants have expected values
	if StatusAllowed != "allowed" {
		t.Errorf("unexpected StatusAllowed value: %s", StatusAllowed)
	}
	if StatusDenied != "denied" {
		t.Errorf("unexpected StatusDenied value: %s", StatusDenied)
	}
	if StatusError != "error" {
		t.Errorf("unexpected StatusError value: %s", StatusError)
	}
	if StatusNotChecked != "not_checked" {
		t.Errorf("unexpected StatusNotChecked value: %s", StatusNotChecked)
	}
}

func TestCheckResult_Fields(t *testing.T) {
	result := CheckResult{
		Feature:  FeaturePolicyLoad,
		Action:   "ssm:GetParameter",
		Resource: "arn:aws:ssm:*:*:parameter/sentinel/*",
		Status:   StatusAllowed,
		Message:  "allowed",
	}

	if result.Feature != FeaturePolicyLoad {
		t.Errorf("unexpected Feature: %s", result.Feature)
	}
	if result.Action != "ssm:GetParameter" {
		t.Errorf("unexpected Action: %s", result.Action)
	}
	if result.Resource != "arn:aws:ssm:*:*:parameter/sentinel/*" {
		t.Errorf("unexpected Resource: %s", result.Resource)
	}
	if result.Status != StatusAllowed {
		t.Errorf("unexpected Status: %s", result.Status)
	}
	if result.Message != "allowed" {
		t.Errorf("unexpected Message: %s", result.Message)
	}
}

func TestCheckSummary_Counts(t *testing.T) {
	summary := CheckSummary{
		Results: []CheckResult{
			{Status: StatusAllowed},
			{Status: StatusAllowed},
			{Status: StatusDenied},
			{Status: StatusError},
		},
		PassCount:  2,
		FailCount:  1,
		ErrorCount: 1,
	}

	if summary.PassCount != 2 {
		t.Errorf("expected PassCount 2, got %d", summary.PassCount)
	}
	if summary.FailCount != 1 {
		t.Errorf("expected FailCount 1, got %d", summary.FailCount)
	}
	if summary.ErrorCount != 1 {
		t.Errorf("expected ErrorCount 1, got %d", summary.ErrorCount)
	}
	if len(summary.Results) != 4 {
		t.Errorf("expected 4 results, got %d", len(summary.Results))
	}
}

func TestChecker_Check_FeatureWithNoPermissions(t *testing.T) {
	stsClient := &mockSTSCheckerClient{}
	iamClient := &mockIAMCheckerClient{}

	checker := newCheckerWithClients(stsClient, iamClient)

	// notify_webhook has no AWS permissions
	summary, err := checker.Check(context.Background(), []Feature{FeatureNotifyWebhook})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have no results since feature has no permissions
	if len(summary.Results) != 0 {
		t.Errorf("expected 0 results for feature with no permissions, got %d", len(summary.Results))
	}
}
