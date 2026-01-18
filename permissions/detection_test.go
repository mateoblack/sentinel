package permissions

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// mockSSMDetectorClient implements ssmDetectorAPI for testing.
type mockSSMDetectorClient struct {
	GetParametersByPathFunc func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
}

func (m *mockSSMDetectorClient) GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	if m.GetParametersByPathFunc != nil {
		return m.GetParametersByPathFunc(ctx, params, optFns...)
	}
	return &ssm.GetParametersByPathOutput{}, nil
}

// mockDynamoDetectorClient implements dynamoDetectorAPI for testing.
type mockDynamoDetectorClient struct {
	DescribeTableFunc func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

func (m *mockDynamoDetectorClient) DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if m.DescribeTableFunc != nil {
		return m.DescribeTableFunc(ctx, params, optFns...)
	}
	return &dynamodb.DescribeTableOutput{}, nil
}

func TestDetect_AllResourcesExist(t *testing.T) {
	ssmClient := &mockSSMDetectorClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/production")},
				},
			}, nil
		},
	}

	dynamoClient := &mockDynamoDetectorClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName: params.TableName,
				},
			}, nil
		},
	}

	detector := newDetectorWithClients(ssmClient, dynamoClient)
	result, err := detector.Detect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check expected features are present
	expectedFeatures := []Feature{
		FeatureCredentialIssue,
		FeatureAuditVerify,
		FeatureEnforceAnalyze,
		FeaturePolicyLoad,
		FeatureBootstrapPlan,
		FeatureApprovalWorkflow,
		FeatureBreakGlass,
	}

	for _, expected := range expectedFeatures {
		found := false
		for _, f := range result.Features {
			if f == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected feature %s not found in result", expected)
		}
	}

	// Check feature details are populated
	for _, f := range result.Features {
		if result.FeatureDetails[f] == "" {
			t.Errorf("feature %s has empty detail", f)
		}
	}

	// Should have no errors
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %d", len(result.Errors))
	}
}

func TestDetect_NoResourcesExist(t *testing.T) {
	ssmClient := &mockSSMDetectorClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{}, // Empty - no parameters
			}, nil
		},
	}

	dynamoClient := &mockDynamoDetectorClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			// Return ResourceNotFoundException for all tables
			return nil, &ddbtypes.ResourceNotFoundException{Message: aws.String("Table not found")}
		},
	}

	detector := newDetectorWithClients(ssmClient, dynamoClient)
	result, err := detector.Detect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have always-detected features
	expectedFeatures := []Feature{
		FeatureCredentialIssue,
		FeatureAuditVerify,
		FeatureEnforceAnalyze,
	}

	if len(result.Features) != len(expectedFeatures) {
		t.Errorf("expected %d features, got %d: %v", len(expectedFeatures), len(result.Features), result.Features)
	}

	for _, expected := range expectedFeatures {
		found := false
		for _, f := range result.Features {
			if f == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected feature %s not found in result", expected)
		}
	}

	// Should have no errors (not found is not an error)
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %d: %v", len(result.Errors), result.Errors)
	}
}

func TestDetect_PartialResourcesExist(t *testing.T) {
	ssmClient := &mockSSMDetectorClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/prod")},
				},
			}, nil
		},
	}

	dynamoClient := &mockDynamoDetectorClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			// Only sentinel-requests exists, not sentinel-breakglass
			if aws.ToString(params.TableName) == "sentinel-requests" {
				return &dynamodb.DescribeTableOutput{
					Table: &ddbtypes.TableDescription{
						TableName: params.TableName,
					},
				}, nil
			}
			return nil, &ddbtypes.ResourceNotFoundException{Message: aws.String("Table not found")}
		},
	}

	detector := newDetectorWithClients(ssmClient, dynamoClient)
	result, err := detector.Detect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that approval_workflow is detected but breakglass is not
	hasApproval := false
	hasBreakglass := false
	for _, f := range result.Features {
		if f == FeatureApprovalWorkflow {
			hasApproval = true
		}
		if f == FeatureBreakGlass {
			hasBreakglass = true
		}
	}

	if !hasApproval {
		t.Error("expected approval_workflow to be detected")
	}
	if hasBreakglass {
		t.Error("expected breakglass to NOT be detected")
	}

	// Should have no errors
	if len(result.Errors) != 0 {
		t.Errorf("expected no errors, got %d", len(result.Errors))
	}
}

func TestDetect_APIErrors(t *testing.T) {
	apiError := errors.New("access denied")

	ssmClient := &mockSSMDetectorClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return nil, apiError
		},
	}

	dynamoClient := &mockDynamoDetectorClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, apiError
		},
	}

	detector := newDetectorWithClients(ssmClient, dynamoClient)
	result, err := detector.Detect(context.Background())

	// Should not return fatal error - detection continues
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}

	// Should still have always-detected features
	if len(result.Features) < 3 {
		t.Errorf("expected at least 3 always-detected features, got %d", len(result.Features))
	}

	// Should have errors logged for policy_load, approval_workflow, breakglass
	if len(result.Errors) < 3 {
		t.Errorf("expected at least 3 errors, got %d: %v", len(result.Errors), result.Errors)
	}
}

func TestDetect_AlwaysDetectedFeatures(t *testing.T) {
	// Empty clients - no resources exist
	ssmClient := &mockSSMDetectorClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{Parameters: []types.Parameter{}}, nil
		},
	}

	dynamoClient := &mockDynamoDetectorClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, &ddbtypes.ResourceNotFoundException{Message: aws.String("Table not found")}
		},
	}

	detector := newDetectorWithClients(ssmClient, dynamoClient)
	result, err := detector.Detect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Always detected features should be present with correct details
	alwaysDetected := map[Feature]string{
		FeatureCredentialIssue: "base feature (always required)",
		FeatureAuditVerify:     "CloudTrail available in all AWS accounts",
		FeatureEnforceAnalyze:  "IAM available in all AWS accounts",
	}

	for feature, expectedDetail := range alwaysDetected {
		found := false
		for _, f := range result.Features {
			if f == feature {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("always-detected feature %s not found", feature)
		}
		if result.FeatureDetails[feature] != expectedDetail {
			t.Errorf("feature %s: expected detail %q, got %q", feature, expectedDetail, result.FeatureDetails[feature])
		}
	}
}

func TestCheckSSMPolicyExists_ParameterNotFound(t *testing.T) {
	ssmClient := &mockSSMDetectorClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return nil, &types.ParameterNotFound{Message: aws.String("not found")}
		},
	}

	detector := newDetectorWithClients(ssmClient, nil)
	exists, err := detector.checkSSMPolicyExists(context.Background())

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected exists to be false for ParameterNotFound")
	}
}

func TestCheckSSMPolicyExists_HasParameters(t *testing.T) {
	ssmClient := &mockSSMDetectorClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/test")},
				},
			}, nil
		},
	}

	detector := newDetectorWithClients(ssmClient, nil)
	exists, err := detector.checkSSMPolicyExists(context.Background())

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected exists to be true when parameters found")
	}
}

func TestCheckSSMPolicyExists_EmptyResult(t *testing.T) {
	ssmClient := &mockSSMDetectorClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{},
			}, nil
		},
	}

	detector := newDetectorWithClients(ssmClient, nil)
	exists, err := detector.checkSSMPolicyExists(context.Background())

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected exists to be false for empty result")
	}
}

func TestCheckDynamoTableExists_TableExists(t *testing.T) {
	dynamoClient := &mockDynamoDetectorClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName: params.TableName,
				},
			}, nil
		},
	}

	detector := newDetectorWithClients(nil, dynamoClient)
	exists, err := detector.checkDynamoTableExists(context.Background(), "test-table")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected exists to be true when table found")
	}
}

func TestCheckDynamoTableExists_TableNotFound(t *testing.T) {
	dynamoClient := &mockDynamoDetectorClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, &ddbtypes.ResourceNotFoundException{Message: aws.String("Table not found")}
		},
	}

	detector := newDetectorWithClients(nil, dynamoClient)
	exists, err := detector.checkDynamoTableExists(context.Background(), "nonexistent-table")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected exists to be false for ResourceNotFoundException")
	}
}

func TestCheckDynamoTableExists_OtherError(t *testing.T) {
	accessDenied := errors.New("access denied")

	dynamoClient := &mockDynamoDetectorClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, accessDenied
		},
	}

	detector := newDetectorWithClients(nil, dynamoClient)
	exists, err := detector.checkDynamoTableExists(context.Background(), "test-table")

	if err == nil {
		t.Error("expected error for access denied")
	}
	if exists {
		t.Error("expected exists to be false on error")
	}
}

func TestIsResourceNotFoundError(t *testing.T) {
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
			name:     "ResourceNotFoundException in message",
			err:      errors.New("ResourceNotFoundException: Table does not exist"),
			expected: true,
		},
		{
			name:     "not found in message",
			err:      errors.New("resource not found"),
			expected: true,
		},
		{
			name:     "does not exist in message",
			err:      errors.New("table does not exist"),
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      errors.New("access denied"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isResourceNotFoundError(tt.err)
			if result != tt.expected {
				t.Errorf("isResourceNotFoundError(%v) = %v, expected %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestDetectorInterface(t *testing.T) {
	// Verify Detector implements DetectorInterface
	var _ DetectorInterface = (*Detector)(nil)
}

func TestNewDetectorWithClients(t *testing.T) {
	ssmClient := &mockSSMDetectorClient{}
	dynamoClient := &mockDynamoDetectorClient{}

	detector := newDetectorWithClients(ssmClient, dynamoClient)

	if detector.ssmClient != ssmClient {
		t.Error("SSM client not set correctly")
	}
	if detector.dynamoClient != dynamoClient {
		t.Error("DynamoDB client not set correctly")
	}
}

func TestDetectionResult_FeatureDetailsConsistency(t *testing.T) {
	ssmClient := &mockSSMDetectorClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/test")},
				},
			}, nil
		},
	}

	dynamoClient := &mockDynamoDetectorClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{TableName: params.TableName},
			}, nil
		},
	}

	detector := newDetectorWithClients(ssmClient, dynamoClient)
	result, err := detector.Detect(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Every feature in Features should have a corresponding detail
	for _, f := range result.Features {
		if _, ok := result.FeatureDetails[f]; !ok {
			t.Errorf("feature %s missing from FeatureDetails", f)
		}
	}

	// Every feature in FeatureDetails should be in Features
	for f := range result.FeatureDetails {
		found := false
		for _, rf := range result.Features {
			if rf == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("feature %s in FeatureDetails but not in Features", f)
		}
	}
}
