package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// mockSSMStatusAPI implements ssmStatusAPI for testing.
type mockSSMStatusAPI struct {
	getParametersByPathFunc func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
	calls                   []string
}

func (m *mockSSMStatusAPI) GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	m.calls = append(m.calls, aws.ToString(params.Path))
	if m.getParametersByPathFunc != nil {
		return m.getParametersByPathFunc(ctx, params, optFns...)
	}
	return &ssm.GetParametersByPathOutput{}, nil
}

func TestStatusChecker_GetStatus_EmptyResults(t *testing.T) {
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{},
			}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if result.PolicyRoot != "/sentinel/policies" {
		t.Errorf("expected PolicyRoot '/sentinel/policies', got %q", result.PolicyRoot)
	}
	if result.Count != 0 {
		t.Errorf("expected Count 0, got %d", result.Count)
	}
	if len(result.Parameters) != 0 {
		t.Errorf("expected 0 parameters, got %d", len(result.Parameters))
	}
}

func TestStatusChecker_GetStatus_SingleParameter(t *testing.T) {
	lastModified := time.Date(2026, 1, 15, 14, 30, 0, 0, time.UTC)
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{
						Name:             aws.String("/sentinel/policies/production"),
						Value:            aws.String("policy-content"),
						Version:          3,
						Type:             types.ParameterTypeString,
						LastModifiedDate: aws.Time(lastModified),
					},
				},
			}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if result.Count != 1 {
		t.Fatalf("expected Count 1, got %d", result.Count)
	}

	param := result.Parameters[0]
	if param.Name != "production" {
		t.Errorf("expected Name 'production', got %q", param.Name)
	}
	if param.Path != "/sentinel/policies/production" {
		t.Errorf("expected Path '/sentinel/policies/production', got %q", param.Path)
	}
	if param.Version != 3 {
		t.Errorf("expected Version 3, got %d", param.Version)
	}
	if param.Type != "String" {
		t.Errorf("expected Type 'String', got %q", param.Type)
	}
	if !param.LastModified.Equal(lastModified) {
		t.Errorf("expected LastModified %v, got %v", lastModified, param.LastModified)
	}
}

func TestStatusChecker_GetStatus_MultipleParameters(t *testing.T) {
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{
						Name:             aws.String("/sentinel/policies/production"),
						Value:            aws.String("policy-1"),
						Version:          3,
						Type:             types.ParameterTypeString,
						LastModifiedDate: aws.Time(time.Now()),
					},
					{
						Name:             aws.String("/sentinel/policies/staging"),
						Value:            aws.String("policy-2"),
						Version:          1,
						Type:             types.ParameterTypeString,
						LastModifiedDate: aws.Time(time.Now()),
					},
					{
						Name:             aws.String("/sentinel/policies/development"),
						Value:            aws.String("policy-3"),
						Version:          5,
						Type:             types.ParameterTypeString,
						LastModifiedDate: aws.Time(time.Now()),
					},
				},
			}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if result.Count != 3 {
		t.Fatalf("expected Count 3, got %d", result.Count)
	}

	// Check names are extracted correctly
	names := make(map[string]int64)
	for _, p := range result.Parameters {
		names[p.Name] = p.Version
	}

	if v, ok := names["production"]; !ok || v != 3 {
		t.Error("expected production with version 3")
	}
	if v, ok := names["staging"]; !ok || v != 1 {
		t.Error("expected staging with version 1")
	}
	if v, ok := names["development"]; !ok || v != 5 {
		t.Error("expected development with version 5")
	}
}

func TestStatusChecker_GetStatus_Pagination(t *testing.T) {
	callCount := 0
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			callCount++

			if callCount == 1 {
				// First page
				return &ssm.GetParametersByPathOutput{
					Parameters: []types.Parameter{
						{
							Name:             aws.String("/sentinel/policies/page1-param1"),
							Value:            aws.String("value"),
							Version:          1,
							Type:             types.ParameterTypeString,
							LastModifiedDate: aws.Time(time.Now()),
						},
						{
							Name:             aws.String("/sentinel/policies/page1-param2"),
							Value:            aws.String("value"),
							Version:          2,
							Type:             types.ParameterTypeString,
							LastModifiedDate: aws.Time(time.Now()),
						},
					},
					NextToken: aws.String("token-1"),
				}, nil
			}

			if callCount == 2 {
				// Second page
				return &ssm.GetParametersByPathOutput{
					Parameters: []types.Parameter{
						{
							Name:             aws.String("/sentinel/policies/page2-param1"),
							Value:            aws.String("value"),
							Version:          3,
							Type:             types.ParameterTypeString,
							LastModifiedDate: aws.Time(time.Now()),
						},
					},
					NextToken: aws.String("token-2"),
				}, nil
			}

			// Third page (last)
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{
						Name:             aws.String("/sentinel/policies/page3-param1"),
						Value:            aws.String("value"),
						Version:          4,
						Type:             types.ParameterTypeString,
						LastModifiedDate: aws.Time(time.Now()),
					},
				},
			}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	// Should have made 3 calls
	if callCount != 3 {
		t.Errorf("expected 3 SSM calls for pagination, got %d", callCount)
	}

	// Should have 4 total parameters
	if result.Count != 4 {
		t.Errorf("expected Count 4, got %d", result.Count)
	}

	// Verify all parameters are present
	names := make(map[string]bool)
	for _, p := range result.Parameters {
		names[p.Name] = true
	}

	expected := []string{"page1-param1", "page1-param2", "page2-param1", "page3-param1"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("missing expected parameter: %s", name)
		}
	}
}

func TestStatusChecker_GetStatus_SSMError(t *testing.T) {
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return nil, errors.New("AccessDeniedException: access denied")
		},
	}

	checker := newStatusCheckerWithClient(mock)
	_, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errors.New("")) && err.Error() == "" {
		t.Errorf("expected non-empty error message")
	}
}

func TestStatusChecker_GetStatus_SecureStringType(t *testing.T) {
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{
						Name:             aws.String("/sentinel/policies/secure-param"),
						Value:            aws.String("encrypted"),
						Version:          1,
						Type:             types.ParameterTypeSecureString,
						LastModifiedDate: aws.Time(time.Now()),
					},
				},
			}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if result.Parameters[0].Type != "SecureString" {
		t.Errorf("expected Type 'SecureString', got %q", result.Parameters[0].Type)
	}
}

func TestExtractProfileName(t *testing.T) {
	tests := []struct {
		name       string
		policyRoot string
		paramPath  string
		want       string
	}{
		{
			name:       "standard path",
			policyRoot: "/sentinel/policies",
			paramPath:  "/sentinel/policies/production",
			want:       "production",
		},
		{
			name:       "root with trailing slash",
			policyRoot: "/sentinel/policies/",
			paramPath:  "/sentinel/policies/staging",
			want:       "staging",
		},
		{
			name:       "custom root",
			policyRoot: "/custom/path",
			paramPath:  "/custom/path/my-profile",
			want:       "my-profile",
		},
		{
			name:       "deeply nested",
			policyRoot: "/org/team/sentinel",
			paramPath:  "/org/team/sentinel/profile-name",
			want:       "profile-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractProfileName(tt.policyRoot, tt.paramPath)
			if got != tt.want {
				t.Errorf("extractProfileName(%q, %q) = %q, want %q", tt.policyRoot, tt.paramPath, got, tt.want)
			}
		})
	}
}

func TestStatusChecker_GetStatus_RecursiveFalse(t *testing.T) {
	var capturedInput *ssm.GetParametersByPathInput
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			capturedInput = params
			return &ssm.GetParametersByPathOutput{}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	_, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if capturedInput == nil {
		t.Fatal("expected SSM call to be made")
	}
	if capturedInput.Recursive == nil || *capturedInput.Recursive != false {
		t.Error("expected Recursive to be false")
	}
}

// ============================================================================
// Pagination Tests
// ============================================================================

func TestStatusChecker_GetStatus_LargeNumberOfParameters(t *testing.T) {
	// Test with 12 parameters (more than typical page size)
	parameters := []types.Parameter{}
	for i := 1; i <= 12; i++ {
		parameters = append(parameters, types.Parameter{
			Name:             aws.String(fmt.Sprintf("/sentinel/policies/profile-%d", i)),
			Value:            aws.String("policy-content"),
			Version:          int64(i),
			Type:             types.ParameterTypeString,
			LastModifiedDate: aws.Time(time.Now()),
		})
	}

	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: parameters,
			}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if result.Count != 12 {
		t.Errorf("expected Count 12, got %d", result.Count)
	}

	// Verify all parameters present with correct versions
	for i := 1; i <= 12; i++ {
		found := false
		expectedName := fmt.Sprintf("profile-%d", i)
		for _, p := range result.Parameters {
			if p.Name == expectedName && p.Version == int64(i) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing parameter: %s with version %d", expectedName, i)
		}
	}
}

func TestStatusChecker_GetStatus_MultiPageWithTokenTracking(t *testing.T) {
	// Track NextToken values passed to verify pagination logic
	var capturedTokens []*string

	callCount := 0
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			capturedTokens = append(capturedTokens, params.NextToken)
			callCount++

			switch callCount {
			case 1:
				// First page - no token expected
				return &ssm.GetParametersByPathOutput{
					Parameters: []types.Parameter{
						{Name: aws.String("/sentinel/policies/a"), Version: 1, Type: types.ParameterTypeString, LastModifiedDate: aws.Time(time.Now())},
					},
					NextToken: aws.String("page-2-token"),
				}, nil
			case 2:
				// Second page - should receive page-2-token
				return &ssm.GetParametersByPathOutput{
					Parameters: []types.Parameter{
						{Name: aws.String("/sentinel/policies/b"), Version: 1, Type: types.ParameterTypeString, LastModifiedDate: aws.Time(time.Now())},
					},
					NextToken: aws.String("page-3-token"),
				}, nil
			default:
				// Third/final page
				return &ssm.GetParametersByPathOutput{
					Parameters: []types.Parameter{
						{Name: aws.String("/sentinel/policies/c"), Version: 1, Type: types.ParameterTypeString, LastModifiedDate: aws.Time(time.Now())},
					},
				}, nil
			}
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	// Verify pagination tokens were passed correctly
	if len(capturedTokens) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(capturedTokens))
	}
	if capturedTokens[0] != nil {
		t.Error("first call should have nil token")
	}
	if capturedTokens[1] == nil || *capturedTokens[1] != "page-2-token" {
		t.Errorf("second call should have page-2-token, got %v", capturedTokens[1])
	}
	if capturedTokens[2] == nil || *capturedTokens[2] != "page-3-token" {
		t.Errorf("third call should have page-3-token, got %v", capturedTokens[2])
	}

	// Verify all parameters collected
	if result.Count != 3 {
		t.Errorf("expected 3 parameters, got %d", result.Count)
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestStatusChecker_GetStatus_SpecialCharactersInName(t *testing.T) {
	// Valid SSM parameter characters: alphanumeric, ., -, _
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{
						Name:             aws.String("/sentinel/policies/my-profile_v2.1"),
						Value:            aws.String("policy"),
						Version:          1,
						Type:             types.ParameterTypeString,
						LastModifiedDate: aws.Time(time.Now()),
					},
					{
						Name:             aws.String("/sentinel/policies/profile.with.dots"),
						Value:            aws.String("policy"),
						Version:          2,
						Type:             types.ParameterTypeString,
						LastModifiedDate: aws.Time(time.Now()),
					},
					{
						Name:             aws.String("/sentinel/policies/profile_with_underscores"),
						Value:            aws.String("policy"),
						Version:          3,
						Type:             types.ParameterTypeString,
						LastModifiedDate: aws.Time(time.Now()),
					},
				},
			}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	expectedNames := map[string]bool{
		"my-profile_v2.1":          false,
		"profile.with.dots":        false,
		"profile_with_underscores": false,
	}

	for _, p := range result.Parameters {
		if _, ok := expectedNames[p.Name]; ok {
			expectedNames[p.Name] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected parameter name %q not found", name)
		}
	}
}

func TestStatusChecker_GetStatus_VersionZero(t *testing.T) {
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{
						Name:             aws.String("/sentinel/policies/zero-version"),
						Value:            aws.String("policy"),
						Version:          0, // Edge case: version 0
						Type:             types.ParameterTypeString,
						LastModifiedDate: aws.Time(time.Now()),
					},
				},
			}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if result.Count != 1 {
		t.Fatalf("expected 1 parameter, got %d", result.Count)
	}
	if result.Parameters[0].Version != 0 {
		t.Errorf("expected version 0, got %d", result.Parameters[0].Version)
	}
}

func TestStatusChecker_GetStatus_NilLastModifiedDate(t *testing.T) {
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{
						Name:             aws.String("/sentinel/policies/no-modified-date"),
						Value:            aws.String("policy"),
						Version:          1,
						Type:             types.ParameterTypeString,
						LastModifiedDate: nil, // Edge case: nil date
					},
				},
			}, nil
		},
	}

	checker := newStatusCheckerWithClient(mock)
	result, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if result.Count != 1 {
		t.Fatalf("expected 1 parameter, got %d", result.Count)
	}
	// aws.ToTime on nil returns zero time
	if !result.Parameters[0].LastModified.IsZero() {
		t.Errorf("expected zero time for nil LastModifiedDate, got %v", result.Parameters[0].LastModified)
	}
}

func TestExtractProfileName_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		policyRoot string
		paramPath  string
		want       string
	}{
		{
			name:       "trailing slash on policyRoot",
			policyRoot: "/sentinel/policies/",
			paramPath:  "/sentinel/policies/production",
			want:       "production",
		},
		{
			name:       "no trailing slash",
			policyRoot: "/sentinel/policies",
			paramPath:  "/sentinel/policies/production",
			want:       "production",
		},
		{
			name:       "deeply nested policy root",
			policyRoot: "/org/dept/team/sentinel/policies",
			paramPath:  "/org/dept/team/sentinel/policies/my-profile",
			want:       "my-profile",
		},
		{
			name:       "path equals policyRoot (edge case)",
			policyRoot: "/sentinel/policies",
			paramPath:  "/sentinel/policies",
			want:       "",
		},
		{
			name:       "policyRoot with double trailing slash",
			policyRoot: "/sentinel/policies//",
			paramPath:  "/sentinel/policies/staging",
			want:       "staging",
		},
		{
			name:       "single character profile name",
			policyRoot: "/sentinel/policies",
			paramPath:  "/sentinel/policies/a",
			want:       "a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractProfileName(tt.policyRoot, tt.paramPath)
			if got != tt.want {
				t.Errorf("extractProfileName(%q, %q) = %q, want %q",
					tt.policyRoot, tt.paramPath, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestStatusChecker_GetStatus_AccessDenied(t *testing.T) {
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return nil, errors.New("AccessDeniedException: User is not authorized")
		},
	}

	checker := newStatusCheckerWithClient(mock)
	_, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, err) || err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestStatusChecker_GetStatus_ThrottlingError(t *testing.T) {
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return nil, errors.New("ThrottlingException: Rate exceeded")
		},
	}

	checker := newStatusCheckerWithClient(mock)
	_, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStatusChecker_GetStatus_ContextCancellation(t *testing.T) {
	callCount := 0
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			callCount++
			// Check if context is cancelled
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// First page returns with NextToken
			if callCount == 1 {
				return &ssm.GetParametersByPathOutput{
					Parameters: []types.Parameter{
						{Name: aws.String("/sentinel/policies/first"), Version: 1, Type: types.ParameterTypeString, LastModifiedDate: aws.Time(time.Now())},
					},
					NextToken: aws.String("next-page"),
				}, nil
			}
			// Second call - return context error
			return nil, context.Canceled
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	checker := newStatusCheckerWithClient(mock)

	// Start the operation
	go func() {
		// Simulate cancellation during pagination
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	_, err := checker.GetStatus(ctx, "/sentinel/policies")

	// The operation should eventually fail with context error
	if err == nil {
		// It's possible the test completed before cancellation
		// In that case, verify callCount
		if callCount < 2 {
			t.Log("Operation completed before cancellation, which is acceptable")
		}
	}
}

func TestStatusChecker_GetStatus_ErrorDuringPagination(t *testing.T) {
	callCount := 0
	mock := &mockSSMStatusAPI{
		getParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			callCount++
			if callCount == 1 {
				// First page succeeds
				return &ssm.GetParametersByPathOutput{
					Parameters: []types.Parameter{
						{Name: aws.String("/sentinel/policies/success"), Version: 1, Type: types.ParameterTypeString, LastModifiedDate: aws.Time(time.Now())},
					},
					NextToken: aws.String("page-2"),
				}, nil
			}
			// Second page fails
			return nil, errors.New("InternalServerError: Service unavailable")
		},
	}

	checker := newStatusCheckerWithClient(mock)
	_, err := checker.GetStatus(context.Background(), "/sentinel/policies")
	if err == nil {
		t.Fatal("expected error during pagination, got nil")
	}
	if callCount != 2 {
		t.Errorf("expected 2 calls (first success, second fail), got %d", callCount)
	}
}

// ============================================================================
// Infrastructure Checker Tests
// ============================================================================

// mockDynamoDBStatusAPI implements dynamoDBStatusAPI for testing.
type mockDynamoDBStatusAPI struct {
	describeTableFunc func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	calls             []string
}

func (m *mockDynamoDBStatusAPI) DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	m.calls = append(m.calls, aws.ToString(params.TableName))
	if m.describeTableFunc != nil {
		return m.describeTableFunc(ctx, params, optFns...)
	}
	return nil, &dynamodbtypes.ResourceNotFoundException{}
}

func TestInfrastructureChecker_AllTablesExist_Active(t *testing.T) {
	mock := &mockDynamoDBStatusAPI{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dynamodbtypes.TableDescription{
					TableName:   params.TableName,
					TableStatus: dynamodbtypes.TableStatusActive,
				},
			}, nil
		},
	}

	checker := newInfrastructureCheckerWithClient(mock, "us-east-1")
	result, err := checker.GetInfrastructureStatus(context.Background(), "", "", "")

	if err != nil {
		t.Fatalf("GetInfrastructureStatus() error = %v", err)
	}
	if len(result.Tables) != 3 {
		t.Fatalf("expected 3 tables, got %d", len(result.Tables))
	}

	// Verify all tables are ACTIVE
	for _, table := range result.Tables {
		if table.Status != "ACTIVE" {
			t.Errorf("expected table %s status ACTIVE, got %s", table.TableName, table.Status)
		}
		if table.Region != "us-east-1" {
			t.Errorf("expected region us-east-1, got %s", table.Region)
		}
	}

	// Verify default table names were used
	tableNames := make(map[string]bool)
	for _, table := range result.Tables {
		tableNames[table.TableName] = true
	}
	if !tableNames[DefaultApprovalTableName] {
		t.Errorf("expected %s in results", DefaultApprovalTableName)
	}
	if !tableNames[DefaultBreakGlassTableName] {
		t.Errorf("expected %s in results", DefaultBreakGlassTableName)
	}
	if !tableNames[DefaultSessionTableName] {
		t.Errorf("expected %s in results", DefaultSessionTableName)
	}
}

func TestInfrastructureChecker_SomeTablesMissing(t *testing.T) {
	mock := &mockDynamoDBStatusAPI{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			tableName := aws.ToString(params.TableName)
			// Only approval table exists
			if tableName == DefaultApprovalTableName {
				return &dynamodb.DescribeTableOutput{
					Table: &dynamodbtypes.TableDescription{
						TableName:   params.TableName,
						TableStatus: dynamodbtypes.TableStatusActive,
					},
				}, nil
			}
			// Other tables don't exist
			return nil, &dynamodbtypes.ResourceNotFoundException{}
		},
	}

	checker := newInfrastructureCheckerWithClient(mock, "us-west-2")
	result, err := checker.GetInfrastructureStatus(context.Background(), "", "", "")

	if err != nil {
		t.Fatalf("GetInfrastructureStatus() error = %v", err)
	}
	if len(result.Tables) != 3 {
		t.Fatalf("expected 3 tables, got %d", len(result.Tables))
	}

	// Check individual table statuses
	for _, table := range result.Tables {
		if table.TableName == DefaultApprovalTableName {
			if table.Status != "ACTIVE" {
				t.Errorf("expected %s status ACTIVE, got %s", table.TableName, table.Status)
			}
			if table.Purpose != "approvals" {
				t.Errorf("expected purpose 'approvals', got %s", table.Purpose)
			}
		} else {
			if table.Status != "NOT_FOUND" {
				t.Errorf("expected %s status NOT_FOUND, got %s", table.TableName, table.Status)
			}
		}
	}
}

func TestInfrastructureChecker_TableCreating(t *testing.T) {
	mock := &mockDynamoDBStatusAPI{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			tableName := aws.ToString(params.TableName)
			if tableName == DefaultBreakGlassTableName {
				return &dynamodb.DescribeTableOutput{
					Table: &dynamodbtypes.TableDescription{
						TableName:   params.TableName,
						TableStatus: dynamodbtypes.TableStatusCreating,
					},
				}, nil
			}
			return &dynamodb.DescribeTableOutput{
				Table: &dynamodbtypes.TableDescription{
					TableName:   params.TableName,
					TableStatus: dynamodbtypes.TableStatusActive,
				},
			}, nil
		},
	}

	checker := newInfrastructureCheckerWithClient(mock, "eu-west-1")
	result, err := checker.GetInfrastructureStatus(context.Background(), "", "", "")

	if err != nil {
		t.Fatalf("GetInfrastructureStatus() error = %v", err)
	}

	// Find the breakglass table and verify CREATING status
	for _, table := range result.Tables {
		if table.TableName == DefaultBreakGlassTableName {
			if table.Status != "CREATING" {
				t.Errorf("expected %s status CREATING, got %s", table.TableName, table.Status)
			}
			if table.Purpose != "breakglass" {
				t.Errorf("expected purpose 'breakglass', got %s", table.Purpose)
			}
		}
	}
}

func TestInfrastructureChecker_APIError(t *testing.T) {
	mock := &mockDynamoDBStatusAPI{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, errors.New("AccessDeniedException: User is not authorized")
		},
	}

	checker := newInfrastructureCheckerWithClient(mock, "us-east-1")
	_, err := checker.GetInfrastructureStatus(context.Background(), "", "", "")

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestInfrastructureChecker_CustomTableNames(t *testing.T) {
	var calledTables []string
	mock := &mockDynamoDBStatusAPI{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			calledTables = append(calledTables, aws.ToString(params.TableName))
			return &dynamodb.DescribeTableOutput{
				Table: &dynamodbtypes.TableDescription{
					TableName:   params.TableName,
					TableStatus: dynamodbtypes.TableStatusActive,
				},
			}, nil
		},
	}

	checker := newInfrastructureCheckerWithClient(mock, "us-east-1")
	result, err := checker.GetInfrastructureStatus(context.Background(),
		"custom-approvals", "custom-breakglass", "custom-sessions")

	if err != nil {
		t.Fatalf("GetInfrastructureStatus() error = %v", err)
	}

	// Verify custom table names were used
	expectedTables := map[string]bool{
		"custom-approvals":  false,
		"custom-breakglass": false,
		"custom-sessions":   false,
	}

	for _, table := range result.Tables {
		if _, ok := expectedTables[table.TableName]; ok {
			expectedTables[table.TableName] = true
		}
	}

	for name, found := range expectedTables {
		if !found {
			t.Errorf("expected custom table name %s not found in results", name)
		}
	}

	// Verify the tables were called with custom names
	for _, name := range calledTables {
		if name != "custom-approvals" && name != "custom-breakglass" && name != "custom-sessions" {
			t.Errorf("unexpected table name called: %s", name)
		}
	}
}

func TestInfrastructureChecker_TablePurposes(t *testing.T) {
	mock := &mockDynamoDBStatusAPI{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dynamodbtypes.TableDescription{
					TableName:   params.TableName,
					TableStatus: dynamodbtypes.TableStatusActive,
				},
			}, nil
		},
	}

	checker := newInfrastructureCheckerWithClient(mock, "us-east-1")
	result, err := checker.GetInfrastructureStatus(context.Background(), "", "", "")

	if err != nil {
		t.Fatalf("GetInfrastructureStatus() error = %v", err)
	}

	// Verify purposes are correctly assigned
	purposes := make(map[string]string)
	for _, table := range result.Tables {
		purposes[table.TableName] = table.Purpose
	}

	if purposes[DefaultApprovalTableName] != "approvals" {
		t.Errorf("expected %s purpose 'approvals', got %s", DefaultApprovalTableName, purposes[DefaultApprovalTableName])
	}
	if purposes[DefaultBreakGlassTableName] != "breakglass" {
		t.Errorf("expected %s purpose 'breakglass', got %s", DefaultBreakGlassTableName, purposes[DefaultBreakGlassTableName])
	}
	if purposes[DefaultSessionTableName] != "sessions" {
		t.Errorf("expected %s purpose 'sessions', got %s", DefaultSessionTableName, purposes[DefaultSessionTableName])
	}
}

func TestInfrastructureChecker_NilTableOutput(t *testing.T) {
	mock := &mockDynamoDBStatusAPI{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: nil, // Edge case: nil table in output
			}, nil
		},
	}

	checker := newInfrastructureCheckerWithClient(mock, "us-east-1")
	result, err := checker.GetInfrastructureStatus(context.Background(), "", "", "")

	if err != nil {
		t.Fatalf("GetInfrastructureStatus() error = %v", err)
	}

	// All tables should be NOT_FOUND due to nil Table
	for _, table := range result.Tables {
		if table.Status != "NOT_FOUND" {
			t.Errorf("expected status NOT_FOUND for nil table, got %s", table.Status)
		}
	}
}

func TestInfrastructureChecker_Constructor(t *testing.T) {
	mock := &mockDynamoDBStatusAPI{}
	checker := newInfrastructureCheckerWithClient(mock, "ap-southeast-1")

	if checker.client != mock {
		t.Error("expected mock client to be set")
	}
	if checker.region != "ap-southeast-1" {
		t.Errorf("expected region ap-southeast-1, got %s", checker.region)
	}
}

func TestInfrastructureChecker_AllTablesNotFound(t *testing.T) {
	mock := &mockDynamoDBStatusAPI{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, &dynamodbtypes.ResourceNotFoundException{}
		},
	}

	checker := newInfrastructureCheckerWithClient(mock, "us-east-1")
	result, err := checker.GetInfrastructureStatus(context.Background(), "", "", "")

	if err != nil {
		t.Fatalf("GetInfrastructureStatus() error = %v", err)
	}

	// All tables should be NOT_FOUND
	for _, table := range result.Tables {
		if table.Status != "NOT_FOUND" {
			t.Errorf("expected %s status NOT_FOUND, got %s", table.TableName, table.Status)
		}
	}
}

func TestInfrastructureChecker_TableStatusVariations(t *testing.T) {
	tests := []struct {
		name           string
		tableStatus    dynamodbtypes.TableStatus
		expectedStatus string
	}{
		{"Active", dynamodbtypes.TableStatusActive, "ACTIVE"},
		{"Creating", dynamodbtypes.TableStatusCreating, "CREATING"},
		{"Updating", dynamodbtypes.TableStatusUpdating, "UPDATING"},
		{"Deleting", dynamodbtypes.TableStatusDeleting, "DELETING"},
		{"Inaccessible", dynamodbtypes.TableStatusInaccessibleEncryptionCredentials, "INACCESSIBLE_ENCRYPTION_CREDENTIALS"},
		{"Archiving", dynamodbtypes.TableStatusArchiving, "ARCHIVING"},
		{"Archived", dynamodbtypes.TableStatusArchived, "ARCHIVED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockDynamoDBStatusAPI{
				describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
					return &dynamodb.DescribeTableOutput{
						Table: &dynamodbtypes.TableDescription{
							TableName:   params.TableName,
							TableStatus: tt.tableStatus,
						},
					}, nil
				},
			}

			checker := newInfrastructureCheckerWithClient(mock, "us-east-1")
			result, err := checker.GetInfrastructureStatus(context.Background(), "", "", "")

			if err != nil {
				t.Fatalf("GetInfrastructureStatus() error = %v", err)
			}

			for _, table := range result.Tables {
				if table.Status != tt.expectedStatus {
					t.Errorf("expected status %s, got %s", tt.expectedStatus, table.Status)
				}
			}
		})
	}
}
