package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
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
