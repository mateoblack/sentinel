package policy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/testutil"
)

func TestErrPolicyNotFound(t *testing.T) {
	// Test that ErrPolicyNotFound is exported and usable with errors.Is
	wrappedErr := errors.New("wrapped: " + policy.ErrPolicyNotFound.Error())

	// Direct comparison
	if policy.ErrPolicyNotFound == nil {
		t.Error("ErrPolicyNotFound should not be nil")
	}

	// Error message
	expected := "policy not found"
	if policy.ErrPolicyNotFound.Error() != expected {
		t.Errorf("ErrPolicyNotFound.Error() = %q, want %q", policy.ErrPolicyNotFound.Error(), expected)
	}

	// Verify it can be used with fmt.Errorf wrapping
	_ = wrappedErr
}

func TestNewLoader(t *testing.T) {
	// Basic smoke test that NewLoader creates a non-nil Loader
	cfg := aws.Config{
		Region: "us-east-1",
	}

	loader := policy.NewLoader(cfg)
	if loader == nil {
		t.Error("NewLoader should return a non-nil Loader")
	}
}

func TestNewLoaderWithClient(t *testing.T) {
	// Verify NewLoaderWithClient creates a non-nil Loader with mock
	mockClient := &testutil.MockSSMClient{}
	loader := policy.NewLoaderWithClient(mockClient)
	if loader == nil {
		t.Error("NewLoaderWithClient should return a non-nil Loader")
	}
}

func TestLoader_Load_Success(t *testing.T) {
	// Valid policy YAML
	policyYAML := `
version: "1"
rules:
  - effect: allow
    profiles: ["dev"]
    users: ["alice@example.com"]
`
	mockClient := &testutil.MockSSMClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:    params.Name,
					Value:   aws.String(policyYAML),
					Version: 1,
				},
			}, nil
		},
	}

	loader := policy.NewLoaderWithClient(mockClient)
	pol, err := loader.Load(context.Background(), "/sentinel/policies/dev")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if pol == nil {
		t.Fatal("Load() returned nil policy")
	}

	// Verify policy parsed correctly
	if pol.Version != "1" {
		t.Errorf("Policy version = %q, want %q", pol.Version, "1")
	}

	if len(pol.Rules) != 1 {
		t.Fatalf("Policy rules count = %d, want 1", len(pol.Rules))
	}

	// Verify GetParameter was called with correct input
	if len(mockClient.GetParameterCalls) != 1 {
		t.Fatalf("GetParameter call count = %d, want 1", len(mockClient.GetParameterCalls))
	}

	call := mockClient.GetParameterCalls[0]
	if aws.ToString(call.Name) != "/sentinel/policies/dev" {
		t.Errorf("GetParameter Name = %q, want %q", aws.ToString(call.Name), "/sentinel/policies/dev")
	}

	if !aws.ToBool(call.WithDecryption) {
		t.Error("GetParameter WithDecryption should be true")
	}
}

func TestLoader_Load_ParameterNotFound(t *testing.T) {
	mockClient := &testutil.MockSSMClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return nil, &types.ParameterNotFound{
				Message: aws.String("Parameter not found"),
			}
		},
	}

	loader := policy.NewLoaderWithClient(mockClient)
	_, err := loader.Load(context.Background(), "/sentinel/policies/missing")

	if err == nil {
		t.Fatal("Load() should return error for missing parameter")
	}

	// Verify error wraps ErrPolicyNotFound
	if !errors.Is(err, policy.ErrPolicyNotFound) {
		t.Errorf("Load() error should wrap ErrPolicyNotFound, got: %v", err)
	}

	// Verify error message includes parameter name
	if !strings.Contains(err.Error(), "/sentinel/policies/missing") {
		t.Errorf("Load() error should include parameter name, got: %v", err)
	}
}

func TestLoader_Load_GenericSSMError(t *testing.T) {
	genericErr := errors.New("network timeout")
	mockClient := &testutil.MockSSMClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return nil, genericErr
		},
	}

	loader := policy.NewLoaderWithClient(mockClient)
	_, err := loader.Load(context.Background(), "/sentinel/policies/dev")

	if err == nil {
		t.Fatal("Load() should return error for SSM failure")
	}

	// Verify error message includes SSM error context
	if !strings.Contains(err.Error(), "SSM error") && !strings.Contains(err.Error(), "ssm GetParameter") {
		t.Errorf("Load() error should include SSM context, got: %v", err)
	}

	// Verify original error is accessible via errors.Unwrap
	unwrapped := errors.Unwrap(err)
	if unwrapped == nil {
		t.Error("Load() error should be unwrappable")
	}

	if !errors.Is(err, genericErr) {
		t.Errorf("Load() error should wrap original error, got: %v", err)
	}
}

func TestLoader_Load_InvalidYAML(t *testing.T) {
	// Invalid YAML content
	invalidYAML := `
version: "1"
rules:
  - effect: [invalid yaml structure
`
	mockClient := &testutil.MockSSMClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:    params.Name,
					Value:   aws.String(invalidYAML),
					Version: 1,
				},
			}, nil
		},
	}

	loader := policy.NewLoaderWithClient(mockClient)
	_, err := loader.Load(context.Background(), "/sentinel/policies/dev")

	if err == nil {
		t.Fatal("Load() should return error for invalid YAML")
	}

	// Verify it's a parse error (not ErrPolicyNotFound)
	if errors.Is(err, policy.ErrPolicyNotFound) {
		t.Error("Load() error should not be ErrPolicyNotFound for invalid YAML")
	}
}
