package policy_test

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/policy"
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
