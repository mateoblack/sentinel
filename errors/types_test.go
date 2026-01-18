package errors

import (
	"errors"
	"testing"
)

func TestSentinelErrorInterface(t *testing.T) {
	// Verify sentinelError implements SentinelError
	var _ SentinelError = &sentinelError{}
}

func TestSentinelError_Error(t *testing.T) {
	err := &sentinelError{
		code:       ErrCodeSSMAccessDenied,
		message:    "access denied to parameter",
		suggestion: "add ssm:GetParameter permission",
		context:    map[string]string{"parameter": "/sentinel/test"},
		cause:      errors.New("underlying error"),
	}

	if got := err.Error(); got != "access denied to parameter" {
		t.Errorf("Error() = %q, want %q", got, "access denied to parameter")
	}
}

func TestSentinelError_Unwrap(t *testing.T) {
	cause := errors.New("original error")
	err := &sentinelError{
		code:       ErrCodeSSMAccessDenied,
		message:    "access denied",
		suggestion: "fix permission",
		cause:      cause,
	}

	if got := err.Unwrap(); got != cause {
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}
}

func TestSentinelError_Unwrap_Nil(t *testing.T) {
	err := &sentinelError{
		code:    ErrCodeSSMAccessDenied,
		message: "access denied",
		cause:   nil,
	}

	if got := err.Unwrap(); got != nil {
		t.Errorf("Unwrap() = %v, want nil", got)
	}
}

func TestSentinelError_Code(t *testing.T) {
	err := &sentinelError{
		code:    ErrCodeDynamoDBTableNotFound,
		message: "table not found",
	}

	if got := err.Code(); got != ErrCodeDynamoDBTableNotFound {
		t.Errorf("Code() = %q, want %q", got, ErrCodeDynamoDBTableNotFound)
	}
}

func TestSentinelError_Suggestion(t *testing.T) {
	suggestion := "run: sentinel init bootstrap"
	err := &sentinelError{
		code:       ErrCodeSSMParameterNotFound,
		message:    "parameter not found",
		suggestion: suggestion,
	}

	if got := err.Suggestion(); got != suggestion {
		t.Errorf("Suggestion() = %q, want %q", got, suggestion)
	}
}

func TestSentinelError_Context(t *testing.T) {
	ctx := map[string]string{
		"parameter": "/sentinel/policies/default",
		"operation": "GetParameter",
	}
	err := &sentinelError{
		code:    ErrCodeSSMAccessDenied,
		message: "access denied",
		context: ctx,
	}

	got := err.Context()
	if len(got) != 2 {
		t.Errorf("Context() has %d entries, want 2", len(got))
	}
	if got["parameter"] != "/sentinel/policies/default" {
		t.Errorf("Context()[\"parameter\"] = %q, want %q", got["parameter"], "/sentinel/policies/default")
	}
	if got["operation"] != "GetParameter" {
		t.Errorf("Context()[\"operation\"] = %q, want %q", got["operation"], "GetParameter")
	}
}

func TestNew(t *testing.T) {
	cause := errors.New("original")
	err := New(ErrCodeSSMAccessDenied, "access denied", "add permission", cause)

	if err.Code() != ErrCodeSSMAccessDenied {
		t.Errorf("Code() = %q, want %q", err.Code(), ErrCodeSSMAccessDenied)
	}
	if err.Error() != "access denied" {
		t.Errorf("Error() = %q, want %q", err.Error(), "access denied")
	}
	if err.Suggestion() != "add permission" {
		t.Errorf("Suggestion() = %q, want %q", err.Suggestion(), "add permission")
	}
	if err.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
	}
	if err.Context() == nil {
		t.Error("Context() is nil, want initialized map")
	}
}

func TestNew_NilCause(t *testing.T) {
	err := New(ErrCodePolicyDenied, "policy denied", "check policy", nil)

	if err.Unwrap() != nil {
		t.Errorf("Unwrap() = %v, want nil", err.Unwrap())
	}
}

func TestWithContext(t *testing.T) {
	original := New(ErrCodeSSMAccessDenied, "access denied", "add permission", nil)
	withCtx := WithContext(original, "parameter", "/sentinel/test")

	// Check new error has context
	ctx := withCtx.Context()
	if ctx["parameter"] != "/sentinel/test" {
		t.Errorf("Context()[\"parameter\"] = %q, want %q", ctx["parameter"], "/sentinel/test")
	}

	// Verify original is not mutated
	if len(original.Context()) != 0 {
		t.Errorf("Original Context() has %d entries, want 0", len(original.Context()))
	}
}

func TestWithContext_PreservesExisting(t *testing.T) {
	// Create error with initial context
	original := New(ErrCodeSSMAccessDenied, "access denied", "add permission", nil)
	withFirst := WithContext(original, "key1", "value1")
	withSecond := WithContext(withFirst, "key2", "value2")

	ctx := withSecond.Context()
	if len(ctx) != 2 {
		t.Errorf("Context() has %d entries, want 2", len(ctx))
	}
	if ctx["key1"] != "value1" {
		t.Errorf("Context()[\"key1\"] = %q, want %q", ctx["key1"], "value1")
	}
	if ctx["key2"] != "value2" {
		t.Errorf("Context()[\"key2\"] = %q, want %q", ctx["key2"], "value2")
	}
}

func TestWithContext_PreservesOtherFields(t *testing.T) {
	cause := errors.New("cause")
	original := New(ErrCodeSSMAccessDenied, "access denied", "add permission", cause)
	withCtx := WithContext(original, "key", "value")

	if withCtx.Code() != ErrCodeSSMAccessDenied {
		t.Errorf("Code() = %q, want %q", withCtx.Code(), ErrCodeSSMAccessDenied)
	}
	if withCtx.Error() != "access denied" {
		t.Errorf("Error() = %q, want %q", withCtx.Error(), "access denied")
	}
	if withCtx.Suggestion() != "add permission" {
		t.Errorf("Suggestion() = %q, want %q", withCtx.Suggestion(), "add permission")
	}
	if withCtx.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", withCtx.Unwrap(), cause)
	}
}

func TestIsSentinelError_SentinelError(t *testing.T) {
	err := New(ErrCodeSSMAccessDenied, "access denied", "add permission", nil)

	got, ok := IsSentinelError(err)
	if !ok {
		t.Error("IsSentinelError() = false, want true")
	}
	if got == nil {
		t.Error("IsSentinelError() returned nil, want error")
	}
	if got.Code() != ErrCodeSSMAccessDenied {
		t.Errorf("Code() = %q, want %q", got.Code(), ErrCodeSSMAccessDenied)
	}
}

func TestIsSentinelError_RegularError(t *testing.T) {
	err := errors.New("regular error")

	got, ok := IsSentinelError(err)
	if ok {
		t.Error("IsSentinelError() = true, want false")
	}
	if got != nil {
		t.Errorf("IsSentinelError() = %v, want nil", got)
	}
}

func TestIsSentinelError_NilError(t *testing.T) {
	got, ok := IsSentinelError(nil)
	if ok {
		t.Error("IsSentinelError(nil) = true, want false")
	}
	if got != nil {
		t.Errorf("IsSentinelError(nil) = %v, want nil", got)
	}
}

func TestGetCode_SentinelError(t *testing.T) {
	err := New(ErrCodeDynamoDBAccessDenied, "access denied", "add permission", nil)

	if got := GetCode(err); got != ErrCodeDynamoDBAccessDenied {
		t.Errorf("GetCode() = %q, want %q", got, ErrCodeDynamoDBAccessDenied)
	}
}

func TestGetCode_RegularError(t *testing.T) {
	err := errors.New("regular error")

	if got := GetCode(err); got != "" {
		t.Errorf("GetCode() = %q, want empty string", got)
	}
}

func TestGetCode_NilError(t *testing.T) {
	if got := GetCode(nil); got != "" {
		t.Errorf("GetCode(nil) = %q, want empty string", got)
	}
}

// Test all error code constants are defined
func TestErrorCodeConstants(t *testing.T) {
	// SSM codes
	if ErrCodeSSMAccessDenied != "SSM_ACCESS_DENIED" {
		t.Errorf("ErrCodeSSMAccessDenied = %q", ErrCodeSSMAccessDenied)
	}
	if ErrCodeSSMParameterNotFound != "SSM_PARAMETER_NOT_FOUND" {
		t.Errorf("ErrCodeSSMParameterNotFound = %q", ErrCodeSSMParameterNotFound)
	}
	if ErrCodeSSMKMSAccessDenied != "SSM_KMS_ACCESS_DENIED" {
		t.Errorf("ErrCodeSSMKMSAccessDenied = %q", ErrCodeSSMKMSAccessDenied)
	}
	if ErrCodeSSMThrottled != "SSM_THROTTLED" {
		t.Errorf("ErrCodeSSMThrottled = %q", ErrCodeSSMThrottled)
	}
	if ErrCodeSSMInvalidParameter != "SSM_INVALID_PARAMETER" {
		t.Errorf("ErrCodeSSMInvalidParameter = %q", ErrCodeSSMInvalidParameter)
	}

	// DynamoDB codes
	if ErrCodeDynamoDBAccessDenied != "DYNAMODB_ACCESS_DENIED" {
		t.Errorf("ErrCodeDynamoDBAccessDenied = %q", ErrCodeDynamoDBAccessDenied)
	}
	if ErrCodeDynamoDBTableNotFound != "DYNAMODB_TABLE_NOT_FOUND" {
		t.Errorf("ErrCodeDynamoDBTableNotFound = %q", ErrCodeDynamoDBTableNotFound)
	}
	if ErrCodeDynamoDBThrottled != "DYNAMODB_THROTTLED" {
		t.Errorf("ErrCodeDynamoDBThrottled = %q", ErrCodeDynamoDBThrottled)
	}
	if ErrCodeDynamoDBConditionFailed != "DYNAMODB_CONDITION_FAILED" {
		t.Errorf("ErrCodeDynamoDBConditionFailed = %q", ErrCodeDynamoDBConditionFailed)
	}

	// IAM codes
	if ErrCodeIAMSimulateAccessDenied != "IAM_SIMULATE_ACCESS_DENIED" {
		t.Errorf("ErrCodeIAMSimulateAccessDenied = %q", ErrCodeIAMSimulateAccessDenied)
	}
	if ErrCodeIAMRoleNotFound != "IAM_ROLE_NOT_FOUND" {
		t.Errorf("ErrCodeIAMRoleNotFound = %q", ErrCodeIAMRoleNotFound)
	}
	if ErrCodeIAMAccessDenied != "IAM_ACCESS_DENIED" {
		t.Errorf("ErrCodeIAMAccessDenied = %q", ErrCodeIAMAccessDenied)
	}

	// Policy codes
	if ErrCodePolicyDenied != "POLICY_DENIED" {
		t.Errorf("ErrCodePolicyDenied = %q", ErrCodePolicyDenied)
	}
	if ErrCodePolicyNotConfigured != "POLICY_NOT_CONFIGURED" {
		t.Errorf("ErrCodePolicyNotConfigured = %q", ErrCodePolicyNotConfigured)
	}

	// Config codes
	if ErrCodeConfigMissingCredentials != "CONFIG_MISSING_CREDENTIALS" {
		t.Errorf("ErrCodeConfigMissingCredentials = %q", ErrCodeConfigMissingCredentials)
	}
	if ErrCodeConfigInvalidRegion != "CONFIG_INVALID_REGION" {
		t.Errorf("ErrCodeConfigInvalidRegion = %q", ErrCodeConfigInvalidRegion)
	}
	if ErrCodeConfigProfileNotFound != "CONFIG_PROFILE_NOT_FOUND" {
		t.Errorf("ErrCodeConfigProfileNotFound = %q", ErrCodeConfigProfileNotFound)
	}
}
