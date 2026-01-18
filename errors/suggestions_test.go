package errors

import (
	"errors"
	"strings"
	"testing"
)

func TestGetSuggestion(t *testing.T) {
	tests := []struct {
		code    string
		wantHas string
	}{
		{ErrCodeSSMAccessDenied, "ssm:GetParameter"},
		{ErrCodeSSMParameterNotFound, "does not exist"},
		{ErrCodeSSMKMSAccessDenied, "kms:Decrypt"},
		{ErrCodeSSMThrottled, "Wait"},
		{ErrCodeDynamoDBAccessDenied, "DynamoDB permissions"},
		{ErrCodeDynamoDBTableNotFound, "does not exist"},
		{ErrCodeIAMSimulateAccessDenied, "SimulatePrincipalPolicy"},
		{ErrCodePolicyDenied, "denied"},
		{ErrCodeConfigMissingCredentials, "credentials"},
		{ErrCodeConfigProfileNotFound, "~/.aws/config"},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := GetSuggestion(tt.code)
			if got == "" {
				t.Errorf("GetSuggestion(%q) = empty string", tt.code)
			}
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tt.wantHas)) {
				t.Errorf("GetSuggestion(%q) = %q, want to contain %q", tt.code, got, tt.wantHas)
			}
		})
	}
}

func TestGetSuggestion_UnknownCode(t *testing.T) {
	got := GetSuggestion("UNKNOWN_CODE")
	if got != "" {
		t.Errorf("GetSuggestion(UNKNOWN_CODE) = %q, want empty string", got)
	}
}

func TestWrapSSMError_ParameterNotFound(t *testing.T) {
	err := errors.New("ParameterNotFound: parameter /sentinel/test not found")
	se := WrapSSMError(err, "/sentinel/test")

	if se.Code() != ErrCodeSSMParameterNotFound {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeSSMParameterNotFound)
	}
	if !strings.Contains(se.Error(), "/sentinel/test") {
		t.Errorf("Error() = %q, want to contain parameter name", se.Error())
	}
	if se.Context()["parameter"] != "/sentinel/test" {
		t.Errorf("Context()[\"parameter\"] = %q, want %q", se.Context()["parameter"], "/sentinel/test")
	}
	if se.Unwrap() != err {
		t.Errorf("Unwrap() = %v, want %v", se.Unwrap(), err)
	}
}

func TestWrapSSMError_AccessDenied(t *testing.T) {
	err := errors.New("AccessDeniedException: User is not authorized to perform ssm:GetParameter")
	se := WrapSSMError(err, "/sentinel/policies/default")

	if se.Code() != ErrCodeSSMAccessDenied {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeSSMAccessDenied)
	}
	if !strings.Contains(se.Suggestion(), "ssm:GetParameter") {
		t.Errorf("Suggestion() = %q, want to contain ssm:GetParameter", se.Suggestion())
	}
}

func TestWrapSSMError_KMSAccessDenied(t *testing.T) {
	err := errors.New("AccessDeniedException: User is not authorized to perform kms:Decrypt on the key")
	se := WrapSSMError(err, "/sentinel/encrypted")

	if se.Code() != ErrCodeSSMKMSAccessDenied {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeSSMKMSAccessDenied)
	}
	if !strings.Contains(se.Suggestion(), "kms:Decrypt") {
		t.Errorf("Suggestion() = %q, want to contain kms:Decrypt", se.Suggestion())
	}
}

func TestWrapSSMError_Throttled(t *testing.T) {
	err := errors.New("ThrottlingException: Rate exceeded")
	se := WrapSSMError(err, "/sentinel/test")

	if se.Code() != ErrCodeSSMThrottled {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeSSMThrottled)
	}
}

func TestWrapSSMError_ValidationError(t *testing.T) {
	err := errors.New("ValidationException: Invalid parameter name")
	se := WrapSSMError(err, "invalid//path")

	if se.Code() != ErrCodeSSMInvalidParameter {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeSSMInvalidParameter)
	}
}

func TestWrapSSMError_UnknownError(t *testing.T) {
	err := errors.New("some unknown SSM error")
	se := WrapSSMError(err, "/sentinel/test")

	// Should default to access denied
	if se.Code() != ErrCodeSSMAccessDenied {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeSSMAccessDenied)
	}
}

func TestWrapSSMError_NilError(t *testing.T) {
	se := WrapSSMError(nil, "/sentinel/test")
	if se != nil {
		t.Errorf("WrapSSMError(nil, ...) = %v, want nil", se)
	}
}

func TestWrapDynamoDBError_ResourceNotFound(t *testing.T) {
	err := errors.New("ResourceNotFoundException: Cannot do operations on a non-existent table")
	se := WrapDynamoDBError(err, "sentinel-requests", "GetItem")

	if se.Code() != ErrCodeDynamoDBTableNotFound {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeDynamoDBTableNotFound)
	}
	if se.Context()["table"] != "sentinel-requests" {
		t.Errorf("Context()[\"table\"] = %q, want %q", se.Context()["table"], "sentinel-requests")
	}
	if se.Context()["operation"] != "GetItem" {
		t.Errorf("Context()[\"operation\"] = %q, want %q", se.Context()["operation"], "GetItem")
	}
}

func TestWrapDynamoDBError_AccessDenied(t *testing.T) {
	err := errors.New("AccessDeniedException: User is not authorized to perform dynamodb:GetItem")
	se := WrapDynamoDBError(err, "sentinel-breakglass", "GetItem")

	if se.Code() != ErrCodeDynamoDBAccessDenied {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeDynamoDBAccessDenied)
	}
}

func TestWrapDynamoDBError_Throttled(t *testing.T) {
	err := errors.New("ProvisionedThroughputExceededException: Throughput exceeded")
	se := WrapDynamoDBError(err, "sentinel-requests", "PutItem")

	if se.Code() != ErrCodeDynamoDBThrottled {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeDynamoDBThrottled)
	}
}

func TestWrapDynamoDBError_ConditionalCheckFailed(t *testing.T) {
	err := errors.New("ConditionalCheckFailedException: The conditional request failed")
	se := WrapDynamoDBError(err, "sentinel-requests", "UpdateItem")

	if se.Code() != ErrCodeDynamoDBConditionFailed {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeDynamoDBConditionFailed)
	}
}

func TestWrapDynamoDBError_NilError(t *testing.T) {
	se := WrapDynamoDBError(nil, "table", "op")
	if se != nil {
		t.Errorf("WrapDynamoDBError(nil, ...) = %v, want nil", se)
	}
}

func TestWrapIAMError_SimulateAccessDenied(t *testing.T) {
	err := errors.New("AccessDeniedException: User is not authorized to perform iam:SimulatePrincipalPolicy")
	se := WrapIAMError(err, "SimulatePrincipalPolicy", "arn:aws:iam::123456789012:user/test")

	if se.Code() != ErrCodeIAMSimulateAccessDenied {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeIAMSimulateAccessDenied)
	}
	if !strings.Contains(se.Suggestion(), "SimulatePrincipalPolicy") {
		t.Errorf("Suggestion() = %q, want to contain SimulatePrincipalPolicy", se.Suggestion())
	}
}

func TestWrapIAMError_RoleNotFound(t *testing.T) {
	err := errors.New("NoSuchEntity: Role not found")
	se := WrapIAMError(err, "AssumeRole", "arn:aws:iam::123456789012:role/missing")

	if se.Code() != ErrCodeIAMRoleNotFound {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeIAMRoleNotFound)
	}
	if se.Context()["action"] != "AssumeRole" {
		t.Errorf("Context()[\"action\"] = %q, want %q", se.Context()["action"], "AssumeRole")
	}
	if se.Context()["resource"] != "arn:aws:iam::123456789012:role/missing" {
		t.Errorf("Context()[\"resource\"] = %q", se.Context()["resource"])
	}
}

func TestWrapIAMError_AccessDenied(t *testing.T) {
	err := errors.New("AccessDeniedException: User is not authorized to perform iam:GetRole")
	se := WrapIAMError(err, "GetRole", "arn:aws:iam::123456789012:role/test")

	if se.Code() != ErrCodeIAMAccessDenied {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodeIAMAccessDenied)
	}
}

func TestWrapIAMError_NilError(t *testing.T) {
	se := WrapIAMError(nil, "action", "resource")
	if se != nil {
		t.Errorf("WrapIAMError(nil, ...) = %v, want nil", se)
	}
}

func TestNewPolicyDeniedError_NoMatchedRule(t *testing.T) {
	se := NewPolicyDeniedError("alice", "production", nil, false, false)

	if se.Code() != ErrCodePolicyDenied {
		t.Errorf("Code() = %q, want %q", se.Code(), ErrCodePolicyDenied)
	}
	if !strings.Contains(se.Error(), "alice") {
		t.Errorf("Error() = %q, want to contain user", se.Error())
	}
	if !strings.Contains(se.Error(), "production") {
		t.Errorf("Error() = %q, want to contain profile", se.Error())
	}
	if !strings.Contains(se.Error(), "no rule matches") {
		t.Errorf("Error() = %q, want to contain 'no rule matches'", se.Error())
	}
	if se.Context()["user"] != "alice" {
		t.Errorf("Context()[\"user\"] = %q, want %q", se.Context()["user"], "alice")
	}
	if se.Context()["profile"] != "production" {
		t.Errorf("Context()[\"profile\"] = %q, want %q", se.Context()["profile"], "production")
	}
}

func TestNewPolicyDeniedError_ExplicitDenyRule(t *testing.T) {
	rule := &PolicyRule{
		Name:        "deny-production-weekends",
		Effect:      "deny",
		Description: "No production access on weekends",
	}
	se := NewPolicyDeniedError("bob", "production", rule, false, false)

	if !strings.Contains(se.Error(), "deny-production-weekends") {
		t.Errorf("Error() = %q, want to contain rule name", se.Error())
	}
	if !strings.Contains(se.Error(), "explicitly denies") {
		t.Errorf("Error() = %q, want to contain 'explicitly denies'", se.Error())
	}
	if !strings.Contains(se.Suggestion(), "No production access on weekends") {
		t.Errorf("Suggestion() = %q, want to contain rule description", se.Suggestion())
	}
	if se.Context()["matched_rule"] != "deny-production-weekends" {
		t.Errorf("Context()[\"matched_rule\"] = %q, want %q", se.Context()["matched_rule"], "deny-production-weekends")
	}
}

func TestNewPolicyDeniedError_ExplicitDenyRule_NoDescription(t *testing.T) {
	rule := &PolicyRule{
		Name:   "deny-all",
		Effect: "deny",
	}
	se := NewPolicyDeniedError("charlie", "staging", rule, false, false)

	if !strings.Contains(se.Suggestion(), "explicitly denies") {
		t.Errorf("Suggestion() = %q, want to contain 'explicitly denies'", se.Suggestion())
	}
	if !strings.Contains(se.Suggestion(), "Contact your administrator") {
		t.Errorf("Suggestion() = %q, want to contain admin contact", se.Suggestion())
	}
}

func TestNewPolicyDeniedError_WithApprovalWorkflow(t *testing.T) {
	se := NewPolicyDeniedError("dave", "production", nil, true, false)

	if !strings.Contains(se.Suggestion(), "sentinel request --profile production") {
		t.Errorf("Suggestion() = %q, want to contain request command", se.Suggestion())
	}
}

func TestNewPolicyDeniedError_WithBreakGlass(t *testing.T) {
	se := NewPolicyDeniedError("eve", "production", nil, false, true)

	if !strings.Contains(se.Suggestion(), "sentinel breakglass --profile production") {
		t.Errorf("Suggestion() = %q, want to contain breakglass command", se.Suggestion())
	}
}

func TestNewPolicyDeniedError_WithBothAlternatives(t *testing.T) {
	se := NewPolicyDeniedError("frank", "production", nil, true, true)

	suggestion := se.Suggestion()
	if !strings.Contains(suggestion, "sentinel request") {
		t.Errorf("Suggestion() = %q, want to contain request command", suggestion)
	}
	if !strings.Contains(suggestion, "sentinel breakglass") {
		t.Errorf("Suggestion() = %q, want to contain breakglass command", suggestion)
	}
	if !strings.Contains(suggestion, "Alternatives") {
		t.Errorf("Suggestion() = %q, want to contain 'Alternatives'", suggestion)
	}
}

// Test helper functions

func TestIsAccessDenied(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"AccessDeniedException: not authorized", true},
		{"access denied to resource", true},
		{"UnauthorizedOperation: operation not allowed", true},
		{"User is not authorized to perform", true},
		{"403 Forbidden", true},
		{"some other error", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isAccessDenied(strings.ToLower(tt.input))
			if got != tt.want {
				t.Errorf("isAccessDenied(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsParameterNotFound(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"ParameterNotFound: param not found", true},
		{"parameter not found in store", true},
		{"ParameterVersionNotFound: version missing", true},
		{"some other error", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isParameterNotFound(strings.ToLower(tt.input))
			if got != tt.want {
				t.Errorf("isParameterNotFound(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsResourceNotFound(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"ResourceNotFoundException: table not found", true},
		{"resource not found", true},
		{"Cannot do operations on a non-existent table", true},
		{"some other error", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isResourceNotFound(strings.ToLower(tt.input))
			if got != tt.want {
				t.Errorf("isResourceNotFound(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsThrottled(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"ThrottlingException: rate exceeded", true},
		{"Rate exceeded for operation", true},
		{"Too many requests", true},
		{"SlowDown: request throttled", true},
		{"some other error", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isThrottled(strings.ToLower(tt.input))
			if got != tt.want {
				t.Errorf("isThrottled(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsKMSAccessDenied(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"AccessDenied: kms:Decrypt not allowed", true},
		{"User not authorized to access key", true},
		{"regular access denied", false},
		{"kms key found", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isKMSAccessDenied(strings.ToLower(tt.input))
			if got != tt.want {
				t.Errorf("isKMSAccessDenied(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsNoSuchEntity(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"NoSuchEntity: role not found", true},
		{"No such entity: user", true},
		{"Cannot find role", true},
		{"some other error", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isNoSuchEntity(strings.ToLower(tt.input))
			if got != tt.want {
				t.Errorf("isNoSuchEntity(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsProvisionedThroughputExceeded(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"ProvisionedThroughputExceededException", true},
		{"Throughput exceeded for table", true},
		{"Write capacity exceeded", true},
		{"some other error", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isProvisionedThroughputExceeded(strings.ToLower(tt.input))
			if got != tt.want {
				t.Errorf("isProvisionedThroughputExceeded(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsConditionalCheckFailed(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"ConditionalCheckFailedException", true},
		{"Conditional check failed", true},
		{"Condition expression not satisfied", true},
		{"some other error", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isConditionalCheckFailed(strings.ToLower(tt.input))
			if got != tt.want {
				t.Errorf("isConditionalCheckFailed(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// Test all error codes have suggestions defined
func TestAllErrorCodesHaveSuggestions(t *testing.T) {
	codes := []string{
		ErrCodeSSMAccessDenied,
		ErrCodeSSMParameterNotFound,
		ErrCodeSSMKMSAccessDenied,
		ErrCodeSSMThrottled,
		ErrCodeSSMInvalidParameter,
		ErrCodeDynamoDBAccessDenied,
		ErrCodeDynamoDBTableNotFound,
		ErrCodeDynamoDBThrottled,
		ErrCodeDynamoDBConditionFailed,
		ErrCodeIAMSimulateAccessDenied,
		ErrCodeIAMRoleNotFound,
		ErrCodeIAMAccessDenied,
		ErrCodePolicyDenied,
		ErrCodePolicyNotConfigured,
		ErrCodeConfigMissingCredentials,
		ErrCodeConfigInvalidRegion,
		ErrCodeConfigProfileNotFound,
	}

	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			suggestion := GetSuggestion(code)
			if suggestion == "" {
				t.Errorf("No suggestion defined for error code %q", code)
			}
		})
	}
}
