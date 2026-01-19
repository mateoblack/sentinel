// Package errors provides structured error types with fix suggestions for Sentinel.
// These error types wrap AWS errors and provide actionable guidance on how to resolve
// common permission failures.
package errors

// SentinelError provides additional context for error handling.
// It wraps underlying errors with error codes and actionable suggestions.
type SentinelError interface {
	error
	Unwrap() error              // Original error
	Code() string               // Error code (e.g., "SSM_ACCESS_DENIED")
	Suggestion() string         // Actionable fix suggestion
	Context() map[string]string // Additional context (parameter, table, etc.)
}

// SSM error codes
const (
	ErrCodeSSMAccessDenied      = "SSM_ACCESS_DENIED"
	ErrCodeSSMParameterNotFound = "SSM_PARAMETER_NOT_FOUND"
	ErrCodeSSMKMSAccessDenied   = "SSM_KMS_ACCESS_DENIED"
	ErrCodeSSMThrottled         = "SSM_THROTTLED"
	ErrCodeSSMInvalidParameter  = "SSM_INVALID_PARAMETER"
)

// DynamoDB error codes
const (
	ErrCodeDynamoDBAccessDenied    = "DYNAMODB_ACCESS_DENIED"
	ErrCodeDynamoDBTableNotFound   = "DYNAMODB_TABLE_NOT_FOUND"
	ErrCodeDynamoDBThrottled       = "DYNAMODB_THROTTLED"
	ErrCodeDynamoDBConditionFailed = "DYNAMODB_CONDITION_FAILED"
)

// IAM error codes
const (
	ErrCodeIAMSimulateAccessDenied = "IAM_SIMULATE_ACCESS_DENIED"
	ErrCodeIAMRoleNotFound         = "IAM_ROLE_NOT_FOUND"
	ErrCodeIAMAccessDenied         = "IAM_ACCESS_DENIED"
)

// STS error codes
const (
	ErrCodeSTSError        = "STS_ERROR"
	ErrCodeSTSAccessDenied = "STS_ACCESS_DENIED"
)

// Policy error codes
const (
	ErrCodePolicyDenied        = "POLICY_DENIED"
	ErrCodePolicyNotConfigured = "POLICY_NOT_CONFIGURED"
)

// Config error codes
const (
	ErrCodeConfigMissingCredentials = "CONFIG_MISSING_CREDENTIALS"
	ErrCodeConfigInvalidRegion      = "CONFIG_INVALID_REGION"
	ErrCodeConfigProfileNotFound    = "CONFIG_PROFILE_NOT_FOUND"
)

// sentinelError implements the SentinelError interface.
type sentinelError struct {
	code       string
	message    string
	suggestion string
	context    map[string]string
	cause      error
}

// Error implements the error interface.
func (e *sentinelError) Error() string {
	return e.message
}

// Unwrap returns the underlying cause error.
func (e *sentinelError) Unwrap() error {
	return e.cause
}

// Code returns the error code.
func (e *sentinelError) Code() string {
	return e.code
}

// Suggestion returns the actionable fix suggestion.
func (e *sentinelError) Suggestion() string {
	return e.suggestion
}

// Context returns additional context about the error.
func (e *sentinelError) Context() map[string]string {
	return e.context
}

// New creates a new SentinelError with the given code, message, suggestion, and cause.
func New(code, message, suggestion string, cause error) SentinelError {
	return &sentinelError{
		code:       code,
		message:    message,
		suggestion: suggestion,
		context:    make(map[string]string),
		cause:      cause,
	}
}

// WithContext adds context to an error and returns a new SentinelError.
// The original error is not modified.
func WithContext(err SentinelError, key, value string) SentinelError {
	// Get existing context
	existingCtx := err.Context()
	newCtx := make(map[string]string, len(existingCtx)+1)
	for k, v := range existingCtx {
		newCtx[k] = v
	}
	newCtx[key] = value

	return &sentinelError{
		code:       err.Code(),
		message:    err.Error(),
		suggestion: err.Suggestion(),
		context:    newCtx,
		cause:      err.Unwrap(),
	}
}

// IsSentinelError checks if err is a SentinelError and returns it.
// If err is nil or not a SentinelError, returns (nil, false).
func IsSentinelError(err error) (SentinelError, bool) {
	if err == nil {
		return nil, false
	}
	if se, ok := err.(SentinelError); ok {
		return se, true
	}
	return nil, false
}

// GetCode extracts the error code from an error.
// Returns empty string if err is not a SentinelError.
func GetCode(err error) string {
	if se, ok := IsSentinelError(err); ok {
		return se.Code()
	}
	return ""
}
