package sso

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/byteness/keyring"
)

func TestClassifySSOError_NilError(t *testing.T) {
	result := ClassifySSOError(nil)
	if result != SSOErrorTypeNone {
		t.Errorf("expected SSOErrorTypeNone for nil error, got %v", result)
	}
}

func TestClassifySSOError_ExpiredTokenException(t *testing.T) {
	err := &types.ExpiredTokenException{Message: awsString("Token has expired")}
	result := ClassifySSOError(err)
	if result != SSOErrorTypeExpiredToken {
		t.Errorf("expected SSOErrorTypeExpiredToken for ExpiredTokenException, got %v", result)
	}
}

func TestClassifySSOError_WrappedExpiredTokenException(t *testing.T) {
	innerErr := &types.ExpiredTokenException{Message: awsString("Token has expired")}
	err := fmt.Errorf("operation failed: %w", innerErr)
	result := ClassifySSOError(err)
	if result != SSOErrorTypeExpiredToken {
		t.Errorf("expected SSOErrorTypeExpiredToken for wrapped ExpiredTokenException, got %v", result)
	}
}

func TestClassifySSOError_KeyringNotFound(t *testing.T) {
	result := ClassifySSOError(keyring.ErrKeyNotFound)
	if result != SSOErrorTypeNoCredentials {
		t.Errorf("expected SSOErrorTypeNoCredentials for keyring.ErrKeyNotFound, got %v", result)
	}
}

func TestClassifySSOError_WrappedKeyringNotFound(t *testing.T) {
	err := fmt.Errorf("cache lookup failed: %w", keyring.ErrKeyNotFound)
	result := ClassifySSOError(err)
	if result != SSOErrorTypeNoCredentials {
		t.Errorf("expected SSOErrorTypeNoCredentials for wrapped keyring.ErrKeyNotFound, got %v", result)
	}
}

func TestClassifySSOError_HTTP401(t *testing.T) {
	resp := &smithyhttp.Response{
		Response: &http.Response{
			StatusCode: http.StatusUnauthorized,
		},
	}
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: resp,
			Err:      errors.New("unauthorized"),
		},
	}
	result := ClassifySSOError(err)
	if result != SSOErrorTypeInvalidToken {
		t.Errorf("expected SSOErrorTypeInvalidToken for HTTP 401, got %v", result)
	}
}

func TestClassifySSOError_HTTP403(t *testing.T) {
	resp := &smithyhttp.Response{
		Response: &http.Response{
			StatusCode: http.StatusForbidden,
		},
	}
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: resp,
			Err:      errors.New("forbidden"),
		},
	}
	result := ClassifySSOError(err)
	if result != SSOErrorTypeInvalidToken {
		t.Errorf("expected SSOErrorTypeInvalidToken for HTTP 403, got %v", result)
	}
}

func TestClassifySSOError_SessionExpiredMessage(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
		want   SSOErrorType
	}{
		{
			name:   "exact session expired message",
			errMsg: "The SSO session associated with this profile has expired",
			want:   SSOErrorTypeExpiredToken,
		},
		{
			name:   "session expired with context",
			errMsg: "Error: The SSO session associated with this profile has expired. Please login again.",
			want:   SSOErrorTypeExpiredToken,
		},
		{
			name:   "alternate expired message",
			errMsg: "SSO session associated with this profile has expired or is invalid",
			want:   SSOErrorTypeExpiredToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ClassifySSOError(err)
			if result != tt.want {
				t.Errorf("expected %v for message %q, got %v", tt.want, tt.errMsg, result)
			}
		})
	}
}

func TestClassifySSOError_InvalidTokenMessage(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
		want   SSOErrorType
	}{
		{
			name:   "InvalidTokenException message",
			errMsg: "InvalidTokenException: The token is not valid",
			want:   SSOErrorTypeInvalidToken,
		},
		{
			name:   "UnauthorizedException message",
			errMsg: "UnauthorizedException: Access denied",
			want:   SSOErrorTypeInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ClassifySSOError(err)
			if result != tt.want {
				t.Errorf("expected %v for message %q, got %v", tt.want, tt.errMsg, result)
			}
		})
	}
}

func TestClassifySSOError_ExpiredTokenMessage(t *testing.T) {
	err := errors.New("ExpiredTokenException: The security token included in the request is expired")
	result := ClassifySSOError(err)
	if result != SSOErrorTypeExpiredToken {
		t.Errorf("expected SSOErrorTypeExpiredToken for ExpiredTokenException message, got %v", result)
	}
}

func TestClassifySSOError_NetworkErrors(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
		want   SSOErrorType
	}{
		{
			name:   "connection refused",
			errMsg: "connection refused",
			want:   SSOErrorTypeNetworkError,
		},
		{
			name:   "connection reset",
			errMsg: "connection reset by peer",
			want:   SSOErrorTypeNetworkError,
		},
		{
			name:   "no such host",
			errMsg: "dial tcp: lookup portal.sso.us-east-1.amazonaws.com: no such host",
			want:   SSOErrorTypeNetworkError,
		},
		{
			name:   "timeout",
			errMsg: "operation timeout exceeded",
			want:   SSOErrorTypeNetworkError,
		},
		{
			name:   "dial tcp error",
			errMsg: "dial tcp 192.168.1.1:443: connect: network is unreachable",
			want:   SSOErrorTypeNetworkError,
		},
		{
			name:   "TLS handshake timeout",
			errMsg: "TLS handshake timeout",
			want:   SSOErrorTypeNetworkError,
		},
		{
			name:   "context deadline exceeded",
			errMsg: "context deadline exceeded",
			want:   SSOErrorTypeNetworkError,
		},
		{
			name:   "i/o timeout",
			errMsg: "read tcp 10.0.0.1:54321->10.0.0.2:443: i/o timeout",
			want:   SSOErrorTypeNetworkError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ClassifySSOError(err)
			if result != tt.want {
				t.Errorf("expected %v for message %q, got %v", tt.want, tt.errMsg, result)
			}
		})
	}
}

func TestClassifySSOError_NonSSOError(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string
	}{
		{
			name:   "generic error",
			errMsg: "something went wrong",
		},
		{
			name:   "permission denied",
			errMsg: "AccessDeniedException: User is not authorized",
		},
		{
			name:   "validation error",
			errMsg: "ValidationException: Invalid parameter value",
		},
		{
			name:   "resource not found",
			errMsg: "ResourceNotFoundException: Role not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.errMsg)
			result := ClassifySSOError(err)
			if result != SSOErrorTypeNone {
				t.Errorf("expected SSOErrorTypeNone for message %q, got %v", tt.errMsg, result)
			}
		})
	}
}

func TestIsSSOCredentialError(t *testing.T) {
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
			name:     "expired token",
			err:      &types.ExpiredTokenException{Message: awsString("expired")},
			expected: true,
		},
		{
			name:     "no credentials",
			err:      keyring.ErrKeyNotFound,
			expected: true,
		},
		{
			name:     "invalid token message",
			err:      errors.New("InvalidTokenException: invalid"),
			expected: true,
		},
		{
			name:     "network error",
			err:      errors.New("connection refused"),
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some other error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSSOCredentialError(tt.err)
			if result != tt.expected {
				t.Errorf("expected IsSSOCredentialError to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsRetriableWithLogin(t *testing.T) {
	// IsRetriableWithLogin is an alias for IsSSOCredentialError
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "expired token is retriable",
			err:      &types.ExpiredTokenException{Message: awsString("expired")},
			expected: true,
		},
		{
			name:     "no credentials is retriable",
			err:      keyring.ErrKeyNotFound,
			expected: true,
		},
		{
			name:     "network error not retriable",
			err:      errors.New("connection refused"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetriableWithLogin(tt.err)
			if result != tt.expected {
				t.Errorf("expected IsRetriableWithLogin to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSSOErrorType_String(t *testing.T) {
	tests := []struct {
		errType  SSOErrorType
		expected string
	}{
		{SSOErrorTypeNone, "none"},
		{SSOErrorTypeExpiredToken, "expired_token"},
		{SSOErrorTypeNoCredentials, "no_credentials"},
		{SSOErrorTypeInvalidToken, "invalid_token"},
		{SSOErrorTypeNetworkError, "network_error"},
		{SSOErrorType(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.errType.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// awsString is a helper to create *string for AWS SDK types
func awsString(s string) *string {
	return &s
}
