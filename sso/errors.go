// Package sso provides SSO error detection and login trigger infrastructure
// for automatic SSO authentication flows.
package sso

import (
	"errors"
	"net/http"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/byteness/keyring"
)

// KeyringErrKeyNotFound mirrors keyring.ErrKeyNotFound for test compatibility.
// This allows tests to check for keyring errors without the full CGO dependency.
var KeyringErrKeyNotFound = keyring.ErrKeyNotFound

// keyringErrMessage is the error message used by keyring.ErrKeyNotFound.
const keyringErrMessage = "The specified item could not be found in the keyring"

// SSOErrorType classifies different categories of SSO-related errors.
type SSOErrorType int

const (
	// SSOErrorTypeNone indicates the error is not SSO-related.
	SSOErrorTypeNone SSOErrorType = iota
	// SSOErrorTypeExpiredToken indicates the OIDC token has expired.
	SSOErrorTypeExpiredToken
	// SSOErrorTypeNoCredentials indicates no cached credentials exist.
	SSOErrorTypeNoCredentials
	// SSOErrorTypeInvalidToken indicates the token was rejected by AWS.
	SSOErrorTypeInvalidToken
	// SSOErrorTypeNetworkError indicates the SSO service is unreachable.
	SSOErrorTypeNetworkError
)

// String returns a human-readable name for the error type.
func (t SSOErrorType) String() string {
	switch t {
	case SSOErrorTypeNone:
		return "none"
	case SSOErrorTypeExpiredToken:
		return "expired_token"
	case SSOErrorTypeNoCredentials:
		return "no_credentials"
	case SSOErrorTypeInvalidToken:
		return "invalid_token"
	case SSOErrorTypeNetworkError:
		return "network_error"
	default:
		return "unknown"
	}
}

// ClassifySSOError examines an error and returns the appropriate SSOErrorType.
// It checks for various SSO-related error conditions including expired tokens,
// missing credentials, invalid tokens, and network errors.
func ClassifySSOError(err error) SSOErrorType {
	if err == nil {
		return SSOErrorTypeNone
	}

	// Check for ExpiredTokenException from SSO OIDC
	var expiredErr *types.ExpiredTokenException
	if errors.As(err, &expiredErr) {
		return SSOErrorTypeExpiredToken
	}

	// Check for keyring.ErrKeyNotFound (no cached token)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return SSOErrorTypeNoCredentials
	}

	// Also check by error message for wrapped or stringified keyring errors
	if strings.Contains(err.Error(), keyringErrMessage) {
		return SSOErrorTypeNoCredentials
	}

	// Check for HTTP 401 responses (invalid/expired access token)
	var rspError *awshttp.ResponseError
	if errors.As(err, &rspError) {
		if rspError.HTTPStatusCode() == http.StatusUnauthorized {
			return SSOErrorTypeInvalidToken
		}
		if rspError.HTTPStatusCode() == http.StatusForbidden {
			return SSOErrorTypeInvalidToken
		}
	}

	// Check error message for common SSO error patterns
	errMsg := err.Error()

	// Check for session expired message
	if strings.Contains(errMsg, "The SSO session associated with this profile has expired") {
		return SSOErrorTypeExpiredToken
	}
	if strings.Contains(errMsg, "SSO session associated with this profile") && strings.Contains(errMsg, "expired") {
		return SSOErrorTypeExpiredToken
	}

	// Check for InvalidTokenException in error message
	if strings.Contains(errMsg, "InvalidTokenException") {
		return SSOErrorTypeInvalidToken
	}

	// Check for UnauthorizedException
	if strings.Contains(errMsg, "UnauthorizedException") {
		return SSOErrorTypeInvalidToken
	}

	// Check for ExpiredTokenException in error message (may be wrapped differently)
	if strings.Contains(errMsg, "ExpiredTokenException") {
		return SSOErrorTypeExpiredToken
	}

	// Check for network errors
	if isNetworkError(errMsg) {
		return SSOErrorTypeNetworkError
	}

	return SSOErrorTypeNone
}

// isNetworkError checks if the error message indicates a network-related failure.
func isNetworkError(errMsg string) bool {
	networkPatterns := []string{
		"connection refused",
		"connection reset",
		"no such host",
		"timeout",
		"dial tcp",
		"network is unreachable",
		"TLS handshake timeout",
		"context deadline exceeded",
		"i/o timeout",
	}

	errMsgLower := strings.ToLower(errMsg)
	for _, pattern := range networkPatterns {
		if strings.Contains(errMsgLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// IsSSOCredentialError returns true if the error is SSO-related and can be
// resolved by triggering the SSO login flow. This includes expired tokens,
// missing credentials, and invalid tokens.
func IsSSOCredentialError(err error) bool {
	errType := ClassifySSOError(err)
	switch errType {
	case SSOErrorTypeExpiredToken, SSOErrorTypeNoCredentials, SSOErrorTypeInvalidToken:
		return true
	default:
		return false
	}
}

// IsRetriableWithLogin returns true if the error can be resolved by
// re-authenticating via the SSO login flow. This is an alias for
// IsSSOCredentialError for clarity in different contexts.
func IsRetriableWithLogin(err error) bool {
	return IsSSOCredentialError(err)
}
