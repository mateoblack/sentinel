// Package sentinel provides security integration tests for v1.16 hardening.
// These tests validate that all security fixes work together:
// 1. Error sanitization - no internal details leaked to clients
// 2. Rate limiting - concurrent requests properly limited
// 3. Combined security chain - full request flow validation
//
// SECURITY: These tests are regression tests for security hardening phases 113, 117, 119.
package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/ratelimit"
)

// ============================================================================
// ERROR SANITIZATION TESTS - Phase 119
// ============================================================================
// These tests verify error responses don't leak internal details to clients.

// TestSecurityIntegration_PolicyLoadErrorSanitized verifies that policy load
// errors return a generic message without exposing SSM parameter paths.
//
// SECURITY: Policy load errors may contain SSM parameter paths, AWS region info,
// or IAM permission errors that should not be exposed to clients.
func TestSecurityIntegration_PolicyLoadErrorSanitized(t *testing.T) {
	ctx := context.Background()

	// Create server with a policy loader that will fail
	config := SentinelServerConfig{
		ProfileName:     "test-profile",
		User:            "test-user",
		LazyLoad:        true, // Skip credential prefetch
		PolicyParameter: "/super/secret/ssm/path/that/should/not/be/exposed",
		PolicyLoader: &mockPolicyLoader{
			loadErr: errPolicyLoadFailed,
		},
	}

	server, err := NewSentinelServer(ctx, config, "test-token", 0)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(ctx)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-token")

	rec := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(rec, req)

	// SECURITY: Verify error is sanitized
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", rec.Code)
	}

	// Parse response
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	message := resp["Message"]

	// Verify message is generic
	if message != "Failed to load policy" {
		t.Errorf("Expected generic error message, got: %s", message)
	}

	// SECURITY: Verify message does NOT contain SSM path
	if strings.Contains(message, "/super/secret") ||
		strings.Contains(message, "ssm") ||
		strings.Contains(message, "SSM") {
		t.Errorf("SECURITY VIOLATION: Error message exposes SSM path: %s", message)
	}
}

// TestSecurityIntegration_CredentialRetrievalErrorSanitized verifies that
// credential retrieval errors return a generic message.
//
// SECURITY: Credential errors may contain ARN details, STS error codes, or
// internal provider information that should not be exposed to clients.
func TestSecurityIntegration_CredentialRetrievalErrorSanitized(t *testing.T) {
	ctx := context.Background()

	// Create server with credential provider that fails
	config := SentinelServerConfig{
		ProfileName:     "test-profile",
		User:            "test-user",
		LazyLoad:        true,
		PolicyParameter: "/test/policy",
		PolicyLoader: &mockPolicyLoader{
			policy: allowAllPolicy(),
		},
		CredentialProvider: &mockCredentialProvider{
			err: errCredentialProviderFailed,
		},
	}

	server, err := NewSentinelServer(ctx, config, "test-token", 0)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(ctx)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-token")

	rec := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(rec, req)

	// SECURITY: Verify error is sanitized
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	message := resp["Message"]

	// Verify message is generic
	if message != "Failed to retrieve credentials" {
		t.Errorf("Expected generic error message, got: %s", message)
	}

	// SECURITY: Verify message does NOT contain provider details
	sensitivePatterns := []string{
		"STS",
		"AssumeRole",
		"arn:",
		"AccessDenied",
		"ExpiredToken",
		"InvalidIdentityToken",
	}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(message, pattern) {
			t.Errorf("SECURITY VIOLATION: Error message contains sensitive detail %q: %s", pattern, message)
		}
	}
}

// ============================================================================
// RATE LIMITING TESTS - Phase 117
// ============================================================================
// These tests verify rate limiting behavior for the credential server.

// TestSecurityIntegration_RateLimitConcurrent verifies that concurrent requests
// are properly rate limited without race conditions.
//
// SECURITY: Rate limiting must work correctly under concurrent load to prevent
// credential endpoint abuse and brute force attacks.
func TestSecurityIntegration_RateLimitConcurrent(t *testing.T) {
	ctx := context.Background()

	// Create rate limiter with low limit for testing
	limiter, err := ratelimit.NewMemoryRateLimiter(ratelimit.Config{
		RequestsPerWindow: 5,
		Window:            time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer limiter.Close()

	config := SentinelServerConfig{
		ProfileName:     "test-profile",
		User:            "test-user",
		LazyLoad:        true,
		PolicyParameter: "/test/policy",
		PolicyLoader: &mockPolicyLoader{
			policy: allowAllPolicy(),
		},
		CredentialProvider: &mockCredentialProvider{
			creds: successfulCredentials(),
		},
		RateLimiter: limiter,
	}

	server, err := NewSentinelServer(ctx, config, "test-token", 0)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(ctx)

	// Run 20 concurrent requests with limit of 5
	const totalRequests = 20
	const expectedAllowed = 5

	var wg sync.WaitGroup
	var successCount int64
	var rateLimitedCount int64

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "test-token")

			rec := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(rec, req)

			if rec.Code == http.StatusOK {
				atomic.AddInt64(&successCount, 1)
			} else if rec.Code == http.StatusTooManyRequests {
				atomic.AddInt64(&rateLimitedCount, 1)
			}
		}()
	}

	wg.Wait()

	// SECURITY: Exactly 5 should succeed, rest should be rate limited
	if successCount != expectedAllowed {
		t.Errorf("SECURITY: Expected exactly %d allowed requests, got %d (race condition may exist)",
			expectedAllowed, successCount)
	}

	expectedRateLimited := int64(totalRequests - expectedAllowed)
	if rateLimitedCount != expectedRateLimited {
		t.Errorf("Expected %d rate limited requests, got %d", expectedRateLimited, rateLimitedCount)
	}
}

// TestSecurityIntegration_RateLimitRetryAfterHeader verifies that rate limit
// responses include the RFC 7231 compliant Retry-After header.
//
// SECURITY: Retry-After header helps clients implement proper backoff and
// prevents tight retry loops that could amplify rate limiting issues.
func TestSecurityIntegration_RateLimitRetryAfterHeader(t *testing.T) {
	ctx := context.Background()

	// Create rate limiter that allows only 1 request
	limiter, err := ratelimit.NewMemoryRateLimiter(ratelimit.Config{
		RequestsPerWindow: 1,
		Window:            time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer limiter.Close()

	config := SentinelServerConfig{
		ProfileName:     "test-profile",
		User:            "test-user",
		LazyLoad:        true,
		PolicyParameter: "/test/policy",
		PolicyLoader: &mockPolicyLoader{
			policy: allowAllPolicy(),
		},
		CredentialProvider: &mockCredentialProvider{
			creds: successfulCredentials(),
		},
		RateLimiter: limiter,
	}

	server, err := NewSentinelServer(ctx, config, "test-token", 0)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(ctx)

	// First request should succeed
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Authorization", "test-token")
	rec1 := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("First request should succeed, got %d", rec1.Code)
	}

	// Second request should be rate limited with Retry-After
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "test-token")
	rec2 := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("Second request should return 429, got %d", rec2.Code)
	}

	// SECURITY: Verify Retry-After header is present
	retryAfter := rec2.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("SECURITY: 429 response must include Retry-After header for RFC 7231 compliance")
	}

	// Verify Retry-After is a reasonable value (should be positive number of seconds)
	if retryAfter != "" && retryAfter[0] == '-' {
		t.Errorf("Retry-After should be positive, got: %s", retryAfter)
	}
}

// ============================================================================
// COMBINED SECURITY SCENARIO TESTS
// ============================================================================
// These tests verify the full security chain works together.

// TestSecurityIntegration_EndToEndSecurityChain verifies the complete request
// flow through auth -> rate limit -> policy -> credential with proper error
// sanitization at each layer.
//
// SECURITY: This test validates that all security layers work together without
// leaking information between layers or providing bypasses.
func TestSecurityIntegration_EndToEndSecurityChain(t *testing.T) {
	ctx := context.Background()

	limiter, err := ratelimit.NewMemoryRateLimiter(ratelimit.Config{
		RequestsPerWindow: 100, // High limit - we're testing the chain, not rate limiting
		Window:            time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	defer limiter.Close()

	testCases := []struct {
		name           string
		authToken      string
		requestToken   string
		policyLoader   *mockPolicyLoader
		credProvider   *mockCredentialProvider
		expectedStatus int
		checkMessage   func(t *testing.T, msg string)
	}{
		{
			name:           "auth_fails_wrong_token",
			authToken:      "correct-token",
			requestToken:   "wrong-token",
			expectedStatus: http.StatusForbidden,
			checkMessage: func(t *testing.T, msg string) {
				if !strings.Contains(msg, "invalid Authorization") {
					t.Errorf("Expected auth error message, got: %s", msg)
				}
			},
		},
		{
			name:         "auth_fails_empty_token",
			authToken:    "correct-token",
			requestToken: "",
			// Empty Authorization header should fail auth check
			expectedStatus: http.StatusForbidden,
			checkMessage: func(t *testing.T, msg string) {
				if !strings.Contains(msg, "invalid Authorization") {
					t.Errorf("Expected auth error message, got: %s", msg)
				}
			},
		},
		{
			name:         "policy_load_fails",
			authToken:    "test-token",
			requestToken: "test-token",
			policyLoader: &mockPolicyLoader{
				loadErr: errPolicyLoadFailed,
			},
			expectedStatus: http.StatusInternalServerError,
			checkMessage: func(t *testing.T, msg string) {
				if msg != "Failed to load policy" {
					t.Errorf("Expected sanitized policy error, got: %s", msg)
				}
			},
		},
		{
			name:         "policy_denies",
			authToken:    "test-token",
			requestToken: "test-token",
			policyLoader: &mockPolicyLoader{
				policy: denyAllPolicy(),
			},
			expectedStatus: http.StatusForbidden,
			checkMessage: func(t *testing.T, msg string) {
				if msg != "Policy denied access" {
					t.Errorf("Expected policy deny message, got: %s", msg)
				}
			},
		},
		{
			name:         "credential_retrieval_fails",
			authToken:    "test-token",
			requestToken: "test-token",
			policyLoader: &mockPolicyLoader{
				policy: allowAllPolicy(),
			},
			credProvider: &mockCredentialProvider{
				err: errCredentialProviderFailed,
			},
			expectedStatus: http.StatusInternalServerError,
			checkMessage: func(t *testing.T, msg string) {
				if msg != "Failed to retrieve credentials" {
					t.Errorf("Expected sanitized credential error, got: %s", msg)
				}
			},
		},
		{
			name:         "full_chain_success",
			authToken:    "test-token",
			requestToken: "test-token",
			policyLoader: &mockPolicyLoader{
				policy: allowAllPolicy(),
			},
			credProvider: &mockCredentialProvider{
				creds: successfulCredentials(),
			},
			expectedStatus: http.StatusOK,
			checkMessage: func(t *testing.T, msg string) {
				// Success case - verify credentials are present
				if msg == "" {
					t.Error("Expected credentials in response")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := SentinelServerConfig{
				ProfileName:        "test-profile",
				User:               "test-user",
				LazyLoad:           true,
				PolicyParameter:    "/test/policy",
				PolicyLoader:       tc.policyLoader,
				CredentialProvider: tc.credProvider,
				RateLimiter:        limiter,
			}

			server, err := NewSentinelServer(ctx, config, tc.authToken, 0)
			if err != nil {
				t.Fatalf("failed to create server: %v", err)
			}
			defer server.Shutdown(ctx)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.requestToken != "" {
				req.Header.Set("Authorization", tc.requestToken)
			}

			rec := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rec.Code)
			}

			// Parse response
			body, _ := io.ReadAll(bytes.NewReader(rec.Body.Bytes()))
			var resp map[string]string
			if err := json.Unmarshal(body, &resp); err != nil {
				// If not JSON, check raw body for success case
				if tc.expectedStatus == http.StatusOK {
					tc.checkMessage(t, string(body))
				}
				return
			}

			tc.checkMessage(t, resp["Message"])
		})
	}
}

// ============================================================================
// MOCK IMPLEMENTATIONS
// ============================================================================

type mockPolicyLoader struct {
	policy  *policy.Policy
	loadErr error
}

func (m *mockPolicyLoader) Load(ctx context.Context, parameter string) (*policy.Policy, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return m.policy, nil
}

type mockCredentialProvider struct {
	creds *CredentialResult
	err   error
}

func (m *mockCredentialProvider) GetCredentialsWithSourceIdentity(ctx context.Context, req CredentialRequest) (*CredentialResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.creds, nil
}

// Error types for testing
var (
	errPolicyLoadFailed         = &testError{msg: "SSM parameter /secret/path not found: AccessDeniedException"}
	errCredentialProviderFailed = &testError{msg: "STS AssumeRole failed: ExpiredToken for arn:aws:iam::123456789012:role/secret-role"}
)

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// allowAllPolicy returns a policy that allows all requests.
func allowAllPolicy() *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-all",
				Effect: policy.EffectAllow,
				Reason: "Allow all for testing",
			},
		},
	}
}

// denyAllPolicy returns a policy that denies all requests.
func denyAllPolicy() *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "deny-all",
				Effect: policy.EffectDeny,
				Reason: "Deny all for testing",
			},
		},
	}
}

// successfulCredentials returns mock credentials for successful responses.
func successfulCredentials() *CredentialResult {
	return &CredentialResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "FwoGZXIvYXdzEBYaDCpjfvk...",
		Expiration:      time.Now().Add(time.Hour),
		CanExpire:       true,
		SourceIdentity:  "sentinel:testuser:direct:abc123",
		RoleARN:         "arn:aws:iam::123456789012:role/test-role",
	}
}
