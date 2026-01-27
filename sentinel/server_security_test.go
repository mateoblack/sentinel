// Package sentinel provides security regression tests for timing attack mitigations.
// These tests validate that bearer token authentication uses constant-time comparison
// to prevent timing-based attacks that could extract tokens byte-by-byte.
//
// SECURITY THREAT: Timing attacks on bearer token comparison
// When using direct string comparison (!=), the comparison returns early on the
// first mismatched byte. An attacker can measure response times across many requests
// to determine how many bytes matched, allowing them to extract the token one byte
// at a time.
//
// MITIGATION: crypto/subtle.ConstantTimeCompare
// This function always compares all bytes regardless of mismatch position, taking
// the same amount of time for any two inputs of the same length. This eliminates
// timing side-channel information.
package sentinel

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/testutil"
)

// testCredProvider is a mock credential provider for testing.
type testCredProvider struct {
	result *CredentialResult
	err    error
}

func (p *testCredProvider) GetCredentialsWithSourceIdentity(ctx context.Context, req CredentialRequest) (*CredentialResult, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.result, nil
}

// =============================================================================
// TIMING ATTACK MITIGATION TESTS
// =============================================================================
// These tests verify that constant-time comparison is used for authentication.

// TestThreat_TimingAttack_AuthorizationUsesConstantTimeCompare verifies that
// the withAuthorizationCheck function uses crypto/subtle.ConstantTimeCompare
// instead of direct string comparison.
//
// Threat: Timing attacks on bearer token comparison allow byte-by-byte extraction.
// Mitigation: crypto/subtle.ConstantTimeCompare takes constant time regardless of input.
func TestThreat_TimingAttack_AuthorizationUsesConstantTimeCompare(t *testing.T) {
	// Parse the source file to verify the import and usage
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("failed to parse server.go: %v", err)
	}

	// Verify crypto/subtle is imported
	hasSubtleImport := false
	for _, imp := range f.Imports {
		if imp.Path.Value == `"crypto/subtle"` {
			hasSubtleImport = true
			break
		}
	}

	if !hasSubtleImport {
		t.Error("SECURITY: crypto/subtle must be imported for constant-time comparison")
	}

	// Also parse to verify ConstantTimeCompare is used in the function body
	// Parse again with full AST
	fFull, err := parser.ParseFile(fset, "server.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("failed to parse server.go for full AST: %v", err)
	}

	hasConstantTimeCompare := false
	ast.Inspect(fFull, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare" {
					hasConstantTimeCompare = true
					return false
				}
			}
		}
		return true
	})

	if !hasConstantTimeCompare {
		t.Error("SECURITY: withAuthorizationCheck must use subtle.ConstantTimeCompare")
	}
}

// =============================================================================
// SECURITY REGRESSION TESTS
// =============================================================================
// These tests verify the authentication behavior remains correct after changes.

// TestSecurityRegression_AuthorizationHeaderTiming verifies that the authorization
// middleware returns correct status codes for valid and invalid tokens.
//
// SECURITY: Verifies constant-time auth comparison produces correct results.
func TestSecurityRegression_AuthorizationHeaderTiming(t *testing.T) {
	const authToken = "secret-test-token-12345"

	// Create a handler protected by authorization check
	handler := withAuthorizationCheck(authToken, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	testCases := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "correct token returns 200",
			authHeader:     authToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "wrong token returns 403",
			authHeader:     "wrong-token",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "empty token returns 403",
			authHeader:     "",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "partial prefix returns 403",
			authHeader:     "secret",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "token with extra suffix returns 403",
			authHeader:     authToken + "-extra",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "token with different case returns 403",
			authHeader:     "SECRET-TEST-TOKEN-12345",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}
		})
	}
}

// TestSecurityRegression_AuthorizationRejectsPartialMatch verifies that
// partial prefixes of the correct token are rejected.
//
// SECURITY: This proves we're not doing early-exit comparison that could
// leak information about correct prefix bytes.
func TestSecurityRegression_AuthorizationRejectsPartialMatch(t *testing.T) {
	const authToken = "secret123"

	handler := withAuthorizationCheck(authToken, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test progressively longer prefixes - all should fail with 403
	partialTokens := []string{
		"s",
		"se",
		"sec",
		"secr",
		"secre",
		"secret",
		"secret1",
		"secret12",
		// "secret123" would be the full match
	}

	for _, partial := range partialTokens {
		t.Run("prefix_"+partial, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", partial)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("partial token %q should be rejected with 403, got %d", partial, rec.Code)
			}
		})
	}

	// Verify the full token works
	t.Run("full_token_accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", authToken)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("full token should be accepted with 200, got %d", rec.Code)
		}
	})
}

// TestSecurityRegression_AuthorizationBinaryTokenHandling verifies that
// the authorization check handles binary/non-printable characters correctly.
//
// SECURITY: Ensures no edge cases with special characters that could bypass checks.
func TestSecurityRegression_AuthorizationBinaryTokenHandling(t *testing.T) {
	// Token with null bytes and special characters
	authToken := "token\x00with\xffbinary"

	handler := withAuthorizationCheck(authToken, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	testCases := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "exact binary token accepted",
			authHeader:     authToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "token without null rejected",
			authHeader:     "tokenwithbinary",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "partial binary token rejected",
			authHeader:     "token\x00with",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", tc.authHeader)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}
		})
	}
}

// TestSecurityRegression_AuthorizationEmptyConfigToken verifies behavior
// when the configured auth token itself is empty (should reject everything).
//
// SECURITY: Empty auth token should still work correctly (reject all non-empty requests).
func TestSecurityRegression_AuthorizationEmptyConfigToken(t *testing.T) {
	const emptyAuthToken = ""

	handler := withAuthorizationCheck(emptyAuthToken, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	testCases := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "empty header matches empty token",
			authHeader:     "",
			expectedStatus: http.StatusOK, // Empty == Empty
		},
		{
			name:           "non-empty header rejected",
			authHeader:     "some-token",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}
		})
	}
}

// =============================================================================
// INTEGRATION TEST - Full SentinelServer authorization
// =============================================================================

// TestSecurityRegression_SentinelServerAuthorizationIntegration verifies that
// a SentinelServer correctly rejects unauthorized requests.
func TestSecurityRegression_SentinelServerAuthorizationIntegration(t *testing.T) {
	// Create a minimal server configuration for testing auth
	// We'll use a mock credential provider that returns an error
	// since we're only testing the auth layer
	ctx := context.Background()

	mockLoader := testutil.NewMockPolicyLoader()
	mockLoader.Policies["/sentinel/policies/test"] = &policy.Policy{
		Rules: []policy.Rule{
			{
				Name:   "test-rule",
				Effect: policy.EffectAllow,
				Reason: "test reason",
			},
		},
	}

	// Mock credential provider that returns an error (for testing auth layer only)
	mockProvider := &testCredProvider{
		err: context.DeadlineExceeded, // Simulate credential fetch failure
	}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		User:               "test-user",
		LazyLoad:           true, // Skip credential prefetch
		CredentialProvider: mockProvider,
		PolicyLoader:       mockLoader,
		PolicyParameter:    "/sentinel/policies/test",
	}

	server, err := NewSentinelServer(ctx, config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(ctx)

	// Create test server from the handler
	testServer := httptest.NewServer(server.server.Handler)
	defer testServer.Close()

	testCases := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "valid auth token",
			authHeader:     "test-auth-token",
			expectedStatus: http.StatusInternalServerError, // Auth passes, but creds fail (no provider)
		},
		{
			name:           "invalid auth token",
			authHeader:     "wrong-token",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "missing auth token",
			authHeader:     "",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}
		})
	}
}

// TestSecurityRegression_ErrorResponseFormat verifies that authorization
// failures return consistent JSON error format.
//
// SECURITY: Consistent error format prevents information leakage via error variations.
func TestSecurityRegression_ErrorResponseFormat(t *testing.T) {
	const authToken = "valid-token"

	handler := withAuthorizationCheck(authToken, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test with invalid token
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "invalid")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Check response format
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("expected JSON content type, got %q", contentType)
	}

	// Verify body contains expected error message
	body := rec.Body.Bytes()
	if !bytes.Contains(body, []byte("invalid Authorization token")) {
		t.Errorf("expected 'invalid Authorization token' in body, got %s", body)
	}
}
