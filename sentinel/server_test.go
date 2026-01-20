package sentinel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/session"
	"github.com/byteness/aws-vault/v7/testutil"
)

// MockCredentialProvider implements CredentialProvider for testing.
type MockCredentialProvider struct {
	mu sync.Mutex

	// Configurable response
	CredentialResult *CredentialResult
	CredentialErr    error

	// Call tracking
	Calls []CredentialRequest
}

func (m *MockCredentialProvider) GetCredentialsWithSourceIdentity(ctx context.Context, req CredentialRequest) (*CredentialResult, error) {
	m.mu.Lock()
	m.Calls = append(m.Calls, req)
	m.mu.Unlock()

	if m.CredentialErr != nil {
		return nil, m.CredentialErr
	}
	if m.CredentialResult != nil {
		return m.CredentialResult, nil
	}
	// Default response
	return &CredentialResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
		Expiration:      time.Now().Add(1 * time.Hour),
		CanExpire:       true,
		SourceIdentity:  "sentinel:testuser:abc12345",
		RoleARN:         "arn:aws:iam::123456789012:role/TestRole",
	}, nil
}

func (m *MockCredentialProvider) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Calls)
}

// createTestPolicy creates a policy for testing.
func createTestPolicy(effect policy.Effect) *policy.Policy {
	return &policy.Policy{
		Rules: []policy.Rule{
			{
				Name:   "test-rule",
				Effect: effect,
				Reason: "test reason",
			},
		},
	}
}

// createTestServer creates a SentinelServer for testing with the given config overrides.
func createTestServer(t *testing.T, policyEffect policy.Effect, opts ...func(*SentinelServerConfig)) (*SentinelServer, string) {
	t.Helper()

	mockLoader := testutil.NewMockPolicyLoader()
	mockLoader.Policies["/sentinel/policies/test"] = createTestPolicy(policyEffect)

	mockProvider := &MockCredentialProvider{}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		Region:             "us-east-1",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		LazyLoad:           true, // Skip prefetch in tests
	}

	// Apply option overrides
	for _, opt := range opts {
		opt(&config)
	}

	server, err := NewSentinelServer(context.Background(), config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	return server, server.authToken
}

func TestSentinelServer_PolicyAllow(t *testing.T) {
	server, authToken := createTestServer(t, policy.EffectAllow)
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	// Record response
	rec := httptest.NewRecorder()

	// Call the handler directly
	server.DefaultRoute(rec, req)

	// Check response
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	// Parse response body
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify credentials are present
	if resp["AccessKeyId"] == "" {
		t.Error("Expected AccessKeyId in response")
	}
	if resp["SecretAccessKey"] == "" {
		t.Error("Expected SecretAccessKey in response")
	}
	if resp["Token"] == "" {
		t.Error("Expected Token in response")
	}
	if resp["Expiration"] == "" {
		t.Error("Expected Expiration in response")
	}
}

func TestSentinelServer_PolicyDeny(t *testing.T) {
	server, authToken := createTestServer(t, policy.EffectDeny)
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	// Record response
	rec := httptest.NewRecorder()

	// Call the handler directly
	server.DefaultRoute(rec, req)

	// Check response
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, rec.Code)
	}

	// Parse response body
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify error message
	if !strings.Contains(resp["Message"], "Policy denied access") {
		t.Errorf("Expected 'Policy denied access' message, got: %s", resp["Message"])
	}
}

func TestSentinelServer_PolicyDenyWithApproval(t *testing.T) {
	mockStore := testutil.NewMockRequestStore()
	// Configure mock to return an approved request
	mockStore.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
		if requester == "testuser" {
			return []*request.Request{
				{
					ID:        "req-12345678",
					Requester: "testuser",
					Profile:   "test-profile",
					Status:    request.StatusApproved,
					Duration:  1 * time.Hour,
					CreatedAt: time.Now().Add(-30 * time.Minute),
					ExpiresAt: time.Now().Add(30 * time.Minute),
				},
			}, nil
		}
		return nil, nil
	}

	server, authToken := createTestServer(t, policy.EffectDeny, func(c *SentinelServerConfig) {
		c.Store = mockStore
	})
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	// Record response
	rec := httptest.NewRecorder()

	// Call the handler directly
	server.DefaultRoute(rec, req)

	// Check response - should succeed due to approval override
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d (approval override), got %d", http.StatusOK, rec.Code)
	}

	// Parse response body
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify credentials are present
	if resp["AccessKeyId"] == "" {
		t.Error("Expected AccessKeyId in response (approval override)")
	}
}

func TestSentinelServer_PolicyDenyWithBreakGlass(t *testing.T) {
	mockStore := testutil.NewMockBreakGlassStore()
	// Configure mock to return an active break-glass event
	mockStore.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		if invoker == "testuser" {
			return []*breakglass.BreakGlassEvent{
				{
					ID:        "bg-12345678",
					Invoker:   "testuser",
					Profile:   "test-profile",
					Status:    breakglass.StatusActive,
					ExpiresAt: time.Now().Add(30 * time.Minute),
					CreatedAt: time.Now().Add(-30 * time.Minute),
				},
			}, nil
		}
		return nil, nil
	}

	server, authToken := createTestServer(t, policy.EffectDeny, func(c *SentinelServerConfig) {
		c.BreakGlassStore = mockStore
	})
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	// Record response
	rec := httptest.NewRecorder()

	// Call the handler directly
	server.DefaultRoute(rec, req)

	// Check response - should succeed due to break-glass override
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d (break-glass override), got %d", http.StatusOK, rec.Code)
	}

	// Parse response body
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify credentials are present
	if resp["AccessKeyId"] == "" {
		t.Error("Expected AccessKeyId in response (break-glass override)")
	}
}

func TestSentinelServer_AuthorizationRequired(t *testing.T) {
	server, _ := createTestServer(t, policy.EffectAllow)
	defer server.Shutdown(context.Background())

	tests := []struct {
		name      string
		authToken string
	}{
		{"missing auth token", ""},
		{"wrong auth token", "wrong-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.authToken != "" {
				req.Header.Set("Authorization", tt.authToken)
			}

			// Record response
			rec := httptest.NewRecorder()

			// Use the full handler with auth middleware
			handler := withAuthorizationCheck(server.authToken, server.DefaultRoute)
			handler(rec, req)

			// Check response
			if rec.Code != http.StatusForbidden {
				t.Errorf("Expected status %d, got %d", http.StatusForbidden, rec.Code)
			}

			// Parse response body
			var resp map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			// Verify error message
			if !strings.Contains(resp["Message"], "invalid Authorization token") {
				t.Errorf("Expected 'invalid Authorization token' message, got: %s", resp["Message"])
			}
		})
	}
}

func TestSentinelServer_DecisionLogging(t *testing.T) {
	tests := []struct {
		name           string
		effect         policy.Effect
		expectedEffect string
	}{
		{"allow decision logged", policy.EffectAllow, "allow"},
		{"deny decision logged", policy.EffectDeny, "deny"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLogger := testutil.NewMockLogger()

			server, authToken := createTestServer(t, tt.effect, func(c *SentinelServerConfig) {
				c.Logger = mockLogger
			})
			defer server.Shutdown(context.Background())

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", authToken)

			// Record response
			rec := httptest.NewRecorder()

			// Call the handler directly
			server.DefaultRoute(rec, req)

			// Verify decision was logged
			if mockLogger.DecisionCount() != 1 {
				t.Fatalf("Expected 1 decision log entry, got %d", mockLogger.DecisionCount())
			}

			entry := mockLogger.LastDecision()
			if entry.Effect != tt.expectedEffect {
				t.Errorf("Expected effect '%s', got '%s'", tt.expectedEffect, entry.Effect)
			}
			if entry.User != "testuser" {
				t.Errorf("Expected user 'testuser', got '%s'", entry.User)
			}
			if entry.Profile != "test-profile" {
				t.Errorf("Expected profile 'test-profile', got '%s'", entry.Profile)
			}
			if entry.PolicyPath != "/sentinel/policies/test" {
				t.Errorf("Expected policy path '/sentinel/policies/test', got '%s'", entry.PolicyPath)
			}
		})
	}
}

func TestSentinelServer_DecisionLogging_AllowWithCredentialFields(t *testing.T) {
	mockLogger := testutil.NewMockLogger()

	server, authToken := createTestServer(t, policy.EffectAllow, func(c *SentinelServerConfig) {
		c.Logger = mockLogger
	})
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	// Record response
	rec := httptest.NewRecorder()

	// Call the handler directly
	server.DefaultRoute(rec, req)

	// Verify decision was logged with credential fields
	if mockLogger.DecisionCount() != 1 {
		t.Fatalf("Expected 1 decision log entry, got %d", mockLogger.DecisionCount())
	}

	entry := mockLogger.LastDecision()

	// For allow decisions, credential fields should be populated
	if entry.Effect != "allow" {
		t.Errorf("Expected effect 'allow', got '%s'", entry.Effect)
	}
	if entry.SourceIdentity == "" {
		t.Error("Expected SourceIdentity in allow decision log")
	}
	if entry.RoleARN == "" {
		t.Error("Expected RoleARN in allow decision log")
	}
	if entry.RequestID == "" {
		t.Error("Expected RequestID in allow decision log")
	}
}

func TestSentinelServer_DecisionLogging_ApprovalOverride(t *testing.T) {
	mockLogger := testutil.NewMockLogger()
	mockStore := testutil.NewMockRequestStore()

	// Configure mock to return an approved request
	mockStore.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
		return []*request.Request{
			{
				ID:        "req-approval123",
				Requester: "testuser",
				Profile:   "test-profile",
				Status:    request.StatusApproved,
				Duration:  1 * time.Hour,
				CreatedAt: time.Now().Add(-30 * time.Minute),
				ExpiresAt: time.Now().Add(30 * time.Minute),
			},
		}, nil
	}

	server, authToken := createTestServer(t, policy.EffectDeny, func(c *SentinelServerConfig) {
		c.Logger = mockLogger
		c.Store = mockStore
	})
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	// Record response
	rec := httptest.NewRecorder()

	// Call the handler directly
	server.DefaultRoute(rec, req)

	// Verify decision was logged with approval ID
	if mockLogger.DecisionCount() != 1 {
		t.Fatalf("Expected 1 decision log entry, got %d", mockLogger.DecisionCount())
	}

	entry := mockLogger.LastDecision()

	// Policy denied but credentials were issued via approval
	if entry.ApprovedRequestID != "req-approval123" {
		t.Errorf("Expected ApprovedRequestID 'req-approval123', got '%s'", entry.ApprovedRequestID)
	}
}

func TestSentinelServer_DecisionLogging_BreakGlassOverride(t *testing.T) {
	mockLogger := testutil.NewMockLogger()
	mockStore := testutil.NewMockBreakGlassStore()

	// Configure mock to return an active break-glass event
	mockStore.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		return []*breakglass.BreakGlassEvent{
			{
				ID:        "bg-breakglass789",
				Invoker:   "testuser",
				Profile:   "test-profile",
				Status:    breakglass.StatusActive,
				ExpiresAt: time.Now().Add(30 * time.Minute),
				CreatedAt: time.Now().Add(-30 * time.Minute),
			},
		}, nil
	}

	server, authToken := createTestServer(t, policy.EffectDeny, func(c *SentinelServerConfig) {
		c.Logger = mockLogger
		c.BreakGlassStore = mockStore
	})
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	// Record response
	rec := httptest.NewRecorder()

	// Call the handler directly
	server.DefaultRoute(rec, req)

	// Verify decision was logged with break-glass ID
	if mockLogger.DecisionCount() != 1 {
		t.Fatalf("Expected 1 decision log entry, got %d", mockLogger.DecisionCount())
	}

	entry := mockLogger.LastDecision()

	// Policy denied but credentials were issued via break-glass
	if entry.BreakGlassEventID != "bg-breakglass789" {
		t.Errorf("Expected BreakGlassEventID 'bg-breakglass789', got '%s'", entry.BreakGlassEventID)
	}
}

func TestSentinelServer_BaseURL(t *testing.T) {
	server, _ := createTestServer(t, policy.EffectAllow)
	defer server.Shutdown(context.Background())

	baseURL := server.BaseURL()
	if !strings.HasPrefix(baseURL, "http://127.0.0.1:") {
		t.Errorf("Expected BaseURL to start with 'http://127.0.0.1:', got '%s'", baseURL)
	}
}

func TestSentinelServer_AuthToken(t *testing.T) {
	server, expectedToken := createTestServer(t, policy.EffectAllow)
	defer server.Shutdown(context.Background())

	authToken := server.AuthToken()
	if authToken != expectedToken {
		t.Errorf("Expected AuthToken '%s', got '%s'", expectedToken, authToken)
	}
}

func TestSentinelServer_GenerateRandomAuthToken(t *testing.T) {
	mockLoader := testutil.NewMockPolicyLoader()
	mockLoader.Policies["/sentinel/policies/test"] = createTestPolicy(policy.EffectAllow)

	mockProvider := &MockCredentialProvider{}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		LazyLoad:           true,
	}

	// Create server without auth token
	server, err := NewSentinelServer(context.Background(), config, "", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	// Auth token should be auto-generated
	if server.AuthToken() == "" {
		t.Error("Expected auto-generated auth token")
	}
	if len(server.AuthToken()) < 30 {
		t.Errorf("Expected auth token length >= 30, got %d", len(server.AuthToken()))
	}
}

func TestSentinelServer_SessionDurationCappedByBreakGlass(t *testing.T) {
	mockProvider := &MockCredentialProvider{}
	mockStore := testutil.NewMockBreakGlassStore()

	// Configure mock to return a break-glass event with 15 min remaining
	bgExpiry := time.Now().Add(15 * time.Minute)
	mockStore.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		return []*breakglass.BreakGlassEvent{
			{
				ID:        "bg-test123",
				Invoker:   "testuser",
				Profile:   "test-profile",
				Status:    breakglass.StatusActive,
				ExpiresAt: bgExpiry,
				CreatedAt: time.Now().Add(-15 * time.Minute),
			},
		}, nil
	}

	server, authToken := createTestServer(t, policy.EffectDeny, func(c *SentinelServerConfig) {
		c.BreakGlassStore = mockStore
		c.CredentialProvider = mockProvider
		c.SessionDuration = 1 * time.Hour // Request 1 hour
	})
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	// Record response
	rec := httptest.NewRecorder()

	// Call the handler directly
	server.DefaultRoute(rec, req)

	// Check that credentials were requested
	if mockProvider.CallCount() != 1 {
		t.Fatalf("Expected 1 credential request, got %d", mockProvider.CallCount())
	}

	// Check that session duration was capped
	credReq := mockProvider.Calls[0]
	// The session duration should be capped to remaining break-glass time (~15 min)
	// Allow 1 minute tolerance for test execution time
	if credReq.SessionDuration > 16*time.Minute {
		t.Errorf("Expected session duration to be capped to ~15 min, got %v", credReq.SessionDuration)
	}
}

func TestSentinelServer_NoLogger(t *testing.T) {
	// Test that server works without a logger configured
	server, authToken := createTestServer(t, policy.EffectAllow, func(c *SentinelServerConfig) {
		c.Logger = nil // No logger
	})
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	// Record response
	rec := httptest.NewRecorder()

	// Should not panic
	server.DefaultRoute(rec, req)

	// Should still return credentials
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestSentinelServer_Shutdown(t *testing.T) {
	server, _ := createTestServer(t, policy.EffectAllow)

	// Start server in background
	go server.Serve()

	// Give it time to start
	time.Sleep(10 * time.Millisecond)

	// Shutdown should succeed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := server.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

// TestWithLoggingMiddleware tests the logging middleware captures status codes.
func TestWithLoggingMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		handlerCode    int
		expectedStatus int
	}{
		{"200 OK", http.StatusOK, http.StatusOK},
		{"403 Forbidden", http.StatusForbidden, http.StatusForbidden},
		{"500 Internal Server Error", http.StatusInternalServerError, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.handlerCode)
			})

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()

			withLogging(handler).ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

// TestGenerateRandomString verifies randomness.
func TestGenerateRandomString(t *testing.T) {
	seen := make(map[string]bool)

	// Generate multiple strings and verify uniqueness
	for i := 0; i < 100; i++ {
		s := generateRandomString()
		if seen[s] {
			t.Errorf("Duplicate random string generated: %s", s)
		}
		seen[s] = true

		// Verify minimum length (30 bytes -> 40 chars in base64)
		if len(s) < 30 {
			t.Errorf("Random string too short: %d chars", len(s))
		}
	}
}

// ============================================================================
// Mode condition tests - verify server mode policy integration
// ============================================================================

// createModeConditionalPolicy creates a policy that only allows a specific mode.
func createModeConditionalPolicy(effect policy.Effect, allowedMode policy.CredentialMode) *policy.Policy {
	return &policy.Policy{
		Rules: []policy.Rule{
			{
				Name:       "mode-conditional",
				Effect:     effect,
				Conditions: policy.Condition{Mode: []policy.CredentialMode{allowedMode}},
			},
		},
	}
}

func TestSentinelServer_ModeCondition_ServerAllowed(t *testing.T) {
	// Policy allows only server mode
	mockLoader := testutil.NewMockPolicyLoader()
	mockLoader.Policies["/sentinel/policies/test"] = createModeConditionalPolicy(policy.EffectAllow, policy.ModeServer)

	mockProvider := &MockCredentialProvider{}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-auth-token")

	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// Server should be allowed (policy allows server mode)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d (server mode allowed), got %d", http.StatusOK, rec.Code)
	}
}

func TestSentinelServer_PassesModeServer(t *testing.T) {
	// Use a mock policy loader that captures the request
	mockLogger := testutil.NewMockLogger()

	server, authToken := createTestServer(t, policy.EffectAllow, func(c *SentinelServerConfig) {
		c.Logger = mockLogger
	})
	defer server.Shutdown(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)

	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// The logged decision should show the request was for server mode
	// We can verify this indirectly through the decision log which includes request details
	if mockLogger.DecisionCount() != 1 {
		t.Fatalf("Expected 1 decision log, got %d", mockLogger.DecisionCount())
	}

	// Verify credentials were issued (mode allowed)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestSentinelServer_ModeCondition_CLIOnlyDeniesServer(t *testing.T) {
	// Policy allows only CLI mode - should deny server requests
	mockLoader := testutil.NewMockPolicyLoader()
	mockLoader.Policies["/sentinel/policies/test"] = createModeConditionalPolicy(policy.EffectAllow, policy.ModeCLI)

	mockProvider := &MockCredentialProvider{}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-auth-token")

	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// Server should be denied (policy only allows CLI mode)
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status %d (CLI-only policy denies server), got %d", http.StatusForbidden, rec.Code)
	}
}

func TestSentinelServer_ModeCondition_CredentialProcessOnlyDeniesServer(t *testing.T) {
	// Policy allows only credential_process mode - should deny server requests
	mockLoader := testutil.NewMockPolicyLoader()
	mockLoader.Policies["/sentinel/policies/test"] = createModeConditionalPolicy(policy.EffectAllow, policy.ModeCredentialProcess)

	mockProvider := &MockCredentialProvider{}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-auth-token")

	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// Server should be denied (policy only allows credential_process mode)
	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status %d (credential_process-only denies server), got %d", http.StatusForbidden, rec.Code)
	}
}

// ============================================================================
// Server duration tests - verify short-lived session handling
// ============================================================================

func TestDefaultServerSessionDuration(t *testing.T) {
	// Verify the constant is 15 minutes
	if DefaultServerSessionDuration != 15*time.Minute {
		t.Errorf("expected DefaultServerSessionDuration to be 15 minutes, got %v", DefaultServerSessionDuration)
	}
}

// createPolicyWithMaxDuration creates a policy with a MaxServerDuration cap.
func createPolicyWithMaxDuration(effect policy.Effect, maxDuration time.Duration) *policy.Policy {
	return &policy.Policy{
		Rules: []policy.Rule{
			{
				Name:              "duration-capped-rule",
				Effect:            effect,
				MaxServerDuration: maxDuration,
			},
		},
	}
}

func TestSentinelServer_PolicyDurationCapping(t *testing.T) {
	mockProvider := &MockCredentialProvider{}
	mockLoader := testutil.NewMockPolicyLoader()

	// Policy allows but caps duration to 5 minutes
	mockLoader.Policies["/sentinel/policies/test"] = createPolicyWithMaxDuration(policy.EffectAllow, 5*time.Minute)

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		SessionDuration:    1 * time.Hour, // Request 1 hour
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-auth-token")

	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// Check response
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	// Check that credentials were requested with capped duration
	if mockProvider.CallCount() != 1 {
		t.Fatalf("Expected 1 credential request, got %d", mockProvider.CallCount())
	}

	credReq := mockProvider.Calls[0]
	// Session duration should be capped to 5 minutes from policy
	if credReq.SessionDuration != 5*time.Minute {
		t.Errorf("Expected session duration to be capped to 5m, got %v", credReq.SessionDuration)
	}
}

func TestSentinelServer_PolicyDurationCap_NoCapWhenZero(t *testing.T) {
	mockProvider := &MockCredentialProvider{}
	mockLoader := testutil.NewMockPolicyLoader()

	// Policy allows but has no duration cap (0 = no cap)
	mockLoader.Policies["/sentinel/policies/test"] = createPolicyWithMaxDuration(policy.EffectAllow, 0)

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		SessionDuration:    30 * time.Minute, // Request 30 minutes
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-auth-token")

	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if mockProvider.CallCount() != 1 {
		t.Fatalf("Expected 1 credential request, got %d", mockProvider.CallCount())
	}

	credReq := mockProvider.Calls[0]
	// Session duration should not be capped (policy has 0 = no cap)
	if credReq.SessionDuration != 30*time.Minute {
		t.Errorf("Expected session duration 30m (no cap), got %v", credReq.SessionDuration)
	}
}

func TestSentinelServer_PolicyAndBreakGlassCapInteraction(t *testing.T) {
	// Test that the smallest cap wins: policy cap vs break-glass remaining time
	mockProvider := &MockCredentialProvider{}
	mockLoader := testutil.NewMockPolicyLoader()
	mockStore := testutil.NewMockBreakGlassStore()

	// Policy caps at 10 minutes
	mockLoader.Policies["/sentinel/policies/test"] = createPolicyWithMaxDuration(policy.EffectDeny, 10*time.Minute)

	// Break-glass expires in 5 minutes (smaller than policy cap)
	bgExpiry := time.Now().Add(5 * time.Minute)
	mockStore.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		return []*breakglass.BreakGlassEvent{
			{
				ID:        "bg-cap-test",
				Invoker:   "testuser",
				Profile:   "test-profile",
				Status:    breakglass.StatusActive,
				ExpiresAt: bgExpiry,
				CreatedAt: time.Now().Add(-5 * time.Minute),
			},
		}, nil
	}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		BreakGlassStore:    mockStore,
		SessionDuration:    1 * time.Hour, // Request 1 hour
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-auth-token")

	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// Should succeed via break-glass override
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if mockProvider.CallCount() != 1 {
		t.Fatalf("Expected 1 credential request, got %d", mockProvider.CallCount())
	}

	credReq := mockProvider.Calls[0]
	// Break-glass remaining (5 min) is smaller than policy cap (10 min)
	// so should be capped to ~5 minutes
	if credReq.SessionDuration > 6*time.Minute {
		t.Errorf("Expected session duration to be capped to ~5m (break-glass remaining), got %v", credReq.SessionDuration)
	}
}

func TestSentinelServer_PolicyCapSmallerThanBreakGlass(t *testing.T) {
	// Test when policy cap is smaller than break-glass remaining time
	mockProvider := &MockCredentialProvider{}
	mockLoader := testutil.NewMockPolicyLoader()
	mockStore := testutil.NewMockBreakGlassStore()

	// Policy caps at 3 minutes
	mockLoader.Policies["/sentinel/policies/test"] = createPolicyWithMaxDuration(policy.EffectDeny, 3*time.Minute)

	// Break-glass expires in 30 minutes (larger than policy cap)
	bgExpiry := time.Now().Add(30 * time.Minute)
	mockStore.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		return []*breakglass.BreakGlassEvent{
			{
				ID:        "bg-larger-test",
				Invoker:   "testuser",
				Profile:   "test-profile",
				Status:    breakglass.StatusActive,
				ExpiresAt: bgExpiry,
				CreatedAt: time.Now().Add(-5 * time.Minute),
			},
		}, nil
	}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		BreakGlassStore:    mockStore,
		SessionDuration:    1 * time.Hour, // Request 1 hour
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-auth-token")

	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// Should succeed via break-glass override
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if mockProvider.CallCount() != 1 {
		t.Fatalf("Expected 1 credential request, got %d", mockProvider.CallCount())
	}

	credReq := mockProvider.Calls[0]
	// Policy cap (3 min) is applied first, which is smaller than break-glass remaining (30 min)
	// So should be capped to 3 minutes from policy
	if credReq.SessionDuration != 3*time.Minute {
		t.Errorf("Expected session duration to be capped to 3m (policy cap), got %v", credReq.SessionDuration)
	}
}

func TestSentinelServer_ModeCondition_EmptyModeAllowsServer(t *testing.T) {
	// Policy with no mode condition (empty) should allow any mode including server
	mockLoader := testutil.NewMockPolicyLoader()
	mockLoader.Policies["/sentinel/policies/test"] = &policy.Policy{
		Rules: []policy.Rule{
			{
				Name:   "any-mode",
				Effect: policy.EffectAllow,
				// No Mode condition - wildcard
			},
		},
	}

	mockProvider := &MockCredentialProvider{}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-auth-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "test-auth-token")

	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// Server should be allowed (empty mode = wildcard)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d (empty mode = wildcard allows server), got %d", http.StatusOK, rec.Code)
	}
}

// ============================================================================
// require_server effect tests - verify server mode allows require_server rules
// ============================================================================

func TestSentinelServer_RequireServerEffect_Allowed(t *testing.T) {
	// Create policy with require_server effect
	requireServerPolicy := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "prod-requires-server",
				Effect: policy.EffectRequireServer,
				Conditions: policy.Condition{
					Profiles: []string{"production"},
				},
				Reason: "Production requires server mode",
			},
		},
	}

	mockLoader := testutil.NewMockPolicyLoader()
	mockLoader.Policies["/sentinel/policies/test"] = requireServerPolicy

	mockProvider := &MockCredentialProvider{
		CredentialResult: &CredentialResult{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "token",
			Expiration:      time.Now().Add(15 * time.Minute),
			CanExpire:       true,
			SourceIdentity:  "sentinel:testuser:abc123",
			RoleARN:         "arn:aws:iam::123456789012:role/TestRole",
		},
	}

	config := SentinelServerConfig{
		ProfileName:        "production",
		PolicyParameter:    "/sentinel/policies/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	// Make request
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "test-token")
	rec := httptest.NewRecorder()

	server.DefaultRoute(rec, req)

	// Should allow - server mode satisfies require_server
	if rec.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d. Body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Verify credentials returned
	var creds map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&creds); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if creds["AccessKeyId"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AccessKeyId = %v, want AKIAIOSFODNN7EXAMPLE", creds["AccessKeyId"])
	}
}

// ============================================================================
// Session tracking tests
// ============================================================================

// MockSessionStore implements session.Store for testing.
type MockSessionStore struct {
	mu sync.Mutex

	// Configurable behavior
	CreateErr error
	GetResult *session.ServerSession
	GetErr    error
	UpdateErr error
	TouchErr  error

	// Call tracking
	CreateCalls []session.ServerSession
	GetCalls    []string
	UpdateCalls []session.ServerSession
	TouchCalls  []string

	// Internal state for tracking created sessions
	sessions map[string]*session.ServerSession
}

func NewMockSessionStore() *MockSessionStore {
	return &MockSessionStore{
		sessions: make(map[string]*session.ServerSession),
	}
}

func (m *MockSessionStore) Create(ctx context.Context, sess *session.ServerSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CreateCalls = append(m.CreateCalls, *sess)
	if m.CreateErr != nil {
		return m.CreateErr
	}
	// Store a copy
	copy := *sess
	m.sessions[sess.ID] = &copy
	return nil
}

func (m *MockSessionStore) Get(ctx context.Context, id string) (*session.ServerSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetCalls = append(m.GetCalls, id)
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	if m.GetResult != nil {
		return m.GetResult, nil
	}
	// Return from internal map if available
	if sess, ok := m.sessions[id]; ok {
		copy := *sess
		return &copy, nil
	}
	return nil, session.ErrSessionNotFound
}

func (m *MockSessionStore) Update(ctx context.Context, sess *session.ServerSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.UpdateCalls = append(m.UpdateCalls, *sess)
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	// Update internal map
	if _, ok := m.sessions[sess.ID]; ok {
		copy := *sess
		m.sessions[sess.ID] = &copy
	}
	return nil
}

func (m *MockSessionStore) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *MockSessionStore) ListByUser(ctx context.Context, user string, limit int) ([]*session.ServerSession, error) {
	return nil, nil
}

func (m *MockSessionStore) ListByStatus(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
	return nil, nil
}

func (m *MockSessionStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*session.ServerSession, error) {
	return nil, nil
}

func (m *MockSessionStore) FindActiveByServerInstance(ctx context.Context, serverInstanceID string) (*session.ServerSession, error) {
	return nil, nil
}

func (m *MockSessionStore) Touch(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TouchCalls = append(m.TouchCalls, id)
	if m.TouchErr != nil {
		return m.TouchErr
	}
	// Update request count if session exists
	if sess, ok := m.sessions[id]; ok {
		sess.RequestCount++
		sess.LastAccessAt = time.Now().UTC()
	}
	return nil
}

func (m *MockSessionStore) CreateCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.CreateCalls)
}

func (m *MockSessionStore) TouchCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.TouchCalls)
}

func (m *MockSessionStore) UpdateCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.UpdateCalls)
}

func (m *MockSessionStore) LastCreateCall() *session.ServerSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.CreateCalls) == 0 {
		return nil
	}
	sess := m.CreateCalls[len(m.CreateCalls)-1]
	return &sess
}

func (m *MockSessionStore) LastUpdateCall() *session.ServerSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.UpdateCalls) == 0 {
		return nil
	}
	sess := m.UpdateCalls[len(m.UpdateCalls)-1]
	return &sess
}

func TestSentinelServer_SessionCreation(t *testing.T) {
	mockStore := NewMockSessionStore()

	server, _ := createTestServer(t, policy.EffectAllow, func(c *SentinelServerConfig) {
		c.SessionStore = mockStore
	})
	defer server.Shutdown(context.Background())

	// Verify Create was called on startup
	if mockStore.CreateCallCount() != 1 {
		t.Fatalf("Expected 1 session Create call on startup, got %d", mockStore.CreateCallCount())
	}

	// Verify session fields
	createdSession := mockStore.LastCreateCall()
	if createdSession == nil {
		t.Fatal("Expected created session to be recorded")
	}
	if createdSession.User != "testuser" {
		t.Errorf("Expected User 'testuser', got '%s'", createdSession.User)
	}
	if createdSession.Profile != "test-profile" {
		t.Errorf("Expected Profile 'test-profile', got '%s'", createdSession.Profile)
	}
	if createdSession.Status != session.StatusActive {
		t.Errorf("Expected Status 'active', got '%s'", createdSession.Status)
	}
	if createdSession.ServerInstanceID == "" {
		t.Error("Expected ServerInstanceID to be set")
	}
	if !session.ValidateSessionID(createdSession.ID) {
		t.Errorf("Expected valid session ID, got '%s'", createdSession.ID)
	}

	// Verify server has sessionID set
	if server.sessionID == "" {
		t.Error("Expected server.sessionID to be set after successful Create")
	}
}

func TestSentinelServer_SessionTouch(t *testing.T) {
	mockStore := NewMockSessionStore()

	server, authToken := createTestServer(t, policy.EffectAllow, func(c *SentinelServerConfig) {
		c.SessionStore = mockStore
	})
	defer server.Shutdown(context.Background())

	// Issue a credential request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)
	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// Verify credentials were issued
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}

	// Verify Touch was called
	if mockStore.TouchCallCount() != 1 {
		t.Fatalf("Expected 1 Touch call after credential issuance, got %d", mockStore.TouchCallCount())
	}

	// Issue another request
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", authToken)
	rec2 := httptest.NewRecorder()
	server.DefaultRoute(rec2, req2)

	// Verify Touch was called again
	if mockStore.TouchCallCount() != 2 {
		t.Fatalf("Expected 2 Touch calls after second credential issuance, got %d", mockStore.TouchCallCount())
	}
}

func TestSentinelServer_SessionShutdown(t *testing.T) {
	mockStore := NewMockSessionStore()

	server, _ := createTestServer(t, policy.EffectAllow, func(c *SentinelServerConfig) {
		c.SessionStore = mockStore
	})

	// Verify session was created
	if mockStore.CreateCallCount() != 1 {
		t.Fatalf("Expected 1 Create call, got %d", mockStore.CreateCallCount())
	}

	// Shutdown server
	err := server.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Verify Update was called to set Status=Expired
	if mockStore.UpdateCallCount() != 1 {
		t.Fatalf("Expected 1 Update call on shutdown, got %d", mockStore.UpdateCallCount())
	}

	updatedSession := mockStore.LastUpdateCall()
	if updatedSession == nil {
		t.Fatal("Expected updated session to be recorded")
	}
	if updatedSession.Status != session.StatusExpired {
		t.Errorf("Expected Status 'expired' on shutdown, got '%s'", updatedSession.Status)
	}
}

func TestSentinelServer_SessionTrackingOptional(t *testing.T) {
	// Test that server works without SessionStore configured
	server, authToken := createTestServer(t, policy.EffectAllow, func(c *SentinelServerConfig) {
		c.SessionStore = nil // No session tracking
	})
	defer server.Shutdown(context.Background())

	// Verify sessionID is empty
	if server.sessionID != "" {
		t.Errorf("Expected empty sessionID when no SessionStore, got '%s'", server.sessionID)
	}

	// Issue a credential request - should not panic
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)
	rec := httptest.NewRecorder()

	// Should not panic
	server.DefaultRoute(rec, req)

	// Should still return credentials
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestSentinelServer_SessionCreationFailure(t *testing.T) {
	// Test that server still starts when session creation fails (best-effort)
	mockStore := NewMockSessionStore()
	mockStore.CreateErr = session.ErrSessionExists // Simulate creation failure

	server, authToken := createTestServer(t, policy.EffectAllow, func(c *SentinelServerConfig) {
		c.SessionStore = mockStore
	})
	defer server.Shutdown(context.Background())

	// Verify Create was attempted
	if mockStore.CreateCallCount() != 1 {
		t.Fatalf("Expected 1 Create call attempt, got %d", mockStore.CreateCallCount())
	}

	// Verify sessionID is empty (creation failed)
	if server.sessionID != "" {
		t.Errorf("Expected empty sessionID after Create failure, got '%s'", server.sessionID)
	}

	// Server should still work (best-effort tracking)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)
	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestSentinelServer_SessionTouchNotOnDeny(t *testing.T) {
	// Test that Touch is NOT called when policy denies access
	mockStore := NewMockSessionStore()

	server, authToken := createTestServer(t, policy.EffectDeny, func(c *SentinelServerConfig) {
		c.SessionStore = mockStore
	})
	defer server.Shutdown(context.Background())

	// Issue a credential request that will be denied
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authToken)
	rec := httptest.NewRecorder()
	server.DefaultRoute(rec, req)

	// Verify request was denied
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected status %d, got %d", http.StatusForbidden, rec.Code)
	}

	// Verify Touch was NOT called (no credentials issued)
	if mockStore.TouchCallCount() != 0 {
		t.Errorf("Expected 0 Touch calls on deny, got %d", mockStore.TouchCallCount())
	}
}
