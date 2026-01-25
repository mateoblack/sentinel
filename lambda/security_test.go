package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// ============================================================================
// Security Regression Tests
//
// These tests verify TVM security properties cannot be bypassed:
// 1. Policy bypass prevention - deny policies must block access
// 2. SourceIdentity enforcement - always stamped on credentials
// 3. Caller identity extraction - from API Gateway context, not spoofable
// 4. Session tracking enforcement - sessions created and revocation enforced
// 5. Approval/break-glass checks - only approved requests bypass deny
// ============================================================================

// TestSecurityRegression_PolicyBypassPrevention verifies that requests are rejected
// when policy denies access, even with valid caller credentials.
func TestSecurityRegression_PolicyBypassPrevention(t *testing.T) {
	t.Run("deny policy blocks valid credentials", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should NEVER be called when policy denies - security violation")
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := testTVMConfig(&mockPolicyLoader{policy: denyAllPolicy()}, mockClient)
		handler := NewHandler(cfg)

		// Valid credentials with valid profile - but policy denies
		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		// MUST return 403 Forbidden
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Policy deny MUST return 403, got %d - SECURITY VIOLATION", resp.StatusCode)
		}

		var errResp TVMError
		if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
			t.Fatalf("Failed to unmarshal error: %v", err)
		}
		if errResp.Code != "POLICY_DENY" {
			t.Errorf("Error code = %s, want POLICY_DENY", errResp.Code)
		}
	})

	t.Run("deny policy with approval/breakglass stores but no overrides", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should NEVER be called when denied with no override - security violation")
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: denyAllPolicy()},
			ApprovalStore:   &mockApprovalStore{},   // Empty - no approved request
			BreakGlassStore: &mockBreakGlassStore{}, // Empty - no break-glass
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Policy deny without override MUST return 403, got %d - SECURITY VIOLATION", resp.StatusCode)
		}
	})

	t.Run("policy deny reason exposed in response", func(t *testing.T) {
		customDenyPolicy := &policy.Policy{
			Rules: []policy.Rule{{
				Name:   "deny-after-hours",
				Effect: policy.EffectDeny,
				Reason: "Access denied outside business hours",
			}},
		}

		mockClient := &testSTSClient{}
		cfg := testTVMConfig(&mockPolicyLoader{policy: customDenyPolicy}, mockClient)
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		var errResp TVMError
		if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
			t.Fatalf("Failed to unmarshal error: %v", err)
		}
		if errResp.Message != "Policy denied: Access denied outside business hours" {
			t.Errorf("Error message = %s, want deny reason included", errResp.Message)
		}
	})
}

// TestSecurityRegression_SourceIdentityEnforcement verifies that SourceIdentity
// is ALWAYS stamped on credentials with the sentinel: prefix.
func TestSecurityRegression_SourceIdentityEnforcement(t *testing.T) {
	t.Run("source identity always starts with sentinel prefix", func(t *testing.T) {
		var capturedSourceIdentity string
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				if params.SourceIdentity != nil {
					capturedSourceIdentity = *params.SourceIdentity
				}
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/test-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected success, got %d", resp.StatusCode)
		}

		// SourceIdentity MUST be set
		if capturedSourceIdentity == "" {
			t.Error("SourceIdentity MUST be set on all credential requests - SECURITY VIOLATION")
		}

		// SourceIdentity MUST start with "sentinel:"
		if len(capturedSourceIdentity) < 9 || capturedSourceIdentity[:9] != "sentinel:" {
			t.Errorf("SourceIdentity MUST start with 'sentinel:', got %s - SECURITY VIOLATION", capturedSourceIdentity)
		}
	})

	t.Run("source identity includes username", func(t *testing.T) {
		var capturedSourceIdentity string
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				if params.SourceIdentity != nil {
					capturedSourceIdentity = *params.SourceIdentity
				}
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/test-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected success")
		}

		// Format: sentinel:<user>:<approval-marker>:<request-id>
		// For direct access: sentinel:testuser:direct:<requestid>
		expectedPrefix := "sentinel:testuser:"
		if len(capturedSourceIdentity) < len(expectedPrefix) ||
			capturedSourceIdentity[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("SourceIdentity = %s, should contain username 'testuser'", capturedSourceIdentity)
		}
	})

	t.Run("source identity includes approval ID when via approved request", func(t *testing.T) {
		var capturedSourceIdentity string
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				if params.SourceIdentity != nil {
					capturedSourceIdentity = *params.SourceIdentity
				}
				return successfulTestSTSResponse(), nil
			},
		}

		approvedReq := &request.Request{
			ID:        "approval-test-abc123",
			Requester: "testuser",
			Profile:   "arn:aws:iam::123456789012:role/prod-role",
			Status:    request.StatusApproved,
			CreatedAt: time.Now().Add(-time.Hour),
			ExpiresAt: time.Now().Add(time.Hour),
			Duration:  2 * time.Hour,
		}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: denyAllPolicy()}, // Deny but approved request overrides
			ApprovalStore:   &mockApprovalStore{approvedRequest: approvedReq},
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected success with approved request override, got %d", resp.StatusCode)
		}

		// Format: sentinel:<user>:<approval-id>:<request-id>
		expectedPrefix := "sentinel:testuser:approval-test-abc123:"
		if len(capturedSourceIdentity) < len(expectedPrefix) ||
			capturedSourceIdentity[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("SourceIdentity = %s, should contain approval ID 'approval-test-abc123'", capturedSourceIdentity)
		}
	})
}

// TestSecurityRegression_CallerIdentityExtraction verifies that caller identity
// is extracted from API Gateway request context (not spoofable from request body/headers).
func TestSecurityRegression_CallerIdentityExtraction(t *testing.T) {
	t.Run("missing IAM auth returns 403", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should not be called without IAM auth")
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
		handler := NewHandler(cfg)

		// Request WITHOUT IAM authorization context
		req := events.APIGatewayV2HTTPRequest{
			QueryStringParameters: map[string]string{
				"profile": "arn:aws:iam::123456789012:role/prod-role",
			},
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				Authorizer: nil, // No IAM authorizer - simulates unsigned request
			},
		}

		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Missing IAM auth MUST return 403, got %d - SECURITY VIOLATION", resp.StatusCode)
		}

		var errResp TVMError
		if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
			t.Fatalf("Failed to unmarshal error: %v", err)
		}
		if errResp.Code != "IAM_AUTH_REQUIRED" {
			t.Errorf("Error code = %s, want IAM_AUTH_REQUIRED", errResp.Code)
		}
	})

	t.Run("empty IAM context returns 403", func(t *testing.T) {
		mockClient := &testSTSClient{}
		cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
		handler := NewHandler(cfg)

		// Request with authorizer but empty IAM context
		req := events.APIGatewayV2HTTPRequest{
			QueryStringParameters: map[string]string{
				"profile": "arn:aws:iam::123456789012:role/prod-role",
			},
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
					IAM: nil, // Empty IAM context
				},
			},
		}

		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Empty IAM context MUST return 403, got %d - SECURITY VIOLATION", resp.StatusCode)
		}
	})

	t.Run("caller identity from API Gateway context not headers", func(t *testing.T) {
		var capturedSourceIdentity string
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				if params.SourceIdentity != nil {
					capturedSourceIdentity = *params.SourceIdentity
				}
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
		handler := NewHandler(cfg)

		// Request with valid API Gateway IAM context (the REAL identity)
		// and potentially spoofed headers (which MUST be ignored)
		req := events.APIGatewayV2HTTPRequest{
			QueryStringParameters: map[string]string{
				"profile": "arn:aws:iam::123456789012:role/test-role",
			},
			Headers: map[string]string{
				// Attempt to spoof identity via headers - MUST be ignored
				"X-Amz-User-Arn": "arn:aws:iam::999999999999:user/attacker",
				"X-Amz-Account":  "999999999999",
			},
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
					IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
						AccountID: "123456789012",
						UserARN:   "arn:aws:iam::123456789012:user/realuser", // REAL identity
						UserID:    "AIDAEXAMPLE",
					},
				},
			},
		}

		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected success, got %d", resp.StatusCode)
		}

		// SourceIdentity MUST contain the REAL user from API Gateway, NOT spoofed header
		expectedPrefix := "sentinel:realuser:"
		if len(capturedSourceIdentity) < len(expectedPrefix) ||
			capturedSourceIdentity[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("SourceIdentity = %s, should use 'realuser' from API Gateway not spoofed header - SECURITY VIOLATION", capturedSourceIdentity)
		}

		// Ensure attacker username is NOT in SourceIdentity
		if len(capturedSourceIdentity) > 0 && capturedSourceIdentity[9:17] == "attacker" {
			t.Errorf("SourceIdentity contains spoofed 'attacker' identity - CRITICAL SECURITY VIOLATION")
		}
	})
}

// TestSecurityRegression_SessionTrackingEnforcement verifies session tracking
// behavior when configured.
func TestSecurityRegression_SessionTrackingEnforcement(t *testing.T) {
	t.Run("session created when store configured", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				return successfulTestSTSResponse(), nil
			},
		}

		sessionStore := &handlerMockSessionStore{}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: allowAllPolicy()},
			SessionStore:    sessionStore,
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/test-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected success, got %d", resp.StatusCode)
		}

		// Session MUST be created
		if sessionStore.session == nil {
			t.Error("Session should have been created when SessionStore is configured")
		} else {
			if sessionStore.session.User != "testuser" {
				t.Errorf("Session User = %s, want testuser", sessionStore.session.User)
			}
			if sessionStore.session.Profile != "arn:aws:iam::123456789012:role/test-role" {
				t.Errorf("Session Profile mismatch")
			}
		}
	})

	t.Run("revoked session blocks credentials", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should NOT be called when session is revoked - SECURITY VIOLATION")
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: allowAllPolicy()},
			SessionStore:    &handlerMockSessionStore{revoked: true}, // Session revoked
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/test-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		// MUST return 403 when session is revoked
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Revoked session MUST return 403, got %d - SECURITY VIOLATION", resp.StatusCode)
		}

		var errResp TVMError
		if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
			t.Fatalf("Failed to unmarshal error: %v", err)
		}
		if errResp.Code != "SESSION_REVOKED" {
			t.Errorf("Error code = %s, want SESSION_REVOKED", errResp.Code)
		}
	})

	t.Run("session ID passed to STS as tag", func(t *testing.T) {
		var capturedSessionTag string
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				for _, tag := range params.Tags {
					if *tag.Key == "SentinelSessionID" {
						capturedSessionTag = *tag.Value
					}
				}
				return successfulTestSTSResponse(), nil
			},
		}

		sessionStore := &handlerMockSessionStore{}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: allowAllPolicy()},
			SessionStore:    sessionStore,
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/test-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected success, got %d", resp.StatusCode)
		}

		// Session ID MUST be passed to STS for downstream revocation checks
		if capturedSessionTag == "" {
			t.Error("SentinelSessionID tag MUST be passed to STS for session tracking")
		}
	})
}

// TestSecurityRegression_ApprovalBreakGlassChecks verifies the approval and
// break-glass override logic.
func TestSecurityRegression_ApprovalBreakGlassChecks(t *testing.T) {
	t.Run("approved request overrides policy deny", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				return successfulTestSTSResponse(), nil
			},
		}

		approvedReq := &request.Request{
			ID:        "approved-request-123",
			Requester: "testuser",
			Profile:   "arn:aws:iam::123456789012:role/prod-role",
			Status:    request.StatusApproved,
			CreatedAt: time.Now().Add(-time.Hour),
			ExpiresAt: time.Now().Add(time.Hour),
			Duration:  2 * time.Hour,
		}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: denyAllPolicy()},
			ApprovalStore:   &mockApprovalStore{approvedRequest: approvedReq},
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		// Should succeed because approved request overrides deny
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Approved request should override policy deny, got %d", resp.StatusCode)
		}
	})

	t.Run("pending request does NOT override policy deny", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should NOT be called for pending (not approved) request")
				return successfulTestSTSResponse(), nil
			},
		}

		// Pending request - NOT approved
		pendingReq := &request.Request{
			ID:        "pending-request-456",
			Requester: "testuser",
			Profile:   "arn:aws:iam::123456789012:role/prod-role",
			Status:    request.StatusPending, // NOT approved
			CreatedAt: time.Now().Add(-time.Hour),
			ExpiresAt: time.Now().Add(time.Hour),
			Duration:  2 * time.Hour,
		}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: denyAllPolicy()},
			ApprovalStore:   &mockApprovalStore{approvedRequest: pendingReq}, // Will not match because status != Approved
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		// Should be denied - pending request doesn't override
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Pending request should NOT override deny, got %d - SECURITY VIOLATION", resp.StatusCode)
		}
	})

	t.Run("break-glass overrides policy deny", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				return successfulTestSTSResponse(), nil
			},
		}

		bgEvent := &breakglass.BreakGlassEvent{
			ID:        "bg-event-789",
			Invoker:   "testuser",
			Profile:   "arn:aws:iam::123456789012:role/prod-role",
			Status:    breakglass.StatusActive,
			CreatedAt: time.Now().Add(-30 * time.Minute),
			ExpiresAt: time.Now().Add(30 * time.Minute),
			Duration:  time.Hour,
		}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: denyAllPolicy()},
			ApprovalStore:   &mockApprovalStore{},                         // Empty - no approved request
			BreakGlassStore: &mockBreakGlassStore{activeEvent: bgEvent},
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		// Should succeed because break-glass overrides deny
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Active break-glass should override policy deny, got %d", resp.StatusCode)
		}
	})

	t.Run("expired break-glass does NOT override policy deny", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should NOT be called for expired break-glass")
				return successfulTestSTSResponse(), nil
			},
		}

		// Expired break-glass event
		expiredBG := &breakglass.BreakGlassEvent{
			ID:        "bg-expired-000",
			Invoker:   "testuser",
			Profile:   "arn:aws:iam::123456789012:role/prod-role",
			Status:    breakglass.StatusExpired, // Expired
			CreatedAt: time.Now().Add(-2 * time.Hour),
			ExpiresAt: time.Now().Add(-time.Hour), // Already expired
			Duration:  time.Hour,
		}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: denyAllPolicy()},
			BreakGlassStore: &mockBreakGlassStore{activeEvent: expiredBG}, // Will not match because status != Active
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		// Should be denied - expired break-glass doesn't override
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expired break-glass should NOT override deny, got %d - SECURITY VIOLATION", resp.StatusCode)
		}
	})

	t.Run("break-glass for wrong profile does NOT override", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should NOT be called for break-glass on different profile")
				return successfulTestSTSResponse(), nil
			},
		}

		// Break-glass for different profile
		wrongProfileBG := &breakglass.BreakGlassEvent{
			ID:        "bg-wrong-profile",
			Invoker:   "testuser",
			Profile:   "arn:aws:iam::123456789012:role/other-role", // Different profile
			Status:    breakglass.StatusActive,
			CreatedAt: time.Now().Add(-30 * time.Minute),
			ExpiresAt: time.Now().Add(30 * time.Minute),
			Duration:  time.Hour,
		}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: denyAllPolicy()},
			BreakGlassStore: &mockBreakGlassStore{activeEvent: wrongProfileBG}, // Wrong profile
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		// Request for prod-role but break-glass is for other-role
		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		// Should be denied - break-glass profile doesn't match
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Break-glass for wrong profile should NOT override, got %d - SECURITY VIOLATION", resp.StatusCode)
		}
	})

	t.Run("approval store error does not grant access", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should NOT be called when approval check fails")
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := &TVMConfig{
			PolicyParameter: "/test/policy",
			PolicyLoader:    &mockPolicyLoader{policy: denyAllPolicy()},
			ApprovalStore:   &mockApprovalStore{listByReqErr: errors.New("DynamoDB connection error")}, // Error
			STSClient:       mockClient,
			Region:          "us-east-1",
			DefaultDuration: 15 * time.Minute,
		}
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		// Should be denied - fail closed on errors
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Approval store error should fail closed, got %d - SECURITY VIOLATION", resp.StatusCode)
		}
	})
}

// TestSecurityRegression_DurationValidation verifies duration constraints are enforced.
func TestSecurityRegression_DurationValidation(t *testing.T) {
	t.Run("duration below minimum rejected", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should NOT be called for invalid duration")
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/test-role")
		req.QueryStringParameters["duration"] = "600" // 10 min, below 15 min minimum

		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Duration below minimum should be rejected, got %d", resp.StatusCode)
		}
	})

	t.Run("duration above maximum rejected", func(t *testing.T) {
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				t.Error("STS should NOT be called for invalid duration")
				return successfulTestSTSResponse(), nil
			},
		}

		cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/test-role")
		req.QueryStringParameters["duration"] = "50000" // Above 43200 (12 hour) maximum

		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("HandleRequest() error: %v", err)
		}

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("Duration above maximum should be rejected, got %d", resp.StatusCode)
		}
	})

	t.Run("policy max_server_duration caps requested duration", func(t *testing.T) {
		var capturedDuration int32
		mockClient := &testSTSClient{
			AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
				if params.DurationSeconds != nil {
					capturedDuration = *params.DurationSeconds
				}
				return successfulTestSTSResponse(), nil
			},
		}

		// Policy caps duration to 10 minutes
		cfg := testTVMConfig(&mockPolicyLoader{policy: maxDurationPolicy(10 * time.Minute)}, mockClient)
		handler := NewHandler(cfg)

		req := validIAMRequest("arn:aws:iam::123456789012:role/test-role")
		req.QueryStringParameters["duration"] = "3600" // Request 1 hour

		resp, err := handler.HandleRequest(context.Background(), req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected success, got %d", resp.StatusCode)
		}

		// Duration MUST be capped to policy max (10 min = 600 sec)
		if capturedDuration != 600 {
			t.Errorf("Duration should be capped to policy max 600, got %d - SECURITY VIOLATION", capturedDuration)
		}
	})
}
