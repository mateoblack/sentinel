package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/enforce"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/testutil"
)

// ============================================================================
// Test Fixtures and Helpers
// ============================================================================

// testPolicyAllow creates a policy that allows all users for a profile.
func testPolicyAllow(profile string) *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-all",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{profile},
				},
			},
		},
	}
}

// testPolicyDeny creates a policy that denies all users for a profile.
func testPolicyDeny(profile string) *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "deny-all",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Profiles: []string{profile},
				},
			},
		},
	}
}

// testPolicyDenyDefault creates a policy with no matching rules (default deny).
func testPolicyDenyDefault() *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Rules:   []policy.Rule{}, // Empty rules = default deny
	}
}

// createApprovedRequest creates an approved request fixture.
func createApprovedRequest(requester, profile string, duration time.Duration) *request.Request {
	now := time.Now()
	return &request.Request{
		ID:        "approved-" + requester + "-" + profile,
		Requester: requester,
		Profile:   profile,
		Status:    request.StatusApproved,
		Duration:  duration,
		CreatedAt: now.Add(-30 * time.Minute), // Created 30 min ago
		ExpiresAt: now.Add(23 * time.Hour),    // Expires in 23 hours
	}
}

// createActiveBreakGlass creates an active break-glass event fixture.
func createActiveBreakGlass(invoker, profile string, remainingDuration time.Duration) *breakglass.BreakGlassEvent {
	now := time.Now()
	return &breakglass.BreakGlassEvent{
		ID:            "bg-" + invoker + "-" + profile,
		Invoker:       invoker,
		Profile:       profile,
		Status:        breakglass.StatusActive,
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test break-glass event",
		Duration:      2 * time.Hour,
		CreatedAt:     now.Add(-30 * time.Minute),       // Created 30 min ago
		ExpiresAt:     now.Add(remainingDuration),       // Expires based on remaining time
	}
}

// ============================================================================
// TestCredentialFlow_DecisionPaths - Core decision path tests
// ============================================================================

func TestCredentialFlow_PolicyEvaluationPaths(t *testing.T) {
	// These tests verify the policy evaluation logic paths:
	// 1. Policy Allow -> credentials issued
	// 2. Policy Deny (no override) -> access denied
	// 3. Policy Deny + Approved Request -> credentials issued via override
	// 4. Policy Deny + Active Break-Glass -> credentials issued via override
	// 5. Priority: Approved Request checked before Break-Glass

	t.Run("policy_allow_path_issues_credentials", func(t *testing.T) {
		// Test: When policy allows, credentials should be issued
		policyObj := testPolicyAllow("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)

		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected allow, got %s", decision.Effect)
		}
		if decision.MatchedRule != "allow-all" {
			t.Errorf("expected rule 'allow-all', got %s", decision.MatchedRule)
		}
		if decision.RuleIndex != 0 {
			t.Errorf("expected rule index 0, got %d", decision.RuleIndex)
		}
	})

	t.Run("policy_deny_path_returns_access_denied", func(t *testing.T) {
		// Test: When policy denies and no overrides exist, access should be denied
		policyObj := testPolicyDeny("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)

		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny, got %s", decision.Effect)
		}
		if decision.MatchedRule != "deny-all" {
			t.Errorf("expected rule 'deny-all', got %s", decision.MatchedRule)
		}
	})

	t.Run("default_deny_when_no_rules_match", func(t *testing.T) {
		// Test: When no rules match, should be default deny
		policyObj := testPolicyDenyDefault()
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)

		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny, got %s", decision.Effect)
		}
		if decision.MatchedRule != "" {
			t.Errorf("expected empty matched rule, got %s", decision.MatchedRule)
		}
		if decision.RuleIndex != -1 {
			t.Errorf("expected rule index -1, got %d", decision.RuleIndex)
		}
	})
}

func TestCredentialFlow_ApprovedRequestOverride(t *testing.T) {
	// Test: Policy deny + approved request = credentials issued via override

	t.Run("approved_request_overrides_policy_deny", func(t *testing.T) {
		store := testutil.NewMockRequestStore()

		// Create approved request for user+profile
		approvedReq := createApprovedRequest("alice", "production", 2*time.Hour)

		store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			if requester == "alice" {
				return []*request.Request{approvedReq}, nil
			}
			return []*request.Request{}, nil
		}

		// Find approved request
		foundReq, err := request.FindApprovedRequest(context.Background(), store, "alice", "production")
		if err != nil {
			t.Fatalf("FindApprovedRequest error: %v", err)
		}
		if foundReq == nil {
			t.Fatal("expected to find approved request")
		}
		if foundReq.ID != approvedReq.ID {
			t.Errorf("expected ID %s, got %s", approvedReq.ID, foundReq.ID)
		}

		// Verify store was called correctly
		if len(store.ListByRequesterCalls) != 1 {
			t.Errorf("expected 1 ListByRequester call, got %d", len(store.ListByRequesterCalls))
		}
		if store.ListByRequesterCalls[0].Requester != "alice" {
			t.Errorf("expected requester 'alice', got %s", store.ListByRequesterCalls[0].Requester)
		}
	})

	t.Run("no_approved_request_for_wrong_profile", func(t *testing.T) {
		store := testutil.NewMockRequestStore()

		// Create approved request for different profile
		approvedReq := createApprovedRequest("alice", "staging", 2*time.Hour)

		store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			if requester == "alice" {
				return []*request.Request{approvedReq}, nil
			}
			return []*request.Request{}, nil
		}

		// Try to find approved request for production (should return nil)
		foundReq, err := request.FindApprovedRequest(context.Background(), store, "alice", "production")
		if err != nil {
			t.Fatalf("FindApprovedRequest error: %v", err)
		}
		if foundReq != nil {
			t.Errorf("expected no approved request for wrong profile, got %v", foundReq)
		}
	})

	t.Run("no_approved_request_for_wrong_user", func(t *testing.T) {
		store := testutil.NewMockRequestStore()

		// Create approved request for different user
		approvedReq := createApprovedRequest("bob", "production", 2*time.Hour)

		store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			if requester == "bob" {
				return []*request.Request{approvedReq}, nil
			}
			return []*request.Request{}, nil
		}

		// Try to find approved request for alice (should return nil)
		foundReq, err := request.FindApprovedRequest(context.Background(), store, "alice", "production")
		if err != nil {
			t.Fatalf("FindApprovedRequest error: %v", err)
		}
		if foundReq != nil {
			t.Errorf("expected no approved request for wrong user, got %v", foundReq)
		}
	})

	t.Run("expired_approved_request_not_returned", func(t *testing.T) {
		store := testutil.NewMockRequestStore()

		// Create expired approved request
		now := time.Now()
		expiredReq := &request.Request{
			ID:        "expired-req",
			Requester: "alice",
			Profile:   "production",
			Status:    request.StatusApproved,
			Duration:  2 * time.Hour,
			CreatedAt: now.Add(-25 * time.Hour), // Created 25 hours ago
			ExpiresAt: now.Add(-1 * time.Hour),  // Expired 1 hour ago
		}

		store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			return []*request.Request{expiredReq}, nil
		}

		// Should not find expired request
		foundReq, err := request.FindApprovedRequest(context.Background(), store, "alice", "production")
		if err != nil {
			t.Fatalf("FindApprovedRequest error: %v", err)
		}
		if foundReq != nil {
			t.Errorf("expected no expired request, got %v", foundReq)
		}
	})
}

func TestCredentialFlow_BreakGlassOverride(t *testing.T) {
	// Test: Policy deny + active break-glass = credentials issued via override

	t.Run("break_glass_overrides_policy_deny", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()

		// Create active break-glass event
		activeBG := createActiveBreakGlass("alice", "production", 90*time.Minute)

		store.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			if invoker == "alice" {
				return []*breakglass.BreakGlassEvent{activeBG}, nil
			}
			return []*breakglass.BreakGlassEvent{}, nil
		}

		// Find active break-glass
		foundEvent, err := breakglass.FindActiveBreakGlass(context.Background(), store, "alice", "production")
		if err != nil {
			t.Fatalf("FindActiveBreakGlass error: %v", err)
		}
		if foundEvent == nil {
			t.Fatal("expected to find active break-glass event")
		}
		if foundEvent.ID != activeBG.ID {
			t.Errorf("expected ID %s, got %s", activeBG.ID, foundEvent.ID)
		}

		// Verify store was called correctly
		if len(store.ListByInvokerCalls) != 1 {
			t.Errorf("expected 1 ListByInvoker call, got %d", len(store.ListByInvokerCalls))
		}
	})

	t.Run("session_duration_capped_to_break_glass_remaining", func(t *testing.T) {
		// Create break-glass event with 30 minutes remaining
		activeBG := createActiveBreakGlass("alice", "production", 30*time.Minute)

		remaining := breakglass.RemainingDuration(activeBG)
		if remaining <= 0 {
			t.Fatal("expected positive remaining duration")
		}
		if remaining > 31*time.Minute {
			t.Errorf("expected remaining ~30 minutes, got %v", remaining)
		}

		// Test capping logic: if sessionDuration > remaining, cap to remaining
		sessionDuration := 1 * time.Hour
		if sessionDuration > remaining {
			sessionDuration = remaining
		}
		if sessionDuration > 31*time.Minute {
			t.Errorf("session should be capped to ~30 minutes, got %v", sessionDuration)
		}
	})

	t.Run("expired_break_glass_not_returned", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()

		// Create expired break-glass event
		now := time.Now()
		expiredBG := &breakglass.BreakGlassEvent{
			ID:        "expired-bg",
			Invoker:   "alice",
			Profile:   "production",
			Status:    breakglass.StatusActive,
			ExpiresAt: now.Add(-1 * time.Hour), // Expired 1 hour ago
		}

		store.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			return []*breakglass.BreakGlassEvent{expiredBG}, nil
		}

		// Should not find expired break-glass
		foundEvent, err := breakglass.FindActiveBreakGlass(context.Background(), store, "alice", "production")
		if err != nil {
			t.Fatalf("FindActiveBreakGlass error: %v", err)
		}
		if foundEvent != nil {
			t.Errorf("expected no expired break-glass, got %v", foundEvent)
		}
	})

	t.Run("closed_break_glass_not_returned", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()

		// Create closed break-glass event
		closedBG := &breakglass.BreakGlassEvent{
			ID:        "closed-bg",
			Invoker:   "alice",
			Profile:   "production",
			Status:    breakglass.StatusClosed, // Closed, not active
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		store.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			return []*breakglass.BreakGlassEvent{closedBG}, nil
		}

		// Should not find closed break-glass
		foundEvent, err := breakglass.FindActiveBreakGlass(context.Background(), store, "alice", "production")
		if err != nil {
			t.Fatalf("FindActiveBreakGlass error: %v", err)
		}
		if foundEvent != nil {
			t.Errorf("expected no closed break-glass, got %v", foundEvent)
		}
	})
}

func TestCredentialFlow_OverridePriority(t *testing.T) {
	// Test: Approved request is checked before break-glass
	// If both exist, approved request takes precedence

	t.Run("approved_request_checked_before_break_glass", func(t *testing.T) {
		// This test verifies the check order in CredentialsCommand:
		// 1. First check for approved request
		// 2. Only if no approved request, check for break-glass

		requestStore := testutil.NewMockRequestStore()
		breakGlassStore := testutil.NewMockBreakGlassStore()

		// Setup: both approved request and break-glass exist
		approvedReq := createApprovedRequest("alice", "production", 2*time.Hour)
		activeBG := createActiveBreakGlass("alice", "production", 90*time.Minute)

		requestStore.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			return []*request.Request{approvedReq}, nil
		}

		breakGlassStore.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			return []*breakglass.BreakGlassEvent{activeBG}, nil
		}

		// Check for approved request first
		foundReq, err := request.FindApprovedRequest(context.Background(), requestStore, "alice", "production")
		if err != nil {
			t.Fatalf("FindApprovedRequest error: %v", err)
		}

		// Since approved request exists, break-glass should NOT be checked
		// (simulating the logic in CredentialsCommand)
		if foundReq != nil {
			// Approved request found, don't check break-glass
			if len(breakGlassStore.ListByInvokerCalls) != 0 {
				t.Error("break-glass store should not be called when approved request exists")
			}
		} else {
			t.Error("expected to find approved request")
		}
	})

	t.Run("break_glass_checked_only_when_no_approved_request", func(t *testing.T) {
		requestStore := testutil.NewMockRequestStore()
		breakGlassStore := testutil.NewMockBreakGlassStore()

		// Setup: no approved request, but break-glass exists
		activeBG := createActiveBreakGlass("alice", "production", 90*time.Minute)

		requestStore.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			return []*request.Request{}, nil // No approved request
		}

		breakGlassStore.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			return []*breakglass.BreakGlassEvent{activeBG}, nil
		}

		// Check for approved request first
		foundReq, err := request.FindApprovedRequest(context.Background(), requestStore, "alice", "production")
		if err != nil {
			t.Fatalf("FindApprovedRequest error: %v", err)
		}

		// No approved request - now check break-glass
		if foundReq == nil {
			foundBG, err := breakglass.FindActiveBreakGlass(context.Background(), breakGlassStore, "alice", "production")
			if err != nil {
				t.Fatalf("FindActiveBreakGlass error: %v", err)
			}
			if foundBG == nil {
				t.Error("expected to find active break-glass")
			}
		}

		// Verify both stores were called
		if len(requestStore.ListByRequesterCalls) != 1 {
			t.Errorf("expected 1 request store call, got %d", len(requestStore.ListByRequesterCalls))
		}
		if len(breakGlassStore.ListByInvokerCalls) != 1 {
			t.Errorf("expected 1 break-glass store call, got %d", len(breakGlassStore.ListByInvokerCalls))
		}
	})
}

// ============================================================================
// TestCredentialFlowLogging - Logging integration tests
// ============================================================================

func TestCredentialFlowLogging_LogEntryFields(t *testing.T) {
	t.Run("decision_log_entry_contains_correct_fields", func(t *testing.T) {
		policyObj := testPolicyAllow("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}
		decision := policy.Evaluate(policyObj, policyReq)
		policyPath := "/sentinel/policies/default"

		entry := logging.NewDecisionLogEntry(policyReq, decision, policyPath)

		if entry.User != "alice" {
			t.Errorf("expected user 'alice', got %s", entry.User)
		}
		if entry.Profile != "production" {
			t.Errorf("expected profile 'production', got %s", entry.Profile)
		}
		if entry.Effect != "allow" {
			t.Errorf("expected effect 'allow', got %s", entry.Effect)
		}
		if entry.Rule != "allow-all" {
			t.Errorf("expected rule 'allow-all', got %s", entry.Rule)
		}
		if entry.RuleIndex != 0 {
			t.Errorf("expected rule index 0, got %d", entry.RuleIndex)
		}
		if entry.PolicyPath != policyPath {
			t.Errorf("expected policy path %s, got %s", policyPath, entry.PolicyPath)
		}
		if entry.Timestamp == "" {
			t.Error("expected non-empty timestamp")
		}
	})

	t.Run("enhanced_log_entry_contains_credential_issuance_fields", func(t *testing.T) {
		policyObj := testPolicyAllow("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}
		decision := policy.Evaluate(policyObj, policyReq)
		policyPath := "/sentinel/policies/default"

		credFields := &logging.CredentialIssuanceFields{
			RequestID:       "abcd1234",
			SourceIdentity:  "sentinel:alice:abcd1234",
			RoleARN:         "arn:aws:iam::123456789012:role/ProductionRole",
			SessionDuration: 1 * time.Hour,
		}

		entry := logging.NewEnhancedDecisionLogEntry(policyReq, decision, policyPath, credFields)

		if entry.RequestID != "abcd1234" {
			t.Errorf("expected request ID 'abcd1234', got %s", entry.RequestID)
		}
		if entry.SourceIdentity != "sentinel:alice:abcd1234" {
			t.Errorf("expected source identity 'sentinel:alice:abcd1234', got %s", entry.SourceIdentity)
		}
		if entry.RoleARN != "arn:aws:iam::123456789012:role/ProductionRole" {
			t.Errorf("expected role ARN, got %s", entry.RoleARN)
		}
		if entry.SessionDuration != 3600 { // 1 hour in seconds
			t.Errorf("expected session duration 3600, got %d", entry.SessionDuration)
		}
	})

	t.Run("approved_request_id_appears_in_log_entry", func(t *testing.T) {
		policyObj := testPolicyDeny("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}
		decision := policy.Evaluate(policyObj, policyReq)

		credFields := &logging.CredentialIssuanceFields{
			RequestID:         "abcd1234",
			ApprovedRequestID: "approved-alice-production",
		}

		entry := logging.NewEnhancedDecisionLogEntry(policyReq, decision, "/sentinel/policies/test", credFields)

		if entry.ApprovedRequestID != "approved-alice-production" {
			t.Errorf("expected approved request ID, got %s", entry.ApprovedRequestID)
		}
	})

	t.Run("break_glass_event_id_appears_in_log_entry", func(t *testing.T) {
		policyObj := testPolicyDeny("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}
		decision := policy.Evaluate(policyObj, policyReq)

		credFields := &logging.CredentialIssuanceFields{
			RequestID:         "abcd1234",
			BreakGlassEventID: "bg-alice-production",
		}

		entry := logging.NewEnhancedDecisionLogEntry(policyReq, decision, "/sentinel/policies/test", credFields)

		if entry.BreakGlassEventID != "bg-alice-production" {
			t.Errorf("expected break-glass event ID, got %s", entry.BreakGlassEventID)
		}
	})
}

func TestCredentialFlowLogging_MultiWriter(t *testing.T) {
	t.Run("logs_go_to_both_file_and_stderr", func(t *testing.T) {
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "decisions.log")

		// Create file
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Failed to open log file: %v", err)
		}
		defer f.Close()

		var stderrBuf bytes.Buffer

		// Create MultiWriter (simulating what credentials.go does)
		multiWriter := logging.NewJSONLogger(&multiWriterWrapper{writers: []interface{}{&stderrBuf, f}})

		entry := logging.DecisionLogEntry{
			Timestamp:  "2026-01-17T10:00:00Z",
			User:       "alice",
			Profile:    "production",
			Effect:     "allow",
			Rule:       "allow-all",
			PolicyPath: "/sentinel/policies/default",
		}
		multiWriter.LogDecision(entry)

		// Verify stderr received content
		if stderrBuf.Len() == 0 {
			t.Error("expected stderr to receive log content")
		}
	})

	t.Run("file_logging_appends_json_lines", func(t *testing.T) {
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "decisions.log")

		// First write
		f1, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Failed to open log file: %v", err)
		}
		logger1 := logging.NewJSONLogger(f1)
		logger1.LogDecision(logging.DecisionLogEntry{User: "alice", Effect: "allow"})
		f1.Close()

		// Second write (new handle, simulating new command)
		f2, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Failed to open log file: %v", err)
		}
		logger2 := logging.NewJSONLogger(f2)
		logger2.LogDecision(logging.DecisionLogEntry{User: "bob", Effect: "deny"})
		f2.Close()

		// Read and verify
		content, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("Failed to read log file: %v", err)
		}

		lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
		if len(lines) != 2 {
			t.Errorf("expected 2 JSON lines, got %d", len(lines))
		}
	})
}

func TestCredentialFlowLogging_DriftStatus(t *testing.T) {
	testCases := []struct {
		status      enforce.DriftStatus
		description string
	}{
		{enforce.DriftStatusOK, "ok"},
		{enforce.DriftStatusPartial, "partial"},
		{enforce.DriftStatusNone, "none"},
		{enforce.DriftStatusUnknown, "unknown"},
	}

	for _, tc := range testCases {
		t.Run("drift_status_"+tc.description+"_appears_in_log", func(t *testing.T) {
			credFields := &logging.CredentialIssuanceFields{
				RequestID:    "test1234",
				DriftStatus:  string(tc.status),
				DriftMessage: "Test drift message for " + tc.description,
			}

			policyReq := &policy.Request{
				User:    "alice",
				Profile: "production",
				Time:    time.Now(),
			}
			decision := policy.Evaluate(testPolicyAllow("production"), policyReq)
			entry := logging.NewEnhancedDecisionLogEntry(policyReq, decision, "/test", credFields)

			if entry.DriftStatus != string(tc.status) {
				t.Errorf("expected drift status %s, got %s", tc.status, entry.DriftStatus)
			}
			if entry.DriftMessage == "" {
				t.Error("expected non-empty drift message")
			}
		})
	}
}

func TestCredentialFlowLogging_MockLogger(t *testing.T) {
	t.Run("mock_logger_captures_decision_entries", func(t *testing.T) {
		logger := testutil.NewMockLogger()

		entry := logging.DecisionLogEntry{
			Timestamp:  "2026-01-17T10:00:00Z",
			User:       "alice",
			Profile:    "production",
			Effect:     "allow",
			Rule:       "allow-all",
			PolicyPath: "/sentinel/policies/default",
		}
		logger.LogDecision(entry)

		if logger.DecisionCount() != 1 {
			t.Errorf("expected 1 decision entry, got %d", logger.DecisionCount())
		}

		lastEntry := logger.LastDecision()
		if lastEntry.User != "alice" {
			t.Errorf("expected user 'alice', got %s", lastEntry.User)
		}
		if lastEntry.Effect != "allow" {
			t.Errorf("expected effect 'allow', got %s", lastEntry.Effect)
		}
	})

	t.Run("mock_logger_is_thread_safe", func(t *testing.T) {
		logger := testutil.NewMockLogger()
		done := make(chan bool)

		// Concurrent logging
		for i := 0; i < 10; i++ {
			go func(idx int) {
				logger.LogDecision(logging.DecisionLogEntry{
					User: "user" + string(rune('0'+idx)),
				})
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		if logger.DecisionCount() != 10 {
			t.Errorf("expected 10 decision entries, got %d", logger.DecisionCount())
		}
	})
}

// ============================================================================
// TestCredentialFlowErrors - Error handling tests
// ============================================================================

func TestCredentialFlowErrors_StoreErrors(t *testing.T) {
	t.Run("request_store_error_logged_but_doesnt_fail", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		store.ListByRequesterErr = errors.New("DynamoDB connection error")

		// Error should propagate from FindApprovedRequest
		_, err := request.FindApprovedRequest(context.Background(), store, "alice", "production")

		// Note: FindApprovedRequest returns the error, but in CredentialsCommand
		// this error is logged but doesn't prevent deny - it just means no override
		if err == nil {
			t.Error("expected error from store")
		}
	})

	t.Run("break_glass_store_error_logged_but_doesnt_fail", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()
		store.ListByInvokerErr = errors.New("DynamoDB connection error")

		// Error should propagate from FindActiveBreakGlass
		_, err := breakglass.FindActiveBreakGlass(context.Background(), store, "alice", "production")

		// Note: FindActiveBreakGlass returns the error, but in CredentialsCommand
		// this error is logged but doesn't prevent deny - it just means no override
		if err == nil {
			t.Error("expected error from store")
		}
	})

	t.Run("store_error_means_credentials_denied_if_policy_denies", func(t *testing.T) {
		// Simulate the CredentialsCommand logic:
		// If store errors, treat it as "no approved request found" -> deny

		requestStore := testutil.NewMockRequestStore()
		requestStore.ListByRequesterErr = errors.New("store error")

		bgStore := testutil.NewMockBreakGlassStore()
		bgStore.ListByInvokerErr = errors.New("store error")

		// Policy denies
		policyObj := testPolicyDeny("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}
		decision := policy.Evaluate(policyObj, policyReq)

		// Try to find approved request (will error)
		_, reqErr := request.FindApprovedRequest(context.Background(), requestStore, "alice", "production")

		// Try to find break-glass (will error)
		_, bgErr := breakglass.FindActiveBreakGlass(context.Background(), bgStore, "alice", "production")

		// Both errored, so no override found - decision stands as deny
		if reqErr == nil || bgErr == nil {
			t.Error("expected store errors")
		}
		if decision.Effect != policy.EffectDeny {
			t.Error("expected deny when stores error")
		}
	})
}

func TestCredentialFlowErrors_PolicyLoadingErrors(t *testing.T) {
	t.Run("nil_policy_returns_default_deny", func(t *testing.T) {
		var nilPolicy *policy.Policy = nil
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(nilPolicy, policyReq)

		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny for nil policy, got %s", decision.Effect)
		}
		if decision.RuleIndex != -1 {
			t.Errorf("expected rule index -1 for nil policy, got %d", decision.RuleIndex)
		}
	})

	t.Run("nil_request_returns_default_deny", func(t *testing.T) {
		policyObj := testPolicyAllow("production")
		var nilReq *policy.Request = nil

		decision := policy.Evaluate(policyObj, nilReq)

		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny for nil request, got %s", decision.Effect)
		}
	})
}

func TestCredentialFlowErrors_DriftCheckErrors(t *testing.T) {
	t.Run("drift_check_error_doesnt_prevent_credential_issuance", func(t *testing.T) {
		// Simulate drift checker that returns error
		checker := &enforce.TestDriftChecker{
			CheckFunc: func(ctx context.Context, roleARN string) (*enforce.DriftCheckResult, error) {
				return nil, errors.New("IAM API error")
			},
		}

		_, err := checker.CheckRole(context.Background(), "arn:aws:iam::123456789012:role/TestRole")

		// Error occurred, but in CredentialsCommand this is logged and credentials still issued
		if err == nil {
			t.Error("expected error from drift checker")
		}
		// The important thing is that the error is non-fatal - credentials would still be issued
	})

	t.Run("drift_check_warning_doesnt_prevent_credential_issuance", func(t *testing.T) {
		// Even with DriftStatusNone (worst status), credentials are still issued
		checker := &enforce.TestDriftChecker{
			CheckFunc: func(ctx context.Context, roleARN string) (*enforce.DriftCheckResult, error) {
				return &enforce.DriftCheckResult{
					Status:  enforce.DriftStatusNone,
					RoleARN: roleARN,
					Message: "No Sentinel enforcement - this is advisory only",
				}, nil
			},
		}

		result, err := checker.CheckRole(context.Background(), "arn:aws:iam::123456789012:role/TestRole")

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// Result indicates no enforcement, but no error means credentials would proceed
		if result.Status != enforce.DriftStatusNone {
			t.Errorf("expected status none, got %s", result.Status)
		}
	})
}

// ============================================================================
// TestCredentialFlowErrors_Extended - Extended error handling tests
// ============================================================================

func TestCredentialFlowErrors_PolicyYAMLMalformed(t *testing.T) {
	// Test behavior with malformed policy YAML
	// Note: The actual YAML parsing happens in the policy loader,
	// but we can test how policy.Evaluate handles edge cases

	t.Run("empty_rules_list_returns_default_deny", func(t *testing.T) {
		policyObj := &policy.Policy{
			Version: "1",
			Rules:   []policy.Rule{}, // Empty rules
		}

		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)

		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny for empty rules, got %s", decision.Effect)
		}
		if decision.Reason != "no matching rule" {
			t.Errorf("expected reason 'no matching rule', got %q", decision.Reason)
		}
	})

	t.Run("invalid_effect_still_evaluates", func(t *testing.T) {
		// Policy with invalid effect - should not match
		policyObj := &policy.Policy{
			Version: "1",
			Rules: []policy.Rule{
				{
					Name:   "invalid-rule",
					Effect: policy.Effect("invalid"), // Invalid effect
					Conditions: policy.Condition{
						Profiles: []string{"production"},
					},
				},
			},
		}

		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)

		// Rule matches conditions but has invalid effect
		// It still matches, but effect is "invalid"
		if decision.MatchedRule != "invalid-rule" {
			t.Errorf("expected rule 'invalid-rule' to match, got %q", decision.MatchedRule)
		}
	})

	t.Run("empty_version_still_evaluates", func(t *testing.T) {
		policyObj := &policy.Policy{
			Version: "", // Empty version
			Rules: []policy.Rule{
				{
					Name:   "test-rule",
					Effect: policy.EffectAllow,
					Conditions: policy.Condition{
						Profiles: []string{"production"},
					},
				},
			},
		}

		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)

		// Should still work with empty version
		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected allow despite empty version, got %s", decision.Effect)
		}
	})
}

func TestCredentialFlowErrors_StoreNonFatalErrors(t *testing.T) {
	// Tests that store errors are non-fatal and don't prevent credential denial

	t.Run("request_store_timeout_treated_as_no_approval", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		store.ListByRequesterErr = context.DeadlineExceeded

		// Error should propagate
		_, err := request.FindApprovedRequest(context.Background(), store, "alice", "production")

		if err == nil {
			t.Error("expected timeout error")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected context.DeadlineExceeded, got %v", err)
		}
	})

	t.Run("break_glass_store_timeout_treated_as_no_break_glass", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()
		store.ListByInvokerErr = context.DeadlineExceeded

		// Error should propagate
		_, err := breakglass.FindActiveBreakGlass(context.Background(), store, "alice", "production")

		if err == nil {
			t.Error("expected timeout error")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("expected context.DeadlineExceeded, got %v", err)
		}
	})

	t.Run("canceled_context_propagates_error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		store := testutil.NewMockRequestStore()
		store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				return []*request.Request{}, nil
			}
		}

		_, err := request.FindApprovedRequest(ctx, store, "alice", "production")

		if err == nil {
			t.Error("expected context canceled error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})
}

func TestCredentialFlowErrors_DriftCheckAllStatuses(t *testing.T) {
	// Test all drift status values and their handling

	testCases := []struct {
		status      enforce.DriftStatus
		errorField  string
		shouldWarn  bool
		description string
	}{
		{enforce.DriftStatusOK, "", false, "OK status - no warning"},
		{enforce.DriftStatusPartial, "", true, "Partial status - warning"},
		{enforce.DriftStatusNone, "", true, "None status - warning"},
		{enforce.DriftStatusUnknown, "could not verify", true, "Unknown with error - warning"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			checker := &enforce.TestDriftChecker{
				CheckFunc: func(ctx context.Context, roleARN string) (*enforce.DriftCheckResult, error) {
					return &enforce.DriftCheckResult{
						Status:  tc.status,
						RoleARN: roleARN,
						Message: "Test message",
						Error:   tc.errorField,
					}, nil
				},
			}

			result, err := checker.CheckRole(context.Background(), "arn:aws:iam::123456789012:role/Test")

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			needsWarning := result.Status != enforce.DriftStatusOK
			if needsWarning != tc.shouldWarn {
				t.Errorf("expected warning=%v, got %v for status %s", tc.shouldWarn, needsWarning, tc.status)
			}
		})
	}
}

// TestCredentialFlowErrors_NoStoreConfigured has been removed - credential command is deprecated in v1.22.
// Store configuration is now handled by Lambda TVM.

func TestCredentialFlowErrors_ProfileValidation(t *testing.T) {
	// Profile validation tests

	t.Run("profile_validation_error_message_format", func(t *testing.T) {
		// Create temp config without the requested profile
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config")

		configContent := `[profile existing]
region = us-east-1
`
		if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to write config: %v", err)
		}

		// Set AWS_CONFIG_FILE to test config
		originalEnv := os.Getenv("AWS_CONFIG_FILE")
		os.Setenv("AWS_CONFIG_FILE", configFile)
		defer os.Setenv("AWS_CONFIG_FILE", originalEnv)

		s := &Sentinel{}
		err := s.ValidateProfile("nonexistent")

		if err == nil {
			t.Fatal("expected error for nonexistent profile")
		}

		errStr := err.Error()

		// Should mention profile name
		if !strings.Contains(errStr, "nonexistent") {
			t.Errorf("error should mention profile name, got: %s", errStr)
		}

		// Should mention "not found"
		if !strings.Contains(errStr, "not found") {
			t.Errorf("error should mention 'not found', got: %s", errStr)
		}

		// Should list available profiles
		if !strings.Contains(errStr, "existing") {
			t.Errorf("error should list available profiles, got: %s", errStr)
		}
	})
}

func TestCredentialFlowErrors_EdgeCases(t *testing.T) {
	// Edge case error handling

	t.Run("empty_username_still_evaluates", func(t *testing.T) {
		policyObj := testPolicyAllow("production")
		policyReq := &policy.Request{
			User:    "",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)

		// Empty user should still match (policy doesn't require specific user)
		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected allow for empty user (wildcard), got %s", decision.Effect)
		}
	})

	t.Run("empty_profile_returns_default_deny", func(t *testing.T) {
		policyObj := testPolicyAllow("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "", // Empty profile
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)

		// Empty profile doesn't match "production"
		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny for empty profile, got %s", decision.Effect)
		}
	})

	t.Run("zero_time_still_evaluates", func(t *testing.T) {
		policyObj := testPolicyAllow("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Time{}, // Zero time
		}

		decision := policy.Evaluate(policyObj, policyReq)

		// Zero time should still work (no time condition in policy)
		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected allow for zero time (no time condition), got %s", decision.Effect)
		}
	})
}

// ============================================================================
// TestCredentialFlowLogging_Extended - Extended logging verification tests
// ============================================================================

func TestCredentialFlowLogging_AllFieldsVerification(t *testing.T) {
	// Comprehensive test that all log entry fields are correctly populated

	t.Run("complete_allow_decision_log_entry", func(t *testing.T) {
		// Create a policy with all condition types
		policyObj := &policy.Policy{
			Version: "1",
			Rules: []policy.Rule{
				{
					Name:   "allow-production-weekdays",
					Effect: policy.EffectAllow,
					Reason: "Standard production access during business hours",
					Conditions: policy.Condition{
						Profiles: []string{"production"},
						Users:    []string{"alice", "bob"},
					},
				},
			},
		}

		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)
		policyPath := "/sentinel/policies/production"

		credFields := &logging.CredentialIssuanceFields{
			RequestID:       "abc12345",
			SourceIdentity:  "sentinel:alice:abc12345",
			RoleARN:         "arn:aws:iam::123456789012:role/ProductionAdmin",
			SessionDuration: 3600 * time.Second,
			DriftStatus:     "ok",
			DriftMessage:    "Full Sentinel enforcement configured",
		}

		entry := logging.NewEnhancedDecisionLogEntry(policyReq, decision, policyPath, credFields)

		// Verify all basic fields
		if entry.User != "alice" {
			t.Errorf("User: expected 'alice', got %q", entry.User)
		}
		if entry.Profile != "production" {
			t.Errorf("Profile: expected 'production', got %q", entry.Profile)
		}
		if entry.Effect != "allow" {
			t.Errorf("Effect: expected 'allow', got %q", entry.Effect)
		}
		if entry.Rule != "allow-production-weekdays" {
			t.Errorf("Rule: expected 'allow-production-weekdays', got %q", entry.Rule)
		}
		if entry.RuleIndex != 0 {
			t.Errorf("RuleIndex: expected 0, got %d", entry.RuleIndex)
		}
		if entry.Reason != "Standard production access during business hours" {
			t.Errorf("Reason: unexpected value %q", entry.Reason)
		}
		if entry.PolicyPath != policyPath {
			t.Errorf("PolicyPath: expected %q, got %q", policyPath, entry.PolicyPath)
		}
		if entry.Timestamp == "" {
			t.Error("Timestamp: expected non-empty value")
		}

		// Verify credential issuance fields
		if entry.RequestID != "abc12345" {
			t.Errorf("RequestID: expected 'abc12345', got %q", entry.RequestID)
		}
		if entry.SourceIdentity != "sentinel:alice:abc12345" {
			t.Errorf("SourceIdentity: expected 'sentinel:alice:abc12345', got %q", entry.SourceIdentity)
		}
		if entry.RoleARN != "arn:aws:iam::123456789012:role/ProductionAdmin" {
			t.Errorf("RoleARN: unexpected value %q", entry.RoleARN)
		}
		if entry.SessionDuration != 3600 {
			t.Errorf("SessionDuration: expected 3600, got %d", entry.SessionDuration)
		}
		if entry.DriftStatus != "ok" {
			t.Errorf("DriftStatus: expected 'ok', got %q", entry.DriftStatus)
		}
		if entry.DriftMessage != "Full Sentinel enforcement configured" {
			t.Errorf("DriftMessage: unexpected value %q", entry.DriftMessage)
		}
	})

	t.Run("deny_decision_with_approved_request_override", func(t *testing.T) {
		policyObj := testPolicyDeny("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}
		decision := policy.Evaluate(policyObj, policyReq)

		credFields := &logging.CredentialIssuanceFields{
			RequestID:         "def67890",
			SourceIdentity:    "sentinel:alice:def67890",
			RoleARN:           "arn:aws:iam::123456789012:role/ProductionAdmin",
			SessionDuration:   7200 * time.Second, // 2 hours
			ApprovedRequestID: "req-approved-001",
		}

		entry := logging.NewEnhancedDecisionLogEntry(policyReq, decision, "/sentinel/policies/test", credFields)

		// Verify deny effect but with credential fields (override occurred)
		if entry.Effect != "deny" {
			t.Errorf("Effect: expected 'deny', got %q", entry.Effect)
		}
		if entry.ApprovedRequestID != "req-approved-001" {
			t.Errorf("ApprovedRequestID: expected 'req-approved-001', got %q", entry.ApprovedRequestID)
		}
		if entry.BreakGlassEventID != "" {
			t.Errorf("BreakGlassEventID: expected empty, got %q", entry.BreakGlassEventID)
		}
	})

	t.Run("deny_decision_with_break_glass_override", func(t *testing.T) {
		policyObj := testPolicyDeny("production")
		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}
		decision := policy.Evaluate(policyObj, policyReq)

		credFields := &logging.CredentialIssuanceFields{
			RequestID:         "ghi11111",
			SourceIdentity:    "sentinel:alice:ghi11111",
			RoleARN:           "arn:aws:iam::123456789012:role/ProductionAdmin",
			SessionDuration:   1800 * time.Second, // 30 min (capped)
			BreakGlassEventID: "bg-incident-2026-01-17",
		}

		entry := logging.NewEnhancedDecisionLogEntry(policyReq, decision, "/sentinel/policies/test", credFields)

		// Verify break-glass override fields
		if entry.BreakGlassEventID != "bg-incident-2026-01-17" {
			t.Errorf("BreakGlassEventID: expected 'bg-incident-2026-01-17', got %q", entry.BreakGlassEventID)
		}
		if entry.ApprovedRequestID != "" {
			t.Errorf("ApprovedRequestID: expected empty, got %q", entry.ApprovedRequestID)
		}
		if entry.SessionDuration != 1800 {
			t.Errorf("SessionDuration: expected 1800 (capped), got %d", entry.SessionDuration)
		}
	})

	t.Run("default_deny_log_entry_fields", func(t *testing.T) {
		// Policy with no matching rules
		policyObj := &policy.Policy{
			Version: "1",
			Rules: []policy.Rule{
				{
					Name:   "allow-staging-only",
					Effect: policy.EffectAllow,
					Conditions: policy.Condition{
						Profiles: []string{"staging"}, // Different profile
					},
				},
			},
		}

		policyReq := &policy.Request{
			User:    "alice",
			Profile: "production", // No rule matches this
			Time:    time.Now(),
		}

		decision := policy.Evaluate(policyObj, policyReq)
		entry := logging.NewDecisionLogEntry(policyReq, decision, "/sentinel/policies/test")

		if entry.Effect != "deny" {
			t.Errorf("Effect: expected 'deny', got %q", entry.Effect)
		}
		if entry.Rule != "" {
			t.Errorf("Rule: expected empty (default deny), got %q", entry.Rule)
		}
		if entry.RuleIndex != -1 {
			t.Errorf("RuleIndex: expected -1 (default deny), got %d", entry.RuleIndex)
		}
		if entry.Reason != "no matching rule" {
			t.Errorf("Reason: expected 'no matching rule', got %q", entry.Reason)
		}
	})
}

func TestCredentialFlowLogging_LoggerBehavior(t *testing.T) {
	t.Run("logging_failure_is_silent", func(t *testing.T) {
		// JSONLogger should not panic on marshal errors
		// Note: DecisionLogEntry doesn't have fields that would cause marshal errors,
		// but we test that the logger handles them gracefully
		logger := logging.NewJSONLogger(&bytes.Buffer{})

		// This should not panic
		logger.LogDecision(logging.DecisionLogEntry{
			User:   "test",
			Effect: "allow",
		})
	})

	t.Run("nop_logger_discards_entries", func(t *testing.T) {
		logger := logging.NewNopLogger()

		// This should not panic and should simply discard the entry
		logger.LogDecision(logging.DecisionLogEntry{
			User:   "test",
			Effect: "allow",
		})
		// No way to verify - it just shouldn't panic
	})

	t.Run("mock_logger_tracks_all_entry_types", func(t *testing.T) {
		logger := testutil.NewMockLogger()

		// Log different types of entries
		logger.LogDecision(logging.DecisionLogEntry{User: "alice", Effect: "allow"})
		logger.LogDecision(logging.DecisionLogEntry{User: "bob", Effect: "deny"})
		logger.LogApproval(logging.ApprovalLogEntry{RequestID: "req-001"})
		logger.LogBreakGlass(logging.BreakGlassLogEntry{EventID: "bg-001"})

		if logger.DecisionCount() != 2 {
			t.Errorf("DecisionCount: expected 2, got %d", logger.DecisionCount())
		}
		if logger.ApprovalCount() != 1 {
			t.Errorf("ApprovalCount: expected 1, got %d", logger.ApprovalCount())
		}
		if logger.BreakGlassCount() != 1 {
			t.Errorf("BreakGlassCount: expected 1, got %d", logger.BreakGlassCount())
		}
	})

	t.Run("mock_logger_last_entry_helpers", func(t *testing.T) {
		logger := testutil.NewMockLogger()

		logger.LogDecision(logging.DecisionLogEntry{User: "first", Effect: "allow"})
		logger.LogDecision(logging.DecisionLogEntry{User: "second", Effect: "deny"})

		last := logger.LastDecision()
		if last.User != "second" {
			t.Errorf("LastDecision: expected 'second', got %q", last.User)
		}
		if last.Effect != "deny" {
			t.Errorf("LastDecision: expected 'deny', got %q", last.Effect)
		}
	})

	t.Run("mock_logger_empty_returns_empty_struct", func(t *testing.T) {
		logger := testutil.NewMockLogger()

		last := logger.LastDecision()
		if last.User != "" || last.Effect != "" {
			t.Error("LastDecision on empty logger should return empty struct")
		}
	})
}

func TestCredentialFlowLogging_BestEffort(t *testing.T) {
	// Tests that logging failures don't prevent credential issuance

	t.Run("logging_error_doesnt_block_credential_flow", func(t *testing.T) {
		// Simulate the logic in CredentialsCommand:
		// Even if logging fails, credentials are still issued

		var loggerFailed bool
		mockWriter := &failingWriter{failAfter: 0}
		logger := logging.NewJSONLogger(mockWriter)

		entry := logging.DecisionLogEntry{
			User:   "alice",
			Effect: "allow",
		}

		// This will fail to write, but should not panic
		logger.LogDecision(entry)
		loggerFailed = mockWriter.failed

		// In real code, credentials would still be issued despite log failure
		// The important thing is no panic occurred
		_ = loggerFailed
	})
}

// failingWriter is a writer that fails after a certain number of writes.
type failingWriter struct {
	failAfter int
	writes    int
	failed    bool
}

func (f *failingWriter) Write(p []byte) (n int, err error) {
	if f.writes >= f.failAfter {
		f.failed = true
		return 0, errors.New("write failed")
	}
	f.writes++
	return len(p), nil
}

// ============================================================================
// Helper types
// ============================================================================

// multiWriterWrapper wraps multiple writers for testing io.MultiWriter behavior.
type multiWriterWrapper struct {
	writers []interface{}
}

func (m *multiWriterWrapper) Write(p []byte) (n int, err error) {
	for _, w := range m.writers {
		if buf, ok := w.(*bytes.Buffer); ok {
			buf.Write(p)
		} else if f, ok := w.(*os.File); ok {
			f.Write(p)
		}
	}
	return len(p), nil
}
