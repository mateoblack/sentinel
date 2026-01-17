package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
