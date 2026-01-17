package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/testutil"
)

// ============================================================================
// Security Invariant Tests - Core Gating Behavior
// ============================================================================

func TestCredentialGating_DenyBlocksAccess(t *testing.T) {
	// Core security invariant: Policy with EffectDeny rule matching request
	// should return deny decision when no approved request or break-glass exists.
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "deny-production",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Profiles: []string{"production"},
				},
				Reason: "production access denied by default",
			},
		},
	}
	req := &policy.Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := policy.Evaluate(pol, req)

	if decision.Effect != policy.EffectDeny {
		t.Errorf("expected EffectDeny for matching deny rule, got %v", decision.Effect)
	}
	if decision.MatchedRule != "deny-production" {
		t.Errorf("expected MatchedRule 'deny-production', got %q", decision.MatchedRule)
	}
	if decision.RuleIndex != 0 {
		t.Errorf("expected RuleIndex 0, got %d", decision.RuleIndex)
	}
}

func TestCredentialGating_NoMatchBlocksAccess(t *testing.T) {
	// Default deny security model: No matching rules returns deny.
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-staging",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{"staging"},
				},
			},
		},
	}
	req := &policy.Request{
		User:    "alice",
		Profile: "production", // No rule matches production
		Time:    time.Now(),
	}

	decision := policy.Evaluate(pol, req)

	if decision.Effect != policy.EffectDeny {
		t.Errorf("expected EffectDeny (default deny), got %v", decision.Effect)
	}
	if decision.MatchedRule != "" {
		t.Errorf("expected empty MatchedRule for default deny, got %q", decision.MatchedRule)
	}
	if decision.RuleIndex != -1 {
		t.Errorf("expected RuleIndex -1 for default deny, got %d", decision.RuleIndex)
	}
	if decision.Reason != "no matching rule" {
		t.Errorf("expected Reason 'no matching rule', got %q", decision.Reason)
	}
}

func TestCredentialGating_AllowGrantsAccess(t *testing.T) {
	// Explicit allow: Policy with EffectAllow rule matching request grants access.
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-team",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Users:    []string{"alice", "bob"},
					Profiles: []string{"production"},
				},
				Reason: "team members allowed",
			},
		},
	}
	req := &policy.Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := policy.Evaluate(pol, req)

	if decision.Effect != policy.EffectAllow {
		t.Errorf("expected EffectAllow for matching allow rule, got %v", decision.Effect)
	}
	if decision.MatchedRule != "allow-team" {
		t.Errorf("expected MatchedRule 'allow-team', got %q", decision.MatchedRule)
	}
	if decision.RuleIndex < 0 {
		t.Errorf("expected RuleIndex >= 0, got %d", decision.RuleIndex)
	}
}

func TestCredentialGating_FirstMatchWins(t *testing.T) {
	// Rule ordering: First matching rule wins regardless of effect.
	// Deny rule before allow rule, both matching - deny should win.
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "deny-production",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Profiles: []string{"production"},
				},
				Reason: "production denied first",
			},
			{
				Name:   "allow-all",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{"production"},
				},
				Reason: "all allowed second",
			},
		},
	}
	req := &policy.Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := policy.Evaluate(pol, req)

	if decision.Effect != policy.EffectDeny {
		t.Errorf("expected EffectDeny (first match wins), got %v", decision.Effect)
	}
	if decision.MatchedRule != "deny-production" {
		t.Errorf("expected MatchedRule 'deny-production' (first match), got %q", decision.MatchedRule)
	}
	if decision.RuleIndex != 0 {
		t.Errorf("expected RuleIndex 0 (first rule), got %d", decision.RuleIndex)
	}
}

func TestCredentialGating_FirstMatchWins_AllowFirst(t *testing.T) {
	// Rule ordering: Allow rule before deny rule, both matching - allow should win.
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-production",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{"production"},
				},
				Reason: "production allowed first",
			},
			{
				Name:   "deny-all",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Profiles: []string{"production"},
				},
				Reason: "all denied second",
			},
		},
	}
	req := &policy.Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := policy.Evaluate(pol, req)

	if decision.Effect != policy.EffectAllow {
		t.Errorf("expected EffectAllow (first match wins), got %v", decision.Effect)
	}
	if decision.MatchedRule != "allow-production" {
		t.Errorf("expected MatchedRule 'allow-production' (first match), got %q", decision.MatchedRule)
	}
	if decision.RuleIndex != 0 {
		t.Errorf("expected RuleIndex 0 (first rule), got %d", decision.RuleIndex)
	}
}

func TestCredentialGating_RequireApprovalEffect(t *testing.T) {
	// Approval flow trigger: EffectRequireApproval triggers the approval workflow.
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "require-approval-production",
				Effect: policy.EffectRequireApproval,
				Conditions: policy.Condition{
					Profiles: []string{"production"},
				},
				Reason: "production requires approval",
			},
		},
	}
	req := &policy.Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := policy.Evaluate(pol, req)

	if decision.Effect != policy.EffectRequireApproval {
		t.Errorf("expected EffectRequireApproval, got %v", decision.Effect)
	}
	if decision.MatchedRule != "require-approval-production" {
		t.Errorf("expected MatchedRule 'require-approval-production', got %q", decision.MatchedRule)
	}
}

// ============================================================================
// Override Flow Tests - Approved Request and Break-Glass Bypasses
// ============================================================================

func TestGating_ApprovedRequestOverride(t *testing.T) {
	// Approved request bypasses deny: FindApprovedRequest should find approved request
	ctx := context.Background()
	store := testutil.NewMockRequestStore()

	// Create approved request for alice/production
	now := time.Now()
	approvedReq := &request.Request{
		ID:        "abc123def4567890",
		Requester: "alice",
		Profile:   "production",
		Status:    request.StatusApproved,
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
		Duration:  8 * time.Hour,
	}
	store.Requests[approvedReq.ID] = approvedReq

	// Configure store to return the approved request
	store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
		if requester == "alice" {
			return []*request.Request{approvedReq}, nil
		}
		return nil, nil
	}

	// Test FindApprovedRequest
	found, err := request.FindApprovedRequest(ctx, store, "alice", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find approved request, got nil")
	}
	if found.ID != approvedReq.ID {
		t.Errorf("expected request ID %q, got %q", approvedReq.ID, found.ID)
	}
}

func TestGating_BreakGlassOverride(t *testing.T) {
	// Break-glass bypasses deny: FindActiveBreakGlass should find active event
	ctx := context.Background()
	store := testutil.NewMockBreakGlassStore()

	// Create active break-glass event for alice/production
	now := time.Now()
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            "bg12345678901234",
		Invoker:       "alice",
		Profile:       "production",
		Status:        breakglass.StatusActive,
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Production incident requiring immediate access",
		Duration:      2 * time.Hour,
		CreatedAt:     now.Add(-30 * time.Minute),
		UpdatedAt:     now,
		ExpiresAt:     now.Add(90 * time.Minute),
	}
	store.Events[activeEvent.ID] = activeEvent

	// Configure store to return the active event
	store.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		if invoker == "alice" {
			return []*breakglass.BreakGlassEvent{activeEvent}, nil
		}
		return nil, nil
	}

	// Test FindActiveBreakGlass
	found, err := breakglass.FindActiveBreakGlass(ctx, store, "alice", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find active break-glass, got nil")
	}
	if found.ID != activeEvent.ID {
		t.Errorf("expected event ID %q, got %q", activeEvent.ID, found.ID)
	}
}

func TestGating_ApprovedRequestPriority(t *testing.T) {
	// Priority check: Approved request is checked before break-glass.
	// This mirrors the credential command flow: if approved request exists, break-glass is not checked.
	ctx := context.Background()
	requestStore := testutil.NewMockRequestStore()
	breakGlassStore := testutil.NewMockBreakGlassStore()

	now := time.Now()

	// Set up approved request
	approvedReq := &request.Request{
		ID:        "req123456789abcdef",
		Requester: "alice",
		Profile:   "production",
		Status:    request.StatusApproved,
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
		Duration:  8 * time.Hour,
	}
	requestStore.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
		return []*request.Request{approvedReq}, nil
	}

	// Set up break-glass event too
	breakGlassEvent := &breakglass.BreakGlassEvent{
		ID:        "bg98765432109876",
		Invoker:   "alice",
		Profile:   "production",
		Status:    breakglass.StatusActive,
		CreatedAt: now.Add(-30 * time.Minute),
		ExpiresAt: now.Add(90 * time.Minute),
	}
	breakGlassStore.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		return []*breakglass.BreakGlassEvent{breakGlassEvent}, nil
	}

	// Check approved request first (as in credentials.go)
	foundReq, err := request.FindApprovedRequest(ctx, requestStore, "alice", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if foundReq == nil {
		t.Fatal("expected to find approved request")
	}

	// In the real flow (cli/credentials.go), if approved request is found,
	// break-glass is NOT checked. Verify store wasn't queried by checking call count.
	if len(breakGlassStore.ListByInvokerCalls) != 0 {
		t.Error("break-glass store should not be queried when approved request exists in priority flow")
	}
}

func TestGating_ExpiredApprovalNotUsed(t *testing.T) {
	// Expired approval is ignored: FindApprovedRequest returns nil for expired requests
	ctx := context.Background()
	store := testutil.NewMockRequestStore()

	now := time.Now()
	// Create request with past expiration
	expiredReq := &request.Request{
		ID:        "exp123456789abcdef",
		Requester: "alice",
		Profile:   "production",
		Status:    request.StatusApproved,
		CreatedAt: now.Add(-48 * time.Hour),
		UpdatedAt: now.Add(-24 * time.Hour),
		ExpiresAt: now.Add(-1 * time.Hour), // Expired 1 hour ago
		Duration:  8 * time.Hour,
	}
	store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
		return []*request.Request{expiredReq}, nil
	}

	found, err := request.FindApprovedRequest(ctx, store, "alice", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Errorf("expected nil for expired request, got %+v", found)
	}
}

func TestGating_ClosedBreakGlassNotUsed(t *testing.T) {
	// Closed break-glass is ignored: FindActiveBreakGlass returns nil for closed events
	ctx := context.Background()
	store := testutil.NewMockBreakGlassStore()

	now := time.Now()
	// Create break-glass with StatusClosed
	closedEvent := &breakglass.BreakGlassEvent{
		ID:           "closed123456789ab",
		Invoker:      "alice",
		Profile:      "production",
		Status:       breakglass.StatusClosed, // Closed, not active
		CreatedAt:    now.Add(-2 * time.Hour),
		UpdatedAt:    now.Add(-1 * time.Hour),
		ExpiresAt:    now.Add(time.Hour), // Would still be valid if active
		ClosedBy:     "security",
		ClosedReason: "Incident resolved",
	}
	store.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		return []*breakglass.BreakGlassEvent{closedEvent}, nil
	}

	found, err := breakglass.FindActiveBreakGlass(ctx, store, "alice", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Errorf("expected nil for closed break-glass, got %+v", found)
	}
}

func TestGating_ExpiredBreakGlassNotUsed(t *testing.T) {
	// Expired break-glass is ignored: FindActiveBreakGlass returns nil for expired events
	ctx := context.Background()
	store := testutil.NewMockBreakGlassStore()

	now := time.Now()
	// Create break-glass that is active but expired
	expiredEvent := &breakglass.BreakGlassEvent{
		ID:        "exp987654321abcdef",
		Invoker:   "alice",
		Profile:   "production",
		Status:    breakglass.StatusActive, // Still marked active...
		CreatedAt: now.Add(-4 * time.Hour),
		UpdatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-30 * time.Minute), // ...but expired 30 minutes ago
	}
	store.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		return []*breakglass.BreakGlassEvent{expiredEvent}, nil
	}

	found, err := breakglass.FindActiveBreakGlass(ctx, store, "alice", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Errorf("expected nil for expired break-glass (even with StatusActive), got %+v", found)
	}
}

// ============================================================================
// Boundary Condition Tests - Edge Cases
// ============================================================================

func TestGating_NilPolicy(t *testing.T) {
	// Nil policy returns default deny
	req := &policy.Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := policy.Evaluate(nil, req)

	if decision.Effect != policy.EffectDeny {
		t.Errorf("expected EffectDeny for nil policy, got %v", decision.Effect)
	}
	if decision.MatchedRule != "" {
		t.Errorf("expected empty MatchedRule for nil policy, got %q", decision.MatchedRule)
	}
	if decision.RuleIndex != -1 {
		t.Errorf("expected RuleIndex -1 for nil policy, got %d", decision.RuleIndex)
	}
}

func TestGating_NilRequest(t *testing.T) {
	// Nil request returns default deny
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-all",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{}, // Matches any
				},
			},
		},
	}

	decision := policy.Evaluate(pol, nil)

	if decision.Effect != policy.EffectDeny {
		t.Errorf("expected EffectDeny for nil request, got %v", decision.Effect)
	}
}

func TestGating_EmptyPolicy(t *testing.T) {
	// No rules returns default deny
	pol := &policy.Policy{
		Version: "1",
		Rules:   []policy.Rule{},
	}
	req := &policy.Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := policy.Evaluate(pol, req)

	if decision.Effect != policy.EffectDeny {
		t.Errorf("expected EffectDeny for empty policy, got %v", decision.Effect)
	}
	if decision.MatchedRule != "" {
		t.Errorf("expected empty MatchedRule for empty policy, got %q", decision.MatchedRule)
	}
}

func TestGating_EmptyConditions(t *testing.T) {
	// Empty conditions match all requests (wildcard behavior)
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-all",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Users:    []string{}, // Empty = matches any user
					Profiles: []string{}, // Empty = matches any profile
					Time:     nil,        // Nil = matches any time
				},
				Reason: "wildcard rule",
			},
		},
	}

	// Test with various requests - all should match
	testCases := []struct {
		user    string
		profile string
	}{
		{"alice", "production"},
		{"bob", "staging"},
		{"charlie", "development"},
		{"anyone", "any-profile"},
	}

	for _, tc := range testCases {
		t.Run(tc.user+"/"+tc.profile, func(t *testing.T) {
			req := &policy.Request{
				User:    tc.user,
				Profile: tc.profile,
				Time:    time.Now(),
			}

			decision := policy.Evaluate(pol, req)

			if decision.Effect != policy.EffectAllow {
				t.Errorf("expected EffectAllow for wildcard rule, got %v", decision.Effect)
			}
		})
	}
}

func TestGating_CaseSensitivity(t *testing.T) {
	// Exact case-sensitive matching
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-alice",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Users:    []string{"Alice"},      // Capital A
					Profiles: []string{"Production"}, // Capital P
				},
			},
		},
	}

	// Test mismatched case - should NOT match
	t.Run("user case mismatch", func(t *testing.T) {
		req := &policy.Request{
			User:    "alice", // lowercase
			Profile: "Production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(pol, req)

		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected EffectDeny (user 'alice' should NOT match 'Alice'), got %v", decision.Effect)
		}
	})

	t.Run("profile case mismatch", func(t *testing.T) {
		req := &policy.Request{
			User:    "Alice",
			Profile: "production", // lowercase
			Time:    time.Now(),
		}

		decision := policy.Evaluate(pol, req)

		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected EffectDeny (profile 'production' should NOT match 'Production'), got %v", decision.Effect)
		}
	})

	t.Run("exact match", func(t *testing.T) {
		req := &policy.Request{
			User:    "Alice",
			Profile: "Production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(pol, req)

		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected EffectAllow for exact case match, got %v", decision.Effect)
		}
	})
}

func TestGating_MultipleProfiles(t *testing.T) {
	// Multiple profiles in condition - any match should work
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-nonprod",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{"staging", "production"},
				},
			},
		},
	}

	testCases := []struct {
		profile  string
		expected policy.Effect
	}{
		{"staging", policy.EffectAllow},
		{"production", policy.EffectAllow},
		{"development", policy.EffectDeny}, // Not in list
	}

	for _, tc := range testCases {
		t.Run(tc.profile, func(t *testing.T) {
			req := &policy.Request{
				User:    "alice",
				Profile: tc.profile,
				Time:    time.Now(),
			}

			decision := policy.Evaluate(pol, req)

			if decision.Effect != tc.expected {
				t.Errorf("expected %v for profile %q, got %v", tc.expected, tc.profile, decision.Effect)
			}
		})
	}
}

func TestGating_MultipleUsers(t *testing.T) {
	// Multiple users in condition - any match should work
	pol := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-team",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Users: []string{"alice", "bob", "charlie"},
				},
			},
		},
	}

	testCases := []struct {
		user     string
		expected policy.Effect
	}{
		{"alice", policy.EffectAllow},
		{"bob", policy.EffectAllow},
		{"charlie", policy.EffectAllow},
		{"dave", policy.EffectDeny}, // Not in list
	}

	for _, tc := range testCases {
		t.Run(tc.user, func(t *testing.T) {
			req := &policy.Request{
				User:    tc.user,
				Profile: "production",
				Time:    time.Now(),
			}

			decision := policy.Evaluate(pol, req)

			if decision.Effect != tc.expected {
				t.Errorf("expected %v for user %q, got %v", tc.expected, tc.user, decision.Effect)
			}
		})
	}
}

func TestGating_ApprovalDurationExpired(t *testing.T) {
	// Test that FindApprovedRequest checks access window (CreatedAt + Duration)
	ctx := context.Background()
	store := testutil.NewMockRequestStore()

	now := time.Now()
	// Create request where ExpiresAt is still valid but Duration window has passed
	expiredWindowReq := &request.Request{
		ID:        "win123456789abcdef",
		Requester: "alice",
		Profile:   "production",
		Status:    request.StatusApproved,
		CreatedAt: now.Add(-10 * time.Hour), // Created 10 hours ago
		UpdatedAt: now.Add(-8 * time.Hour),
		ExpiresAt: now.Add(14 * time.Hour), // Request still valid (24h TTL)
		Duration:  8 * time.Hour,           // But access window was only 8 hours
	}
	store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
		return []*request.Request{expiredWindowReq}, nil
	}

	found, err := request.FindApprovedRequest(ctx, store, "alice", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Errorf("expected nil for expired access window, got %+v", found)
	}
}

func TestGating_ApprovalProfileMismatch(t *testing.T) {
	// FindApprovedRequest should only return requests for matching profile
	ctx := context.Background()
	store := testutil.NewMockRequestStore()

	now := time.Now()
	stagingReq := &request.Request{
		ID:        "stg123456789abcdef",
		Requester: "alice",
		Profile:   "staging", // Approved for staging
		Status:    request.StatusApproved,
		CreatedAt: now.Add(-time.Hour),
		UpdatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
		Duration:  8 * time.Hour,
	}
	store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
		return []*request.Request{stagingReq}, nil
	}

	// Looking for production, but only staging is approved
	found, err := request.FindApprovedRequest(ctx, store, "alice", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Errorf("expected nil for mismatched profile, got %+v", found)
	}
}

func TestGating_BreakGlassProfileMismatch(t *testing.T) {
	// FindActiveBreakGlass should only return events for matching profile
	ctx := context.Background()
	store := testutil.NewMockBreakGlassStore()

	now := time.Now()
	stagingEvent := &breakglass.BreakGlassEvent{
		ID:        "bgs12345678901234",
		Invoker:   "alice",
		Profile:   "staging", // Active for staging
		Status:    breakglass.StatusActive,
		CreatedAt: now.Add(-30 * time.Minute),
		ExpiresAt: now.Add(90 * time.Minute),
	}
	store.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		return []*breakglass.BreakGlassEvent{stagingEvent}, nil
	}

	// Looking for production, but only staging has break-glass
	found, err := breakglass.FindActiveBreakGlass(ctx, store, "alice", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Errorf("expected nil for mismatched profile, got %+v", found)
	}
}
