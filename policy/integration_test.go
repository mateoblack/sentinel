// Package policy_test contains integration tests for the policy package.
// These tests verify the interaction between policy evaluation and the approval workflow.
package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/testutil"
)

// ============================================================================
// EffectRequireApproval Flow Integration Tests
// ============================================================================

func TestIntegration_RequireApprovalFlow(t *testing.T) {
	// Test the complete flow: policy evaluation -> require_approval -> approve -> access granted

	// Create policy with require_approval effect
	accessPolicy := &policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				Name:   "require-approval-for-prod",
				Effect: policy.EffectRequireApproval,
				Conditions: policy.Condition{
					Profiles: []string{"prod"},
				},
				Reason: "Production access requires approval",
			},
			{
				Name:   "allow-dev",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{"dev"},
				},
			},
		},
	}

	// Create approval policy
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1.0",
		Rules: []policy.ApprovalRule{
			{
				Name:      "prod-approvers",
				Profiles:  []string{"prod"},
				Approvers: []string{"manager1", "manager2"},
			},
		},
	}

	// Setup mock store with ListByRequester implementation that queries in-memory storage
	store := testutil.NewMockRequestStore()

	// Configure ListByRequester to return matching requests from internal storage
	// The mock uses a map keyed by ID, we filter by requester
	store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
		var results []*request.Request
		for _, req := range store.Requests {
			if req.Requester == requester {
				results = append(results, req)
			}
		}
		return results, nil
	}

	t.Run("step1_evaluate_returns_require_approval", func(t *testing.T) {
		req := &policy.Request{
			User:    "alice",
			Profile: "prod",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(accessPolicy, req)

		if decision.Effect != policy.EffectRequireApproval {
			t.Errorf("expected EffectRequireApproval, got %s", decision.Effect)
		}
		if decision.MatchedRule != "require-approval-for-prod" {
			t.Errorf("expected rule 'require-approval-for-prod', got %s", decision.MatchedRule)
		}
	})

	t.Run("step2_create_approval_request", func(t *testing.T) {
		ctx := context.Background()
		now := time.Now()

		approvalReq := &request.Request{
			ID:            "a1b2c3d4e5f6a7b8",
			Requester:     "alice",
			Profile:       "prod",
			Justification: "Need to deploy hotfix for incident #123",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}

		err := store.Create(ctx, approvalReq)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		// Verify request is in store
		got, err := store.Get(ctx, approvalReq.ID)
		if err != nil {
			t.Fatalf("failed to get request: %v", err)
		}
		if got.Status != request.StatusPending {
			t.Errorf("expected pending status, got %s", got.Status)
		}
	})

	t.Run("step3_verify_approver_authorization", func(t *testing.T) {
		rule := policy.FindApprovalRule(approvalPolicy, "prod")
		if rule == nil {
			t.Fatal("expected to find approval rule for prod")
		}

		// Authorized approver
		if !policy.CanApprove(rule, "manager1") {
			t.Error("manager1 should be authorized to approve")
		}
		if !policy.CanApprove(rule, "manager2") {
			t.Error("manager2 should be authorized to approve")
		}

		// Unauthorized user
		if policy.CanApprove(rule, "alice") {
			t.Error("alice should NOT be authorized to approve (requester)")
		}
		if policy.CanApprove(rule, "bob") {
			t.Error("bob should NOT be authorized to approve")
		}
	})

	t.Run("step4_approve_and_verify_access", func(t *testing.T) {
		ctx := context.Background()

		// Approve the request
		req, err := store.Get(ctx, "a1b2c3d4e5f6a7b8")
		if err != nil {
			t.Fatalf("failed to get request: %v", err)
		}

		req.Status = request.StatusApproved
		req.Approver = "manager1"
		req.ApproverComment = "Approved for hotfix deployment"
		req.UpdatedAt = time.Now()

		err = store.Update(ctx, req)
		if err != nil {
			t.Fatalf("failed to update request: %v", err)
		}

		// Verify approved request can be found
		approved, err := request.FindApprovedRequest(ctx, store, "alice", "prod")
		if err != nil {
			t.Fatalf("failed to find approved request: %v", err)
		}
		if approved == nil {
			t.Fatal("expected to find approved request")
		}
		if approved.Status != request.StatusApproved {
			t.Errorf("expected approved status, got %s", approved.Status)
		}
		if approved.Approver != "manager1" {
			t.Errorf("expected approver 'manager1', got %s", approved.Approver)
		}
	})
}

func TestIntegration_DenyAfterRequireApproval(t *testing.T) {
	// Test the flow where a request is denied

	store := testutil.NewMockRequestStore()
	ctx := context.Background()
	now := time.Now()

	// Create pending request
	req := &request.Request{
		ID:            "b2c3d4e5f6a7b8c9",
		Requester:     "bob",
		Profile:       "prod",
		Justification: "Testing denial flow",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(request.DefaultRequestTTL),
	}

	err := store.Create(ctx, req)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Deny the request
	req.Status = request.StatusDenied
	req.Approver = "manager1"
	req.ApproverComment = "Denied - use staging instead"
	req.UpdatedAt = time.Now()

	err = store.Update(ctx, req)
	if err != nil {
		t.Fatalf("failed to update request: %v", err)
	}

	// Verify denied request is NOT found as approved
	approved, err := request.FindApprovedRequest(ctx, store, "bob", "prod")
	if err != nil {
		t.Fatalf("failed to find approved request: %v", err)
	}
	if approved != nil {
		t.Error("denied request should NOT be found as approved")
	}
}

// ============================================================================
// Auto-Approve Policy Integration Tests
// ============================================================================

func TestIntegration_AutoApprovePolicy(t *testing.T) {
	// Test auto-approve conditions with user list and time window

	t.Run("auto_approve_matching_user", func(t *testing.T) {
		approvalPolicy := &policy.ApprovalPolicy{
			Version: "1.0",
			Rules: []policy.ApprovalRule{
				{
					Name:      "auto-approve-oncall",
					Profiles:  []string{"staging"},
					Approvers: []string{"manager1"},
					AutoApprove: &policy.AutoApproveCondition{
						Users:       []string{"oncall1", "oncall2"},
						MaxDuration: 2 * time.Hour,
					},
				},
			},
		}

		rule := policy.FindApprovalRule(approvalPolicy, "staging")
		if rule == nil {
			t.Fatal("expected to find approval rule")
		}

		// Matching user with acceptable duration
		if !policy.ShouldAutoApprove(rule, "oncall1", time.Now(), 1*time.Hour) {
			t.Error("oncall1 should be auto-approved")
		}

		// Matching user with max duration exactly
		if !policy.ShouldAutoApprove(rule, "oncall2", time.Now(), 2*time.Hour) {
			t.Error("oncall2 should be auto-approved at max duration")
		}

		// Non-matching user
		if policy.ShouldAutoApprove(rule, "alice", time.Now(), 1*time.Hour) {
			t.Error("alice should NOT be auto-approved (not in user list)")
		}

		// Duration exceeds max
		if policy.ShouldAutoApprove(rule, "oncall1", time.Now(), 3*time.Hour) {
			t.Error("oncall1 should NOT be auto-approved (duration exceeds max)")
		}
	})

	t.Run("auto_approve_time_window", func(t *testing.T) {
		approvalPolicy := &policy.ApprovalPolicy{
			Version: "1.0",
			Rules: []policy.ApprovalRule{
				{
					Name:      "business-hours-auto-approve",
					Profiles:  []string{"dev"},
					Approvers: []string{"manager1"},
					AutoApprove: &policy.AutoApproveCondition{
						Users: []string{"dev1"},
						Time: &policy.TimeWindow{
							Days: []policy.Weekday{
								policy.Monday, policy.Tuesday, policy.Wednesday,
								policy.Thursday, policy.Friday,
							},
							Hours: &policy.HourRange{
								Start: "09:00",
								End:   "18:00",
							},
							Timezone: "UTC",
						},
					},
				},
			},
		}

		rule := policy.FindApprovalRule(approvalPolicy, "dev")
		if rule == nil {
			t.Fatal("expected to find approval rule")
		}

		// Request during business hours (Monday 10:00 UTC)
		businessHours := time.Date(2026, 1, 19, 10, 0, 0, 0, time.UTC) // Monday
		if !policy.ShouldAutoApprove(rule, "dev1", businessHours, 1*time.Hour) {
			t.Error("should auto-approve during business hours")
		}

		// Request outside business hours (Monday 20:00 UTC)
		afterHours := time.Date(2026, 1, 19, 20, 0, 0, 0, time.UTC) // Monday
		if policy.ShouldAutoApprove(rule, "dev1", afterHours, 1*time.Hour) {
			t.Error("should NOT auto-approve after business hours")
		}

		// Request on weekend (Saturday)
		weekend := time.Date(2026, 1, 17, 10, 0, 0, 0, time.UTC) // Saturday
		if policy.ShouldAutoApprove(rule, "dev1", weekend, 1*time.Hour) {
			t.Error("should NOT auto-approve on weekend")
		}
	})

	t.Run("auto_approve_empty_users_means_all", func(t *testing.T) {
		// Empty users list means any user can auto-approve (if other conditions match)
		approvalPolicy := &policy.ApprovalPolicy{
			Version: "1.0",
			Rules: []policy.ApprovalRule{
				{
					Name:      "all-users-auto-approve",
					Profiles:  []string{"sandbox"},
					Approvers: []string{"anyone"},
					AutoApprove: &policy.AutoApproveCondition{
						Users:       []string{}, // Empty = any user
						MaxDuration: 1 * time.Hour,
					},
				},
			},
		}

		rule := policy.FindApprovalRule(approvalPolicy, "sandbox")
		if rule == nil {
			t.Fatal("expected to find approval rule")
		}

		// Any user should be auto-approved
		if !policy.ShouldAutoApprove(rule, "random-user", time.Now(), 30*time.Minute) {
			t.Error("any user should be auto-approved when Users list is empty")
		}
	})

	t.Run("no_auto_approve_when_nil", func(t *testing.T) {
		approvalPolicy := &policy.ApprovalPolicy{
			Version: "1.0",
			Rules: []policy.ApprovalRule{
				{
					Name:        "manual-approval-only",
					Profiles:    []string{"production"},
					Approvers:   []string{"admin"},
					AutoApprove: nil, // No auto-approve
				},
			},
		}

		rule := policy.FindApprovalRule(approvalPolicy, "production")
		if rule == nil {
			t.Fatal("expected to find approval rule")
		}

		// No one should be auto-approved
		if policy.ShouldAutoApprove(rule, "anyone", time.Now(), 1*time.Hour) {
			t.Error("no one should be auto-approved when AutoApprove is nil")
		}
	})
}

// ============================================================================
// Approver Authorization Integration Tests
// ============================================================================

func TestIntegration_ApproverAuthorization(t *testing.T) {
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1.0",
		Rules: []policy.ApprovalRule{
			{
				Name:      "prod-approvers",
				Profiles:  []string{"prod-us", "prod-eu"},
				Approvers: []string{"admin", "security-team"},
			},
			{
				Name:      "staging-approvers",
				Profiles:  []string{"staging"},
				Approvers: []string{"lead-dev", "admin"},
			},
			{
				Name:      "catchall-approvers",
				Profiles:  []string{}, // Empty = matches all
				Approvers: []string{"super-admin"},
			},
		},
	}

	t.Run("authorized_approvers_for_profile", func(t *testing.T) {
		// Prod profiles
		rule := policy.FindApprovalRule(approvalPolicy, "prod-us")
		if rule == nil {
			t.Fatal("expected to find rule for prod-us")
		}
		if !policy.CanApprove(rule, "admin") {
			t.Error("admin should be able to approve prod-us")
		}
		if !policy.CanApprove(rule, "security-team") {
			t.Error("security-team should be able to approve prod-us")
		}
		if policy.CanApprove(rule, "lead-dev") {
			t.Error("lead-dev should NOT be able to approve prod-us")
		}

		// Staging
		rule = policy.FindApprovalRule(approvalPolicy, "staging")
		if rule == nil {
			t.Fatal("expected to find rule for staging")
		}
		if !policy.CanApprove(rule, "lead-dev") {
			t.Error("lead-dev should be able to approve staging")
		}
		if !policy.CanApprove(rule, "admin") {
			t.Error("admin should be able to approve staging")
		}
		if policy.CanApprove(rule, "security-team") {
			t.Error("security-team should NOT be able to approve staging")
		}
	})

	t.Run("wildcard_profile_matching", func(t *testing.T) {
		// Unknown profile should match catchall rule
		rule := policy.FindApprovalRule(approvalPolicy, "unknown-profile")
		if rule == nil {
			t.Fatal("expected to find catchall rule")
		}
		if rule.Name != "catchall-approvers" {
			t.Errorf("expected catchall-approvers rule, got %s", rule.Name)
		}
		if !policy.CanApprove(rule, "super-admin") {
			t.Error("super-admin should be able to approve unknown profiles")
		}
	})

	t.Run("first_match_wins", func(t *testing.T) {
		// prod-us should match first specific rule, not catchall
		rule := policy.FindApprovalRule(approvalPolicy, "prod-us")
		if rule == nil {
			t.Fatal("expected to find rule")
		}
		if rule.Name != "prod-approvers" {
			t.Errorf("expected prod-approvers (first match), got %s", rule.Name)
		}
	})

	t.Run("unauthorized_approver", func(t *testing.T) {
		rule := policy.FindApprovalRule(approvalPolicy, "prod-us")
		if rule == nil {
			t.Fatal("expected to find rule")
		}
		if policy.CanApprove(rule, "random-user") {
			t.Error("random-user should NOT be able to approve")
		}
		if policy.CanApprove(rule, "") {
			t.Error("empty approver should NOT be able to approve")
		}
	})

	t.Run("nil_rule_returns_false", func(t *testing.T) {
		if policy.CanApprove(nil, "admin") {
			t.Error("nil rule should return false for CanApprove")
		}
	})

	t.Run("nil_policy_returns_nil_rule", func(t *testing.T) {
		rule := policy.FindApprovalRule(nil, "any-profile")
		if rule != nil {
			t.Error("nil policy should return nil rule")
		}
	})
}

// ============================================================================
// Time Window Policy Evaluation Integration Tests
// ============================================================================

func TestIntegration_TimeWindowPolicyEvaluation(t *testing.T) {
	// Policy that only allows access during business hours
	accessPolicy := &policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				Name:   "business-hours-only",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{"restricted"},
					Time: &policy.TimeWindow{
						Days: []policy.Weekday{
							policy.Monday, policy.Tuesday, policy.Wednesday,
							policy.Thursday, policy.Friday,
						},
						Hours: &policy.HourRange{
							Start: "09:00",
							End:   "18:00",
						},
						Timezone: "UTC",
					},
				},
				Reason: "Access only during business hours",
			},
			{
				Name:   "deny-outside-hours",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Profiles: []string{"restricted"},
				},
				Reason: "Access denied outside business hours",
			},
		},
	}

	t.Run("allowed_during_business_hours", func(t *testing.T) {
		// Wednesday 14:00 UTC
		businessHours := time.Date(2026, 1, 21, 14, 0, 0, 0, time.UTC)
		req := &policy.Request{
			User:    "alice",
			Profile: "restricted",
			Time:    businessHours,
		}

		decision := policy.Evaluate(accessPolicy, req)
		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected allow during business hours, got %s", decision.Effect)
		}
		if decision.MatchedRule != "business-hours-only" {
			t.Errorf("expected 'business-hours-only' rule, got %s", decision.MatchedRule)
		}
	})

	t.Run("denied_outside_hours", func(t *testing.T) {
		// Wednesday 20:00 UTC (after hours)
		afterHours := time.Date(2026, 1, 21, 20, 0, 0, 0, time.UTC)
		req := &policy.Request{
			User:    "alice",
			Profile: "restricted",
			Time:    afterHours,
		}

		decision := policy.Evaluate(accessPolicy, req)
		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny after hours, got %s", decision.Effect)
		}
		if decision.MatchedRule != "deny-outside-hours" {
			t.Errorf("expected 'deny-outside-hours' rule, got %s", decision.MatchedRule)
		}
	})

	t.Run("denied_on_weekend", func(t *testing.T) {
		// Saturday 12:00 UTC (weekend, even though within hour range)
		weekend := time.Date(2026, 1, 17, 12, 0, 0, 0, time.UTC) // Saturday
		req := &policy.Request{
			User:    "alice",
			Profile: "restricted",
			Time:    weekend,
		}

		decision := policy.Evaluate(accessPolicy, req)
		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny on weekend, got %s", decision.Effect)
		}
	})

	t.Run("boundary_start_time", func(t *testing.T) {
		// Monday exactly 09:00 UTC - should be allowed
		exactStart := time.Date(2026, 1, 19, 9, 0, 0, 0, time.UTC)
		req := &policy.Request{
			User:    "alice",
			Profile: "restricted",
			Time:    exactStart,
		}

		decision := policy.Evaluate(accessPolicy, req)
		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected allow at exactly 09:00, got %s (rule: %s)", decision.Effect, decision.MatchedRule)
		}
	})

	t.Run("boundary_end_time", func(t *testing.T) {
		// Monday exactly 18:00 UTC - should be denied (end time is exclusive)
		exactEnd := time.Date(2026, 1, 19, 18, 0, 0, 0, time.UTC)
		req := &policy.Request{
			User:    "alice",
			Profile: "restricted",
			Time:    exactEnd,
		}

		decision := policy.Evaluate(accessPolicy, req)
		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny at exactly 18:00 (exclusive end), got %s", decision.Effect)
		}
	})

	t.Run("one_minute_before_end", func(t *testing.T) {
		// Monday 17:59 UTC - should be allowed
		beforeEnd := time.Date(2026, 1, 19, 17, 59, 0, 0, time.UTC)
		req := &policy.Request{
			User:    "alice",
			Profile: "restricted",
			Time:    beforeEnd,
		}

		decision := policy.Evaluate(accessPolicy, req)
		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected allow at 17:59, got %s", decision.Effect)
		}
	})

	t.Run("one_minute_before_start", func(t *testing.T) {
		// Monday 08:59 UTC - should be denied
		beforeStart := time.Date(2026, 1, 19, 8, 59, 0, 0, time.UTC)
		req := &policy.Request{
			User:    "alice",
			Profile: "restricted",
			Time:    beforeStart,
		}

		decision := policy.Evaluate(accessPolicy, req)
		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny at 08:59, got %s", decision.Effect)
		}
	})
}

func TestIntegration_TimeWindowWithTimezone(t *testing.T) {
	// Policy with timezone conversion
	accessPolicy := &policy.Policy{
		Version: "1.0",
		Rules: []policy.Rule{
			{
				Name:   "tokyo-hours",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{"japan-prod"},
					Time: &policy.TimeWindow{
						Days: []policy.Weekday{
							policy.Monday, policy.Tuesday, policy.Wednesday,
							policy.Thursday, policy.Friday,
						},
						Hours: &policy.HourRange{
							Start: "09:00",
							End:   "18:00",
						},
						Timezone: "Asia/Tokyo",
					},
				},
			},
			{
				Name:   "deny-japan",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Profiles: []string{"japan-prod"},
				},
			},
		},
	}

	t.Run("tokyo_business_hours_from_utc", func(t *testing.T) {
		// 12:00 Tokyo = 03:00 UTC
		utcTime := time.Date(2026, 1, 21, 3, 0, 0, 0, time.UTC) // Wednesday 03:00 UTC = 12:00 Tokyo
		req := &policy.Request{
			User:    "alice",
			Profile: "japan-prod",
			Time:    utcTime,
		}

		decision := policy.Evaluate(accessPolicy, req)
		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected allow during Tokyo business hours, got %s", decision.Effect)
		}
	})

	t.Run("outside_tokyo_hours_from_utc", func(t *testing.T) {
		// 20:00 Tokyo = 11:00 UTC
		utcTime := time.Date(2026, 1, 21, 11, 0, 0, 0, time.UTC) // Wednesday 11:00 UTC = 20:00 Tokyo
		req := &policy.Request{
			User:    "alice",
			Profile: "japan-prod",
			Time:    utcTime,
		}

		decision := policy.Evaluate(accessPolicy, req)
		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected deny outside Tokyo hours, got %s", decision.Effect)
		}
	})
}

// ============================================================================
// GetApprovers Integration Tests
// ============================================================================

func TestIntegration_GetApprovers(t *testing.T) {
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1.0",
		Rules: []policy.ApprovalRule{
			{
				Name:      "prod-team",
				Profiles:  []string{"prod"},
				Approvers: []string{"admin1", "admin2", "security"},
			},
			{
				Name:      "default-team",
				Profiles:  []string{}, // Catchall
				Approvers: []string{"manager"},
			},
		},
	}

	t.Run("returns_approvers_for_matching_profile", func(t *testing.T) {
		approvers := policy.GetApprovers(approvalPolicy, "prod")
		if len(approvers) != 3 {
			t.Errorf("expected 3 approvers, got %d", len(approvers))
		}
		expected := map[string]bool{"admin1": true, "admin2": true, "security": true}
		for _, a := range approvers {
			if !expected[a] {
				t.Errorf("unexpected approver: %s", a)
			}
		}
	})

	t.Run("returns_catchall_for_unknown_profile", func(t *testing.T) {
		approvers := policy.GetApprovers(approvalPolicy, "unknown")
		if len(approvers) != 1 {
			t.Errorf("expected 1 approver from catchall, got %d", len(approvers))
		}
		if approvers[0] != "manager" {
			t.Errorf("expected 'manager', got %s", approvers[0])
		}
	})

	t.Run("returns_nil_for_nil_policy", func(t *testing.T) {
		approvers := policy.GetApprovers(nil, "any")
		if approvers != nil {
			t.Error("expected nil for nil policy")
		}
	})
}
