// Security invariant tests for break-glass rate limiting.
// These tests verify security boundaries beyond functional correctness:
// - Check ordering (security-critical sequencing)
// - Boundary conditions (exact limit behavior)
// - Rule matching invariants (first-match-wins, case sensitivity)

package breakglass

import (
	"context"
	"testing"
	"time"
)

// ============================================================================
// Call-Tracking Mock for Order Verification
// ============================================================================

// orderTrackingStore is a mock that records the order of method calls.
// Used to verify security-critical check ordering in CheckRateLimit.
type orderTrackingStore struct {
	Calls []string

	// Configurable return values
	lastEvent     *BreakGlassEvent
	lastEventErr  error
	userCount     int
	userCountErr  error
	profileCount  int
	profileCountErr error
}

func (m *orderTrackingStore) Create(ctx context.Context, event *BreakGlassEvent) error {
	m.Calls = append(m.Calls, "Create")
	return nil
}

func (m *orderTrackingStore) Get(ctx context.Context, id string) (*BreakGlassEvent, error) {
	m.Calls = append(m.Calls, "Get")
	return nil, nil
}

func (m *orderTrackingStore) Update(ctx context.Context, event *BreakGlassEvent) error {
	m.Calls = append(m.Calls, "Update")
	return nil
}

func (m *orderTrackingStore) Delete(ctx context.Context, id string) error {
	m.Calls = append(m.Calls, "Delete")
	return nil
}

func (m *orderTrackingStore) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
	m.Calls = append(m.Calls, "ListByInvoker")
	return []*BreakGlassEvent{}, nil
}

func (m *orderTrackingStore) ListByStatus(ctx context.Context, status BreakGlassStatus, limit int) ([]*BreakGlassEvent, error) {
	m.Calls = append(m.Calls, "ListByStatus")
	return []*BreakGlassEvent{}, nil
}

func (m *orderTrackingStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*BreakGlassEvent, error) {
	m.Calls = append(m.Calls, "ListByProfile")
	return []*BreakGlassEvent{}, nil
}

func (m *orderTrackingStore) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	m.Calls = append(m.Calls, "FindActiveByInvokerAndProfile")
	return nil, nil
}

func (m *orderTrackingStore) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	m.Calls = append(m.Calls, "CountByInvokerSince")
	return m.userCount, m.userCountErr
}

func (m *orderTrackingStore) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	m.Calls = append(m.Calls, "CountByProfileSince")
	return m.profileCount, m.profileCountErr
}

func (m *orderTrackingStore) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	m.Calls = append(m.Calls, "GetLastByInvokerAndProfile")
	return m.lastEvent, m.lastEventErr
}

// ============================================================================
// Check Order Security Tests
// ============================================================================

// TestCheckRateLimit_Order_CooldownBeforeQuota verifies that cooldown is checked
// before user/profile quota. This is security-critical because cooldown provides
// immediate rate limiting and should short-circuit early on failure.
func TestCheckRateLimit_Order_CooldownBeforeQuota(t *testing.T) {
	now := time.Now()
	lastEventTime := now.Add(-30 * time.Minute) // 30 minutes ago, within cooldown

	store := &orderTrackingStore{
		lastEvent: &BreakGlassEvent{
			ID:        "last001",
			Invoker:   "alice",
			Profile:   "production",
			CreatedAt: lastEventTime,
		},
		userCount:    0, // Should never be checked
		profileCount: 0, // Should never be checked
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:          "production",
				Profiles:      []string{"production"},
				Cooldown:      time.Hour,    // 1 hour cooldown, only 30 min elapsed
				MaxPerUser:    5,            // Set quota to verify it's not checked
				MaxPerProfile: 10,
				QuotaWindow:   24 * time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	// Should be blocked by cooldown
	if result.Allowed {
		t.Error("CheckRateLimit() should block when cooldown hasn't elapsed")
	}
	if result.Reason != "cooldown period not elapsed" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "cooldown period not elapsed")
	}

	// Verify check order: only cooldown was checked (GetLastByInvokerAndProfile)
	// CountByInvokerSince and CountByProfileSince should NOT be called
	expectedCalls := []string{"GetLastByInvokerAndProfile"}
	if len(store.Calls) != len(expectedCalls) {
		t.Fatalf("CheckRateLimit() made %d calls, want %d: %v", len(store.Calls), len(expectedCalls), store.Calls)
	}
	for i, call := range expectedCalls {
		if store.Calls[i] != call {
			t.Errorf("CheckRateLimit() call[%d] = %q, want %q", i, store.Calls[i], call)
		}
	}
}

// TestCheckRateLimit_Order_UserQuotaBeforeProfileQuota verifies that user quota
// is checked before profile quota. This ensures per-user limits are enforced
// before more permissive per-profile limits.
func TestCheckRateLimit_Order_UserQuotaBeforeProfileQuota(t *testing.T) {
	now := time.Now()

	store := &orderTrackingStore{
		lastEvent:    nil, // No cooldown configured or passed
		userCount:    5,   // At user limit - should block
		profileCount: 0,   // Should never be checked
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:          "production",
				Profiles:      []string{"production"},
				MaxPerUser:    5,
				MaxPerProfile: 10,
				QuotaWindow:   24 * time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	// Should be blocked by user quota
	if result.Allowed {
		t.Error("CheckRateLimit() should block when user quota exceeded")
	}
	if result.Reason != "user quota exceeded" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "user quota exceeded")
	}

	// Verify check order: user quota checked, profile quota NOT checked
	expectedCalls := []string{"CountByInvokerSince"}
	if len(store.Calls) != len(expectedCalls) {
		t.Fatalf("CheckRateLimit() made %d calls, want %d: %v", len(store.Calls), len(expectedCalls), store.Calls)
	}
	for i, call := range expectedCalls {
		if store.Calls[i] != call {
			t.Errorf("CheckRateLimit() call[%d] = %q, want %q", i, store.Calls[i], call)
		}
	}
}

// TestCheckRateLimit_Order_EscalationDoesNotBlock verifies that escalation threshold
// flags for notification but never blocks access. This is a security design decision:
// escalation is informational, not a blocking control.
func TestCheckRateLimit_Order_EscalationDoesNotBlock(t *testing.T) {
	now := time.Now()

	store := &orderTrackingStore{
		lastEvent:    nil,
		userCount:    4, // At escalation threshold (4) but under user quota (5)
		profileCount: 3, // Under profile quota
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:                "production",
				Profiles:            []string{"production"},
				MaxPerUser:          5,
				MaxPerProfile:       10,
				QuotaWindow:         24 * time.Hour,
				EscalationThreshold: 4, // At this count, escalation should be flagged
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	// Should be ALLOWED even at escalation threshold
	if !result.Allowed {
		t.Errorf("CheckRateLimit() should allow when at escalation threshold but under quota, got Reason=%q", result.Reason)
	}

	// Escalation flag should be set
	if !result.ShouldEscalate {
		t.Error("CheckRateLimit() ShouldEscalate should be true when at escalation threshold")
	}

	// Verify all checks ran (escalation doesn't short-circuit)
	// Order: CountByInvokerSince, CountByProfileSince
	expectedCalls := []string{"CountByInvokerSince", "CountByProfileSince"}
	if len(store.Calls) != len(expectedCalls) {
		t.Fatalf("CheckRateLimit() made %d calls, want %d: %v", len(store.Calls), len(expectedCalls), store.Calls)
	}
	for i, call := range expectedCalls {
		if store.Calls[i] != call {
			t.Errorf("CheckRateLimit() call[%d] = %q, want %q", i, store.Calls[i], call)
		}
	}
}

// TestCheckRateLimit_Order_FullCheckSequence verifies the complete check order
// when all checks pass: cooldown -> user quota -> profile quota -> escalation.
func TestCheckRateLimit_Order_FullCheckSequence(t *testing.T) {
	now := time.Now()
	lastEventTime := now.Add(-2 * time.Hour) // Well past cooldown

	store := &orderTrackingStore{
		lastEvent: &BreakGlassEvent{
			ID:        "last001",
			CreatedAt: lastEventTime,
		},
		userCount:    2, // Under user quota
		profileCount: 5, // Under profile quota
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:                "production",
				Profiles:            []string{"production"},
				Cooldown:            time.Hour,
				MaxPerUser:          5,
				MaxPerProfile:       10,
				QuotaWindow:         24 * time.Hour,
				EscalationThreshold: 4,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	if !result.Allowed {
		t.Errorf("CheckRateLimit() should be allowed, got Reason=%q", result.Reason)
	}

	// Verify complete check order
	expectedCalls := []string{
		"GetLastByInvokerAndProfile", // Cooldown check
		"CountByInvokerSince",        // User quota check
		"CountByProfileSince",        // Profile quota check
	}
	if len(store.Calls) != len(expectedCalls) {
		t.Fatalf("CheckRateLimit() made %d calls, want %d: %v", len(store.Calls), len(expectedCalls), store.Calls)
	}
	for i, call := range expectedCalls {
		if store.Calls[i] != call {
			t.Errorf("CheckRateLimit() call[%d] = %q, want %q", i, store.Calls[i], call)
		}
	}
}

// ============================================================================
// Boundary Condition Security Tests
// ============================================================================

// boundaryStore is a mock for precise boundary condition testing.
type boundaryStore struct {
	lastEvent    *BreakGlassEvent
	userCount    int
	profileCount int
}

func (m *boundaryStore) Create(ctx context.Context, event *BreakGlassEvent) error { return nil }
func (m *boundaryStore) Get(ctx context.Context, id string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *boundaryStore) Update(ctx context.Context, event *BreakGlassEvent) error { return nil }
func (m *boundaryStore) Delete(ctx context.Context, id string) error              { return nil }
func (m *boundaryStore) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *boundaryStore) ListByStatus(ctx context.Context, status BreakGlassStatus, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *boundaryStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *boundaryStore) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *boundaryStore) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	return m.userCount, nil
}
func (m *boundaryStore) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	return m.profileCount, nil
}
func (m *boundaryStore) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return m.lastEvent, nil
}

// TestCheckRateLimit_Boundary_ExactlyAtUserLimit verifies that count == MaxPerUser
// blocks access (>= comparison). This is security-critical: must not allow
// count >= limit.
func TestCheckRateLimit_Boundary_ExactlyAtUserLimit(t *testing.T) {
	now := time.Now()

	store := &boundaryStore{
		userCount: 5, // Exactly at limit
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:        "production",
				Profiles:    []string{"production"},
				MaxPerUser:  5,
				QuotaWindow: 24 * time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	if result.Allowed {
		t.Error("CheckRateLimit() should BLOCK when count == MaxPerUser (boundary)")
	}
	if result.Reason != "user quota exceeded" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "user quota exceeded")
	}
}

// TestCheckRateLimit_Boundary_OneBelowUserLimit verifies that count == MaxPerUser-1
// allows access. This validates the >= boundary is correct.
func TestCheckRateLimit_Boundary_OneBelowUserLimit(t *testing.T) {
	now := time.Now()

	store := &boundaryStore{
		userCount: 4, // One below limit (MaxPerUser=5)
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:        "production",
				Profiles:    []string{"production"},
				MaxPerUser:  5,
				QuotaWindow: 24 * time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	if !result.Allowed {
		t.Errorf("CheckRateLimit() should ALLOW when count == MaxPerUser-1, got Reason=%q", result.Reason)
	}
}

// TestCheckRateLimit_Boundary_ExactlyAtProfileLimit verifies that count == MaxPerProfile
// blocks access (>= comparison).
func TestCheckRateLimit_Boundary_ExactlyAtProfileLimit(t *testing.T) {
	now := time.Now()

	store := &boundaryStore{
		userCount:    2, // Under user limit
		profileCount: 10, // Exactly at profile limit
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:          "production",
				Profiles:      []string{"production"},
				MaxPerUser:    5,
				MaxPerProfile: 10,
				QuotaWindow:   24 * time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	if result.Allowed {
		t.Error("CheckRateLimit() should BLOCK when count == MaxPerProfile (boundary)")
	}
	if result.Reason != "profile quota exceeded" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "profile quota exceeded")
	}
}

// TestCheckRateLimit_Boundary_OneBelowProfileLimit verifies that count == MaxPerProfile-1
// allows access.
func TestCheckRateLimit_Boundary_OneBelowProfileLimit(t *testing.T) {
	now := time.Now()

	store := &boundaryStore{
		userCount:    2, // Under user limit
		profileCount: 9, // One below profile limit (MaxPerProfile=10)
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:          "production",
				Profiles:      []string{"production"},
				MaxPerUser:    5,
				MaxPerProfile: 10,
				QuotaWindow:   24 * time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	if !result.Allowed {
		t.Errorf("CheckRateLimit() should ALLOW when count == MaxPerProfile-1, got Reason=%q", result.Reason)
	}
}

// TestCheckRateLimit_Boundary_ExactlyAtCooldown verifies that elapsed == Cooldown
// allows access (cooldown period has exactly elapsed).
func TestCheckRateLimit_Boundary_ExactlyAtCooldown(t *testing.T) {
	now := time.Now()
	cooldown := time.Hour
	// Last event exactly 1 hour ago (cooldown has just elapsed)
	lastEventTime := now.Add(-cooldown)

	store := &boundaryStore{
		lastEvent: &BreakGlassEvent{
			ID:        "last001",
			CreatedAt: lastEventTime,
		},
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Cooldown: cooldown,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	// elapsed == cooldown means exactly at boundary, should NOT be blocked
	// The comparison is: if elapsed < rule.Cooldown (strict less than)
	// So elapsed == cooldown should be ALLOWED
	if !result.Allowed {
		t.Errorf("CheckRateLimit() should ALLOW when elapsed == Cooldown (boundary), got Reason=%q", result.Reason)
	}
}

// TestCheckRateLimit_Boundary_OneNanosecondBeforeCooldown verifies that elapsed == Cooldown-1ns
// blocks access. This validates the < comparison is strict.
func TestCheckRateLimit_Boundary_OneNanosecondBeforeCooldown(t *testing.T) {
	now := time.Now()
	cooldown := time.Hour
	// Last event 1 nanosecond short of cooldown completion
	lastEventTime := now.Add(-cooldown + time.Nanosecond)

	store := &boundaryStore{
		lastEvent: &BreakGlassEvent{
			ID:        "last001",
			CreatedAt: lastEventTime,
		},
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Cooldown: cooldown,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	if result.Allowed {
		t.Error("CheckRateLimit() should BLOCK when elapsed < Cooldown by 1ns (boundary)")
	}
	if result.Reason != "cooldown period not elapsed" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "cooldown period not elapsed")
	}
}

// TestCheckRateLimit_Boundary_ZeroElapsed verifies that elapsed == 0 blocks access.
// This is an edge case where the last event was at exactly "now".
func TestCheckRateLimit_Boundary_ZeroElapsed(t *testing.T) {
	now := time.Now()
	// Last event at exactly "now" (0 elapsed time)
	lastEventTime := now

	store := &boundaryStore{
		lastEvent: &BreakGlassEvent{
			ID:        "last001",
			CreatedAt: lastEventTime,
		},
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Cooldown: time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	if result.Allowed {
		t.Error("CheckRateLimit() should BLOCK when elapsed == 0")
	}
	if result.Reason != "cooldown period not elapsed" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "cooldown period not elapsed")
	}
}

// TestCheckRateLimit_Boundary_QuotaLimitZero verifies behavior when MaxPerUser is 0 (disabled).
// Zero quota means no limit, not "always blocked".
func TestCheckRateLimit_Boundary_QuotaLimitZero(t *testing.T) {
	now := time.Now()

	store := &boundaryStore{
		userCount: 100, // Many events but no quota set
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Cooldown: time.Hour, // Cooldown set but no quota
				// MaxPerUser: 0 (disabled)
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	// MaxPerUser=0 means quota check is skipped entirely
	if !result.Allowed {
		t.Errorf("CheckRateLimit() should ALLOW when MaxPerUser=0 (disabled), got Reason=%q", result.Reason)
	}
}

// TestCheckRateLimit_Boundary_EscalationThresholdExact verifies escalation flag at exact threshold.
func TestCheckRateLimit_Boundary_EscalationThresholdExact(t *testing.T) {
	now := time.Now()

	store := &boundaryStore{
		userCount: 3, // Exactly at escalation threshold
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:                "production",
				Profiles:            []string{"production"},
				MaxPerUser:          5,
				QuotaWindow:         24 * time.Hour,
				EscalationThreshold: 3,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	if !result.Allowed {
		t.Errorf("CheckRateLimit() should ALLOW at escalation threshold, got Reason=%q", result.Reason)
	}
	if !result.ShouldEscalate {
		t.Error("CheckRateLimit() ShouldEscalate should be true at exact threshold (count >= threshold)")
	}
}

// TestCheckRateLimit_Boundary_EscalationThresholdOneBelowt verifies no escalation below threshold.
func TestCheckRateLimit_Boundary_EscalationThresholdOneBelow(t *testing.T) {
	now := time.Now()

	store := &boundaryStore{
		userCount: 2, // One below escalation threshold
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:                "production",
				Profiles:            []string{"production"},
				MaxPerUser:          5,
				QuotaWindow:         24 * time.Hour,
				EscalationThreshold: 3,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}

	if !result.Allowed {
		t.Errorf("CheckRateLimit() should ALLOW below escalation threshold, got Reason=%q", result.Reason)
	}
	if result.ShouldEscalate {
		t.Error("CheckRateLimit() ShouldEscalate should be false when below threshold")
	}
}

// ============================================================================
// Rule Matching Security Tests
// ============================================================================

// TestFindRateLimitRule_FirstMatchWins_Strict verifies that when multiple rules
// could match, the first one wins. This tests specific-before-wildcard ordering.
func TestFindRateLimitRule_FirstMatchWins_Strict(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production-strict",
				Profiles: []string{"production"}, // Specific rule first
				Cooldown: time.Hour,
			},
			{
				Name:     "default-wildcard",
				Profiles: []string{}, // Wildcard after specific
				Cooldown: 30 * time.Minute,
			},
		},
	}

	rule := FindRateLimitRule(policy, "production")
	if rule == nil {
		t.Fatal("FindRateLimitRule() returned nil")
	}
	if rule.Name != "production-strict" {
		t.Errorf("FindRateLimitRule() = %q, want %q (first match should win)", rule.Name, "production-strict")
	}
	// Verify the rule's cooldown to ensure we got the right one
	if rule.Cooldown != time.Hour {
		t.Errorf("FindRateLimitRule().Cooldown = %v, want %v", rule.Cooldown, time.Hour)
	}
}

// TestFindRateLimitRule_FirstMatchWins_WildcardFirst verifies that if wildcard
// comes first, it applies even when a more specific rule exists later.
// This is a security design decision: rule order determines precedence.
func TestFindRateLimitRule_FirstMatchWins_WildcardFirst(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "default-wildcard",
				Profiles: []string{}, // Wildcard first
				Cooldown: 30 * time.Minute,
			},
			{
				Name:     "production-strict",
				Profiles: []string{"production"}, // Specific rule after wildcard
				Cooldown: time.Hour,
			},
		},
	}

	rule := FindRateLimitRule(policy, "production")
	if rule == nil {
		t.Fatal("FindRateLimitRule() returned nil")
	}
	// Wildcard should match first, even though production-strict exists
	if rule.Name != "default-wildcard" {
		t.Errorf("FindRateLimitRule() = %q, want %q (wildcard came first)", rule.Name, "default-wildcard")
	}
	if rule.Cooldown != 30*time.Minute {
		t.Errorf("FindRateLimitRule().Cooldown = %v, want %v", rule.Cooldown, 30*time.Minute)
	}
}

// TestFindRateLimitRule_ProfileCaseSensitive verifies that profile matching
// is case-sensitive. "Production" and "production" are different profiles.
func TestFindRateLimitRule_ProfileCaseSensitive(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production-lower",
				Profiles: []string{"production"},
				Cooldown: time.Hour,
			},
		},
	}

	tests := []struct {
		profile   string
		wantMatch bool
	}{
		{"production", true},
		{"Production", false}, // Different case
		{"PRODUCTION", false}, // Different case
		{"prod", false},       // Different string
		{"production ", false}, // Trailing space
		{" production", false}, // Leading space
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			rule := FindRateLimitRule(policy, tt.profile)
			if tt.wantMatch {
				if rule == nil {
					t.Errorf("FindRateLimitRule(%q) = nil, want match", tt.profile)
				}
			} else {
				if rule != nil {
					t.Errorf("FindRateLimitRule(%q) = %q, want nil (case sensitive)", tt.profile, rule.Name)
				}
			}
		})
	}
}

// TestFindRateLimitRule_EmptyProfile verifies that empty profile string
// only matches wildcard rules (empty Profiles list).
func TestFindRateLimitRule_EmptyProfile(t *testing.T) {
	t.Run("no match without wildcard", func(t *testing.T) {
		policy := &RateLimitPolicy{
			Version: "1",
			Rules: []RateLimitRule{
				{
					Name:     "production-only",
					Profiles: []string{"production"},
					Cooldown: time.Hour,
				},
			},
		}

		rule := FindRateLimitRule(policy, "")
		if rule != nil {
			t.Errorf("FindRateLimitRule(\"\") = %q, want nil (no wildcard)", rule.Name)
		}
	})

	t.Run("matches wildcard", func(t *testing.T) {
		policy := &RateLimitPolicy{
			Version: "1",
			Rules: []RateLimitRule{
				{
					Name:     "wildcard-all",
					Profiles: []string{}, // Wildcard
					Cooldown: time.Hour,
				},
			},
		}

		rule := FindRateLimitRule(policy, "")
		if rule == nil {
			t.Fatal("FindRateLimitRule(\"\") = nil, want wildcard match")
		}
		if rule.Name != "wildcard-all" {
			t.Errorf("FindRateLimitRule(\"\") = %q, want %q", rule.Name, "wildcard-all")
		}
	})
}

// TestFindRateLimitRule_MultipleWildcards verifies that when multiple wildcard
// rules exist, the first one wins.
func TestFindRateLimitRule_MultipleWildcards(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "first-wildcard",
				Profiles: []string{}, // First wildcard
				Cooldown: time.Hour,
			},
			{
				Name:     "second-wildcard",
				Profiles: []string{}, // Second wildcard
				Cooldown: 2 * time.Hour,
			},
			{
				Name:     "third-wildcard",
				Profiles: []string{}, // Third wildcard
				Cooldown: 3 * time.Hour,
			},
		},
	}

	rule := FindRateLimitRule(policy, "any-profile")
	if rule == nil {
		t.Fatal("FindRateLimitRule() = nil")
	}
	if rule.Name != "first-wildcard" {
		t.Errorf("FindRateLimitRule() = %q, want %q (first wildcard wins)", rule.Name, "first-wildcard")
	}
}

// ruleMatchTrackingStore is a mock that tracks which rules were evaluated.
type ruleMatchTrackingStore struct {
	lastEvent    *BreakGlassEvent
	userCount    int
	profileCount int
}

func (m *ruleMatchTrackingStore) Create(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}
func (m *ruleMatchTrackingStore) Get(ctx context.Context, id string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *ruleMatchTrackingStore) Update(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}
func (m *ruleMatchTrackingStore) Delete(ctx context.Context, id string) error { return nil }
func (m *ruleMatchTrackingStore) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *ruleMatchTrackingStore) ListByStatus(ctx context.Context, status BreakGlassStatus, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *ruleMatchTrackingStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *ruleMatchTrackingStore) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *ruleMatchTrackingStore) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	return m.userCount, nil
}
func (m *ruleMatchTrackingStore) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	return m.profileCount, nil
}
func (m *ruleMatchTrackingStore) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return m.lastEvent, nil
}

// TestCheckRateLimit_DifferentRulesForDifferentProfiles verifies that different
// profiles get different rules applied, demonstrating rule isolation.
func TestCheckRateLimit_DifferentRulesForDifferentProfiles(t *testing.T) {
	now := time.Now()

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:        "production-strict",
				Profiles:    []string{"production"},
				MaxPerUser:  2, // Strict limit for production
				QuotaWindow: 24 * time.Hour,
			},
			{
				Name:        "staging-lenient",
				Profiles:    []string{"staging"},
				MaxPerUser:  10, // Lenient limit for staging
				QuotaWindow: 24 * time.Hour,
			},
		},
	}

	tests := []struct {
		profile   string
		userCount int
		wantAllow bool
		wantRule  string
	}{
		// Production with 2 events should block (MaxPerUser=2)
		{"production", 2, false, "production-strict"},
		// Production with 1 event should allow
		{"production", 1, true, "production-strict"},
		// Staging with 5 events should allow (MaxPerUser=10)
		{"staging", 5, true, "staging-lenient"},
		// Staging with 10 events should block
		{"staging", 10, false, "staging-lenient"},
	}

	for _, tt := range tests {
		t.Run(tt.profile+"_count_"+string(rune('0'+tt.userCount)), func(t *testing.T) {
			store := &ruleMatchTrackingStore{
				userCount: tt.userCount,
			}

			result, err := CheckRateLimit(context.Background(), store, policy, "alice", tt.profile, now)
			if err != nil {
				t.Fatalf("CheckRateLimit() error = %v", err)
			}

			if result.Allowed != tt.wantAllow {
				t.Errorf("CheckRateLimit() Allowed = %v, want %v (profile=%s, count=%d)",
					result.Allowed, tt.wantAllow, tt.profile, tt.userCount)
			}
		})
	}
}

// TestCheckRateLimit_RateLimitNotAppliedWhenNoMatch verifies that when no rule
// matches the profile, rate limiting is not applied (allowed by default).
// This is a security design decision: no matching rule = no rate limit.
func TestCheckRateLimit_RateLimitNotAppliedWhenNoMatch(t *testing.T) {
	now := time.Now()

	// Very restrictive policy that only applies to "production"
	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:        "production-only",
				Profiles:    []string{"production"},
				MaxPerUser:  1, // Very restrictive
				QuotaWindow: 24 * time.Hour,
			},
		},
	}

	// Simulate 100 events for a profile that doesn't match
	store := &ruleMatchTrackingStore{
		userCount: 100,
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "development", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v", err)
	}

	// Should be allowed because "development" doesn't match any rule
	if !result.Allowed {
		t.Errorf("CheckRateLimit() Allowed = false, want true (no matching rule)")
	}
}

// TestFindRateLimitRule_MultiProfileMatch verifies that rules with multiple
// profiles correctly match any of them.
func TestFindRateLimitRule_MultiProfileMatch(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "prod-environments",
				Profiles: []string{"production", "production-dr", "production-eu"},
				Cooldown: time.Hour,
			},
			{
				Name:     "non-prod",
				Profiles: []string{}, // Wildcard for others
				Cooldown: 15 * time.Minute,
			},
		},
	}

	tests := []struct {
		profile  string
		wantRule string
	}{
		{"production", "prod-environments"},
		{"production-dr", "prod-environments"},
		{"production-eu", "prod-environments"},
		{"staging", "non-prod"},       // Falls to wildcard
		{"development", "non-prod"},   // Falls to wildcard
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			rule := FindRateLimitRule(policy, tt.profile)
			if rule == nil {
				t.Fatalf("FindRateLimitRule(%q) = nil, want %q", tt.profile, tt.wantRule)
			}
			if rule.Name != tt.wantRule {
				t.Errorf("FindRateLimitRule(%q) = %q, want %q", tt.profile, rule.Name, tt.wantRule)
			}
		})
	}
}

// TestFindRateLimitRule_ExactMatchRequired verifies that partial matches don't work.
// "prod" should not match "production".
func TestFindRateLimitRule_ExactMatchRequired(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production-rule",
				Profiles: []string{"production"},
				Cooldown: time.Hour,
			},
		},
	}

	partialMatches := []string{
		"prod",           // Prefix
		"duction",        // Suffix
		"oductio",        // Middle
		"production1",    // Extra chars
		"my-production",  // Prefix addition
		"production-new", // Suffix addition
	}

	for _, partial := range partialMatches {
		t.Run(partial, func(t *testing.T) {
			rule := FindRateLimitRule(policy, partial)
			if rule != nil {
				t.Errorf("FindRateLimitRule(%q) = %q, want nil (exact match required)", partial, rule.Name)
			}
		})
	}
}
