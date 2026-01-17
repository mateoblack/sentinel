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
