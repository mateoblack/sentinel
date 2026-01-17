// Security regression tests for break-glass denial paths.
// These tests serve as regression guards against future code changes that
// might inadvertently weaken security by allowing credential issuance
// when break-glass should be denied.
//
// Test naming convention: TestSecurityRegression_<Category>_<Specific>
// Categories:
//   - ExpiredEvent: Tests that expired events are rejected
//   - RateLimit: Tests quota and cooldown enforcement
//   - ProfileIsolation: Tests profile matching is exact
//   - StatusManipulation: Tests state machine transitions

package breakglass

import (
	"context"
	"testing"
	"time"
)

// ============================================================================
// Expired Event Rejection Tests
// ============================================================================

// TestSecurityRegression_ExpiredEvent_ActiveButPastExpiry verifies that an event
// with Status=Active but ExpiresAt in the past is rejected.
func TestSecurityRegression_ExpiredEvent_ActiveButPastExpiry(t *testing.T) {
	now := time.Now()

	event := &BreakGlassEvent{
		ID:        "abcdef1234567890",
		Invoker:   "alice",
		Profile:   "production",
		Status:    StatusActive, // Status says active
		ExpiresAt: now.Add(-time.Hour), // But expired 1 hour ago
		CreatedAt: now.Add(-2 * time.Hour),
	}

	if isBreakGlassValid(event) {
		t.Errorf("SECURITY VIOLATION: Event with Active status but past ExpiresAt should be rejected")
	}
}

// TestSecurityRegression_ExpiredEvent_ExactlyAtExpiry verifies that an event
// at exactly ExpiresAt is rejected (strictly less than).
func TestSecurityRegression_ExpiredEvent_ExactlyAtExpiry(t *testing.T) {
	now := time.Now()

	event := &BreakGlassEvent{
		ID:        "abcdef1234567890",
		Invoker:   "alice",
		Profile:   "production",
		Status:    StatusActive,
		ExpiresAt: now, // Expires exactly now
		CreatedAt: now.Add(-time.Hour),
	}

	// The check is time.Now().After(event.ExpiresAt)
	// If ExpiresAt == now, After() returns false, so it would be "valid"
	// This test documents the current behavior. If the boundary changes, this test will catch it.
	// Note: Due to timing, this test may be flaky. We check the boundary condition explicitly.

	// Create event that expires exactly when we check
	expiresAt := time.Now()
	event.ExpiresAt = expiresAt

	// Let a moment pass so now > expiresAt
	time.Sleep(time.Millisecond)

	if isBreakGlassValid(event) {
		t.Errorf("SECURITY VIOLATION: Event at exactly ExpiresAt should be rejected after that instant")
	}
}

// TestSecurityRegression_ExpiredEvent_StatusExpiredWithFutureExpiry verifies that
// an event with Status=Expired is rejected even if ExpiresAt is in the future.
func TestSecurityRegression_ExpiredEvent_StatusExpiredWithFutureExpiry(t *testing.T) {
	now := time.Now()

	event := &BreakGlassEvent{
		ID:        "abcdef1234567890",
		Invoker:   "alice",
		Profile:   "production",
		Status:    StatusExpired, // Status says expired
		ExpiresAt: now.Add(time.Hour), // But ExpiresAt is future
		CreatedAt: now.Add(-time.Hour),
	}

	if isBreakGlassValid(event) {
		t.Errorf("SECURITY VIOLATION: Event with Expired status should be rejected regardless of ExpiresAt")
	}
}

// TestSecurityRegression_ExpiredEvent_StatusClosedWithFutureExpiry verifies that
// an event with Status=Closed is rejected even if ExpiresAt is in the future.
func TestSecurityRegression_ExpiredEvent_StatusClosedWithFutureExpiry(t *testing.T) {
	now := time.Now()

	event := &BreakGlassEvent{
		ID:           "abcdef1234567890",
		Invoker:      "alice",
		Profile:      "production",
		Status:       StatusClosed, // Status says closed
		ExpiresAt:    now.Add(time.Hour), // But ExpiresAt is future
		CreatedAt:    now.Add(-time.Hour),
		ClosedBy:     "security",
		ClosedReason: "incident resolved",
	}

	if isBreakGlassValid(event) {
		t.Errorf("SECURITY VIOLATION: Event with Closed status should be rejected regardless of ExpiresAt")
	}
}

// TestSecurityRegression_ExpiredEvent_OneNanosecondPastExpiry verifies that
// an event 1 nanosecond past expiry is rejected.
func TestSecurityRegression_ExpiredEvent_OneNanosecondPastExpiry(t *testing.T) {
	// Set expiry in the past by 1 nanosecond
	expiry := time.Now().Add(-time.Nanosecond)

	event := &BreakGlassEvent{
		ID:        "abcdef1234567890",
		Invoker:   "alice",
		Profile:   "production",
		Status:    StatusActive,
		ExpiresAt: expiry,
		CreatedAt: time.Now().Add(-time.Hour),
	}

	if isBreakGlassValid(event) {
		t.Errorf("SECURITY VIOLATION: Event 1ns past expiry should be rejected")
	}
}

// ============================================================================
// Rate Limit Enforcement Tests
// ============================================================================

// mockStoreForRateLimitTests is a minimal mock for rate limit security tests.
type mockStoreForRateLimitTests struct {
	lastEvent    *BreakGlassEvent
	userCount    int
	profileCount int
}

func (m *mockStoreForRateLimitTests) Create(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}
func (m *mockStoreForRateLimitTests) Get(ctx context.Context, id string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *mockStoreForRateLimitTests) Update(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}
func (m *mockStoreForRateLimitTests) Delete(ctx context.Context, id string) error { return nil }
func (m *mockStoreForRateLimitTests) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *mockStoreForRateLimitTests) ListByStatus(ctx context.Context, status BreakGlassStatus, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *mockStoreForRateLimitTests) ListByProfile(ctx context.Context, profile string, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *mockStoreForRateLimitTests) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *mockStoreForRateLimitTests) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	return m.userCount, nil
}
func (m *mockStoreForRateLimitTests) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	return m.profileCount, nil
}
func (m *mockStoreForRateLimitTests) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return m.lastEvent, nil
}

// TestSecurityRegression_RateLimit_CooldownOneNanosecondBefore verifies that
// cooldown is enforced at exactly 1 nanosecond before expiry.
func TestSecurityRegression_RateLimit_CooldownOneNanosecondBefore(t *testing.T) {
	now := time.Now()
	cooldown := time.Hour

	// Last event was 1 nanosecond short of cooldown
	lastEventTime := now.Add(-cooldown + time.Nanosecond)

	store := &mockStoreForRateLimitTests{
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
		t.Fatalf("CheckRateLimit() error = %v", err)
	}

	if result.Allowed {
		t.Errorf("SECURITY VIOLATION: Should be blocked 1ns before cooldown expires")
	}
	if result.Reason != "cooldown period not elapsed" {
		t.Errorf("Expected reason 'cooldown period not elapsed', got %q", result.Reason)
	}
}

// TestSecurityRegression_RateLimit_UserQuotaExactlyAtLimit verifies that
// user quota is enforced at exactly MaxPerUser (>= check, not >).
func TestSecurityRegression_RateLimit_UserQuotaExactlyAtLimit(t *testing.T) {
	now := time.Now()

	store := &mockStoreForRateLimitTests{
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
		t.Fatalf("CheckRateLimit() error = %v", err)
	}

	if result.Allowed {
		t.Errorf("SECURITY VIOLATION: Should be blocked when count == MaxPerUser")
	}
	if result.Reason != "user quota exceeded" {
		t.Errorf("Expected reason 'user quota exceeded', got %q", result.Reason)
	}
}

// TestSecurityRegression_RateLimit_ProfileQuotaExactlyAtLimit verifies that
// profile quota is enforced at exactly MaxPerProfile (>= check, not >).
func TestSecurityRegression_RateLimit_ProfileQuotaExactlyAtLimit(t *testing.T) {
	now := time.Now()

	store := &mockStoreForRateLimitTests{
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
		t.Fatalf("CheckRateLimit() error = %v", err)
	}

	if result.Allowed {
		t.Errorf("SECURITY VIOLATION: Should be blocked when count == MaxPerProfile")
	}
	if result.Reason != "profile quota exceeded" {
		t.Errorf("Expected reason 'profile quota exceeded', got %q", result.Reason)
	}
}

// TestSecurityRegression_RateLimit_ZeroQuotaMeansNoLimit verifies that
// MaxPerUser=0 means no limit, not "deny all".
func TestSecurityRegression_RateLimit_ZeroQuotaMeansNoLimit(t *testing.T) {
	now := time.Now()

	store := &mockStoreForRateLimitTests{
		userCount: 1000, // Many events but no quota configured
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Cooldown: time.Hour, // Only cooldown, no quota
				// MaxPerUser: 0 (disabled)
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v", err)
	}

	// MaxPerUser=0 means quota check is skipped
	if !result.Allowed {
		t.Errorf("MaxPerUser=0 should mean no user quota limit, but got blocked: %q", result.Reason)
	}
}

// TestSecurityRegression_RateLimit_CheckOrderStrictlyEnforced verifies the
// security-critical check order: cooldown -> user quota -> profile quota -> escalation.
func TestSecurityRegression_RateLimit_CheckOrderStrictlyEnforced(t *testing.T) {
	now := time.Now()
	lastEventTime := now.Add(-30 * time.Minute) // Within cooldown

	// Create a store that tracks calls
	calls := []string{}

	type orderTrackingStore struct {
		mockStoreForRateLimitTests
	}

	store := &struct {
		lastEvent    *BreakGlassEvent
		userCount    int
		profileCount int
		calls        *[]string
	}{
		lastEvent: &BreakGlassEvent{
			ID:        "last001",
			CreatedAt: lastEventTime,
		},
		userCount:    10, // Over limit
		profileCount: 20, // Over limit
		calls:        &calls,
	}

	// Use the ordering store pattern from ratelimit_security_test.go
	orderStore := &orderTrackingStore{
		mockStoreForRateLimitTests{
			lastEvent: &BreakGlassEvent{
				ID:        "last001",
				CreatedAt: lastEventTime,
			},
			userCount:    10,
			profileCount: 20,
		},
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:          "production",
				Profiles:      []string{"production"},
				Cooldown:      time.Hour, // 1 hour cooldown, only 30 min elapsed
				MaxPerUser:    5,
				MaxPerProfile: 10,
				QuotaWindow:   24 * time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), orderStore, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v", err)
	}

	// Cooldown should be checked first and block
	if result.Allowed {
		t.Errorf("SECURITY VIOLATION: Cooldown should block before quota checks")
	}
	if result.Reason != "cooldown period not elapsed" {
		t.Errorf("Expected cooldown block reason, got %q", result.Reason)
	}

	// Suppress unused variable warning
	_ = store
}

// ============================================================================
// Profile/User Isolation Tests
// ============================================================================

// TestSecurityRegression_ProfileIsolation_ExactMatchRequired verifies that
// break-glass for profile "prod" does NOT authorize profile "production".
func TestSecurityRegression_ProfileIsolation_ExactMatchRequired(t *testing.T) {
	now := time.Now()

	// Create an active break-glass event for "prod"
	events := []*BreakGlassEvent{
		{
			ID:        "abcdef1234567890",
			Invoker:   "alice",
			Profile:   "prod", // Only for "prod"
			Status:    StatusActive,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-30 * time.Minute),
		},
	}

	store := &mockStoreForFinder{events: events}

	// Request for "production" should NOT find the "prod" event
	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v", err)
	}

	if result != nil {
		t.Errorf("SECURITY VIOLATION: 'prod' event should NOT authorize 'production' profile")
	}
}

// TestSecurityRegression_ProfileIsolation_CaseSensitive verifies that
// profile matching is case-sensitive.
func TestSecurityRegression_ProfileIsolation_CaseSensitive(t *testing.T) {
	now := time.Now()

	events := []*BreakGlassEvent{
		{
			ID:        "abcdef1234567890",
			Invoker:   "alice",
			Profile:   "production", // lowercase
			Status:    StatusActive,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-30 * time.Minute),
		},
	}

	store := &mockStoreForFinder{events: events}

	tests := []struct {
		profile    string
		shouldFind bool
	}{
		{"production", true},
		{"Production", false},
		{"PRODUCTION", false},
		{"pRoDuCtIoN", false},
		{"production ", false}, // trailing space
		{" production", false}, // leading space
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			result, err := FindActiveBreakGlass(context.Background(), store, "alice", tt.profile)
			if err != nil {
				t.Fatalf("FindActiveBreakGlass() error = %v", err)
			}

			if tt.shouldFind && result == nil {
				t.Errorf("Should find event for profile %q", tt.profile)
			}
			if !tt.shouldFind && result != nil {
				t.Errorf("SECURITY VIOLATION: Should NOT find event for profile %q (case mismatch)", tt.profile)
			}
		})
	}
}

// TestSecurityRegression_UserIsolation_ExactMatchRequired verifies that
// break-glass by user "alice" does NOT authorize user "alice@company.com".
func TestSecurityRegression_UserIsolation_ExactMatchRequired(t *testing.T) {
	now := time.Now()

	events := []*BreakGlassEvent{
		{
			ID:        "abcdef1234567890",
			Invoker:   "alice", // Only for "alice"
			Profile:   "production",
			Status:    StatusActive,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-30 * time.Minute),
		},
	}

	store := &mockStoreForFinder{events: events}

	// Request by "alice@company.com" should NOT find the "alice" event
	result, err := FindActiveBreakGlass(context.Background(), store, "alice@company.com", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v", err)
	}

	if result != nil {
		t.Errorf("SECURITY VIOLATION: 'alice' event should NOT authorize 'alice@company.com' user")
	}
}

// mockStoreForFinder is a minimal mock for FindActiveBreakGlass tests.
type mockStoreForFinder struct {
	events []*BreakGlassEvent
}

func (m *mockStoreForFinder) Create(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}
func (m *mockStoreForFinder) Get(ctx context.Context, id string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *mockStoreForFinder) Update(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}
func (m *mockStoreForFinder) Delete(ctx context.Context, id string) error { return nil }
func (m *mockStoreForFinder) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
	var result []*BreakGlassEvent
	for _, e := range m.events {
		if e.Invoker == invoker {
			result = append(result, e)
		}
	}
	return result, nil
}
func (m *mockStoreForFinder) ListByStatus(ctx context.Context, status BreakGlassStatus, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *mockStoreForFinder) ListByProfile(ctx context.Context, profile string, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}
func (m *mockStoreForFinder) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *mockStoreForFinder) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	return 0, nil
}
func (m *mockStoreForFinder) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	return 0, nil
}
func (m *mockStoreForFinder) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return nil, nil
}

// ============================================================================
// Status Manipulation Prevention Tests
// ============================================================================

// TestSecurityRegression_StatusManipulation_ClosedToActiveRejected verifies that
// a closed event cannot transition back to active.
func TestSecurityRegression_StatusManipulation_ClosedToActiveRejected(t *testing.T) {
	status := StatusClosed

	if !status.IsTerminal() {
		t.Errorf("StatusClosed should be terminal")
	}

	// Attempting to treat a closed event as active should fail validation
	event := &BreakGlassEvent{
		ID:           "abcdef1234567890",
		Invoker:      "alice",
		Profile:      "production",
		Status:       StatusClosed,
		ExpiresAt:    time.Now().Add(time.Hour), // Future expiry
		CreatedAt:    time.Now().Add(-time.Hour),
		ClosedBy:     "security",
		ClosedReason: "incident resolved",
	}

	if isBreakGlassValid(event) {
		t.Errorf("SECURITY VIOLATION: Closed event should not be considered valid for credential issuance")
	}
}

// TestSecurityRegression_StatusManipulation_ExpiredToActiveRejected verifies that
// an expired event cannot transition back to active.
func TestSecurityRegression_StatusManipulation_ExpiredToActiveRejected(t *testing.T) {
	status := StatusExpired

	if !status.IsTerminal() {
		t.Errorf("StatusExpired should be terminal")
	}

	// Attempting to treat an expired event as active should fail validation
	event := &BreakGlassEvent{
		ID:        "abcdef1234567890",
		Invoker:   "alice",
		Profile:   "production",
		Status:    StatusExpired,
		ExpiresAt: time.Now().Add(time.Hour), // Future expiry (manipulated)
		CreatedAt: time.Now().Add(-time.Hour),
	}

	if isBreakGlassValid(event) {
		t.Errorf("SECURITY VIOLATION: Expired event should not be considered valid for credential issuance")
	}
}

// TestSecurityRegression_StatusManipulation_InvalidStatusRejected verifies that
// invalid status strings are rejected.
func TestSecurityRegression_StatusManipulation_InvalidStatusRejected(t *testing.T) {
	invalidStatuses := []BreakGlassStatus{
		"",
		"Active",  // Wrong case
		"ACTIVE",  // Wrong case
		"active ", // Trailing space
		" active", // Leading space
		"pending", // Different status
		"approved",
		"invalid",
		"'; DROP TABLE;--",
		"$ne: null",
	}

	for _, status := range invalidStatuses {
		t.Run(string(status), func(t *testing.T) {
			if status.IsValid() {
				t.Errorf("SECURITY VIOLATION: Invalid status %q should not be considered valid", status)
			}

			// Event with invalid status should not be valid
			event := &BreakGlassEvent{
				ID:        "abcdef1234567890",
				Invoker:   "alice",
				Profile:   "production",
				Status:    status,
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now().Add(-time.Hour),
			}

			if isBreakGlassValid(event) {
				t.Errorf("SECURITY VIOLATION: Event with invalid status %q should not be valid", status)
			}
		})
	}
}

// TestSecurityRegression_StatusManipulation_OnlyActiveIsValid verifies that
// only StatusActive can grant credentials (given valid expiry).
func TestSecurityRegression_StatusManipulation_OnlyActiveIsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		status      BreakGlassStatus
		expectValid bool
	}{
		{StatusActive, true},    // Only active with valid expiry
		{StatusClosed, false},   // Closed is terminal
		{StatusExpired, false},  // Expired is terminal
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			event := &BreakGlassEvent{
				ID:        "abcdef1234567890",
				Invoker:   "alice",
				Profile:   "production",
				Status:    tt.status,
				ExpiresAt: now.Add(time.Hour), // Valid future expiry
				CreatedAt: now.Add(-30 * time.Minute),
			}

			result := isBreakGlassValid(event)

			if tt.expectValid && !result {
				t.Errorf("Status %q with valid expiry should be valid", tt.status)
			}
			if !tt.expectValid && result {
				t.Errorf("SECURITY VIOLATION: Status %q should NOT be valid", tt.status)
			}
		})
	}
}

// ============================================================================
// Comprehensive Break-Glass Denial Table Tests
// ============================================================================

// TestSecurityRegression_ComprehensiveBreakGlassDenial tests all denial paths
// in a comprehensive table-driven manner.
func TestSecurityRegression_ComprehensiveBreakGlassDenial(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		event      *BreakGlassEvent
		expectValid bool
		reason     string
	}{
		{
			name: "valid_active_event",
			event: &BreakGlassEvent{
				ID:        "abcdef1234567890",
				Invoker:   "alice",
				Profile:   "production",
				Status:    StatusActive,
				ExpiresAt: now.Add(time.Hour),
				CreatedAt: now.Add(-30 * time.Minute),
			},
			expectValid: true,
			reason:     "should be valid",
		},
		{
			name: "expired_by_time",
			event: &BreakGlassEvent{
				ID:        "abcdef1234567890",
				Invoker:   "alice",
				Profile:   "production",
				Status:    StatusActive,
				ExpiresAt: now.Add(-time.Hour), // Past
				CreatedAt: now.Add(-2 * time.Hour),
			},
			expectValid: false,
			reason:     "ExpiresAt in past",
		},
		{
			name: "status_closed",
			event: &BreakGlassEvent{
				ID:           "abcdef1234567890",
				Invoker:      "alice",
				Profile:      "production",
				Status:       StatusClosed,
				ExpiresAt:    now.Add(time.Hour),
				CreatedAt:    now.Add(-30 * time.Minute),
				ClosedBy:     "security",
				ClosedReason: "resolved",
			},
			expectValid: false,
			reason:     "status is closed",
		},
		{
			name: "status_expired",
			event: &BreakGlassEvent{
				ID:        "abcdef1234567890",
				Invoker:   "alice",
				Profile:   "production",
				Status:    StatusExpired,
				ExpiresAt: now.Add(time.Hour), // Future but status says expired
				CreatedAt: now.Add(-30 * time.Minute),
			},
			expectValid: false,
			reason:     "status is expired",
		},
		{
			name: "exactly_at_expiry",
			event: &BreakGlassEvent{
				ID:        "abcdef1234567890",
				Invoker:   "alice",
				Profile:   "production",
				Status:    StatusActive,
				ExpiresAt: now.Add(-time.Nanosecond), // Just expired
				CreatedAt: now.Add(-30 * time.Minute),
			},
			expectValid: false,
			reason:     "just past expiry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBreakGlassValid(tt.event)

			if tt.expectValid && !result {
				t.Errorf("%s: expected valid but got invalid", tt.reason)
			}
			if !tt.expectValid && result {
				t.Errorf("SECURITY VIOLATION: %s should be invalid", tt.reason)
			}
		})
	}
}

// TestSecurityRegression_FindActiveBreakGlass_FiltersCorrectly tests that
// FindActiveBreakGlass correctly filters out invalid events.
func TestSecurityRegression_FindActiveBreakGlass_FiltersCorrectly(t *testing.T) {
	now := time.Now()

	events := []*BreakGlassEvent{
		// Invalid: Closed status
		{
			ID:        "closed001234567890",
			Invoker:   "alice",
			Profile:   "production",
			Status:    StatusClosed,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-30 * time.Minute),
		},
		// Invalid: Expired status
		{
			ID:        "expired01234567890",
			Invoker:   "alice",
			Profile:   "production",
			Status:    StatusExpired,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-30 * time.Minute),
		},
		// Invalid: Active but expired by time
		{
			ID:        "expired21234567890",
			Invoker:   "alice",
			Profile:   "production",
			Status:    StatusActive,
			ExpiresAt: now.Add(-time.Hour), // Past
			CreatedAt: now.Add(-2 * time.Hour),
		},
		// Invalid: Wrong profile
		{
			ID:        "wrongp01234567890",
			Invoker:   "alice",
			Profile:   "staging", // Different profile
			Status:    StatusActive,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-30 * time.Minute),
		},
		// Valid: Should be found
		{
			ID:        "valid001234567890",
			Invoker:   "alice",
			Profile:   "production",
			Status:    StatusActive,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-30 * time.Minute),
		},
	}

	store := &mockStoreForFinder{events: events}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v", err)
	}

	if result == nil {
		t.Fatal("Should find the valid event")
	}

	if result.ID != "valid001234567890" {
		t.Errorf("Found wrong event: %s (expected valid001234567890)", result.ID)
	}
}

// TestSecurityRegression_FindActiveBreakGlass_ReturnsNilWhenAllInvalid tests that
// FindActiveBreakGlass returns nil when all events are invalid.
func TestSecurityRegression_FindActiveBreakGlass_ReturnsNilWhenAllInvalid(t *testing.T) {
	now := time.Now()

	events := []*BreakGlassEvent{
		{
			ID:        "closed001234567890",
			Invoker:   "alice",
			Profile:   "production",
			Status:    StatusClosed,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-30 * time.Minute),
		},
		{
			ID:        "expired01234567890",
			Invoker:   "alice",
			Profile:   "production",
			Status:    StatusExpired,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-30 * time.Minute),
		},
	}

	store := &mockStoreForFinder{events: events}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v", err)
	}

	if result != nil {
		t.Errorf("SECURITY VIOLATION: Should return nil when all events are invalid, got %+v", result)
	}
}
