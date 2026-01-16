package breakglass

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockCheckerStore implements Store interface for testing break-glass checker functions.
type mockCheckerStore struct {
	listByInvokerFunc             func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error)
	countByInvokerSinceFunc       func(ctx context.Context, invoker string, since time.Time) (int, error)
	countByProfileSinceFunc       func(ctx context.Context, profile string, since time.Time) (int, error)
	getLastByInvokerAndProfileFunc func(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error)
}

func (m *mockCheckerStore) Create(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}

func (m *mockCheckerStore) Get(ctx context.Context, id string) (*BreakGlassEvent, error) {
	return nil, nil
}

func (m *mockCheckerStore) Update(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}

func (m *mockCheckerStore) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockCheckerStore) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
	if m.listByInvokerFunc != nil {
		return m.listByInvokerFunc(ctx, invoker, limit)
	}
	return []*BreakGlassEvent{}, nil
}

func (m *mockCheckerStore) ListByStatus(ctx context.Context, status BreakGlassStatus, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}

func (m *mockCheckerStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*BreakGlassEvent, error) {
	return []*BreakGlassEvent{}, nil
}

func (m *mockCheckerStore) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return nil, nil
}

func (m *mockCheckerStore) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	if m.countByInvokerSinceFunc != nil {
		return m.countByInvokerSinceFunc(ctx, invoker, since)
	}
	return 0, nil
}

func (m *mockCheckerStore) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	if m.countByProfileSinceFunc != nil {
		return m.countByProfileSinceFunc(ctx, profile, since)
	}
	return 0, nil
}

func (m *mockCheckerStore) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	if m.getLastByInvokerAndProfileFunc != nil {
		return m.getLastByInvokerAndProfileFunc(ctx, invoker, profile)
	}
	return nil, nil
}

// TestFindActiveBreakGlass_Found tests finding an active break-glass for matching invoker+profile.
func TestFindActiveBreakGlass_Found(t *testing.T) {
	now := time.Now()
	activeEvent := &BreakGlassEvent{
		ID:            "active001",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    ReasonIncident,
		Justification: "Production incident - service degradation",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     now.Add(-30 * time.Minute),
		UpdatedAt:     now.Add(-30 * time.Minute),
		ExpiresAt:     now.Add(3*time.Hour + 30*time.Minute), // Still valid
	}

	store := &mockCheckerStore{
		listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
			return []*BreakGlassEvent{activeEvent}, nil
		},
	}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v, want nil", err)
	}
	if result == nil {
		t.Fatal("FindActiveBreakGlass() = nil, want active event")
	}
	if result.ID != "active001" {
		t.Errorf("FindActiveBreakGlass().ID = %q, want %q", result.ID, "active001")
	}
}

// TestFindActiveBreakGlass_NoActiveEvent tests returning nil when no active event exists.
func TestFindActiveBreakGlass_NoActiveEvent(t *testing.T) {
	store := &mockCheckerStore{
		listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
			return []*BreakGlassEvent{}, nil
		},
	}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("FindActiveBreakGlass() = %v, want nil for no active event", result)
	}
}

// TestFindActiveBreakGlass_StatusClosed tests returning nil when event has closed status.
func TestFindActiveBreakGlass_StatusClosed(t *testing.T) {
	now := time.Now()
	closedEvent := &BreakGlassEvent{
		ID:           "closed001",
		Invoker:      "alice",
		Profile:      "production",
		Status:       StatusClosed,
		CreatedAt:    now.Add(-time.Hour),
		ExpiresAt:    now.Add(3 * time.Hour),
		ClosedBy:     "bob",
		ClosedReason: "Incident resolved",
	}

	store := &mockCheckerStore{
		listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
			return []*BreakGlassEvent{closedEvent}, nil
		},
	}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("FindActiveBreakGlass() = %v, want nil for closed event", result)
	}
}

// TestFindActiveBreakGlass_StatusExpired tests returning nil when event has expired status.
func TestFindActiveBreakGlass_StatusExpired(t *testing.T) {
	now := time.Now()
	expiredEvent := &BreakGlassEvent{
		ID:        "expired001",
		Invoker:   "alice",
		Profile:   "production",
		Status:    StatusExpired,
		CreatedAt: now.Add(-5 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}

	store := &mockCheckerStore{
		listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
			return []*BreakGlassEvent{expiredEvent}, nil
		},
	}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("FindActiveBreakGlass() = %v, want nil for expired status event", result)
	}
}

// TestFindActiveBreakGlass_WrongProfile tests returning nil when profile doesn't match.
func TestFindActiveBreakGlass_WrongProfile(t *testing.T) {
	now := time.Now()
	stagingEvent := &BreakGlassEvent{
		ID:        "staging001",
		Invoker:   "alice",
		Profile:   "staging", // Wrong profile
		Status:    StatusActive,
		CreatedAt: now.Add(-30 * time.Minute),
		ExpiresAt: now.Add(3*time.Hour + 30*time.Minute),
	}

	store := &mockCheckerStore{
		listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
			return []*BreakGlassEvent{stagingEvent}, nil
		},
	}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("FindActiveBreakGlass() = %v, want nil for wrong profile", result)
	}
}

// TestFindActiveBreakGlass_PastExpiresAt tests returning nil when ExpiresAt has passed.
func TestFindActiveBreakGlass_PastExpiresAt(t *testing.T) {
	now := time.Now()
	expiredTimeEvent := &BreakGlassEvent{
		ID:        "expiredtime001",
		Invoker:   "alice",
		Profile:   "production",
		Status:    StatusActive, // Status still active but time expired
		CreatedAt: now.Add(-5 * time.Hour),
		ExpiresAt: now.Add(-time.Hour), // Past ExpiresAt
	}

	store := &mockCheckerStore{
		listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
			return []*BreakGlassEvent{expiredTimeEvent}, nil
		},
	}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("FindActiveBreakGlass() = %v, want nil for past ExpiresAt", result)
	}
}

// TestFindActiveBreakGlass_StoreError tests returning error when store fails.
func TestFindActiveBreakGlass_StoreError(t *testing.T) {
	expectedErr := errors.New("database connection failed")
	store := &mockCheckerStore{
		listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
			return nil, expectedErr
		},
	}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err == nil {
		t.Fatal("FindActiveBreakGlass() error = nil, want error")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("FindActiveBreakGlass() error = %v, want %v", err, expectedErr)
	}
	if result != nil {
		t.Errorf("FindActiveBreakGlass() = %v, want nil on error", result)
	}
}

// TestFindActiveBreakGlass_MultipleCandidates tests returning first valid match.
func TestFindActiveBreakGlass_MultipleCandidates(t *testing.T) {
	now := time.Now()

	// Mix of valid and invalid events
	events := []*BreakGlassEvent{
		{
			ID:        "closed001",
			Invoker:   "alice",
			Profile:   "production",
			Status:    StatusClosed, // Wrong status
			CreatedAt: now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(2 * time.Hour),
		},
		{
			ID:        "staging001",
			Invoker:   "alice",
			Profile:   "staging", // Wrong profile
			Status:    StatusActive,
			CreatedAt: now.Add(-time.Hour),
			ExpiresAt: now.Add(3 * time.Hour),
		},
		{
			ID:            "valid001",
			Invoker:       "alice",
			Profile:       "production",
			Status:        StatusActive,
			ReasonCode:    ReasonIncident,
			Justification: "First valid event - production incident",
			CreatedAt:     now.Add(-30 * time.Minute),
			ExpiresAt:     now.Add(3*time.Hour + 30*time.Minute),
		},
		{
			ID:            "valid002",
			Invoker:       "alice",
			Profile:       "production",
			Status:        StatusActive,
			ReasonCode:    ReasonSecurity,
			Justification: "Second valid event - security incident",
			CreatedAt:     now.Add(-15 * time.Minute),
			ExpiresAt:     now.Add(3*time.Hour + 45*time.Minute),
		},
	}

	store := &mockCheckerStore{
		listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
			return events, nil
		},
	}

	result, err := FindActiveBreakGlass(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass() error = %v, want nil", err)
	}
	if result == nil {
		t.Fatal("FindActiveBreakGlass() = nil, want valid event")
	}
	// Should find valid001 as the first valid match
	if result.ID != "valid001" {
		t.Errorf("FindActiveBreakGlass().ID = %q, want %q (first valid match)", result.ID, "valid001")
	}
}

// TestRemainingDuration tests the RemainingDuration function.
func TestRemainingDuration(t *testing.T) {
	tests := []struct {
		name     string
		event    *BreakGlassEvent
		wantZero bool
	}{
		{
			name: "future expiry returns positive duration",
			event: &BreakGlassEvent{
				ExpiresAt: time.Now().Add(time.Hour),
			},
			wantZero: false,
		},
		{
			name: "past expiry returns zero",
			event: &BreakGlassEvent{
				ExpiresAt: time.Now().Add(-time.Hour),
			},
			wantZero: true,
		},
		{
			name: "zero ExpiresAt returns zero",
			event: &BreakGlassEvent{
				ExpiresAt: time.Time{}, // Zero value
			},
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RemainingDuration(tt.event)
			if tt.wantZero && got != 0 {
				t.Errorf("RemainingDuration() = %v, want 0", got)
			}
			if !tt.wantZero && got <= 0 {
				t.Errorf("RemainingDuration() = %v, want positive duration", got)
			}
		})
	}
}

// TestRemainingDuration_PositiveDuration tests exact remaining duration calculation.
func TestRemainingDuration_PositiveDuration(t *testing.T) {
	// Use a specific future time
	futureExpiry := time.Now().Add(2 * time.Hour)
	event := &BreakGlassEvent{
		ExpiresAt: futureExpiry,
	}

	got := RemainingDuration(event)

	// Should be approximately 2 hours (within a few seconds tolerance)
	if got < (2*time.Hour - 5*time.Second) || got > (2*time.Hour + 5*time.Second) {
		t.Errorf("RemainingDuration() = %v, want approximately 2 hours", got)
	}
}

// TestIsBreakGlassValid tests the isBreakGlassValid internal function.
func TestIsBreakGlassValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		event *BreakGlassEvent
		want  bool
	}{
		{
			name: "active and not expired returns true",
			event: &BreakGlassEvent{
				Status:    StatusActive,
				ExpiresAt: now.Add(time.Hour),
			},
			want: true,
		},
		{
			name: "closed status returns false",
			event: &BreakGlassEvent{
				Status:    StatusClosed,
				ExpiresAt: now.Add(time.Hour),
			},
			want: false,
		},
		{
			name: "expired status returns false",
			event: &BreakGlassEvent{
				Status:    StatusExpired,
				ExpiresAt: now.Add(time.Hour),
			},
			want: false,
		},
		{
			name: "active but past ExpiresAt returns false",
			event: &BreakGlassEvent{
				Status:    StatusActive,
				ExpiresAt: now.Add(-time.Hour), // Past
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBreakGlassValid(tt.event)
			if got != tt.want {
				t.Errorf("isBreakGlassValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// CheckRateLimit Tests
// ============================================================================

// TestCheckRateLimit_NilPolicy tests that nil policy returns allowed.
func TestCheckRateLimit_NilPolicy(t *testing.T) {
	store := &mockCheckerStore{}
	now := time.Now()

	result, err := CheckRateLimit(context.Background(), store, nil, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}
	if !result.Allowed {
		t.Error("CheckRateLimit() with nil policy should be allowed")
	}
}

// TestCheckRateLimit_NoMatchingRule tests that no matching rule returns allowed.
func TestCheckRateLimit_NoMatchingRule(t *testing.T) {
	store := &mockCheckerStore{}
	now := time.Now()

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "staging-only",
				Profiles: []string{"staging"},
				Cooldown: time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}
	if !result.Allowed {
		t.Error("CheckRateLimit() with no matching rule should be allowed")
	}
}

// TestCheckRateLimit_CooldownBlocked tests blocking when cooldown hasn't elapsed.
func TestCheckRateLimit_CooldownBlocked(t *testing.T) {
	now := time.Now()
	lastEventTime := now.Add(-30 * time.Minute) // 30 minutes ago

	store := &mockCheckerStore{
		getLastByInvokerAndProfileFunc: func(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
			return &BreakGlassEvent{
				ID:        "last001",
				Invoker:   invoker,
				Profile:   profile,
				CreatedAt: lastEventTime,
			}, nil
		},
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Cooldown: time.Hour, // 1 hour cooldown, only 30 min elapsed
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}
	if result.Allowed {
		t.Error("CheckRateLimit() should block when cooldown hasn't elapsed")
	}
	if result.Reason != "cooldown period not elapsed" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "cooldown period not elapsed")
	}
	// Should have approximately 30 minutes remaining
	if result.RetryAfter < 25*time.Minute || result.RetryAfter > 35*time.Minute {
		t.Errorf("CheckRateLimit() RetryAfter = %v, want approximately 30 minutes", result.RetryAfter)
	}
}

// TestCheckRateLimit_CooldownElapsed tests allowing when cooldown has elapsed.
func TestCheckRateLimit_CooldownElapsed(t *testing.T) {
	now := time.Now()
	lastEventTime := now.Add(-2 * time.Hour) // 2 hours ago

	store := &mockCheckerStore{
		getLastByInvokerAndProfileFunc: func(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
			return &BreakGlassEvent{
				ID:        "last001",
				Invoker:   invoker,
				Profile:   profile,
				CreatedAt: lastEventTime,
			}, nil
		},
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Cooldown: time.Hour, // 1 hour cooldown, 2 hours elapsed
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "production", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}
	if !result.Allowed {
		t.Error("CheckRateLimit() should allow when cooldown has elapsed")
	}
	if result.RetryAfter != 0 {
		t.Errorf("CheckRateLimit() RetryAfter = %v, want 0", result.RetryAfter)
	}
}

// TestCheckRateLimit_UserQuotaExceeded tests blocking when user quota is exceeded.
func TestCheckRateLimit_UserQuotaExceeded(t *testing.T) {
	now := time.Now()

	store := &mockCheckerStore{
		countByInvokerSinceFunc: func(ctx context.Context, invoker string, since time.Time) (int, error) {
			return 5, nil // Already at limit
		},
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
		t.Error("CheckRateLimit() should block when user quota exceeded")
	}
	if result.Reason != "user quota exceeded" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "user quota exceeded")
	}
	if result.UserCount != 5 {
		t.Errorf("CheckRateLimit() UserCount = %d, want 5", result.UserCount)
	}
}

// TestCheckRateLimit_ProfileQuotaExceeded tests blocking when profile quota is exceeded.
func TestCheckRateLimit_ProfileQuotaExceeded(t *testing.T) {
	now := time.Now()

	store := &mockCheckerStore{
		countByInvokerSinceFunc: func(ctx context.Context, invoker string, since time.Time) (int, error) {
			return 2, nil // Under user limit
		},
		countByProfileSinceFunc: func(ctx context.Context, profile string, since time.Time) (int, error) {
			return 10, nil // At profile limit
		},
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
		t.Error("CheckRateLimit() should block when profile quota exceeded")
	}
	if result.Reason != "profile quota exceeded" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "profile quota exceeded")
	}
	if result.ProfileCount != 10 {
		t.Errorf("CheckRateLimit() ProfileCount = %d, want 10", result.ProfileCount)
	}
}

// TestCheckRateLimit_EscalationFlagged tests escalation flag when threshold met.
func TestCheckRateLimit_EscalationFlagged(t *testing.T) {
	now := time.Now()

	store := &mockCheckerStore{
		countByInvokerSinceFunc: func(ctx context.Context, invoker string, since time.Time) (int, error) {
			return 3, nil // At escalation threshold but under quota
		},
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
		t.Error("CheckRateLimit() should allow when under quota even at escalation threshold")
	}
	if !result.ShouldEscalate {
		t.Error("CheckRateLimit() ShouldEscalate should be true when at escalation threshold")
	}
	if result.UserCount != 3 {
		t.Errorf("CheckRateLimit() UserCount = %d, want 3", result.UserCount)
	}
}

// TestCheckRateLimit_AllChecksPass tests successful pass through all checks.
func TestCheckRateLimit_AllChecksPass(t *testing.T) {
	now := time.Now()
	lastEventTime := now.Add(-2 * time.Hour) // Well past cooldown

	store := &mockCheckerStore{
		getLastByInvokerAndProfileFunc: func(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
			return &BreakGlassEvent{
				ID:        "last001",
				Invoker:   invoker,
				Profile:   profile,
				CreatedAt: lastEventTime,
			}, nil
		},
		countByInvokerSinceFunc: func(ctx context.Context, invoker string, since time.Time) (int, error) {
			return 2, nil // Under user limit
		},
		countByProfileSinceFunc: func(ctx context.Context, profile string, since time.Time) (int, error) {
			return 5, nil // Under profile limit
		},
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
	if result.UserCount != 2 {
		t.Errorf("CheckRateLimit() UserCount = %d, want 2", result.UserCount)
	}
	if result.ProfileCount != 5 {
		t.Errorf("CheckRateLimit() ProfileCount = %d, want 5", result.ProfileCount)
	}
	if result.ShouldEscalate {
		t.Error("CheckRateLimit() ShouldEscalate should be false when under threshold")
	}
	if result.RetryAfter != 0 {
		t.Errorf("CheckRateLimit() RetryAfter = %v, want 0", result.RetryAfter)
	}
}

// TestCheckRateLimit_WildcardRuleMatches tests that wildcard rule (empty Profiles) matches any profile.
func TestCheckRateLimit_WildcardRuleMatches(t *testing.T) {
	now := time.Now()

	store := &mockCheckerStore{
		countByInvokerSinceFunc: func(ctx context.Context, invoker string, since time.Time) (int, error) {
			return 10, nil // At limit
		},
	}

	policy := &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:        "global-limit",
				Profiles:    []string{}, // Wildcard - matches all profiles
				MaxPerUser:  10,
				QuotaWindow: 24 * time.Hour,
			},
		},
	}

	result, err := CheckRateLimit(context.Background(), store, policy, "alice", "any-profile", now)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v, want nil", err)
	}
	if result.Allowed {
		t.Error("CheckRateLimit() wildcard rule should match any profile")
	}
	if result.Reason != "user quota exceeded" {
		t.Errorf("CheckRateLimit() Reason = %q, want %q", result.Reason, "user quota exceeded")
	}
}

// TestCheckRateLimit_CooldownNoLastEvent tests cooldown check with no previous event.
func TestCheckRateLimit_CooldownNoLastEvent(t *testing.T) {
	now := time.Now()

	store := &mockCheckerStore{
		getLastByInvokerAndProfileFunc: func(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
			return nil, nil // No previous event
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
	if !result.Allowed {
		t.Error("CheckRateLimit() should allow when no previous event exists")
	}
}

// TestCheckRateLimit_StoreErrorOnCooldown tests error propagation from store during cooldown check.
func TestCheckRateLimit_StoreErrorOnCooldown(t *testing.T) {
	now := time.Now()
	expectedErr := errors.New("database connection failed")

	store := &mockCheckerStore{
		getLastByInvokerAndProfileFunc: func(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
			return nil, expectedErr
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
	if err == nil {
		t.Fatal("CheckRateLimit() error = nil, want error")
	}
	if result != nil {
		t.Errorf("CheckRateLimit() result = %v, want nil on error", result)
	}
}

// TestCheckRateLimit_StoreErrorOnUserCount tests error propagation from store during user count.
func TestCheckRateLimit_StoreErrorOnUserCount(t *testing.T) {
	now := time.Now()
	expectedErr := errors.New("database timeout")

	store := &mockCheckerStore{
		countByInvokerSinceFunc: func(ctx context.Context, invoker string, since time.Time) (int, error) {
			return 0, expectedErr
		},
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
	if err == nil {
		t.Fatal("CheckRateLimit() error = nil, want error")
	}
	if result != nil {
		t.Errorf("CheckRateLimit() result = %v, want nil on error", result)
	}
}

// TestCheckRateLimit_StoreErrorOnProfileCount tests error propagation from store during profile count.
func TestCheckRateLimit_StoreErrorOnProfileCount(t *testing.T) {
	now := time.Now()
	expectedErr := errors.New("database timeout")

	store := &mockCheckerStore{
		countByInvokerSinceFunc: func(ctx context.Context, invoker string, since time.Time) (int, error) {
			return 2, nil // Under user limit
		},
		countByProfileSinceFunc: func(ctx context.Context, profile string, since time.Time) (int, error) {
			return 0, expectedErr
		},
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
	if err == nil {
		t.Fatal("CheckRateLimit() error = nil, want error")
	}
	if result != nil {
		t.Errorf("CheckRateLimit() result = %v, want nil on error", result)
	}
}
