package breakglass

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockCheckerStore implements Store interface for testing FindActiveBreakGlass.
type mockCheckerStore struct {
	listByInvokerFunc func(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error)
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
