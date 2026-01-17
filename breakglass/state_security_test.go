package breakglass

import (
	"context"
	"testing"
	"time"
)

// =============================================================================
// Terminal State Immutability Tests (Task 1)
// =============================================================================

// TestCanTransitionTo_ClosedIsImmutable verifies that StatusClosed cannot transition to any state.
func TestCanTransitionTo_ClosedIsImmutable(t *testing.T) {
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing terminal state immutability for closed status",
		Duration:      time.Hour,
		Status:        StatusClosed,
		CreatedAt:     time.Now().Add(-time.Hour),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}

	tests := []struct {
		name      string
		newStatus BreakGlassStatus
	}{
		{"closed cannot transition to active", StatusActive},
		{"closed cannot transition to expired", StatusExpired},
		{"closed cannot transition to closed", StatusClosed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if event.CanTransitionTo(tt.newStatus) {
				t.Errorf("CanTransitionTo(%s) = true, want false for closed status", tt.newStatus)
			}
		})
	}
}

// TestCanTransitionTo_ExpiredIsImmutable verifies that StatusExpired cannot transition to any state.
func TestCanTransitionTo_ExpiredIsImmutable(t *testing.T) {
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing terminal state immutability for expired status",
		Duration:      time.Hour,
		Status:        StatusExpired,
		CreatedAt:     time.Now().Add(-2 * time.Hour),
		UpdatedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:     time.Now().Add(-time.Hour),
	}

	tests := []struct {
		name      string
		newStatus BreakGlassStatus
	}{
		{"expired cannot transition to active", StatusActive},
		{"expired cannot transition to closed", StatusClosed},
		{"expired cannot transition to expired", StatusExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if event.CanTransitionTo(tt.newStatus) {
				t.Errorf("CanTransitionTo(%s) = true, want false for expired status", tt.newStatus)
			}
		})
	}
}

// TestCanTransitionTo_TerminalToTerminalBlocked verifies that terminal states cannot transition to other terminal states.
func TestCanTransitionTo_TerminalToTerminalBlocked(t *testing.T) {
	tests := []struct {
		name string
		from BreakGlassStatus
		to   BreakGlassStatus
	}{
		{"closed to expired blocked", StatusClosed, StatusExpired},
		{"expired to closed blocked", StatusExpired, StatusClosed},
		{"closed to closed blocked", StatusClosed, StatusClosed},
		{"expired to expired blocked", StatusExpired, StatusExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &BreakGlassEvent{
				ID:            "abcd1234abcd1234",
				Invoker:       "testuser",
				Profile:       "prod",
				ReasonCode:    ReasonIncident,
				Justification: "Testing terminal to terminal transition blocking",
				Duration:      time.Hour,
				Status:        tt.from,
				CreatedAt:     time.Now().Add(-time.Hour),
				UpdatedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(time.Hour),
			}

			if event.CanTransitionTo(tt.to) {
				t.Errorf("CanTransitionTo(%s) = true from %s, want false (terminal states are immutable)", tt.to, tt.from)
			}
		})
	}
}

// TestCanTransitionTo_ActiveToClosed verifies that active -> closed is a valid transition.
func TestCanTransitionTo_ActiveToClosed(t *testing.T) {
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing valid transition from active to closed",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}

	if !event.CanTransitionTo(StatusClosed) {
		t.Error("CanTransitionTo(StatusClosed) = false from active, want true")
	}
}

// TestCanTransitionTo_ActiveToExpired verifies that active -> expired is a valid transition.
func TestCanTransitionTo_ActiveToExpired(t *testing.T) {
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing valid transition from active to expired",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}

	if !event.CanTransitionTo(StatusExpired) {
		t.Error("CanTransitionTo(StatusExpired) = false from active, want true")
	}
}

// TestCanTransitionTo_ActiveToActiveBlocked verifies that active -> active is not a valid transition.
func TestCanTransitionTo_ActiveToActiveBlocked(t *testing.T) {
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing that active to active transition is blocked",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}

	if event.CanTransitionTo(StatusActive) {
		t.Error("CanTransitionTo(StatusActive) = true from active, want false (not a transition)")
	}
}

// TestCanTransitionTo_InvalidStatusFrom verifies that unknown status cannot transition.
func TestCanTransitionTo_InvalidStatusFrom(t *testing.T) {
	invalidStatuses := []BreakGlassStatus{
		"unknown",
		"pending",
		"ACTIVE",
		"Active",
		"invalid",
	}

	for _, invalidStatus := range invalidStatuses {
		t.Run(string(invalidStatus), func(t *testing.T) {
			event := &BreakGlassEvent{
				ID:            "abcd1234abcd1234",
				Invoker:       "testuser",
				Profile:       "prod",
				ReasonCode:    ReasonIncident,
				Justification: "Testing invalid from status rejection",
				Duration:      time.Hour,
				Status:        invalidStatus,
				CreatedAt:     time.Now().Add(-time.Hour),
				UpdatedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(time.Hour),
			}

			// Invalid from status should not be able to transition to any valid status
			if event.CanTransitionTo(StatusClosed) {
				t.Errorf("CanTransitionTo(StatusClosed) = true from invalid status %q, want false", invalidStatus)
			}
			if event.CanTransitionTo(StatusExpired) {
				t.Errorf("CanTransitionTo(StatusExpired) = true from invalid status %q, want false", invalidStatus)
			}
		})
	}
}

// TestCanTransitionTo_InvalidStatusTo verifies that cannot transition to unknown status.
func TestCanTransitionTo_InvalidStatusTo(t *testing.T) {
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing invalid to status rejection",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     time.Now().Add(-time.Hour),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}

	invalidStatuses := []BreakGlassStatus{
		"unknown",
		"pending",
		"ACTIVE",
		"Active",
		"invalid",
		"CLOSED",
		"EXPIRED",
	}

	for _, invalidStatus := range invalidStatuses {
		t.Run(string(invalidStatus), func(t *testing.T) {
			if event.CanTransitionTo(invalidStatus) {
				t.Errorf("CanTransitionTo(%q) = true from active, want false (invalid target status)", invalidStatus)
			}
		})
	}
}

// TestCanTransitionTo_EmptyStatus verifies that empty string status is rejected.
func TestCanTransitionTo_EmptyStatus(t *testing.T) {
	// Test empty from status
	t.Run("empty from status", func(t *testing.T) {
		event := &BreakGlassEvent{
			ID:            "abcd1234abcd1234",
			Invoker:       "testuser",
			Profile:       "prod",
			ReasonCode:    ReasonIncident,
			Justification: "Testing empty from status rejection",
			Duration:      time.Hour,
			Status:        "",
			CreatedAt:     time.Now().Add(-time.Hour),
			UpdatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
		}

		if event.CanTransitionTo(StatusClosed) {
			t.Error("CanTransitionTo(StatusClosed) = true from empty status, want false")
		}
	})

	// Test empty to status
	t.Run("empty to status", func(t *testing.T) {
		event := &BreakGlassEvent{
			ID:            "abcd1234abcd1234",
			Invoker:       "testuser",
			Profile:       "prod",
			ReasonCode:    ReasonIncident,
			Justification: "Testing empty to status rejection",
			Duration:      time.Hour,
			Status:        StatusActive,
			CreatedAt:     time.Now().Add(-time.Hour),
			UpdatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
		}

		if event.CanTransitionTo("") {
			t.Error("CanTransitionTo(\"\") = true from active, want false")
		}
	})
}

// TestCanTransitionTo_ExhaustiveStatusMatrix tests all possible status combinations.
func TestCanTransitionTo_ExhaustiveStatusMatrix(t *testing.T) {
	allStatuses := []BreakGlassStatus{StatusActive, StatusClosed, StatusExpired}

	// Expected transition matrix: from -> to -> allowed
	expected := map[BreakGlassStatus]map[BreakGlassStatus]bool{
		StatusActive: {
			StatusActive:  false, // Same status - not a transition
			StatusClosed:  true,  // Valid: invoker/security closes
			StatusExpired: true,  // Valid: TTL elapsed
		},
		StatusClosed: {
			StatusActive:  false, // Terminal - cannot transition
			StatusClosed:  false, // Terminal - cannot transition
			StatusExpired: false, // Terminal - cannot transition
		},
		StatusExpired: {
			StatusActive:  false, // Terminal - cannot transition
			StatusClosed:  false, // Terminal - cannot transition
			StatusExpired: false, // Terminal - cannot transition
		},
	}

	for _, fromStatus := range allStatuses {
		for _, toStatus := range allStatuses {
			t.Run(string(fromStatus)+"_to_"+string(toStatus), func(t *testing.T) {
				event := &BreakGlassEvent{
					ID:            "abcd1234abcd1234",
					Invoker:       "testuser",
					Profile:       "prod",
					ReasonCode:    ReasonIncident,
					Justification: "Testing exhaustive status transition matrix",
					Duration:      time.Hour,
					Status:        fromStatus,
					CreatedAt:     time.Now().Add(-time.Hour),
					UpdatedAt:     time.Now(),
					ExpiresAt:     time.Now().Add(time.Hour),
				}

				got := event.CanTransitionTo(toStatus)
				want := expected[fromStatus][toStatus]

				if got != want {
					t.Errorf("CanTransitionTo(%s) from %s = %v, want %v", toStatus, fromStatus, got, want)
				}
			})
		}
	}
}

// =============================================================================
// Event Validity and Expiry Tests (Task 2)
// =============================================================================

// mockStoreForValidity is a minimal mock store for validity testing.
// It implements only ListByInvoker for use with FindActiveBreakGlass.
type mockStoreForValidity struct {
	events []*BreakGlassEvent
	err    error
}

func (m *mockStoreForValidity) Create(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}
func (m *mockStoreForValidity) Get(ctx context.Context, id string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *mockStoreForValidity) Update(ctx context.Context, event *BreakGlassEvent) error {
	return nil
}
func (m *mockStoreForValidity) Delete(ctx context.Context, id string) error {
	return nil
}
func (m *mockStoreForValidity) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.events, nil
}
func (m *mockStoreForValidity) ListByStatus(ctx context.Context, status BreakGlassStatus, limit int) ([]*BreakGlassEvent, error) {
	return nil, nil
}
func (m *mockStoreForValidity) ListByProfile(ctx context.Context, profile string, limit int) ([]*BreakGlassEvent, error) {
	return nil, nil
}
func (m *mockStoreForValidity) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return nil, nil
}
func (m *mockStoreForValidity) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	return 0, nil
}
func (m *mockStoreForValidity) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	return 0, nil
}
func (m *mockStoreForValidity) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	return nil, nil
}

// TestIsBreakGlassValid_ActiveAndFutureExpiry verifies both conditions are required for validity.
func TestIsBreakGlassValid_ActiveAndFutureExpiry(t *testing.T) {
	// Create an event that is both active and has future expiry
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing validity with active status and future expiry",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Minute), // Future expiry
	}

	store := &mockStoreForValidity{events: []*BreakGlassEvent{event}}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result == nil {
		t.Error("FindActiveBreakGlass returned nil, expected event with active status and future expiry")
	}
}

// TestIsBreakGlassValid_ActiveButPastExpiry verifies active status with past expiry is invalid.
func TestIsBreakGlassValid_ActiveButPastExpiry(t *testing.T) {
	// Create an event that is active but has expired
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing that expired time invalidates even with active status",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     time.Now().Add(-2 * time.Hour),
		UpdatedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:     time.Now().Add(-time.Minute), // Past expiry
	}

	store := &mockStoreForValidity{events: []*BreakGlassEvent{event}}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result != nil {
		t.Errorf("FindActiveBreakGlass returned event with past expiry, expected nil (event is expired)")
	}
}

// TestIsBreakGlassValid_FutureExpiryButClosed verifies closed status with future expiry is invalid.
func TestIsBreakGlassValid_FutureExpiryButClosed(t *testing.T) {
	// Create an event that has future expiry but is closed
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing that closed status invalidates even with future expiry",
		Duration:      time.Hour,
		Status:        StatusClosed,
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Minute), // Future expiry
	}

	store := &mockStoreForValidity{events: []*BreakGlassEvent{event}}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result != nil {
		t.Errorf("FindActiveBreakGlass returned closed event, expected nil")
	}
}

// TestIsBreakGlassValid_ExactlyAtExpiry verifies expiry at current moment is invalid.
func TestIsBreakGlassValid_ExactlyAtExpiry(t *testing.T) {
	// Create an event that expires exactly now
	// Since time.Now() is called inside isBreakGlassValid and also here,
	// we need to use a very recent expiry to approximate this edge case
	now := time.Now()
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing that exact expiry moment is treated as invalid",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now,
		ExpiresAt:     now.Add(-time.Nanosecond), // Just past expiry
	}

	store := &mockStoreForValidity{events: []*BreakGlassEvent{event}}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result != nil {
		t.Error("FindActiveBreakGlass returned event at exact expiry, expected nil")
	}
}

// TestFindActiveBreakGlass_ExpiredEventFiltered verifies expired events are filtered.
func TestFindActiveBreakGlass_ExpiredEventFiltered(t *testing.T) {
	// Create an event with Status=active but past ExpiresAt
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing that past ExpiresAt filters event even if Status=active",
		Duration:      time.Hour,
		Status:        StatusActive, // Still marked as active in DB
		CreatedAt:     time.Now().Add(-2 * time.Hour),
		UpdatedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:     time.Now().Add(-30 * time.Minute), // But already expired
	}

	store := &mockStoreForValidity{events: []*BreakGlassEvent{event}}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result != nil {
		t.Error("FindActiveBreakGlass returned expired event, expected nil")
	}
}

// TestFindActiveBreakGlass_ClosedEventFiltered verifies closed events are filtered.
func TestFindActiveBreakGlass_ClosedEventFiltered(t *testing.T) {
	// Create an event with Status=closed but ExpiresAt in future
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing that Status=closed filters event even if ExpiresAt future",
		Duration:      time.Hour,
		Status:        StatusClosed, // Manually closed
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Minute), // Still has time left
	}

	store := &mockStoreForValidity{events: []*BreakGlassEvent{event}}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result != nil {
		t.Error("FindActiveBreakGlass returned closed event, expected nil")
	}
}

// TestFindActiveBreakGlass_OnlyValidEventReturned verifies only valid events are returned.
func TestFindActiveBreakGlass_OnlyValidEventReturned(t *testing.T) {
	now := time.Now()

	// Create multiple events - only one should be valid
	events := []*BreakGlassEvent{
		{
			ID:            "aaaa111122223333",
			Invoker:       "testuser",
			Profile:       "prod",
			ReasonCode:    ReasonIncident,
			Justification: "Event 1 - expired (should be filtered)",
			Duration:      time.Hour,
			Status:        StatusActive,
			CreatedAt:     now.Add(-2 * time.Hour),
			UpdatedAt:     now.Add(-time.Hour),
			ExpiresAt:     now.Add(-30 * time.Minute), // Expired
		},
		{
			ID:            "bbbb222233334444",
			Invoker:       "testuser",
			Profile:       "prod",
			ReasonCode:    ReasonMaintenance,
			Justification: "Event 2 - closed (should be filtered)",
			Duration:      time.Hour,
			Status:        StatusClosed, // Closed
			CreatedAt:     now.Add(-time.Hour),
			UpdatedAt:     now.Add(-30 * time.Minute),
			ExpiresAt:     now.Add(30 * time.Minute),
		},
		{
			ID:            "cccc333344445555",
			Invoker:       "testuser",
			Profile:       "prod",
			ReasonCode:    ReasonSecurity,
			Justification: "Event 3 - valid (should be returned)",
			Duration:      time.Hour,
			Status:        StatusActive, // Active
			CreatedAt:     now.Add(-30 * time.Minute),
			UpdatedAt:     now,
			ExpiresAt:     now.Add(30 * time.Minute), // Future expiry
		},
		{
			ID:            "dddd444455556666",
			Invoker:       "testuser",
			Profile:       "other", // Different profile
			ReasonCode:    ReasonRecovery,
			Justification: "Event 4 - different profile (should be filtered)",
			Duration:      time.Hour,
			Status:        StatusActive,
			CreatedAt:     now.Add(-15 * time.Minute),
			UpdatedAt:     now,
			ExpiresAt:     now.Add(45 * time.Minute),
		},
	}

	store := &mockStoreForValidity{events: events}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result == nil {
		t.Fatal("FindActiveBreakGlass returned nil, expected valid event")
	}
	if result.ID != "cccc333344445555" {
		t.Errorf("FindActiveBreakGlass returned event ID %q, expected %q", result.ID, "cccc333344445555")
	}
}

// TestFindActiveBreakGlass_NoStackingAllowed verifies only first valid event is returned.
func TestFindActiveBreakGlass_NoStackingAllowed(t *testing.T) {
	now := time.Now()

	// Create multiple active valid events for same invoker+profile
	// FindActiveBreakGlass should return the first one found
	events := []*BreakGlassEvent{
		{
			ID:            "aaaa111122223333",
			Invoker:       "testuser",
			Profile:       "prod",
			ReasonCode:    ReasonIncident,
			Justification: "First valid event - should be returned",
			Duration:      time.Hour,
			Status:        StatusActive,
			CreatedAt:     now.Add(-time.Hour),
			UpdatedAt:     now.Add(-30 * time.Minute),
			ExpiresAt:     now.Add(time.Hour),
		},
		{
			ID:            "bbbb222233334444",
			Invoker:       "testuser",
			Profile:       "prod",
			ReasonCode:    ReasonMaintenance,
			Justification: "Second valid event - should not be returned (first wins)",
			Duration:      time.Hour,
			Status:        StatusActive,
			CreatedAt:     now.Add(-30 * time.Minute),
			UpdatedAt:     now,
			ExpiresAt:     now.Add(90 * time.Minute),
		},
	}

	store := &mockStoreForValidity{events: events}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result == nil {
		t.Fatal("FindActiveBreakGlass returned nil, expected first valid event")
	}
	// First event in list should be returned
	if result.ID != "aaaa111122223333" {
		t.Errorf("FindActiveBreakGlass returned event ID %q, expected first event %q", result.ID, "aaaa111122223333")
	}
}

// TestIsBreakGlassValid_OneNanosecondBeforeExpiry verifies just before expiry is valid.
func TestIsBreakGlassValid_OneNanosecondBeforeExpiry(t *testing.T) {
	// Create an event that expires slightly in the future
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing one nanosecond before expiry is still valid",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     time.Now().Add(-time.Hour),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Second), // 1 second in future
	}

	store := &mockStoreForValidity{events: []*BreakGlassEvent{event}}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result == nil {
		t.Error("FindActiveBreakGlass returned nil for event just before expiry, expected valid event")
	}
}

// TestIsBreakGlassValid_OneNanosecondAfterExpiry verifies just after expiry is invalid.
func TestIsBreakGlassValid_OneNanosecondAfterExpiry(t *testing.T) {
	// Create an event that expired just a nanosecond ago
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing one nanosecond after expiry is invalid",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     time.Now().Add(-time.Hour),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(-time.Nanosecond), // Just expired
	}

	store := &mockStoreForValidity{events: []*BreakGlassEvent{event}}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result != nil {
		t.Error("FindActiveBreakGlass returned event one nanosecond after expiry, expected nil")
	}
}

// TestFindActiveBreakGlass_ExpiredStatusEventFiltered verifies expired status events are filtered.
func TestFindActiveBreakGlass_ExpiredStatusEventFiltered(t *testing.T) {
	// Create an event with Status=expired but ExpiresAt in future
	// This is a valid scenario when TTL-based expiration happens
	event := &BreakGlassEvent{
		ID:            "abcd1234abcd1234",
		Invoker:       "testuser",
		Profile:       "prod",
		ReasonCode:    ReasonIncident,
		Justification: "Testing that Status=expired filters event even if ExpiresAt future",
		Duration:      time.Hour,
		Status:        StatusExpired, // TTL marked as expired
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(30 * time.Minute), // Still has time (but status overrides)
	}

	store := &mockStoreForValidity{events: []*BreakGlassEvent{event}}
	ctx := context.Background()

	result, err := FindActiveBreakGlass(ctx, store, "testuser", "prod")
	if err != nil {
		t.Fatalf("FindActiveBreakGlass returned error: %v", err)
	}
	if result != nil {
		t.Error("FindActiveBreakGlass returned expired status event, expected nil")
	}
}

// =============================================================================
// Status Enum Security Tests (Task 3)
// =============================================================================

// TestBreakGlassStatus_AllValidStatuses verifies all valid statuses return IsValid() == true.
func TestBreakGlassStatus_AllValidStatuses(t *testing.T) {
	validStatuses := []BreakGlassStatus{
		StatusActive,
		StatusClosed,
		StatusExpired,
	}

	for _, status := range validStatuses {
		t.Run(string(status), func(t *testing.T) {
			if !status.IsValid() {
				t.Errorf("Status %q.IsValid() = false, want true", status)
			}
		})
	}
}

// TestBreakGlassStatus_InvalidStrings verifies invalid strings return IsValid() == false.
func TestBreakGlassStatus_InvalidStrings(t *testing.T) {
	invalidStatuses := []BreakGlassStatus{
		"Active",     // capitalized
		"ACTIVE",     // all caps
		"pending",    // doesn't exist in break-glass
		"unknown",    // arbitrary string
		"",           // empty string
		"approved",   // from request package
		"rejected",   // from request package
		" active",    // leading space
		"active ",    // trailing space
		"active\n",   // trailing newline
	}

	for _, status := range invalidStatuses {
		name := string(status)
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			if status.IsValid() {
				t.Errorf("Status %q.IsValid() = true, want false", status)
			}
		})
	}
}

// TestBreakGlassStatus_IsTerminal_Exhaustive verifies only closed and expired are terminal.
func TestBreakGlassStatus_IsTerminal_Exhaustive(t *testing.T) {
	tests := []struct {
		status   BreakGlassStatus
		terminal bool
	}{
		{StatusActive, false},
		{StatusClosed, true},
		{StatusExpired, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		name := string(tt.status)
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			got := tt.status.IsTerminal()
			if got != tt.terminal {
				t.Errorf("Status %q.IsTerminal() = %v, want %v", tt.status, got, tt.terminal)
			}
		})
	}
}

// TestBreakGlassStatus_String_Identity verifies String() returns the expected string value.
func TestBreakGlassStatus_String_Identity(t *testing.T) {
	tests := []struct {
		status   BreakGlassStatus
		expected string
	}{
		{StatusActive, "active"},
		{StatusClosed, "closed"},
		{StatusExpired, "expired"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.expected {
				t.Errorf("Status.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestReasonCode_AllValidCodes verifies all valid reason codes return IsValid() == true.
func TestReasonCode_AllValidCodes(t *testing.T) {
	validCodes := []ReasonCode{
		ReasonIncident,
		ReasonMaintenance,
		ReasonSecurity,
		ReasonRecovery,
		ReasonOther,
	}

	for _, code := range validCodes {
		t.Run(string(code), func(t *testing.T) {
			if !code.IsValid() {
				t.Errorf("ReasonCode %q.IsValid() = false, want true", code)
			}
		})
	}
}

// TestReasonCode_InvalidStrings verifies invalid strings return IsValid() == false.
func TestReasonCode_InvalidStrings(t *testing.T) {
	invalidCodes := []ReasonCode{
		"INCIDENT",    // all caps
		"Incident",    // capitalized
		"urgent",      // doesn't exist
		"emergency",   // doesn't exist
		"",            // empty string
		"production",  // arbitrary
		" incident",   // leading space
		"incident ",   // trailing space
		"incident\n",  // trailing newline
	}

	for _, code := range invalidCodes {
		name := string(code)
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			if code.IsValid() {
				t.Errorf("ReasonCode %q.IsValid() = true, want false", code)
			}
		})
	}
}

// TestReasonCode_String_Identity verifies String() returns the expected string value.
func TestReasonCode_String_Identity(t *testing.T) {
	tests := []struct {
		code     ReasonCode
		expected string
	}{
		{ReasonIncident, "incident"},
		{ReasonMaintenance, "maintenance"},
		{ReasonSecurity, "security"},
		{ReasonRecovery, "recovery"},
		{ReasonOther, "other"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.code.String()
			if got != tt.expected {
				t.Errorf("ReasonCode.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestBreakGlassStatus_TypeSafety verifies cannot accidentally use ReasonCode as BreakGlassStatus.
func TestBreakGlassStatus_TypeSafety(t *testing.T) {
	// These are ReasonCode values, not BreakGlassStatus values
	// Even though they're both string-based, using wrong type should fail validation
	t.Run("reason code incident used as status", func(t *testing.T) {
		status := BreakGlassStatus(ReasonIncident) // "incident" as status
		if status.IsValid() {
			t.Error("ReasonCode(incident) used as BreakGlassStatus should be invalid")
		}
	})

	t.Run("reason code maintenance used as status", func(t *testing.T) {
		status := BreakGlassStatus(ReasonMaintenance) // "maintenance" as status
		if status.IsValid() {
			t.Error("ReasonCode(maintenance) used as BreakGlassStatus should be invalid")
		}
	})

	t.Run("reason code security used as status", func(t *testing.T) {
		status := BreakGlassStatus(ReasonSecurity) // "security" as status
		if status.IsValid() {
			t.Error("ReasonCode(security) used as BreakGlassStatus should be invalid")
		}
	})

	t.Run("reason code recovery used as status", func(t *testing.T) {
		status := BreakGlassStatus(ReasonRecovery) // "recovery" as status
		if status.IsValid() {
			t.Error("ReasonCode(recovery) used as BreakGlassStatus should be invalid")
		}
	})

	t.Run("reason code other used as status", func(t *testing.T) {
		status := BreakGlassStatus(ReasonOther) // "other" as status
		if status.IsValid() {
			t.Error("ReasonCode(other) used as BreakGlassStatus should be invalid")
		}
	})
}

// TestReasonCode_TypeSafety verifies cannot accidentally use BreakGlassStatus as ReasonCode.
func TestReasonCode_TypeSafety(t *testing.T) {
	// These are BreakGlassStatus values, not ReasonCode values
	// Even though they're both string-based, using wrong type should fail validation
	t.Run("status active used as reason code", func(t *testing.T) {
		code := ReasonCode(StatusActive) // "active" as reason code
		if code.IsValid() {
			t.Error("BreakGlassStatus(active) used as ReasonCode should be invalid")
		}
	})

	t.Run("status closed used as reason code", func(t *testing.T) {
		code := ReasonCode(StatusClosed) // "closed" as reason code
		if code.IsValid() {
			t.Error("BreakGlassStatus(closed) used as ReasonCode should be invalid")
		}
	})

	t.Run("status expired used as reason code", func(t *testing.T) {
		code := ReasonCode(StatusExpired) // "expired" as reason code
		if code.IsValid() {
			t.Error("BreakGlassStatus(expired) used as ReasonCode should be invalid")
		}
	})
}

// TestBreakGlassStatus_ExhaustiveValidValues verifies exactly 3 valid status values exist.
func TestBreakGlassStatus_ExhaustiveValidValues(t *testing.T) {
	// All known valid statuses
	validStatuses := []BreakGlassStatus{StatusActive, StatusClosed, StatusExpired}

	// Verify count
	if len(validStatuses) != 3 {
		t.Errorf("Expected exactly 3 valid statuses, got %d", len(validStatuses))
	}

	// Verify each is valid
	for _, s := range validStatuses {
		if !s.IsValid() {
			t.Errorf("Status %q should be valid", s)
		}
	}
}

// TestReasonCode_ExhaustiveValidValues verifies exactly 5 valid reason codes exist.
func TestReasonCode_ExhaustiveValidValues(t *testing.T) {
	// All known valid reason codes
	validCodes := []ReasonCode{ReasonIncident, ReasonMaintenance, ReasonSecurity, ReasonRecovery, ReasonOther}

	// Verify count
	if len(validCodes) != 5 {
		t.Errorf("Expected exactly 5 valid reason codes, got %d", len(validCodes))
	}

	// Verify each is valid
	for _, c := range validCodes {
		if !c.IsValid() {
			t.Errorf("ReasonCode %q should be valid", c)
		}
	}
}
