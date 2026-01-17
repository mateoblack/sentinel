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
