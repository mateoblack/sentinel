package breakglass

import (
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
		name      string
		from      BreakGlassStatus
		to        BreakGlassStatus
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
