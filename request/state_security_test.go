package request

import (
	"strings"
	"testing"
)

// ============================================================================
// Task 1: Terminal State Immutability Security Tests
// ============================================================================

// TestSecurity_TerminalStateImmutability exhaustively verifies that terminal
// states cannot transition to any other state, including invalid ones.
func TestSecurity_TerminalStateImmutability(t *testing.T) {
	terminalStatuses := []RequestStatus{
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	// All possible targets including valid and invalid
	targetStatuses := []RequestStatus{
		StatusPending,
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
		// Invalid/malformed status strings
		"",
		"APPROVED",
		"Pending",
		"invalid",
		"pending ",
		" pending",
		"approved\n",
		"denied\x00",
		"'; DROP TABLE requests;--",
		"$ne: null",
		"__proto__",
		"constructor",
	}

	for _, fromStatus := range terminalStatuses {
		for _, toStatus := range targetStatuses {
			t.Run(string(fromStatus)+"_to_"+string(toStatus), func(t *testing.T) {
				r := &Request{Status: fromStatus}
				if r.CanTransitionTo(toStatus) {
					t.Errorf("Terminal status %q should NOT be able to transition to %q",
						fromStatus, toStatus)
				}
			})
		}
	}
}

// TestSecurity_StatusEnumExhaustive verifies that IsValid correctly identifies
// all valid and invalid status values.
func TestSecurity_StatusEnumExhaustive(t *testing.T) {
	// Valid statuses
	validStatuses := []RequestStatus{
		StatusPending,
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	for _, status := range validStatuses {
		t.Run("valid_"+string(status), func(t *testing.T) {
			if !status.IsValid() {
				t.Errorf("Status %q should be valid", status)
			}
		})
	}

	// Invalid statuses - comprehensive attack patterns
	invalidStatuses := []RequestStatus{
		// Empty and whitespace
		"",
		" ",
		"\t",
		"\n",
		"  ",
		// Case variations (status is case-sensitive)
		"PENDING",
		"APPROVED",
		"DENIED",
		"EXPIRED",
		"CANCELLED",
		"Pending",
		"Approved",
		"Denied",
		"Expired",
		"Cancelled",
		"pEnDiNg",
		// Common typos
		"approveed",
		"denyed",
		"expird",
		"canceled", // American spelling vs British "cancelled"
		// Whitespace padding
		" pending",
		"pending ",
		" pending ",
		"approved\n",
		"denied\t",
		"\rpending",
		// SQL injection patterns
		"'; DROP TABLE requests;--",
		"1; SELECT * FROM users",
		"' OR '1'='1",
		"1 UNION SELECT * FROM secrets",
		// NoSQL injection patterns
		"$ne: null",
		"$gt: ''",
		"$where: '1==1'",
		"{$gt: ''}",
		// JavaScript prototype pollution
		"__proto__",
		"constructor",
		"prototype",
		// Null bytes and control characters
		"pending\x00",
		"approved\x00extra",
		"\x00pending",
		// Unicode confusables
		"p\u0435nding",  // Cyrillic 'e'
		"approv\u0435d", // Cyrillic 'e'
		// Path traversal (shouldn't apply but test anyway)
		"../../../etc/passwd",
		// Random garbage
		"abc123",
		"true",
		"false",
		"null",
		"undefined",
		"NaN",
	}

	for _, status := range invalidStatuses {
		testName := "invalid_" + strings.ReplaceAll(string(status), "\n", "\\n")
		testName = strings.ReplaceAll(testName, "\t", "\\t")
		testName = strings.ReplaceAll(testName, "\r", "\\r")
		testName = strings.ReplaceAll(testName, "\x00", "\\x00")
		if len(testName) > 50 {
			testName = testName[:50]
		}

		t.Run(testName, func(t *testing.T) {
			if status.IsValid() {
				t.Errorf("Status %q should NOT be valid", status)
			}
		})
	}
}

// TestSecurity_StateTransitionBoundaries verifies the exact set of valid
// state transitions and that no invalid transitions are allowed.
func TestSecurity_StateTransitionBoundaries(t *testing.T) {
	t.Run("exactly_four_valid_transitions", func(t *testing.T) {
		// Pending can transition to exactly 4 terminal states
		pendingRequest := &Request{Status: StatusPending}
		validTargets := []RequestStatus{
			StatusApproved,
			StatusDenied,
			StatusExpired,
			StatusCancelled,
		}

		validCount := 0
		for _, target := range validTargets {
			if pendingRequest.CanTransitionTo(target) {
				validCount++
			}
		}

		if validCount != 4 {
			t.Errorf("Expected exactly 4 valid transitions from pending, got %d", validCount)
		}
	})

	t.Run("pending_to_pending_rejected", func(t *testing.T) {
		r := &Request{Status: StatusPending}
		if r.CanTransitionTo(StatusPending) {
			t.Error("Pending -> pending transition should be rejected (no-op)")
		}
	})

	// Exhaustive terminal -> * rejection tests (4 terminal x 5 statuses = 20 tests)
	terminalStatuses := []RequestStatus{
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	allStatuses := []RequestStatus{
		StatusPending,
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	for _, fromStatus := range terminalStatuses {
		for _, toStatus := range allStatuses {
			testName := "terminal_" + string(fromStatus) + "_to_" + string(toStatus) + "_rejected"
			t.Run(testName, func(t *testing.T) {
				r := &Request{Status: fromStatus}
				if r.CanTransitionTo(toStatus) {
					t.Errorf("Terminal status %q should NOT be able to transition to %q",
						fromStatus, toStatus)
				}
			})
		}
	}
}

// TestSecurity_IsTerminalExhaustive verifies IsTerminal correctly identifies
// terminal and non-terminal states.
func TestSecurity_IsTerminalExhaustive(t *testing.T) {
	terminalStatuses := []RequestStatus{
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	nonTerminalStatuses := []RequestStatus{
		StatusPending,
	}

	for _, status := range terminalStatuses {
		t.Run("terminal_"+string(status), func(t *testing.T) {
			if !status.IsTerminal() {
				t.Errorf("Status %q should be terminal", status)
			}
		})
	}

	for _, status := range nonTerminalStatuses {
		t.Run("non_terminal_"+string(status), func(t *testing.T) {
			if status.IsTerminal() {
				t.Errorf("Status %q should NOT be terminal", status)
			}
		})
	}

	// Invalid statuses should not be terminal (IsTerminal returns false for unknown)
	invalidStatuses := []RequestStatus{
		"",
		"invalid",
		"APPROVED",
	}

	for _, status := range invalidStatuses {
		t.Run("invalid_not_terminal_"+string(status), func(t *testing.T) {
			if status.IsTerminal() {
				t.Errorf("Invalid status %q should NOT be terminal", status)
			}
		})
	}
}

// TestSecurity_TransitionToInvalidStatus verifies that transitions to invalid
// statuses are always rejected, even from pending.
func TestSecurity_TransitionToInvalidStatus(t *testing.T) {
	r := &Request{Status: StatusPending}

	invalidTargets := []RequestStatus{
		"",
		"invalid",
		"APPROVED",
		"Pending",
		"'; DROP TABLE",
		"$ne: null",
	}

	for _, target := range invalidTargets {
		testName := "pending_to_invalid_" + string(target)
		if len(testName) > 50 {
			testName = testName[:50]
		}
		t.Run(testName, func(t *testing.T) {
			if r.CanTransitionTo(target) {
				t.Errorf("Pending should NOT be able to transition to invalid status %q", target)
			}
		})
	}
}
