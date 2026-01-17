package request

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

// ============================================================================
// Task 2: Concurrent State Transition Security Tests
// ============================================================================

// concurrentTransitionStore simulates a store with first-writer-wins semantics.
// Used to test concurrent state transition behavior.
type concurrentTransitionStore struct {
	mu            sync.Mutex
	request       *Request
	successCount  int32
	failureCount  int32
	updateCalls   []*Request
	firstWinnerID string
}

// newConcurrentTransitionStore creates a store with a pending request.
func newConcurrentTransitionStore() *concurrentTransitionStore {
	now := time.Now()
	return &concurrentTransitionStore{
		request: &Request{
			ID:            "abcdef1234567890",
			Requester:     "alice",
			Profile:       "production",
			Justification: "Concurrent test request",
			Duration:      time.Hour,
			Status:        StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(DefaultRequestTTL),
		},
	}
}

// Get retrieves the current request state.
func (s *concurrentTransitionStore) Get(_ context.Context, _ string) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Return a copy to prevent data races
	r := *s.request
	return &r, nil
}

// Update attempts to transition the request. First writer wins.
func (s *concurrentTransitionStore) Update(_ context.Context, req *Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.updateCalls = append(s.updateCalls, req)

	// Check if transition is valid
	if !s.request.CanTransitionTo(req.Status) {
		atomic.AddInt32(&s.failureCount, 1)
		return errors.New("invalid transition: request is already in terminal state")
	}

	// First writer wins - apply the transition
	s.request.Status = req.Status
	s.request.UpdatedAt = req.UpdatedAt
	if req.Approver != "" {
		s.request.Approver = req.Approver
	}
	atomic.AddInt32(&s.successCount, 1)
	s.firstWinnerID = req.Approver
	return nil
}

// TestConcurrent_RaceConditionDetection tests that only one transition succeeds
// when multiple goroutines attempt simultaneous state transitions.
func TestConcurrent_RaceConditionDetection(t *testing.T) {
	store := newConcurrentTransitionStore()

	numGoroutines := 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Countdown latch for synchronized start
	startSignal := make(chan struct{})

	// Each goroutine attempts a transition to a different terminal state
	terminalStatuses := []RequestStatus{
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()

			// Wait for start signal
			<-startSignal

			// Attempt to transition
			ctx := context.Background()
			targetStatus := terminalStatuses[goroutineID%len(terminalStatuses)]

			// Get current state
			req, err := store.Get(ctx, "abcdef1234567890")
			if err != nil {
				return
			}

			// Prepare update
			req.Status = targetStatus
			req.UpdatedAt = time.Now()
			req.Approver = "approver-" + string(rune('A'+goroutineID))

			// Attempt update
			_ = store.Update(ctx, req)
		}(i)
	}

	// Release all goroutines simultaneously
	close(startSignal)
	wg.Wait()

	// Verify exactly one transition succeeded
	successCount := atomic.LoadInt32(&store.successCount)
	failureCount := atomic.LoadInt32(&store.failureCount)

	if successCount != 1 {
		t.Errorf("Expected exactly 1 successful transition, got %d", successCount)
	}

	if failureCount != int32(numGoroutines-1) {
		t.Errorf("Expected %d failed transitions, got %d", numGoroutines-1, failureCount)
	}

	// Verify request is in exactly one terminal state
	finalReq, _ := store.Get(context.Background(), "abcdef1234567890")
	if !finalReq.Status.IsTerminal() {
		t.Errorf("Request should be in terminal state, got %q", finalReq.Status)
	}

	// Verify approver field is set (from the winning transition)
	if finalReq.Approver == "" && finalReq.Status != StatusExpired {
		t.Error("Approver should be set for approved/denied transitions")
	}
}

// TestConcurrent_DoubleApprovalPrevention tests that an already-approved request
// cannot be approved again, even under concurrent access.
func TestConcurrent_DoubleApprovalPrevention(t *testing.T) {
	now := time.Now()
	store := &concurrentTransitionStore{
		request: &Request{
			ID:            "abcdef1234567890",
			Requester:     "alice",
			Profile:       "production",
			Justification: "Already approved request",
			Duration:      time.Hour,
			Status:        StatusApproved, // Already approved
			CreatedAt:     now.Add(-time.Hour),
			UpdatedAt:     now.Add(-30 * time.Minute),
			ExpiresAt:     now.Add(DefaultRequestTTL - time.Hour),
			Approver:      "original-approver",
		},
	}

	numGoroutines := 5
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	startSignal := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			<-startSignal

			ctx := context.Background()
			req, _ := store.Get(ctx, "abcdef1234567890")

			// Try to re-approve
			req.Status = StatusApproved
			req.UpdatedAt = time.Now()
			req.Approver = "attacker-" + string(rune('A'+goroutineID))

			_ = store.Update(ctx, req)
		}(i)
	}

	close(startSignal)
	wg.Wait()

	// Verify all re-approval attempts failed
	successCount := atomic.LoadInt32(&store.successCount)
	if successCount != 0 {
		t.Errorf("Expected 0 successful re-approvals, got %d", successCount)
	}

	// Verify original approver unchanged
	finalReq, _ := store.Get(context.Background(), "abcdef1234567890")
	if finalReq.Approver != "original-approver" {
		t.Errorf("Approver should remain 'original-approver', got %q", finalReq.Approver)
	}
}

// TestConcurrent_ExpirationRace tests the race between approval and expiration.
func TestConcurrent_ExpirationRace(t *testing.T) {
	store := newConcurrentTransitionStore()

	var wg sync.WaitGroup
	wg.Add(2)

	startSignal := make(chan struct{})

	// Goroutine 1: Attempt approval
	go func() {
		defer wg.Done()
		<-startSignal

		ctx := context.Background()
		req, _ := store.Get(ctx, "abcdef1234567890")
		req.Status = StatusApproved
		req.UpdatedAt = time.Now()
		req.Approver = "approver"
		_ = store.Update(ctx, req)
	}()

	// Goroutine 2: Attempt expiration
	go func() {
		defer wg.Done()
		<-startSignal

		ctx := context.Background()
		req, _ := store.Get(ctx, "abcdef1234567890")
		req.Status = StatusExpired
		req.UpdatedAt = time.Now()
		_ = store.Update(ctx, req)
	}()

	close(startSignal)
	wg.Wait()

	// Verify exactly one transition succeeded
	successCount := atomic.LoadInt32(&store.successCount)
	if successCount != 1 {
		t.Errorf("Expected exactly 1 successful transition, got %d", successCount)
	}

	// Verify request is in exactly one terminal state
	finalReq, _ := store.Get(context.Background(), "abcdef1234567890")
	if !finalReq.Status.IsTerminal() {
		t.Errorf("Request should be in terminal state, got %q", finalReq.Status)
	}

	// Verify no mixed state
	if finalReq.Status == StatusApproved && finalReq.Approver == "" {
		t.Error("Approved request should have an approver")
	}
	if finalReq.Status == StatusExpired && finalReq.Approver != "" {
		t.Error("Expired request should not have an approver set during expiration")
	}
}

// TestConcurrent_ManyWriters tests first-writer-wins with many concurrent writers.
func TestConcurrent_ManyWriters(t *testing.T) {
	for iteration := 0; iteration < 10; iteration++ {
		t.Run("iteration", func(t *testing.T) {
			store := newConcurrentTransitionStore()

			numGoroutines := 50
			var wg sync.WaitGroup
			wg.Add(numGoroutines)

			startSignal := make(chan struct{})

			for i := 0; i < numGoroutines; i++ {
				go func(id int) {
					defer wg.Done()
					<-startSignal

					ctx := context.Background()
					req, _ := store.Get(ctx, "abcdef1234567890")

					// Mix of different target statuses
					statuses := []RequestStatus{StatusApproved, StatusDenied, StatusCancelled}
					req.Status = statuses[id%len(statuses)]
					req.UpdatedAt = time.Now()
					req.Approver = "writer-" + string(rune('A'+(id%26)))

					_ = store.Update(ctx, req)
				}(i)
			}

			close(startSignal)
			wg.Wait()

			// Exactly one writer should win
			successCount := atomic.LoadInt32(&store.successCount)
			if successCount != 1 {
				t.Errorf("Expected exactly 1 successful transition, got %d", successCount)
			}

			// Request should be terminal
			finalReq, _ := store.Get(context.Background(), "abcdef1234567890")
			if !finalReq.Status.IsTerminal() {
				t.Errorf("Request should be terminal, got %q", finalReq.Status)
			}
		})
	}
}

// TestConcurrent_CanTransitionToIsThreadSafe tests that CanTransitionTo is
// safe to call from multiple goroutines without data races.
func TestConcurrent_CanTransitionToIsThreadSafe(t *testing.T) {
	r := &Request{Status: StatusPending}

	numGoroutines := 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			// All these reads should be safe
			_ = r.CanTransitionTo(StatusApproved)
			_ = r.CanTransitionTo(StatusDenied)
			_ = r.CanTransitionTo(StatusExpired)
			_ = r.CanTransitionTo(StatusCancelled)
			_ = r.Status.IsValid()
			_ = r.Status.IsTerminal()
			_ = r.Status.String()
		}()
	}

	wg.Wait()
	// If we get here without -race detecting issues, the test passes
}

// ============================================================================
// Task 3: Request Validation Security Edge Cases
// ============================================================================

// TestSecurityEdge_InputSanitization tests that validation handles malicious
// input patterns without panicking or behaving unexpectedly.
func TestSecurityEdge_InputSanitization(t *testing.T) {
	// Helper to create a valid request for modification
	makeValid := func() *Request {
		now := time.Now()
		return &Request{
			ID:            "abcdef1234567890",
			Requester:     "alice",
			Profile:       "production",
			Justification: "Valid justification for access request testing",
			Duration:      time.Hour,
			Status:        StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(DefaultRequestTTL),
		}
	}

	// Test requester field with special characters
	t.Run("requester_special_characters", func(t *testing.T) {
		testCases := []struct {
			name      string
			value     string
			expectErr bool
		}{
			{"newline", "alice\nBob", false},    // No validation on content, just empty check
			{"null_byte", "alice\x00bob", false}, // Passes (no content validation)
			{"unicode", "ali\u0107e", false},     // Passes (unicode allowed)
			{"empty", "", true},                  // Rejected (empty)
			{"spaces_only", "   ", false},        // Passes (not empty)
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r := makeValid()
				r.Requester = tc.value
				err := r.Validate()
				if tc.expectErr && err == nil {
					t.Errorf("Expected error for requester %q", tc.value)
				}
				if !tc.expectErr && err != nil && strings.Contains(err.Error(), "requester") {
					t.Errorf("Unexpected requester error for %q: %v", tc.value, err)
				}
			})
		}
	})

	// Test profile field with special characters
	t.Run("profile_special_characters", func(t *testing.T) {
		testCases := []struct {
			name      string
			value     string
			expectErr bool
		}{
			{"newline", "prod\nstaging", false},
			{"null_byte", "prod\x00test", false},
			{"unicode", "prod\u00e9ction", false},
			{"empty", "", true},
			{"html", "<script>alert(1)</script>", false}, // Passes (no HTML validation)
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r := makeValid()
				r.Profile = tc.value
				err := r.Validate()
				if tc.expectErr && err == nil {
					t.Errorf("Expected error for profile %q", tc.value)
				}
				if !tc.expectErr && err != nil && strings.Contains(err.Error(), "profile") {
					t.Errorf("Unexpected profile error for %q: %v", tc.value, err)
				}
			})
		}
	})

	// Test justification field with injection patterns
	t.Run("justification_injection_patterns", func(t *testing.T) {
		testCases := []struct {
			name  string
			value string
		}{
			{"html_script", "<script>alert('XSS')</script>12345"}, // Pad to min length
			{"html_img", "<img src=x onerror=alert(1)>!12"},
			{"sql_injection", "'; DROP TABLE requests;--!"},
			{"nosql_injection", "{ $gt: '' } padding text"},
			{"path_traversal", "../../../etc/passwd pad"},
			{"command_injection", "; rm -rf / ; padding"},
			{"crlf_injection", "line1\r\nX-Header: value"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r := makeValid()
				r.Justification = tc.value
				// Should not panic - validation only checks length
				err := r.Validate()
				// These should pass (no content filtering, just length)
				if err != nil && strings.Contains(err.Error(), "justification") &&
					!strings.Contains(err.Error(), "too short") &&
					!strings.Contains(err.Error(), "too long") {
					t.Errorf("Unexpected justification error for %q: %v", tc.name, err)
				}
			})
		}
	})

	// Test ID field with non-hex characters
	t.Run("id_non_hex_characters", func(t *testing.T) {
		testCases := []struct {
			name      string
			value     string
			expectErr bool
		}{
			{"valid_lowercase_hex", "abcdef1234567890", false},
			{"uppercase_hex", "ABCDEF1234567890", true},  // Rejected (uppercase)
			{"mixed_case", "AbCdEf1234567890", true},     // Rejected (mixed)
			{"non_hex_g", "ghijkl1234567890", true},      // Rejected (non-hex)
			{"cyrillic_a_lookalike", "\u0430bcdef1234567890", true}, // Rejected (Cyrillic 'a')
			{"too_short", "abcdef12345678", true},        // Rejected (14 chars)
			{"too_long", "abcdef123456789012", true},     // Rejected (18 chars)
			{"with_space", "abcdef12 34567890", true},    // Rejected (space)
			{"with_dash", "abcdef12-34567890", true},     // Rejected (dash)
			{"sql_injection", "'; DROP TABLE--", true},   // Rejected (not hex)
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r := makeValid()
				r.ID = tc.value
				err := r.Validate()
				if tc.expectErr && err == nil {
					t.Errorf("Expected error for ID %q", tc.value)
				}
				if !tc.expectErr && err != nil {
					t.Errorf("Unexpected error for ID %q: %v", tc.value, err)
				}
			})
		}
	})
}

// TestSecurityEdge_BoundaryConditions tests exact boundary values for
// security-relevant fields.
func TestSecurityEdge_BoundaryConditions(t *testing.T) {
	// Helper to create a valid request for modification
	makeValid := func() *Request {
		now := time.Now()
		return &Request{
			ID:            "abcdef1234567890",
			Requester:     "alice",
			Profile:       "production",
			Justification: "Valid justification for access request testing",
			Duration:      time.Hour,
			Status:        StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(DefaultRequestTTL),
		}
	}

	// Duration boundary tests
	t.Run("duration_boundary", func(t *testing.T) {
		testCases := []struct {
			name      string
			duration  time.Duration
			expectErr bool
		}{
			{"exactly_max", MaxDuration, false},
			{"max_plus_1ns", MaxDuration + time.Nanosecond, true},
			{"max_plus_1s", MaxDuration + time.Second, true},
			{"max_plus_1m", MaxDuration + time.Minute, true},
			{"min_positive", time.Nanosecond, false},
			{"zero", 0, true},
			{"negative_1ns", -time.Nanosecond, true},
			{"negative_1h", -time.Hour, true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r := makeValid()
				r.Duration = tc.duration
				err := r.Validate()
				if tc.expectErr && err == nil {
					t.Errorf("Expected error for duration %v", tc.duration)
				}
				if !tc.expectErr && err != nil {
					t.Errorf("Unexpected error for duration %v: %v", tc.duration, err)
				}
			})
		}
	})

	// Justification length boundary tests
	t.Run("justification_length_boundary", func(t *testing.T) {
		testCases := []struct {
			name      string
			length    int
			expectErr bool
		}{
			{"exactly_min", MinJustificationLength, false},
			{"min_minus_1", MinJustificationLength - 1, true},
			{"exactly_max", MaxJustificationLength, false},
			{"max_plus_1", MaxJustificationLength + 1, true},
			{"zero_length", 0, true},
			{"one_char", 1, true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r := makeValid()
				r.Justification = strings.Repeat("x", tc.length)
				err := r.Validate()
				if tc.expectErr && err == nil {
					t.Errorf("Expected error for justification length %d", tc.length)
				}
				if !tc.expectErr && err != nil {
					t.Errorf("Unexpected error for justification length %d: %v", tc.length, err)
				}
			})
		}
	})

	// Request ID length boundary tests
	t.Run("request_id_length_boundary", func(t *testing.T) {
		testCases := []struct {
			name      string
			length    int
			expectErr bool
		}{
			{"exactly_16", 16, false},
			{"15_chars", 15, true},
			{"17_chars", 17, true},
			{"0_chars", 0, true},
			{"32_chars", 32, true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r := makeValid()
				r.ID = strings.Repeat("a", tc.length)
				err := r.Validate()
				if tc.expectErr && err == nil {
					t.Errorf("Expected error for ID length %d", tc.length)
				}
				if !tc.expectErr && err != nil {
					t.Errorf("Unexpected error for ID length %d: %v", tc.length, err)
				}
			})
		}
	})
}

// TestSecurityEdge_TimestampManipulation tests validation behavior with
// unusual timestamp values. This documents current behavior rather than
// enforcing specific outcomes.
func TestSecurityEdge_TimestampManipulation(t *testing.T) {
	// Helper to create a valid request for modification
	makeValid := func() *Request {
		now := time.Now()
		return &Request{
			ID:            "abcdef1234567890",
			Requester:     "alice",
			Profile:       "production",
			Justification: "Valid justification for access request testing",
			Duration:      time.Hour,
			Status:        StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(DefaultRequestTTL),
		}
	}

	// Test future CreatedAt
	t.Run("future_created_at", func(t *testing.T) {
		r := makeValid()
		r.CreatedAt = time.Now().Add(24 * time.Hour) // 1 day in future

		// Document current behavior: validation does not check if CreatedAt is in future
		err := r.Validate()
		// Note: This passes because validation only checks for zero timestamps
		// Future timestamps may warrant additional validation depending on security requirements
		t.Logf("Future CreatedAt validation result: err=%v (passes=%v)", err, err == nil)
	})

	// Test ExpiresAt before CreatedAt (logically impossible)
	t.Run("expires_before_created", func(t *testing.T) {
		r := makeValid()
		r.CreatedAt = time.Now()
		r.ExpiresAt = r.CreatedAt.Add(-time.Hour) // Expires before created

		// Document current behavior: validation does not check temporal consistency
		err := r.Validate()
		t.Logf("ExpiresAt before CreatedAt validation result: err=%v (passes=%v)", err, err == nil)
	})

	// Test UpdatedAt before CreatedAt
	t.Run("updated_before_created", func(t *testing.T) {
		r := makeValid()
		r.CreatedAt = time.Now()
		r.UpdatedAt = r.CreatedAt.Add(-time.Hour) // Updated before created

		// Document current behavior: validation does not check temporal consistency
		err := r.Validate()
		t.Logf("UpdatedAt before CreatedAt validation result: err=%v (passes=%v)", err, err == nil)
	})

	// Test timestamps at Unix epoch
	t.Run("epoch_timestamps", func(t *testing.T) {
		r := makeValid()
		epoch := time.Unix(0, 0)

		// Non-zero Unix epoch should pass
		r.CreatedAt = epoch
		r.UpdatedAt = epoch
		r.ExpiresAt = epoch.Add(time.Hour)

		err := r.Validate()
		// Unix epoch is not a zero time (time.Time{} is zero, not Unix epoch)
		t.Logf("Unix epoch timestamps validation result: err=%v (passes=%v)", err, err == nil)
	})

	// Test zero timestamps are rejected
	t.Run("zero_timestamps_rejected", func(t *testing.T) {
		testCases := []struct {
			name  string
			setup func(*Request)
			field string
		}{
			{
				name:  "zero_created_at",
				setup: func(r *Request) { r.CreatedAt = time.Time{} },
				field: "created_at",
			},
			{
				name:  "zero_updated_at",
				setup: func(r *Request) { r.UpdatedAt = time.Time{} },
				field: "updated_at",
			},
			{
				name:  "zero_expires_at",
				setup: func(r *Request) { r.ExpiresAt = time.Time{} },
				field: "expires_at",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r := makeValid()
				tc.setup(r)
				err := r.Validate()
				if err == nil {
					t.Errorf("Expected error for zero %s", tc.field)
				}
				if err != nil && !strings.Contains(err.Error(), tc.field) {
					t.Errorf("Error should mention %s, got: %v", tc.field, err)
				}
			})
		}
	})

	// Test far future timestamps (year 9999)
	t.Run("far_future_timestamps", func(t *testing.T) {
		r := makeValid()
		farFuture := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		r.CreatedAt = farFuture
		r.UpdatedAt = farFuture
		r.ExpiresAt = farFuture.Add(time.Hour)

		// Document: Should pass (no upper bound validation)
		err := r.Validate()
		t.Logf("Far future timestamps validation result: err=%v (passes=%v)", err, err == nil)
	})
}

// TestSecurityEdge_ValidateRequestID tests the ValidateRequestID function
// with various edge cases.
func TestSecurityEdge_ValidateRequestID(t *testing.T) {
	testCases := []struct {
		name     string
		id       string
		expected bool
	}{
		// Valid cases
		{"valid_all_hex_digits", "0123456789abcdef", true},
		{"valid_all_letters", "abcdefabcdefabcd", true},
		{"valid_mixed", "a1b2c3d4e5f67890", true},

		// Invalid: wrong length
		{"empty", "", false},
		{"too_short_15", "abcdef123456789", false},
		{"too_long_17", "abcdef12345678901", false},

		// Invalid: wrong characters
		{"uppercase", "ABCDEF1234567890", false},
		{"mixed_case", "AbCdEf1234567890", false},
		{"non_hex_g", "ghijkl1234567890", false},
		{"non_hex_z", "zzzzzz1234567890", false},
		{"with_space", "abcdef 1234567890", false},
		{"with_dash", "abcdef-123456789", false},
		{"with_underscore", "abcdef_123456789", false},

		// Invalid: special characters
		{"null_byte", "abcdef12\x00567890", false},
		{"newline", "abcdef12\n567890", false},

		// Invalid: injection patterns
		{"sql_like_16", "' OR '1'='1'; --", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateRequestID(tc.id)
			if result != tc.expected {
				t.Errorf("ValidateRequestID(%q) = %v, want %v", tc.id, result, tc.expected)
			}
		})
	}
}

// TestSecurityEdge_NewRequestID tests that generated request IDs are always valid.
func TestSecurityEdge_NewRequestID(t *testing.T) {
	// Generate many IDs and verify they're all valid
	for i := 0; i < 100; i++ {
		id := NewRequestID()

		if len(id) != RequestIDLength {
			t.Errorf("NewRequestID() length = %d, want %d", len(id), RequestIDLength)
		}

		if !ValidateRequestID(id) {
			t.Errorf("NewRequestID() = %q is not valid", id)
		}

		// Verify lowercase hex only
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("NewRequestID() contains invalid character %q", c)
			}
		}
	}
}

// TestSecurityEdge_RequestIDUniqueness tests that generated request IDs are unique.
func TestSecurityEdge_RequestIDUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	count := 1000

	for i := 0; i < count; i++ {
		id := NewRequestID()
		if seen[id] {
			t.Errorf("Duplicate request ID generated: %s", id)
		}
		seen[id] = true
	}
}
