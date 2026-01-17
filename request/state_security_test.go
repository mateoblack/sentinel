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
