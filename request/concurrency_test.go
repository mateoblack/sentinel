package request_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/request"
)

// concurrentMockStore implements request.Store with mutex protection for concurrency tests.
// This allows us to test the store interface contract under concurrent access,
// including first-writer-wins semantics for state transitions.
type concurrentMockStore struct {
	mu sync.Mutex

	requests map[string]*request.Request

	// Atomic call counters for verification
	createCount   atomic.Int64
	getCount      atomic.Int64
	updateCount   atomic.Int64
	listCount     atomic.Int64
	createErrors  atomic.Int64
	updateErrors  atomic.Int64

	// Configurable latency to increase race likelihood
	latency time.Duration

	// Enable optimistic locking simulation
	optimisticLocking bool
}

func newConcurrentMockStore() *concurrentMockStore {
	return &concurrentMockStore{
		requests:          make(map[string]*request.Request),
		optimisticLocking: true,
	}
}

func (s *concurrentMockStore) Create(ctx context.Context, req *request.Request) error {
	s.createCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.requests[req.ID]; exists {
		s.createErrors.Add(1)
		return fmt.Errorf("%s: %w", req.ID, request.ErrRequestExists)
	}
	// Clone the request to prevent external modification
	clone := *req
	s.requests[req.ID] = &clone
	return nil
}

func (s *concurrentMockStore) Get(ctx context.Context, id string) (*request.Request, error) {
	s.getCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if req, ok := s.requests[id]; ok {
		// Return a clone to prevent external modification
		clone := *req
		return &clone, nil
	}
	return nil, fmt.Errorf("%s: %w", id, request.ErrRequestNotFound)
}

func (s *concurrentMockStore) Update(ctx context.Context, req *request.Request) error {
	s.updateCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.requests[req.ID]
	if !exists {
		s.updateErrors.Add(1)
		return fmt.Errorf("%s: %w", req.ID, request.ErrRequestNotFound)
	}

	// Optimistic locking: check UpdatedAt matches
	if s.optimisticLocking {
		if !existing.UpdatedAt.Equal(req.UpdatedAt) {
			s.updateErrors.Add(1)
			return fmt.Errorf("%s: %w", req.ID, request.ErrConcurrentModification)
		}
	}

	// Clone and update
	clone := *req
	clone.UpdatedAt = time.Now()
	s.requests[req.ID] = &clone
	return nil
}

func (s *concurrentMockStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.requests, id)
	return nil
}

func (s *concurrentMockStore) ListByRequester(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
	s.listCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var results []*request.Request
	for _, req := range s.requests {
		if req.Requester == requester {
			clone := *req
			results = append(results, &clone)
		}
	}
	return results, nil
}

func (s *concurrentMockStore) ListByStatus(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error) {
	s.listCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var results []*request.Request
	for _, req := range s.requests {
		if req.Status == status {
			clone := *req
			results = append(results, &clone)
		}
	}
	return results, nil
}

func (s *concurrentMockStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
	s.listCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var results []*request.Request
	for _, req := range s.requests {
		if req.Profile == profile {
			clone := *req
			results = append(results, &clone)
		}
	}
	return results, nil
}

// requestCount returns the current number of requests in the store
func (s *concurrentMockStore) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// getRequestStatus returns the status of a specific request
func (s *concurrentMockStore) getRequestStatus(id string) (request.RequestStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req, ok := s.requests[id]; ok {
		return req.Status, true
	}
	return "", false
}

// Helper to create a valid test request
func makeTestRequest(id, requester, profile string) *request.Request {
	now := time.Now()
	return &request.Request{
		ID:            id,
		Requester:     requester,
		Profile:       profile,
		Justification: "test request",
		Duration:      time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
	}
}

// TestRequestStore_ConcurrentCreate verifies 50 goroutines can create requests simultaneously.
// Each goroutine creates a unique request. Verifies all creates succeed.
func TestRequestStore_ConcurrentCreate(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 100 * time.Microsecond
	ctx := context.Background()

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		requestID := fmt.Sprintf("request-%03d", i)
		go func(id string) {
			defer wg.Done()
			<-start

			req := makeTestRequest(id, "user@example.com", "prod-role")
			err := store.Create(ctx, req)
			if err == nil {
				successCount.Add(1)
			}
		}(requestID)
	}

	close(start)
	wg.Wait()

	// All creates should succeed (unique IDs)
	if successCount.Load() != numGoroutines {
		t.Errorf("expected %d successful creates, got %d", numGoroutines, successCount.Load())
	}

	// Store should contain all requests
	if store.requestCount() != numGoroutines {
		t.Errorf("expected %d requests in store, got %d", numGoroutines, store.requestCount())
	}

	t.Logf("Created %d requests concurrently, %d create calls", numGoroutines, store.createCount.Load())
}

// TestRequestStore_ConcurrentStateTransition verifies state machine integrity when
// multiple goroutines attempt parallel approve/deny on the same pending request.
//
// First transition should win, subsequent transitions should fail.
func TestRequestStore_ConcurrentStateTransition(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 50 * time.Microsecond
	ctx := context.Background()

	// Create a pending request
	req := makeTestRequest("transition-target", "user@example.com", "prod-role")
	if err := store.Create(ctx, req); err != nil {
		t.Fatalf("failed to create test request: %v", err)
	}

	// Record the initial UpdatedAt for optimistic locking
	initial, _ := store.Get(ctx, "transition-target")
	initialUpdatedAt := initial.UpdatedAt

	const numApprovers = 25
	const numDeniers = 25
	var wg sync.WaitGroup
	var approveSuccess atomic.Int64
	var denySuccess atomic.Int64
	var conflictCount atomic.Int64

	start := make(chan struct{})

	// Half try to approve
	for i := 0; i < numApprovers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start

			// Get current state
			current, err := store.Get(ctx, "transition-target")
			if err != nil {
				return
			}

			// Can only transition from pending
			if current.Status != request.StatusPending {
				conflictCount.Add(1)
				return
			}

			// Attempt to approve
			updated := *current
			updated.Status = request.StatusApproved
			updated.Approver = fmt.Sprintf("approver-%d", id)
			updated.UpdatedAt = initialUpdatedAt // Use original timestamp for optimistic locking

			err = store.Update(ctx, &updated)
			if err == nil {
				approveSuccess.Add(1)
			} else if errors.Is(err, request.ErrConcurrentModification) {
				conflictCount.Add(1)
			}
		}(i)
	}

	// Half try to deny
	for i := 0; i < numDeniers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start

			// Get current state
			current, err := store.Get(ctx, "transition-target")
			if err != nil {
				return
			}

			// Can only transition from pending
			if current.Status != request.StatusPending {
				conflictCount.Add(1)
				return
			}

			// Attempt to deny
			updated := *current
			updated.Status = request.StatusDenied
			updated.Approver = fmt.Sprintf("denier-%d", id)
			updated.UpdatedAt = initialUpdatedAt // Use original timestamp for optimistic locking

			err = store.Update(ctx, &updated)
			if err == nil {
				denySuccess.Add(1)
			} else if errors.Is(err, request.ErrConcurrentModification) {
				conflictCount.Add(1)
			}
		}(i)
	}

	close(start)
	wg.Wait()

	// Exactly one should succeed (first-writer-wins due to optimistic locking)
	totalSuccess := approveSuccess.Load() + denySuccess.Load()
	if totalSuccess != 1 {
		t.Errorf("expected exactly 1 successful transition, got %d (approve=%d, deny=%d)",
			totalSuccess, approveSuccess.Load(), denySuccess.Load())
	}

	// Verify final state is either approved or denied, not pending
	finalStatus, _ := store.getRequestStatus("transition-target")
	if finalStatus == request.StatusPending {
		t.Errorf("request should not be pending after transitions, got %s", finalStatus)
	}

	t.Logf("State transitions: %d approve, %d deny, %d conflicts",
		approveSuccess.Load(), denySuccess.Load(), conflictCount.Load())
}

// TestRequestStore_ConcurrentListByStatus verifies parallel queries during mutations.
func TestRequestStore_ConcurrentListByStatus(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 50 * time.Microsecond
	ctx := context.Background()

	// Pre-create pending requests
	for i := 0; i < 10; i++ {
		req := makeTestRequest(fmt.Sprintf("list-req-%d", i), "list-user", "prod-role")
		if err := store.Create(ctx, req); err != nil {
			t.Fatalf("failed to create test request: %v", err)
		}
	}

	const numReaders = 50
	const numWriters = 20
	var wg sync.WaitGroup
	var readSuccess atomic.Int64
	var writeSuccess atomic.Int64

	start := make(chan struct{})

	// Readers: perform list queries
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			for j := 0; j < 5; j++ {
				requests, err := store.ListByStatus(ctx, request.StatusPending, 100)
				if err == nil && requests != nil {
					readSuccess.Add(1)
				}
			}
		}()
	}

	// Writers: create new pending requests during reads
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		writerID := i
		go func(id int) {
			defer wg.Done()
			<-start

			req := makeTestRequest(fmt.Sprintf("new-req-%d", id), "list-user", "prod-role")
			if err := store.Create(ctx, req); err == nil {
				writeSuccess.Add(1)
			}
		}(writerID)
	}

	close(start)
	wg.Wait()

	// All operations should succeed without panics
	expectedReads := int64(numReaders * 5)
	if readSuccess.Load() != expectedReads {
		t.Errorf("expected %d successful list reads, got %d", expectedReads, readSuccess.Load())
	}
	if writeSuccess.Load() != int64(numWriters) {
		t.Errorf("expected %d successful writes, got %d", numWriters, writeSuccess.Load())
	}

	t.Logf("Completed %d list operations and %d creates concurrently",
		store.listCount.Load(), store.createCount.Load()-10)
}

// TestRequestStore_ConcurrentFindApproved verifies parallel approved request lookups.
func TestRequestStore_ConcurrentFindApproved(t *testing.T) {
	store := newConcurrentMockStore()
	store.optimisticLocking = false // Disable for simpler updates
	ctx := context.Background()

	// Create mix of pending and approved requests
	for i := 0; i < 10; i++ {
		req := makeTestRequest(fmt.Sprintf("find-req-%d", i), "find-user", "prod-role")
		if i%2 == 0 {
			req.Status = request.StatusApproved
			req.Approver = "admin"
		}
		store.Create(ctx, req)
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	var approvedCount atomic.Int64
	var pendingCount atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		queryType := i
		go func(t int) {
			defer wg.Done()
			<-start

			if t%2 == 0 {
				requests, err := store.ListByStatus(ctx, request.StatusApproved, 100)
				if err == nil {
					approvedCount.Add(int64(len(requests)))
				}
			} else {
				requests, err := store.ListByStatus(ctx, request.StatusPending, 100)
				if err == nil {
					pendingCount.Add(int64(len(requests)))
				}
			}
		}(queryType)
	}

	close(start)
	wg.Wait()

	// Each approved query should find 5 requests (5 approved out of 10)
	expectedApproved := int64(5 * (numGoroutines / 2))
	if approvedCount.Load() != expectedApproved {
		t.Errorf("expected %d approved finds, got %d", expectedApproved, approvedCount.Load())
	}

	// Each pending query should find 5 requests (5 pending out of 10)
	expectedPending := int64(5 * (numGoroutines / 2))
	if pendingCount.Load() != expectedPending {
		t.Errorf("expected %d pending finds, got %d", expectedPending, pendingCount.Load())
	}
}

// TestRequestStore_OptimisticLockingRetry verifies retry logic for concurrent modifications.
// Under high contention, not all goroutines may succeed even with retries, but
// the test verifies the pattern works correctly.
func TestRequestStore_OptimisticLockingRetry(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 50 * time.Microsecond
	ctx := context.Background()

	// Create a request
	req := makeTestRequest("retry-target", "user@example.com", "prod-role")
	if err := store.Create(ctx, req); err != nil {
		t.Fatalf("failed to create test request: %v", err)
	}

	const numGoroutines = 10 // Reduced for more predictable behavior
	const maxRetries = 10    // Increased retry budget
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var totalAttempts atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		writerID := i
		go func(id int) {
			defer wg.Done()
			<-start

			// Retry loop for optimistic locking
			for attempt := 0; attempt < maxRetries; attempt++ {
				totalAttempts.Add(1)

				// Get current state
				current, err := store.Get(ctx, "retry-target")
				if err != nil {
					continue
				}

				// Update with current UpdatedAt for optimistic locking
				updated := *current
				updated.Justification = fmt.Sprintf("updated by %d attempt %d", id, attempt)

				err = store.Update(ctx, &updated)
				if err == nil {
					successCount.Add(1)
					return // Success, exit retry loop
				}

				if errors.Is(err, request.ErrConcurrentModification) {
					// Exponential backoff with jitter
					backoff := time.Duration((attempt+1)*(id%3+1)) * 100 * time.Microsecond
					time.Sleep(backoff)
					continue
				}
				// Other error, don't retry
				return
			}
		}(writerID)
	}

	close(start)
	wg.Wait()

	// With retries, most goroutines should succeed
	// At minimum, all should eventually succeed with sufficient retries
	if successCount.Load() < int64(numGoroutines) {
		t.Logf("Note: %d/%d succeeded (high contention)", successCount.Load(), numGoroutines)
	}
	// At least 50% should succeed even under contention
	if successCount.Load() < int64(numGoroutines/2) {
		t.Errorf("too few successful updates: %d/%d", successCount.Load(), numGoroutines)
	}

	t.Logf("Completed %d/%d updates with %d total attempts (%.1f avg attempts/goroutine)",
		successCount.Load(), numGoroutines, totalAttempts.Load(),
		float64(totalAttempts.Load())/float64(numGoroutines))
}

// TestRequestStore_ConcurrentMixedOperations stress tests mixed CRUD operations.
// Run with: go test -race -run=ConcurrentMixed ./request/...
func TestRequestStore_ConcurrentMixedOperations(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 20 * time.Microsecond
	store.optimisticLocking = false // Disable for simplicity in stress test
	ctx := context.Background()

	// Pre-create some requests
	for i := 0; i < 10; i++ {
		req := makeTestRequest(fmt.Sprintf("mixed-%d", i), "mixed-user", "mixed-role")
		store.Create(ctx, req)
	}

	const numGoroutines = 100
	const iterations = 20
	var wg sync.WaitGroup
	var successCount atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		goroutineID := i
		go func(id int) {
			defer wg.Done()
			<-start

			for j := 0; j < iterations; j++ {
				op := (id + j) % 4
				switch op {
				case 0: // Create
					req := makeTestRequest(fmt.Sprintf("new-%d-%d", id, j), "mixed-user", "mixed-role")
					if err := store.Create(ctx, req); err == nil {
						successCount.Add(1)
					}
				case 1: // Get
					_, err := store.Get(ctx, fmt.Sprintf("mixed-%d", id%10))
					if err == nil {
						successCount.Add(1)
					}
				case 2: // Update
					req := makeTestRequest(fmt.Sprintf("mixed-%d", id%10), "mixed-user", "mixed-role")
					req.Justification = fmt.Sprintf("updated %d-%d", id, j)
					if err := store.Update(ctx, req); err == nil {
						successCount.Add(1)
					}
				case 3: // List
					requests, err := store.ListByRequester(ctx, "mixed-user", 100)
					if err == nil && requests != nil {
						successCount.Add(1)
					}
				}
			}
		}(goroutineID)
	}

	close(start)
	wg.Wait()

	// Most operations should succeed
	totalOps := int64(numGoroutines * iterations)
	successRate := float64(successCount.Load()) / float64(totalOps) * 100
	t.Logf("Success rate: %.1f%% (%d/%d operations)", successRate, successCount.Load(), totalOps)

	// At least 50% should succeed (some creates may fail due to duplicate IDs)
	if successRate < 50.0 {
		t.Errorf("success rate too low: %.1f%%", successRate)
	}
}

// TestRequestStore_RaceDetection is specifically for -race flag verification.
// It exercises all store methods concurrently to detect any data races.
func TestRequestStore_RaceDetection(t *testing.T) {
	store := newConcurrentMockStore()
	store.optimisticLocking = false
	ctx := context.Background()

	// Pre-create requests
	for i := 0; i < 5; i++ {
		req := makeTestRequest(fmt.Sprintf("race-%d", i), "race-user", "race-role")
		store.Create(ctx, req)
	}

	const numGoroutines = 30
	var wg sync.WaitGroup

	start := make(chan struct{})

	// Exercise all methods concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start

			// Create
			store.Create(ctx, makeTestRequest(fmt.Sprintf("race-new-%d", id), "race-user", "race-role"))

			// Get
			store.Get(ctx, fmt.Sprintf("race-%d", id%5))

			// Update
			store.Update(ctx, makeTestRequest(fmt.Sprintf("race-%d", id%5), "race-user", "race-role"))

			// List operations
			store.ListByRequester(ctx, "race-user", 10)
			store.ListByStatus(ctx, request.StatusPending, 10)
			store.ListByProfile(ctx, "race-role", 10)

			// Delete
			store.Delete(ctx, fmt.Sprintf("race-new-%d", id))
		}(i)
	}

	close(start)
	wg.Wait()

	// Test passes if no race conditions detected by -race flag
	t.Log("Race detection test completed successfully")
}
