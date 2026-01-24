package breakglass_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
)

// concurrentMockStore implements breakglass.Store with mutex protection for concurrency tests.
// This allows us to test the store interface contract under concurrent access.
type concurrentMockStore struct {
	mu sync.Mutex

	events map[string]*breakglass.BreakGlassEvent

	// Atomic call counters for verification
	createCount  atomic.Int64
	getCount     atomic.Int64
	updateCount  atomic.Int64
	listCount    atomic.Int64
	createErrors atomic.Int64

	// Configurable latency to increase race likelihood
	latency time.Duration
}

func newConcurrentMockStore() *concurrentMockStore {
	return &concurrentMockStore{
		events: make(map[string]*breakglass.BreakGlassEvent),
	}
}

func (s *concurrentMockStore) Create(ctx context.Context, event *breakglass.BreakGlassEvent) error {
	s.createCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.events[event.ID]; exists {
		s.createErrors.Add(1)
		return fmt.Errorf("%s: %w", event.ID, breakglass.ErrEventExists)
	}
	s.events[event.ID] = event
	return nil
}

func (s *concurrentMockStore) Get(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
	s.getCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if event, ok := s.events[id]; ok {
		return event, nil
	}
	return nil, fmt.Errorf("%s: %w", id, breakglass.ErrEventNotFound)
}

func (s *concurrentMockStore) Update(ctx context.Context, event *breakglass.BreakGlassEvent) error {
	s.updateCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.events[event.ID]; !exists {
		return fmt.Errorf("%s: %w", event.ID, breakglass.ErrEventNotFound)
	}
	// Set UpdatedAt to match real DynamoDB store behavior
	event.UpdatedAt = time.Now()
	// Last-writer-wins for simplicity in mock
	s.events[event.ID] = event
	return nil
}

func (s *concurrentMockStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.events, id)
	return nil
}

func (s *concurrentMockStore) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
	s.listCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var results []*breakglass.BreakGlassEvent
	for _, event := range s.events {
		if event.Invoker == invoker {
			results = append(results, event)
		}
	}
	return results, nil
}

func (s *concurrentMockStore) ListByStatus(ctx context.Context, status breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error) {
	s.listCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var results []*breakglass.BreakGlassEvent
	for _, event := range s.events {
		if event.Status == status {
			results = append(results, event)
		}
	}
	return results, nil
}

func (s *concurrentMockStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*breakglass.BreakGlassEvent, error) {
	s.listCount.Add(1)
	if s.latency > 0 {
		time.Sleep(s.latency)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var results []*breakglass.BreakGlassEvent
	for _, event := range s.events {
		if event.Profile == profile {
			results = append(results, event)
		}
	}
	return results, nil
}

func (s *concurrentMockStore) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, event := range s.events {
		if event.Invoker == invoker && event.Profile == profile && event.Status == breakglass.StatusActive {
			return event, nil
		}
	}
	return nil, nil
}

func (s *concurrentMockStore) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, event := range s.events {
		if event.Invoker == invoker && event.CreatedAt.After(since) {
			count++
		}
	}
	return count, nil
}

func (s *concurrentMockStore) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, event := range s.events {
		if event.Profile == profile && event.CreatedAt.After(since) {
			count++
		}
	}
	return count, nil
}

func (s *concurrentMockStore) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var latest *breakglass.BreakGlassEvent
	for _, event := range s.events {
		if event.Invoker == invoker && event.Profile == profile {
			if latest == nil || event.CreatedAt.After(latest.CreatedAt) {
				latest = event
			}
		}
	}
	return latest, nil
}

// eventCount returns the current number of events in the store
func (s *concurrentMockStore) eventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// Helper to create a valid test event
func makeTestEvent(id, invoker, profile string) *breakglass.BreakGlassEvent {
	now := time.Now()
	return &breakglass.BreakGlassEvent{
		ID:            id,
		Invoker:       invoker,
		Profile:       profile,
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "test event",
		Duration:      time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(time.Hour),
	}
}

// TestStore_ConcurrentCreate verifies 50 goroutines can create events simultaneously.
// Each goroutine creates a unique event. Verifies all creates succeed.
func TestStore_ConcurrentCreate(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 100 * time.Microsecond
	ctx := context.Background()

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		eventID := fmt.Sprintf("event-%03d", i)
		go func(id string) {
			defer wg.Done()
			<-start

			event := makeTestEvent(id, "user@example.com", "prod-role")
			err := store.Create(ctx, event)
			if err == nil {
				successCount.Add(1)
			}
		}(eventID)
	}

	close(start)
	wg.Wait()

	// All creates should succeed (unique IDs)
	if successCount.Load() != numGoroutines {
		t.Errorf("expected %d successful creates, got %d", numGoroutines, successCount.Load())
	}

	// Store should contain all events
	if store.eventCount() != numGoroutines {
		t.Errorf("expected %d events in store, got %d", numGoroutines, store.eventCount())
	}

	t.Logf("Created %d events concurrently, %d create calls", numGoroutines, store.createCount.Load())
}

// TestStore_ConcurrentCreateDuplicates verifies duplicate ID handling under concurrent access.
// Multiple goroutines attempt to create events with the same ID.
func TestStore_ConcurrentCreateDuplicates(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 50 * time.Microsecond
	ctx := context.Background()

	const numGoroutines = 20
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64

	start := make(chan struct{})

	// All goroutines try to create an event with the same ID
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			event := makeTestEvent("duplicate-id", "user@example.com", "prod-role")
			err := store.Create(ctx, event)
			if err == nil {
				successCount.Add(1)
			} else {
				errorCount.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	// Exactly one should succeed, rest should fail with ErrEventExists
	if successCount.Load() != 1 {
		t.Errorf("expected exactly 1 successful create, got %d", successCount.Load())
	}
	if errorCount.Load() != int64(numGoroutines-1) {
		t.Errorf("expected %d errors, got %d", numGoroutines-1, errorCount.Load())
	}

	// Store should contain exactly one event
	if store.eventCount() != 1 {
		t.Errorf("expected 1 event in store, got %d", store.eventCount())
	}
}

// TestStore_ConcurrentGet verifies 100 goroutines can read the same event simultaneously.
// All reads should return consistent data.
func TestStore_ConcurrentGet(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 50 * time.Microsecond
	ctx := context.Background()

	// Pre-create an event
	event := makeTestEvent("shared-event", "user@example.com", "prod-role")
	if err := store.Create(ctx, event); err != nil {
		t.Fatalf("failed to create test event: %v", err)
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var inconsistentCount atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			got, err := store.Get(ctx, "shared-event")
			if err != nil {
				return
			}

			// Verify data consistency
			if got.ID != "shared-event" ||
				got.Invoker != "user@example.com" ||
				got.Profile != "prod-role" {
				inconsistentCount.Add(1)
				return
			}
			successCount.Add(1)
		}()
	}

	close(start)
	wg.Wait()

	if successCount.Load() != numGoroutines {
		t.Errorf("expected %d successful reads, got %d", numGoroutines, successCount.Load())
	}
	if inconsistentCount.Load() != 0 {
		t.Errorf("expected 0 inconsistent reads, got %d", inconsistentCount.Load())
	}

	t.Logf("Completed %d concurrent reads", store.getCount.Load())
}

// TestStore_ConcurrentUpdate verifies 50 goroutines can update the same event.
// Uses last-writer-wins semantics - all updates should succeed.
func TestStore_ConcurrentUpdate(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 50 * time.Microsecond
	ctx := context.Background()

	// Pre-create an event
	event := makeTestEvent("update-target", "user@example.com", "prod-role")
	if err := store.Create(ctx, event); err != nil {
		t.Fatalf("failed to create test event: %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		writerID := i
		go func(id int) {
			defer wg.Done()
			<-start

			// Each goroutine updates with a unique justification
			updatedEvent := makeTestEvent("update-target", "user@example.com", "prod-role")
			updatedEvent.Justification = fmt.Sprintf("updated by goroutine %d", id)
			updatedEvent.UpdatedAt = time.Now()

			err := store.Update(ctx, updatedEvent)
			if err == nil {
				successCount.Add(1)
			}
		}(writerID)
	}

	close(start)
	wg.Wait()

	// All updates should succeed (last-writer-wins)
	if successCount.Load() != numGoroutines {
		t.Errorf("expected %d successful updates, got %d", numGoroutines, successCount.Load())
	}

	// Verify final state is consistent (some goroutine's update)
	final, err := store.Get(ctx, "update-target")
	if err != nil {
		t.Fatalf("failed to get final event: %v", err)
	}
	if final.Invoker != "user@example.com" {
		t.Errorf("final event has unexpected invoker: %s", final.Invoker)
	}

	t.Logf("Completed %d concurrent updates", store.updateCount.Load())
}

// TestStore_ConcurrentListByInvoker verifies parallel list queries don't panic
// when concurrent mutations are happening.
func TestStore_ConcurrentListByInvoker(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 50 * time.Microsecond
	ctx := context.Background()

	// Pre-create some events
	for i := 0; i < 10; i++ {
		event := makeTestEvent(fmt.Sprintf("list-event-%d", i), "list-user", "prod-role")
		if err := store.Create(ctx, event); err != nil {
			t.Fatalf("failed to create test event: %v", err)
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
				events, err := store.ListByInvoker(ctx, "list-user", 100)
				if err == nil && events != nil {
					readSuccess.Add(1)
				}
			}
		}()
	}

	// Writers: create new events during reads
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		writerID := i
		go func(id int) {
			defer wg.Done()
			<-start

			event := makeTestEvent(fmt.Sprintf("new-event-%d", id), "list-user", "prod-role")
			if err := store.Create(ctx, event); err == nil {
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

	t.Logf("Completed %d list operations and %d creates concurrently", store.listCount.Load(), store.createCount.Load()-10)
}

// TestStore_ConcurrentListByStatus verifies status-based queries during mutations.
func TestStore_ConcurrentListByStatus(t *testing.T) {
	store := newConcurrentMockStore()
	ctx := context.Background()

	// Pre-create events with different statuses
	for i := 0; i < 5; i++ {
		event := makeTestEvent(fmt.Sprintf("active-%d", i), "user", "role")
		event.Status = breakglass.StatusActive
		store.Create(ctx, event)
	}
	for i := 0; i < 5; i++ {
		event := makeTestEvent(fmt.Sprintf("closed-%d", i), "user", "role")
		event.Status = breakglass.StatusClosed
		store.Create(ctx, event)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	var activeQueries atomic.Int64
	var closedQueries atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start

			if id%2 == 0 {
				events, err := store.ListByStatus(ctx, breakglass.StatusActive, 100)
				if err == nil && events != nil {
					activeQueries.Add(1)
				}
			} else {
				events, err := store.ListByStatus(ctx, breakglass.StatusClosed, 100)
				if err == nil && events != nil {
					closedQueries.Add(1)
				}
			}
		}(i)
	}

	close(start)
	wg.Wait()

	expectedActiveQueries := int64(numGoroutines / 2)
	expectedClosedQueries := int64(numGoroutines / 2)

	if activeQueries.Load() != expectedActiveQueries {
		t.Errorf("expected %d active queries, got %d", expectedActiveQueries, activeQueries.Load())
	}
	if closedQueries.Load() != expectedClosedQueries {
		t.Errorf("expected %d closed queries, got %d", expectedClosedQueries, closedQueries.Load())
	}
}

// TestStore_ConcurrentMixedOperations stress tests mixed CRUD operations.
// Run with: go test -race -run=ConcurrentMixed ./breakglass/...
func TestStore_ConcurrentMixedOperations(t *testing.T) {
	store := newConcurrentMockStore()
	store.latency = 20 * time.Microsecond
	ctx := context.Background()

	// Pre-create some events
	for i := 0; i < 10; i++ {
		event := makeTestEvent(fmt.Sprintf("mixed-%d", i), "mixed-user", "mixed-role")
		store.Create(ctx, event)
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
					event := makeTestEvent(fmt.Sprintf("new-%d-%d", id, j), "mixed-user", "mixed-role")
					if err := store.Create(ctx, event); err == nil {
						successCount.Add(1)
					}
				case 1: // Get
					_, err := store.Get(ctx, fmt.Sprintf("mixed-%d", id%10))
					if err == nil {
						successCount.Add(1)
					}
				case 2: // Update
					event := makeTestEvent(fmt.Sprintf("mixed-%d", id%10), "mixed-user", "mixed-role")
					event.Justification = fmt.Sprintf("updated %d-%d", id, j)
					if err := store.Update(ctx, event); err == nil {
						successCount.Add(1)
					}
				case 3: // List
					events, err := store.ListByInvoker(ctx, "mixed-user", 100)
					if err == nil && events != nil {
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

// TestStore_RaceDetection is specifically for -race flag verification.
// It exercises all store methods concurrently to detect any data races.
func TestStore_RaceDetection(t *testing.T) {
	store := newConcurrentMockStore()
	ctx := context.Background()

	// Pre-create events
	for i := 0; i < 5; i++ {
		event := makeTestEvent(fmt.Sprintf("race-%d", i), "race-user", "race-role")
		store.Create(ctx, event)
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
			store.Create(ctx, makeTestEvent(fmt.Sprintf("race-new-%d", id), "race-user", "race-role"))

			// Get
			store.Get(ctx, fmt.Sprintf("race-%d", id%5))

			// Update
			store.Update(ctx, makeTestEvent(fmt.Sprintf("race-%d", id%5), "race-user", "race-role"))

			// List operations
			store.ListByInvoker(ctx, "race-user", 10)
			store.ListByStatus(ctx, breakglass.StatusActive, 10)
			store.ListByProfile(ctx, "race-role", 10)

			// Find/Count operations
			store.FindActiveByInvokerAndProfile(ctx, "race-user", "race-role")
			store.CountByInvokerSince(ctx, "race-user", time.Now().Add(-time.Hour))
			store.CountByProfileSince(ctx, "race-role", time.Now().Add(-time.Hour))
			store.GetLastByInvokerAndProfile(ctx, "race-user", "race-role")

			// Delete
			store.Delete(ctx, fmt.Sprintf("race-new-%d", id))
		}(i)
	}

	close(start)
	wg.Wait()

	// Test passes if no race conditions detected by -race flag
	t.Log("Race detection test completed successfully")
}
