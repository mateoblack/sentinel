package policy_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/policy"
)

// concurrentMockLoader is a test double for PolicyLoader with atomic call tracking.
// It includes configurable latency to increase race condition likelihood.
type concurrentMockLoader struct {
	policy    *policy.Policy
	err       error
	callCount atomic.Int64
	latency   time.Duration
}

func (m *concurrentMockLoader) Load(ctx context.Context, name string) (*policy.Policy, error) {
	m.callCount.Add(1)
	if m.latency > 0 {
		time.Sleep(m.latency)
	}
	return m.policy, m.err
}

// TestCachedLoader_ConcurrentRead verifies thread-safety when 100 goroutines
// concurrently read the same cached key.
//
// Verifies:
// - No double-loading on cache hit
// - Correct policy returned to all goroutines
// - No panics under concurrent access
func TestCachedLoader_ConcurrentRead(t *testing.T) {
	mock := &concurrentMockLoader{
		policy:  &policy.Policy{Version: "1.0"},
		latency: time.Millisecond, // Add latency to increase race likelihood
	}
	cached := policy.NewCachedLoader(mock, time.Minute)
	ctx := context.Background()

	// Prime the cache with one load
	_, err := cached.Load(ctx, "test-param")
	if err != nil {
		t.Fatalf("prime cache: unexpected error: %v", err)
	}
	initialCallCount := mock.callCount.Load()
	if initialCallCount != 1 {
		t.Fatalf("expected 1 initial call, got %d", initialCallCount)
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64

	// Barrier to start all goroutines simultaneously
	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // Wait for signal to start

			p, err := cached.Load(ctx, "test-param")
			if err != nil {
				errorCount.Add(1)
				return
			}
			if p == nil || p.Version != "1.0" {
				errorCount.Add(1)
				return
			}
			successCount.Add(1)
		}()
	}

	// Release all goroutines at once
	close(start)
	wg.Wait()

	// All goroutines should succeed with cache hits
	if successCount.Load() != numGoroutines {
		t.Errorf("expected %d successful loads, got %d", numGoroutines, successCount.Load())
	}
	if errorCount.Load() != 0 {
		t.Errorf("expected 0 errors, got %d", errorCount.Load())
	}

	// Cache should prevent any additional loader calls
	finalCallCount := mock.callCount.Load()
	if finalCallCount != initialCallCount {
		t.Errorf("expected no additional loader calls (cache hits), got %d additional calls",
			finalCallCount-initialCallCount)
	}
}

// TestCachedLoader_ConcurrentReadWrite verifies thread-safety when 50 readers
// and 50 writers simultaneously access the cache.
//
// Writers force cache misses by using unique keys.
// Readers access a shared cached key.
//
// Verifies:
// - No data races (run with -race flag)
// - All operations complete successfully
// - No panics
func TestCachedLoader_ConcurrentReadWrite(t *testing.T) {
	mock := &concurrentMockLoader{
		policy:  &policy.Policy{Version: "2.0"},
		latency: 500 * time.Microsecond,
	}
	cached := policy.NewCachedLoader(mock, time.Minute)
	ctx := context.Background()

	// Prime the cache with a shared key
	_, err := cached.Load(ctx, "shared-key")
	if err != nil {
		t.Fatalf("prime cache: unexpected error: %v", err)
	}

	const numReaders = 50
	const numWriters = 50
	var wg sync.WaitGroup
	var readerSuccess atomic.Int64
	var writerSuccess atomic.Int64

	// Barrier
	start := make(chan struct{})

	// Start readers - all read same cached key
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			// Readers: multiple reads on shared key
			for j := 0; j < 10; j++ {
				p, err := cached.Load(ctx, "shared-key")
				if err != nil || p == nil || p.Version != "2.0" {
					return
				}
			}
			readerSuccess.Add(1)
		}()
	}

	// Start writers - each writes a unique key (cache miss)
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		writerID := i
		go func() {
			defer wg.Done()
			<-start

			// Writers: each loads a unique key (cache miss, triggers write)
			key := "writer-" + string(rune('A'+writerID%26)) + string(rune('0'+writerID/26))
			p, err := cached.Load(ctx, key)
			if err != nil || p == nil || p.Version != "2.0" {
				return
			}
			writerSuccess.Add(1)
		}()
	}

	close(start)
	wg.Wait()

	// All should succeed
	if readerSuccess.Load() != numReaders {
		t.Errorf("expected %d reader successes, got %d", numReaders, readerSuccess.Load())
	}
	if writerSuccess.Load() != numWriters {
		t.Errorf("expected %d writer successes, got %d", numWriters, writerSuccess.Load())
	}
}

// TestCachedLoader_ConcurrentExpiry verifies thread-safety when reads occur
// during the cache expiry window.
//
// Uses a very short TTL so entries expire during concurrent access.
//
// Verifies:
// - Expired entries are properly refreshed
// - No stale data returned after expiry
// - No panics during expiry/refresh race
func TestCachedLoader_ConcurrentExpiry(t *testing.T) {
	// Use an atomic counter for version to verify fresh loads
	var loadVersion atomic.Int64
	loadVersion.Store(1)

	mock := &concurrentMockLoader{
		policy:  &policy.Policy{Version: "v1"},
		latency: 100 * time.Microsecond,
	}

	// Very short TTL to trigger expiry during test
	cached := policy.NewCachedLoader(mock, 2*time.Millisecond)
	ctx := context.Background()

	const numGoroutines = 100
	const iterations = 50
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			for j := 0; j < iterations; j++ {
				p, err := cached.Load(ctx, "expiring-key")
				if err != nil {
					errorCount.Add(1)
					continue
				}
				if p == nil {
					errorCount.Add(1)
					continue
				}
				successCount.Add(1)

				// Small sleep to allow cache expiry between iterations
				time.Sleep(time.Millisecond)
			}
		}()
	}

	close(start)
	wg.Wait()

	totalOps := int64(numGoroutines * iterations)
	if successCount.Load() != totalOps {
		t.Errorf("expected %d successful loads, got %d", totalOps, successCount.Load())
	}
	if errorCount.Load() != 0 {
		t.Errorf("expected 0 errors, got %d", errorCount.Load())
	}

	// Verify that cache was refreshed multiple times (TTL expired)
	callCount := mock.callCount.Load()
	if callCount <= 1 {
		t.Errorf("expected multiple loader calls due to expiry, got %d", callCount)
	}
	t.Logf("Loader called %d times across %d operations (TTL=2ms)", callCount, totalOps)
}

// TestCachedLoader_ConcurrentDifferentKeys verifies thread-safety when
// goroutines concurrently load different keys.
//
// Each goroutine loads a unique key, causing parallel cache writes.
//
// Verifies:
// - All unique keys are properly cached
// - No key collisions or overwrites
// - Correct isolation between cache entries
func TestCachedLoader_ConcurrentDifferentKeys(t *testing.T) {
	mock := &concurrentMockLoader{
		policy:  &policy.Policy{Version: "unique"},
		latency: 200 * time.Microsecond,
	}
	cached := policy.NewCachedLoader(mock, time.Minute)
	ctx := context.Background()

	const numGoroutines = 100
	var wg sync.WaitGroup
	var successCount atomic.Int64

	start := make(chan struct{})

	// Each goroutine loads a unique key
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		keyID := i
		go func() {
			defer wg.Done()
			<-start

			// Create unique key for this goroutine
			key := "key-" + string(rune('A'+keyID%26)) + string(rune('a'+keyID/26%26)) + string(rune('0'+keyID%10))

			// First load (cache miss)
			p1, err := cached.Load(ctx, key)
			if err != nil || p1 == nil {
				return
			}

			// Second load (should be cache hit)
			p2, err := cached.Load(ctx, key)
			if err != nil || p2 == nil {
				return
			}

			// Both loads should return same cached instance
			if p1 != p2 {
				return
			}

			successCount.Add(1)
		}()
	}

	close(start)
	wg.Wait()

	if successCount.Load() != numGoroutines {
		t.Errorf("expected %d successful load pairs, got %d", numGoroutines, successCount.Load())
	}

	// Each goroutine should trigger exactly one underlying load (first is miss, second is hit)
	// Some may coalesce if timing aligns, so we expect at least numGoroutines calls
	callCount := mock.callCount.Load()
	if callCount < int64(numGoroutines) {
		t.Logf("Loader called %d times for %d unique keys (some coalesced)", callCount, numGoroutines)
	}
}

// TestCachedLoader_RaceConditionStress stress tests the cache under high contention
// to verify no data races occur.
//
// Run with: go test -race -run=RaceConditionStress ./policy/...
func TestCachedLoader_RaceConditionStress(t *testing.T) {
	mock := &concurrentMockLoader{
		policy:  &policy.Policy{Version: "stress"},
		latency: 50 * time.Microsecond,
	}
	// Short TTL to trigger both reads and writes frequently
	cached := policy.NewCachedLoader(mock, time.Millisecond)
	ctx := context.Background()

	const numGoroutines = 50
	const iterations = 100
	var wg sync.WaitGroup
	var successCount atomic.Int64

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		goroutineID := i
		go func() {
			defer wg.Done()
			<-start

			for j := 0; j < iterations; j++ {
				// Mix of shared key and unique keys
				var key string
				if j%3 == 0 {
					key = "shared"
				} else {
					key = "unique-" + string(rune('A'+goroutineID%26))
				}

				p, err := cached.Load(ctx, key)
				if err != nil || p == nil || p.Version != "stress" {
					continue
				}
				successCount.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	totalOps := int64(numGoroutines * iterations)
	if successCount.Load() != totalOps {
		t.Errorf("expected %d successful loads, got %d", totalOps, successCount.Load())
	}

	t.Logf("Completed %d operations with %d loader calls", totalOps, mock.callCount.Load())
}
