package ratelimit

import (
	"context"
	"sync"
	"time"
)

// MemoryRateLimiter implements RateLimiter using an in-memory sliding window log.
// Safe for concurrent use. For Lambda, each warm instance shares this memory.
type MemoryRateLimiter struct {
	config Config

	mu      sync.Mutex
	buckets map[string]*bucket

	// cleanupInterval controls how often expired entries are removed.
	cleanupInterval time.Duration

	// done signals the cleanup goroutine to stop.
	done chan struct{}
	// wg waits for cleanup goroutine to finish.
	wg sync.WaitGroup
}

// bucket holds request timestamps for a single key.
type bucket struct {
	timestamps []time.Time
}

// NewMemoryRateLimiter creates a new in-memory rate limiter.
// Starts a background goroutine to clean up expired entries.
// Call Close() to stop the cleanup goroutine.
func NewMemoryRateLimiter(cfg Config) (*MemoryRateLimiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	m := &MemoryRateLimiter{
		config:          cfg,
		buckets:         make(map[string]*bucket),
		cleanupInterval: 10 * time.Minute,
		done:            make(chan struct{}),
	}

	// Start background cleanup
	m.wg.Add(1)
	go m.cleanupLoop()

	return m, nil
}

// NewMemoryRateLimiterWithCleanup creates a rate limiter with custom cleanup interval.
// Useful for testing with shorter cleanup intervals.
func NewMemoryRateLimiterWithCleanup(cfg Config, cleanupInterval time.Duration) (*MemoryRateLimiter, error) {
	m, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		return nil, err
	}
	m.cleanupInterval = cleanupInterval
	return m, nil
}

// Allow checks if a request should be allowed for the given key.
// Uses sliding window log algorithm: counts requests in the last Window period.
func (m *MemoryRateLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-m.config.Window)

	// Get or create bucket for this key
	b, exists := m.buckets[key]
	if !exists {
		b = &bucket{timestamps: make([]time.Time, 0, m.config.EffectiveBurstSize())}
		m.buckets[key] = b
	}

	// Remove expired timestamps (older than window)
	b.timestamps = filterValid(b.timestamps, windowStart)

	// Check limit
	limit := m.config.EffectiveBurstSize()
	if len(b.timestamps) >= limit {
		// Calculate retry-after: time until oldest request expires
		oldest := b.timestamps[0]
		retryAfter := oldest.Add(m.config.Window).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
		return false, retryAfter, nil
	}

	// Add current request timestamp
	b.timestamps = append(b.timestamps, now)

	return true, 0, nil
}

// Close stops the background cleanup goroutine.
// Safe to call multiple times.
func (m *MemoryRateLimiter) Close() error {
	select {
	case <-m.done:
		// Already closed
		return nil
	default:
		close(m.done)
	}
	m.wg.Wait()
	return nil
}

// cleanupLoop periodically removes expired entries from memory.
func (m *MemoryRateLimiter) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup removes expired entries from all buckets.
func (m *MemoryRateLimiter) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-m.config.Window)

	for key, b := range m.buckets {
		b.timestamps = filterValid(b.timestamps, windowStart)
		if len(b.timestamps) == 0 {
			delete(m.buckets, key)
		}
	}
}

// filterValid returns only timestamps after the cutoff.
func filterValid(timestamps []time.Time, cutoff time.Time) []time.Time {
	valid := timestamps[:0]
	for _, t := range timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	return valid
}

// Stats returns current statistics for monitoring.
type Stats struct {
	// TotalKeys is the number of unique keys being tracked.
	TotalKeys int
	// TotalRequests is the total number of timestamps across all buckets.
	TotalRequests int
}

// Stats returns current rate limiter statistics.
func (m *MemoryRateLimiter) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats := Stats{TotalKeys: len(m.buckets)}
	for _, b := range m.buckets {
		stats.TotalRequests += len(b.timestamps)
	}
	return stats
}
