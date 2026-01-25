package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryRateLimiter_Allow(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 3,
		Window:            time.Second,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		allowed, retryAfter, err := limiter.Allow(ctx, "user1")
		if err != nil {
			t.Fatalf("Allow returned error: %v", err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
		if retryAfter != 0 {
			t.Errorf("retryAfter should be 0 when allowed, got %v", retryAfter)
		}
	}

	// 4th request should be denied
	allowed, retryAfter, err := limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}
	if allowed {
		t.Error("4th request should be denied")
	}
	if retryAfter <= 0 || retryAfter > time.Second {
		t.Errorf("retryAfter should be between 0 and 1s, got %v", retryAfter)
	}
}

func TestMemoryRateLimiter_WindowExpiry(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 2,
		Window:            100 * time.Millisecond,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// Use all allowed requests
	for i := 0; i < 2; i++ {
		allowed, _, _ := limiter.Allow(ctx, "user1")
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// Should be denied now
	allowed, _, _ := limiter.Allow(ctx, "user1")
	if allowed {
		t.Error("should be denied after limit")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	allowed, _, _ = limiter.Allow(ctx, "user1")
	if !allowed {
		t.Error("should be allowed after window expiry")
	}
}

func TestMemoryRateLimiter_DifferentKeys(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 1,
		Window:            time.Second,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// Each key has its own limit
	allowed1, _, _ := limiter.Allow(ctx, "user1")
	if !allowed1 {
		t.Error("user1 first request should be allowed")
	}

	allowed2, _, _ := limiter.Allow(ctx, "user2")
	if !allowed2 {
		t.Error("user2 first request should be allowed")
	}

	// user1 should be denied (limit reached)
	allowed1Again, _, _ := limiter.Allow(ctx, "user1")
	if allowed1Again {
		t.Error("user1 second request should be denied")
	}

	// user2 should also be denied (limit reached)
	allowed2Again, _, _ := limiter.Allow(ctx, "user2")
	if allowed2Again {
		t.Error("user2 second request should be denied")
	}
}

func TestMemoryRateLimiter_Concurrent(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 100,
		Window:            time.Second,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// Run 200 concurrent requests - should allow exactly 100
	var wg sync.WaitGroup
	var allowedCount int
	var mu sync.Mutex

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _, err := limiter.Allow(ctx, "concurrent-test")
			if err != nil {
				t.Errorf("concurrent Allow returned error: %v", err)
				return
			}
			if allowed {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Exactly 100 should have been allowed
	if allowedCount != 100 {
		t.Errorf("expected 100 allowed requests, got %d", allowedCount)
	}
}

func TestMemoryRateLimiter_Cleanup(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 10,
		Window:            50 * time.Millisecond,
	}

	// Create with short cleanup interval for testing
	limiter, err := NewMemoryRateLimiterWithCleanup(cfg, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiterWithCleanup failed: %v", err)
	}
	defer limiter.Close()

	// Add some requests
	for i := 0; i < 5; i++ {
		limiter.Allow(ctx, "cleanup-test")
	}

	// Verify keys exist
	stats := limiter.Stats()
	if stats.TotalKeys != 1 {
		t.Errorf("expected 1 key, got %d", stats.TotalKeys)
	}
	if stats.TotalRequests != 5 {
		t.Errorf("expected 5 requests, got %d", stats.TotalRequests)
	}

	// Wait for window to expire + cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Keys should be cleaned up
	stats = limiter.Stats()
	if stats.TotalKeys != 0 {
		t.Errorf("expected 0 keys after cleanup, got %d", stats.TotalKeys)
	}
}

func TestMemoryRateLimiter_BurstSize(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 2,
		Window:            time.Second,
		BurstSize:         5, // Allow bursts up to 5
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// Should allow up to burst size (5)
	for i := 0; i < 5; i++ {
		allowed, _, _ := limiter.Allow(ctx, "burst-test")
		if !allowed {
			t.Errorf("request %d should be allowed (within burst)", i+1)
		}
	}

	// 6th request should be denied
	allowed, _, _ := limiter.Allow(ctx, "burst-test")
	if allowed {
		t.Error("6th request should be denied (exceeds burst)")
	}
}

func TestMemoryRateLimiter_Close(t *testing.T) {
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Second,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}

	// Close should return without error
	err = limiter.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Close again should be safe
	err = limiter.Close()
	if err != nil {
		t.Errorf("Second Close returned error: %v", err)
	}
}

func TestNewMemoryRateLimiter_InvalidConfig(t *testing.T) {
	cfg := Config{
		RequestsPerWindow: 0, // Invalid
		Window:            time.Second,
	}

	_, err := NewMemoryRateLimiter(cfg)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}
