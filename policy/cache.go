// Package policy provides SSM-based policy loading for Sentinel.
// This file implements a caching layer around policy loaders to reduce
// SSM API calls and latency for repeated credential requests within
// short time windows.
package policy

import (
	"context"
	"sync"
	"time"
)

// PolicyLoader loads policies from a source.
type PolicyLoader interface {
	Load(ctx context.Context, parameterName string) (*Policy, error)
}

// cacheEntry holds a cached policy with its expiration time.
type cacheEntry struct {
	policy *Policy
	expiry time.Time
}

// CachedLoader wraps a PolicyLoader with in-memory TTL-based caching.
// It is safe for concurrent use.
type CachedLoader struct {
	loader PolicyLoader
	mu     sync.RWMutex
	cache  map[string]*cacheEntry
	ttl    time.Duration
}

// NewCachedLoader creates a new CachedLoader that wraps the given loader
// and caches results for the specified TTL duration.
func NewCachedLoader(loader PolicyLoader, ttl time.Duration) *CachedLoader {
	return &CachedLoader{
		loader: loader,
		cache:  make(map[string]*cacheEntry),
		ttl:    ttl,
	}
}

// Load fetches a policy by parameter name, using cached values when available.
// Cache misses and expired entries trigger a fresh load from the underlying loader.
// Errors are not cached.
func (c *CachedLoader) Load(ctx context.Context, parameterName string) (*Policy, error) {
	// Try read lock first for cache hit
	c.mu.RLock()
	if entry, ok := c.cache[parameterName]; ok && time.Now().Before(entry.expiry) {
		c.mu.RUnlock()
		return entry.policy, nil
	}
	c.mu.RUnlock()

	// Cache miss or expired, acquire write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have populated)
	if entry, ok := c.cache[parameterName]; ok && time.Now().Before(entry.expiry) {
		return entry.policy, nil
	}

	// Fetch from underlying loader
	policy, err := c.loader.Load(ctx, parameterName)
	if err != nil {
		// Don't cache errors
		return nil, err
	}

	// Cache the result
	c.cache[parameterName] = &cacheEntry{
		policy: policy,
		expiry: time.Now().Add(c.ttl),
	}
	return policy, nil
}
