// Package ratelimit provides API rate limiting types and implementations.
// Designed for protecting Lambda TVM and credential server endpoints from abuse.
package ratelimit

import (
	"context"
	"fmt"
	"time"
)

// RateLimiter defines the interface for rate limiting implementations.
// Implementations must be safe for concurrent use.
type RateLimiter interface {
	// Allow checks if a request should be allowed for the given key.
	// Returns (allowed, retryAfter, error).
	// retryAfter indicates when to retry if blocked (0 if allowed).
	Allow(ctx context.Context, key string) (bool, time.Duration, error)
}

// Config contains rate limit configuration.
type Config struct {
	// RequestsPerWindow is the max requests allowed in Window.
	RequestsPerWindow int

	// Window is the time window for counting requests.
	Window time.Duration

	// BurstSize allows short bursts above the rate (optional).
	// If zero, defaults to RequestsPerWindow.
	BurstSize int
}

// Result provides detailed rate limit information.
type Result struct {
	// Allowed indicates if the request was permitted.
	Allowed bool

	// Remaining is the number of requests remaining in the current window.
	Remaining int

	// RetryAfter indicates when to retry if blocked (0 if allowed).
	RetryAfter time.Duration

	// ResetAt is when the current window resets.
	ResetAt time.Time
}

// Validate checks if the Config is valid.
// Returns an error if configuration values are invalid.
func (c *Config) Validate() error {
	if c.RequestsPerWindow <= 0 {
		return fmt.Errorf("RequestsPerWindow must be positive, got %d", c.RequestsPerWindow)
	}
	if c.Window <= 0 {
		return fmt.Errorf("Window must be positive, got %v", c.Window)
	}
	if c.BurstSize < 0 {
		return fmt.Errorf("BurstSize cannot be negative, got %d", c.BurstSize)
	}
	return nil
}

// EffectiveBurstSize returns the effective burst size.
// Returns BurstSize if set, otherwise RequestsPerWindow.
func (c *Config) EffectiveBurstSize() int {
	if c.BurstSize > 0 {
		return c.BurstSize
	}
	return c.RequestsPerWindow
}
