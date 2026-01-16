package breakglass

import (
	"context"
	"fmt"
	"time"
)

// RateLimitResult contains the result of a rate limit check.
// It indicates whether break-glass is allowed and provides context
// about current usage counts and escalation status.
type RateLimitResult struct {
	// Allowed indicates whether break-glass is allowed.
	Allowed bool
	// Reason explains why break-glass was blocked (empty if allowed).
	Reason string
	// RetryAfter indicates when to retry if blocked by cooldown (0 if allowed or permanent block).
	RetryAfter time.Duration
	// UserCount is the current count of events for the user in the quota window.
	UserCount int
	// ProfileCount is the current count of events for the profile in the quota window.
	ProfileCount int
	// ShouldEscalate indicates whether the escalation threshold was exceeded.
	ShouldEscalate bool
}

// CheckRateLimit checks if break-glass is allowed for the given user and profile.
// It checks cooldown, per-user quota, and per-profile quota against the policy.
// Returns RateLimitResult indicating if allowed and why if blocked.
//
// The check order is:
//  1. Find matching rule (nil policy or no matching rule = allowed)
//  2. Check cooldown (minimum time between events per user+profile)
//  3. Check per-user quota (max events per user in window)
//  4. Check per-profile quota (max events per profile in window)
//  5. Check escalation threshold (flags for notification but doesn't block)
func CheckRateLimit(ctx context.Context, store Store, policy *RateLimitPolicy, invoker, profile string, now time.Time) (*RateLimitResult, error) {
	// 1. Find matching rule - nil policy or no matching rule means no limits
	rule := FindRateLimitRule(policy, profile)
	if rule == nil {
		return &RateLimitResult{Allowed: true}, nil
	}

	result := &RateLimitResult{Allowed: true}

	// 2. Check cooldown if configured
	if rule.Cooldown > 0 {
		lastEvent, err := store.GetLastByInvokerAndProfile(ctx, invoker, profile)
		if err != nil {
			return nil, fmt.Errorf("failed to get last event for cooldown check: %w", err)
		}
		if lastEvent != nil {
			elapsed := now.Sub(lastEvent.CreatedAt)
			if elapsed < rule.Cooldown {
				remaining := rule.Cooldown - elapsed
				return &RateLimitResult{
					Allowed:    false,
					Reason:     "cooldown period not elapsed",
					RetryAfter: remaining,
				}, nil
			}
		}
	}

	// 3. Check per-user quota if configured
	if rule.MaxPerUser > 0 {
		since := now.Add(-rule.QuotaWindow)
		count, err := store.CountByInvokerSince(ctx, invoker, since)
		if err != nil {
			return nil, fmt.Errorf("failed to count user events for quota check: %w", err)
		}
		result.UserCount = count
		if count >= rule.MaxPerUser {
			return &RateLimitResult{
				Allowed:   false,
				Reason:    "user quota exceeded",
				UserCount: count,
			}, nil
		}
	}

	// 4. Check per-profile quota if configured
	if rule.MaxPerProfile > 0 {
		since := now.Add(-rule.QuotaWindow)
		count, err := store.CountByProfileSince(ctx, profile, since)
		if err != nil {
			return nil, fmt.Errorf("failed to count profile events for quota check: %w", err)
		}
		result.ProfileCount = count
		if count >= rule.MaxPerProfile {
			return &RateLimitResult{
				Allowed:      false,
				Reason:       "profile quota exceeded",
				ProfileCount: count,
			}, nil
		}
	}

	// 5. Check escalation threshold (doesn't block, just flags for notification)
	if rule.EscalationThreshold > 0 && result.UserCount >= rule.EscalationThreshold {
		result.ShouldEscalate = true
	}

	return result, nil
}

// FindActiveBreakGlass searches for a valid active break-glass event for a specific invoker and profile.
// It queries the store for all events by the invoker, then filters for:
//   - Status == StatusActive
//   - Profile matches the requested profile
//   - ExpiresAt > now (not expired)
//
// Returns the first matching event if found, or nil if no valid active event exists.
// Returns error only for store errors, not for "no active event found".
func FindActiveBreakGlass(ctx context.Context, store Store, invoker string, profile string) (*BreakGlassEvent, error) {
	events, err := store.ListByInvoker(ctx, invoker, MaxQueryLimit)
	if err != nil {
		return nil, err
	}

	for _, event := range events {
		if event.Status == StatusActive && event.Profile == profile && isBreakGlassValid(event) {
			return event, nil
		}
	}

	return nil, nil
}

// RemainingDuration returns the time remaining until the break-glass event expires.
// Returns 0 if the event is already expired or has zero ExpiresAt.
func RemainingDuration(event *BreakGlassEvent) time.Duration {
	if event.ExpiresAt.IsZero() {
		return 0
	}

	remaining := time.Until(event.ExpiresAt)
	if remaining < 0 {
		return 0
	}

	return remaining
}

// isBreakGlassValid checks if a break-glass event is still valid for credential issuance.
// An event is valid if:
//   - Status is active (not closed or expired)
//   - ExpiresAt > now (event hasn't expired)
func isBreakGlassValid(event *BreakGlassEvent) bool {
	// Check status is active
	if event.Status != StatusActive {
		return false
	}

	// Check event hasn't expired
	if time.Now().After(event.ExpiresAt) {
		return false
	}

	return true
}
