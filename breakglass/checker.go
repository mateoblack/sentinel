package breakglass

import (
	"context"
	"time"
)

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
