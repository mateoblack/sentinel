package breakglass

import (
	"context"
	"errors"
	"time"
)

// Query limit constants for List operations.
const (
	// DefaultQueryLimit is the default number of results for List operations.
	DefaultQueryLimit = 100
	// MaxQueryLimit is the maximum number of results for List operations.
	MaxQueryLimit = 1000
)

// Storage-related sentinel errors for Store implementations.
// These errors support errors.Is() checking for robust error handling.
var (
	// ErrEventNotFound is returned when the requested break-glass event does not exist.
	ErrEventNotFound = errors.New("break-glass event not found")

	// ErrEventExists is returned when attempting to create an event with an ID
	// that already exists in the store.
	ErrEventExists = errors.New("break-glass event already exists")

	// ErrConcurrentModification is returned when an update fails due to optimistic
	// locking - another process modified the event between read and write.
	ErrConcurrentModification = errors.New("concurrent modification detected")
)

// Store defines the interface for break-glass event persistence.
// Implementations must be safe for concurrent use.
type Store interface {
	// Create stores a new break-glass event. Returns ErrEventExists if ID already exists.
	// The event must be valid according to BreakGlassEvent.Validate().
	Create(ctx context.Context, event *BreakGlassEvent) error

	// Get retrieves a break-glass event by ID. Returns ErrEventNotFound if not exists.
	Get(ctx context.Context, id string) (*BreakGlassEvent, error)

	// Update modifies an existing event. Returns ErrEventNotFound if not exists.
	// Uses optimistic locking via UpdatedAt to prevent concurrent modification.
	// Returns ErrConcurrentModification if the event was modified since last read.
	Update(ctx context.Context, event *BreakGlassEvent) error

	// Delete removes a break-glass event by ID. No-op if not exists (idempotent).
	Delete(ctx context.Context, id string) error

	// ListByInvoker returns all events from a specific user, ordered by created_at desc.
	// Returns empty slice if no events found.
	// If limit is 0, DefaultQueryLimit is used. Limit is capped at MaxQueryLimit.
	ListByInvoker(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error)

	// ListByStatus returns all events with a specific status, ordered by created_at desc.
	// Commonly used to list active break-glass events for security review.
	// If limit is 0, DefaultQueryLimit is used. Limit is capped at MaxQueryLimit.
	ListByStatus(ctx context.Context, status BreakGlassStatus, limit int) ([]*BreakGlassEvent, error)

	// ListByProfile returns all events for a specific AWS profile, ordered by created_at desc.
	// Useful for viewing break-glass history for a profile.
	// If limit is 0, DefaultQueryLimit is used. Limit is capped at MaxQueryLimit.
	ListByProfile(ctx context.Context, profile string, limit int) ([]*BreakGlassEvent, error)

	// FindActiveByInvokerAndProfile checks if the user already has active break-glass access
	// for a profile. Returns the active event if found, nil if no active event exists.
	// This is critical to prevent stacking of break-glass access.
	FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error)

	// CountByInvokerSince counts events from a specific user since the given time.
	// Used for per-user quota checking in rate limiting.
	CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error)

	// CountByProfileSince counts events for a specific profile since the given time.
	// Used for per-profile quota checking in rate limiting.
	CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error)

	// GetLastByInvokerAndProfile returns the most recent event for a user+profile combination.
	// Returns nil, nil if no events found. Used for cooldown checking.
	GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error)
}
