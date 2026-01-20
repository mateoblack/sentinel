package session

import (
	"context"
	"errors"
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
	// ErrSessionNotFound is returned when the requested session does not exist.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExists is returned when attempting to create a session with an ID
	// that already exists in the store.
	ErrSessionExists = errors.New("session already exists")

	// ErrConcurrentModification is returned when an update fails due to optimistic
	// locking - another process modified the session between read and write.
	ErrConcurrentModification = errors.New("concurrent modification detected")
)

// Store defines the interface for server session persistence.
// Implementations must be safe for concurrent use.
type Store interface {
	// Create stores a new server session. Returns ErrSessionExists if ID already exists.
	Create(ctx context.Context, session *ServerSession) error

	// Get retrieves a server session by ID. Returns ErrSessionNotFound if not exists.
	Get(ctx context.Context, id string) (*ServerSession, error)

	// Update modifies an existing session. Returns ErrSessionNotFound if not exists.
	// Uses optimistic locking via UpdatedAt to prevent concurrent modification.
	// Returns ErrConcurrentModification if the session was modified since last read.
	Update(ctx context.Context, session *ServerSession) error

	// Delete removes a server session by ID. No-op if not exists (idempotent).
	Delete(ctx context.Context, id string) error

	// ListByUser returns all sessions from a specific user, ordered by created_at desc.
	// Returns empty slice if no sessions found.
	// If limit is 0, DefaultQueryLimit is used. Limit is capped at MaxQueryLimit.
	ListByUser(ctx context.Context, user string, limit int) ([]*ServerSession, error)

	// ListByStatus returns all sessions with a specific status, ordered by created_at desc.
	// Commonly used to list active sessions for monitoring.
	// If limit is 0, DefaultQueryLimit is used. Limit is capped at MaxQueryLimit.
	ListByStatus(ctx context.Context, status SessionStatus, limit int) ([]*ServerSession, error)

	// ListByProfile returns all sessions for a specific AWS profile, ordered by created_at desc.
	// Useful for viewing session history for a profile.
	// If limit is 0, DefaultQueryLimit is used. Limit is capped at MaxQueryLimit.
	ListByProfile(ctx context.Context, profile string, limit int) ([]*ServerSession, error)

	// FindActiveByServerInstance finds the active session for a specific server instance.
	// Returns nil, nil if no active session exists for that server instance.
	// This is used to locate the session when a server needs to update or close its session.
	FindActiveByServerInstance(ctx context.Context, serverInstanceID string) (*ServerSession, error)

	// Touch updates LastAccessAt and increments RequestCount atomically.
	// This is a hot-path operation called on every credential request,
	// so implementations should be optimized for efficiency.
	// Returns ErrSessionNotFound if session doesn't exist.
	Touch(ctx context.Context, id string) error
}
