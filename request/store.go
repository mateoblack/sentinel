package request

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
	// ErrRequestNotFound is returned when the requested request does not exist.
	ErrRequestNotFound = errors.New("request not found")

	// ErrRequestExists is returned when attempting to create a request with an ID
	// that already exists in the store.
	ErrRequestExists = errors.New("request already exists")

	// ErrConcurrentModification is returned when an update fails due to optimistic
	// locking - another process modified the request between read and write.
	ErrConcurrentModification = errors.New("concurrent modification detected")
)

// Store defines the interface for approval request persistence.
// Implementations must be safe for concurrent use.
type Store interface {
	// Create stores a new request. Returns ErrRequestExists if ID already exists.
	// The request must be valid according to Request.Validate().
	Create(ctx context.Context, req *Request) error

	// Get retrieves a request by ID. Returns ErrRequestNotFound if not exists.
	Get(ctx context.Context, id string) (*Request, error)

	// Update modifies an existing request. Returns ErrRequestNotFound if not exists.
	// Uses optimistic locking via UpdatedAt to prevent concurrent modification.
	// Returns ErrConcurrentModification if the request was modified since last read.
	Update(ctx context.Context, req *Request) error

	// Delete removes a request by ID. No-op if not exists (idempotent).
	Delete(ctx context.Context, id string) error

	// ListByRequester returns all requests from a specific user, ordered by created_at desc.
	// Returns empty slice if no requests found.
	// If limit is 0, DefaultQueryLimit is used. Limit is capped at MaxQueryLimit.
	ListByRequester(ctx context.Context, requester string, limit int) ([]*Request, error)

	// ListByStatus returns all requests with a specific status, ordered by created_at desc.
	// Commonly used to list pending requests for approvers.
	// If limit is 0, DefaultQueryLimit is used. Limit is capped at MaxQueryLimit.
	ListByStatus(ctx context.Context, status RequestStatus, limit int) ([]*Request, error)

	// ListByProfile returns all requests for a specific AWS profile, ordered by created_at desc.
	// Useful for viewing request history for a profile.
	// If limit is 0, DefaultQueryLimit is used. Limit is capped at MaxQueryLimit.
	ListByProfile(ctx context.Context, profile string, limit int) ([]*Request, error)
}
