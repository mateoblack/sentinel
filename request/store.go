package request

import (
	"context"
	"errors"
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
}
