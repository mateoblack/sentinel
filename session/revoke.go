package session

import (
	"context"
	"errors"
	"time"
)

// Revocation-related sentinel errors.
// These errors support errors.Is() checking for robust error handling.
var (
	// ErrSessionAlreadyRevoked is returned when attempting to revoke an already-revoked session.
	ErrSessionAlreadyRevoked = errors.New("session already revoked")

	// ErrSessionExpired is returned when attempting to revoke an already-expired session.
	ErrSessionExpired = errors.New("session already expired")

	// ErrInvalidRevokeInput is returned when revocation input is invalid.
	ErrInvalidRevokeInput = errors.New("invalid revoke input")
)

// RevokeInput contains the input parameters for revoking a session.
type RevokeInput struct {
	// SessionID is the ID of the session to revoke.
	SessionID string

	// RevokedBy is the identity of who is revoking the session.
	RevokedBy string

	// Reason is the reason for revocation.
	Reason string
}

// Validate checks that all required fields are populated.
func (r *RevokeInput) Validate() error {
	if r.SessionID == "" {
		return ErrInvalidRevokeInput
	}
	if r.RevokedBy == "" {
		return ErrInvalidRevokeInput
	}
	if r.Reason == "" {
		return ErrInvalidRevokeInput
	}
	if !ValidateSessionID(r.SessionID) {
		return ErrInvalidRevokeInput
	}
	return nil
}

// Revoke terminates an active session immediately.
// It validates state transitions and updates the session with revocation details.
//
// State transitions:
//   - active -> revoked (valid)
//   - revoked -> revoked (returns ErrSessionAlreadyRevoked)
//   - expired -> revoked (returns ErrSessionExpired)
//
// Returns the updated session on success, or an error if revocation failed.
func Revoke(ctx context.Context, store Store, input RevokeInput) (*ServerSession, error) {
	// Validate input
	if err := input.Validate(); err != nil {
		return nil, err
	}

	// Get session from store
	sess, err := store.Get(ctx, input.SessionID)
	if err != nil {
		return nil, err
	}

	// Check current status and validate state transition
	switch sess.Status {
	case StatusRevoked:
		return nil, ErrSessionAlreadyRevoked
	case StatusExpired:
		return nil, ErrSessionExpired
	case StatusActive:
		// Valid transition - proceed with revocation
	default:
		// Unknown status - treat as invalid state
		return nil, ErrSessionAlreadyRevoked
	}

	// Update session for revocation
	now := time.Now().UTC()
	sess.Status = StatusRevoked
	sess.RevokedBy = input.RevokedBy
	sess.RevokedReason = input.Reason
	sess.UpdatedAt = now

	// Persist changes with optimistic locking
	if err := store.Update(ctx, sess); err != nil {
		return nil, err
	}

	return sess, nil
}

// IsSessionRevoked checks if a session has been revoked.
// Returns true if the session exists and has been revoked.
// Returns false if the session is not found or is in any other state.
// This is a fail-open check - store errors return false, nil to avoid blocking credentials.
func IsSessionRevoked(ctx context.Context, store Store, sessionID string) (bool, error) {
	sess, err := store.Get(ctx, sessionID)
	if err != nil {
		// Session not found - not revoked (fail-open)
		if errors.Is(err, ErrSessionNotFound) {
			return false, nil
		}
		// Store error - return the error for caller to decide handling
		return false, err
	}

	return sess.Status == StatusRevoked, nil
}
