package request

import (
	"fmt"
)

// Validate checks if the Request is semantically correct.
// It verifies all required fields are present and valid.
func (r *Request) Validate() error {
	// Validate ID
	if !ValidateRequestID(r.ID) {
		return fmt.Errorf("invalid request ID: must be %d lowercase hex characters", RequestIDLength)
	}

	// Validate requester
	if r.Requester == "" {
		return fmt.Errorf("requester cannot be empty")
	}

	// Validate profile
	if r.Profile == "" {
		return fmt.Errorf("profile cannot be empty")
	}

	// Validate justification
	if len(r.Justification) < MinJustificationLength {
		return fmt.Errorf("justification too short: minimum %d characters", MinJustificationLength)
	}
	if len(r.Justification) > MaxJustificationLength {
		return fmt.Errorf("justification too long: maximum %d characters", MaxJustificationLength)
	}

	// Validate status
	if !r.Status.IsValid() {
		return fmt.Errorf("invalid status: %q", r.Status)
	}

	// Validate duration
	if r.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	if r.Duration > MaxDuration {
		return fmt.Errorf("duration exceeds maximum of %v", MaxDuration)
	}

	// Validate timestamps
	if r.CreatedAt.IsZero() {
		return fmt.Errorf("created_at cannot be zero")
	}
	if r.UpdatedAt.IsZero() {
		return fmt.Errorf("updated_at cannot be zero")
	}
	if r.ExpiresAt.IsZero() {
		return fmt.Errorf("expires_at cannot be zero")
	}

	return nil
}

// CanTransitionTo checks if the request can transition to the given status.
// Only pending requests can transition; terminal states cannot change.
//
// Valid transitions:
//   - pending -> approved
//   - pending -> denied
//   - pending -> expired
//   - pending -> cancelled
func (r *Request) CanTransitionTo(newStatus RequestStatus) bool {
	// Terminal states cannot transition
	if r.Status.IsTerminal() {
		return false
	}

	// Only pending can transition
	if r.Status != StatusPending {
		return false
	}

	// New status must be valid and terminal (transitions from pending always go to terminal)
	return newStatus.IsValid() && newStatus != StatusPending
}
