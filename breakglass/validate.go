package breakglass

import (
	"fmt"
)

// Validate checks if the BreakGlassEvent is semantically correct.
// It verifies all required fields are present and valid.
func (e *BreakGlassEvent) Validate() error {
	// Validate ID
	if !ValidateBreakGlassID(e.ID) {
		return fmt.Errorf("invalid break-glass ID: must be %d lowercase hex characters", BreakGlassIDLength)
	}

	// Validate invoker
	if e.Invoker == "" {
		return fmt.Errorf("invoker cannot be empty")
	}

	// Validate profile
	if e.Profile == "" {
		return fmt.Errorf("profile cannot be empty")
	}

	// Validate reason code
	if !e.ReasonCode.IsValid() {
		return fmt.Errorf("invalid reason code: %q", e.ReasonCode)
	}

	// Validate justification
	if len(e.Justification) < MinJustificationLength {
		return fmt.Errorf("justification too short: minimum %d characters", MinJustificationLength)
	}
	if len(e.Justification) > MaxJustificationLength {
		return fmt.Errorf("justification too long: maximum %d characters", MaxJustificationLength)
	}

	// Validate status
	if !e.Status.IsValid() {
		return fmt.Errorf("invalid status: %q", e.Status)
	}

	// Validate duration
	if e.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	if e.Duration > MaxDuration {
		return fmt.Errorf("duration exceeds maximum of %v", MaxDuration)
	}

	// Validate timestamps
	if e.CreatedAt.IsZero() {
		return fmt.Errorf("created_at cannot be zero")
	}
	if e.UpdatedAt.IsZero() {
		return fmt.Errorf("updated_at cannot be zero")
	}
	if e.ExpiresAt.IsZero() {
		return fmt.Errorf("expires_at cannot be zero")
	}

	return nil
}

// CanTransitionTo checks if the break-glass event can transition to the given status.
// Only active events can transition; terminal states cannot change.
//
// Valid transitions:
//   - active -> closed (by invoker or security)
//   - active -> expired (by TTL)
func (e *BreakGlassEvent) CanTransitionTo(newStatus BreakGlassStatus) bool {
	// Terminal states cannot transition
	if e.Status.IsTerminal() {
		return false
	}

	// Only active can transition
	if e.Status != StatusActive {
		return false
	}

	// New status must be valid and terminal (transitions from active always go to terminal)
	// Cannot transition to same status (active -> active is not allowed)
	return newStatus.IsValid() && newStatus != StatusActive
}
