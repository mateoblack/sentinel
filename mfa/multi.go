package mfa

import (
	"context"
	"errors"
)

// ErrNoVerifiersConfigured is returned when a MultiVerifier has no verifiers.
var ErrNoVerifiersConfigured = errors.New("no MFA verifiers configured")

// ErrNoChallengeIssued is returned when no verifier could issue a challenge.
var ErrNoChallengeIssued = errors.New("no verifier could issue challenge")

// MultiVerifier combines multiple MFA verifiers and tries them in order.
// For Challenge: tries first verifier that works for the user.
// For Verify: tries all verifiers until one succeeds.
type MultiVerifier struct {
	verifiers []Verifier
}

// NewMultiVerifier creates a MultiVerifier from the given verifiers.
// At least one verifier must be provided.
func NewMultiVerifier(verifiers ...Verifier) *MultiVerifier {
	return &MultiVerifier{verifiers: verifiers}
}

// Challenge initiates MFA verification for the given user.
// Tries each verifier in order until one successfully issues a challenge.
// Returns ErrUserNotFound if no verifier recognizes the user.
func (m *MultiVerifier) Challenge(ctx context.Context, userID string) (*MFAChallenge, error) {
	if len(m.verifiers) == 0 {
		return nil, ErrNoVerifiersConfigured
	}

	var lastErr error
	for _, v := range m.verifiers {
		challenge, err := v.Challenge(ctx, userID)
		if err == nil {
			return challenge, nil
		}
		// If it's a user not found error, try next verifier
		if errors.Is(err, ErrUserNotFound) {
			lastErr = err
			continue
		}
		// Other errors are returned immediately
		return nil, err
	}

	// All verifiers returned user not found
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoChallengeIssued
}

// Verify checks if the provided code is valid.
// For TOTP, challengeID is the userID (stateless verification).
// For SMS, challengeID identifies the specific challenge.
// Tries all verifiers - returns true if any verifier accepts the code.
func (m *MultiVerifier) Verify(ctx context.Context, challengeID string, code string) (bool, error) {
	if len(m.verifiers) == 0 {
		return false, ErrNoVerifiersConfigured
	}

	for _, v := range m.verifiers {
		valid, err := v.Verify(ctx, challengeID, code)
		if err == nil && valid {
			return true, nil
		}
		// Continue trying other verifiers on error or invalid
		// (TOTP returns ErrUserNotFound if user not in that verifier,
		// SMS returns error if challenge not found)
	}

	return false, nil
}

// VerifiersCount returns the number of configured verifiers.
// Useful for testing and debugging.
func (m *MultiVerifier) VerifiersCount() int {
	return len(m.verifiers)
}
