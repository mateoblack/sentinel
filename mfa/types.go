// Package mfa provides multi-factor authentication verification for Sentinel.
// It defines the Verifier interface and types for TOTP and SMS-based MFA
// used during break-glass secondary verification.
//
// # MFA Challenge Flow
//
// 1. Challenge() initiates MFA verification (sends SMS or returns empty for TOTP)
// 2. User provides code (from authenticator app or SMS)
// 3. Verify() validates the code
//
// # Challenge ID Format
//
// Challenge IDs are 16-character lowercase hexadecimal strings (64 bits of entropy),
// matching the break-glass ID format for consistency.
package mfa

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"time"
)

const (
	// DefaultChallengeTTL is how long an MFA challenge remains valid.
	// 5 minutes is standard for SMS codes.
	DefaultChallengeTTL = 5 * time.Minute

	// CodeLength is the number of digits in MFA codes.
	CodeLength = 6

	// ChallengeIDLength is the exact length for challenge IDs (16 hex chars).
	ChallengeIDLength = 16
)

// MFAMethod represents the type of MFA verification.
type MFAMethod string

const (
	// MethodTOTP is Time-based One-Time Password (RFC 6238).
	MethodTOTP MFAMethod = "totp"
	// MethodSMS is SMS-delivered verification code.
	MethodSMS MFAMethod = "sms"
)

// IsValid returns true if the MFAMethod is a known value.
func (m MFAMethod) IsValid() bool {
	switch m {
	case MethodTOTP, MethodSMS:
		return true
	}
	return false
}

// String returns the string representation of the MFAMethod.
func (m MFAMethod) String() string {
	return string(m)
}

// MFAChallenge represents an MFA verification challenge.
// For TOTP, most fields are empty as verification is stateless.
// For SMS, contains the challenge ID and masked target for tracking.
type MFAChallenge struct {
	// ID is the unique challenge identifier (16 lowercase hex chars).
	// Empty for TOTP (stateless verification).
	ID string `json:"id,omitempty"`

	// Method is which MFA method was used.
	Method MFAMethod `json:"method"`

	// Target is the masked destination (e.g., "***-***-1234" for SMS).
	// Empty for TOTP.
	Target string `json:"target,omitempty"`

	// Code is the generated code (internal use only, not exposed in JSON).
	// Used by SMS verifier to store sent code for verification.
	Code string `json:"-"`

	// ExpiresAt is when the challenge expires.
	ExpiresAt time.Time `json:"expires_at"`

	// CreatedAt is when the challenge was created.
	CreatedAt time.Time `json:"created_at"`
}

// IsExpired returns true if the challenge has expired.
func (c *MFAChallenge) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// Verifier is the interface for MFA verification providers.
// Implementations include TOTP (authenticator apps) and SMS (text messages).
type Verifier interface {
	// Challenge initiates MFA verification for the given user.
	// For TOTP, returns empty challenge (user provides code from their app).
	// For SMS, sends code and returns challenge with ID for verification.
	Challenge(ctx context.Context, userID string) (*MFAChallenge, error)

	// Verify checks if the provided code is valid.
	// For TOTP, challengeID is ignored (stateless verification against user's secret).
	// For SMS, challengeID identifies the specific challenge being verified.
	// Returns (true, nil) on success, (false, nil) on invalid code,
	// (false, error) on system errors (e.g., user not found).
	Verify(ctx context.Context, challengeID string, code string) (bool, error)
}

// challengeIDRegex matches valid challenge IDs (16 lowercase hex chars).
var challengeIDRegex = regexp.MustCompile(`^[0-9a-f]{16}$`)

// NewChallengeID generates a new 16-character lowercase hex challenge ID.
// It uses crypto/rand for cryptographic randomness.
func NewChallengeID() string {
	// Generate 8 random bytes (64 bits of entropy)
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		// This should never happen with crypto/rand
		// Fall back to zeros rather than panic
		return "0000000000000000"
	}

	// Encode as 16-character lowercase hex string
	return hex.EncodeToString(bytes)
}

// ValidateChallengeID checks if the given string is a valid challenge ID.
// A valid challenge ID is exactly 16 lowercase hexadecimal characters.
func ValidateChallengeID(id string) bool {
	return challengeIDRegex.MatchString(id)
}
