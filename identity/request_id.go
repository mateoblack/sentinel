package identity

import (
	"crypto/rand"
	"encoding/hex"
)

// NewRequestID generates a new 8-character lowercase hex request-id.
// It uses crypto/rand for cryptographic randomness.
//
// The request-id provides:
//   - Uniqueness per credential request
//   - Correlation between Sentinel logs and CloudTrail events
//   - No PII or sensitive data (just random identifier)
func NewRequestID() string {
	// Generate 4 random bytes (32 bits of entropy)
	bytes := make([]byte, 4)
	_, err := rand.Read(bytes)
	if err != nil {
		// This should never happen with crypto/rand
		// Fall back to zeros rather than panic
		return "00000000"
	}

	// Encode as 8-character lowercase hex string
	return hex.EncodeToString(bytes)
}

// ValidateRequestID checks if the given string is a valid request-id.
// A valid request-id is exactly 8 lowercase hexadecimal characters.
func ValidateRequestID(id string) bool {
	return requestIDRegex.MatchString(id)
}
