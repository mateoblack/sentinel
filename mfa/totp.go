package mfa

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrUserNotFound is returned when a user is not found in the verifier config.
var ErrUserNotFound = errors.New("user not found")

// TOTPConfig holds configuration for a single user's TOTP verification.
type TOTPConfig struct {
	// Secret is the Base32-encoded shared secret.
	Secret string

	// Digits is the number of digits in the OTP (default 6).
	Digits int

	// Period is the time step in seconds (default 30).
	Period int

	// Skew is the number of adjacent time steps to accept (default 1 for clock drift).
	Skew int
}

// TOTPVerifier implements the Verifier interface using TOTP (RFC 6238).
// It validates time-based one-time passwords from authenticator apps.
type TOTPVerifier struct {
	secrets map[string]TOTPConfig // userID -> config
}

// NewTOTPVerifier creates a new TOTP verifier with the given secrets.
// The secrets map associates user IDs with their TOTP configuration.
func NewTOTPVerifier(secrets map[string]TOTPConfig) *TOTPVerifier {
	return &TOTPVerifier{
		secrets: secrets,
	}
}

// Challenge returns an empty challenge for TOTP.
// TOTP is stateless - the user provides a code from their authenticator app.
func (v *TOTPVerifier) Challenge(ctx context.Context, userID string) (*MFAChallenge, error) {
	// Check user exists
	if _, exists := v.secrets[userID]; !exists {
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}

	// TOTP challenges are empty - user provides code from their app
	return &MFAChallenge{
		Method:    MethodTOTP,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(DefaultChallengeTTL),
	}, nil
}

// Verify checks if the provided code is valid for the user.
// The challengeID is ignored for TOTP as verification is stateless.
// Returns (true, nil) on success, (false, nil) on invalid code,
// (false, ErrUserNotFound) if user is not found.
func (v *TOTPVerifier) Verify(ctx context.Context, challengeID string, code string) (bool, error) {
	// The challengeID for TOTP actually contains the userID since TOTP is stateless
	userID := challengeID

	config, exists := v.secrets[userID]
	if !exists {
		return false, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}

	// Apply defaults
	digits := config.Digits
	if digits == 0 {
		digits = CodeLength // 6
	}
	period := config.Period
	if period == 0 {
		period = 30
	}
	skew := config.Skew
	if skew == 0 {
		skew = 1
	}

	// Get current time counter
	now := time.Now().Unix()
	counter := uint64(now) / uint64(period)

	// Check current period and adjacent periods for clock skew
	for i := -skew; i <= skew; i++ {
		adjustedCounter := counter + uint64(i)
		if i < 0 {
			// Handle negative offset
			adjustedCounter = counter - uint64(-i)
		}

		expected := generateTOTP(config.Secret, adjustedCounter, digits)
		if expected == code {
			return true, nil
		}
	}

	return false, nil
}

// generateTOTP generates a TOTP code using HMAC-SHA1 per RFC 6238.
// secret is the Base32-encoded shared secret.
// counter is the time counter (current unix time / period).
// digits is the number of digits in the OTP.
func generateTOTP(secret string, counter uint64, digits int) string {
	// Decode Base32 secret (handle padding)
	secret = strings.ToUpper(strings.TrimSpace(secret))
	// Remove any padding and add back correct amount
	secret = strings.TrimRight(secret, "=")
	// Add padding if needed
	if mod := len(secret) % 8; mod != 0 {
		secret += strings.Repeat("=", 8-mod)
	}

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "" // Invalid secret
	}

	// Convert counter to 8-byte big-endian
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	// Compute HMAC-SHA1
	h := hmac.New(sha1.New, key)
	h.Write(counterBytes)
	hash := h.Sum(nil)

	// Dynamic truncation per RFC 4226
	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Format with leading zeros
	divisor := uint32(1)
	for i := 0; i < digits; i++ {
		divisor *= 10
	}

	return fmt.Sprintf("%0*d", digits, code%divisor)
}

// GenerateTOTPAtTime generates a TOTP code for a specific time.
// This is exported for testing purposes.
func GenerateTOTPAtTime(secret string, t time.Time, period int, digits int) string {
	if period == 0 {
		period = 30
	}
	if digits == 0 {
		digits = 6
	}
	counter := uint64(t.Unix()) / uint64(period)
	return generateTOTP(secret, counter, digits)
}
