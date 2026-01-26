package logging

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/byteness/aws-vault/v7/iso8601"
)

// MinKeyLength is the minimum required length for HMAC-SHA256 secret keys.
// 32 bytes (256 bits) matches the SHA256 output size for optimal security.
const MinKeyLength = 32

// ErrKeyTooShort is returned when the secret key is shorter than MinKeyLength.
var ErrKeyTooShort = errors.New("secret key must be at least 32 bytes")

// SignatureConfig holds configuration for log signing.
type SignatureConfig struct {
	KeyID     string // Identifier for the signing key (for key rotation)
	SecretKey []byte // HMAC-SHA256 secret key (32 bytes recommended)
}

// Validate checks that the configuration is valid.
func (c *SignatureConfig) Validate() error {
	if len(c.SecretKey) < MinKeyLength {
		return ErrKeyTooShort
	}
	return nil
}

// SignedEntry wraps a log entry with its cryptographic signature.
// The signature covers the JSON representation of entry + timestamp + key_id.
// Entry is stored as json.RawMessage to preserve exact bytes for verification.
type SignedEntry struct {
	Entry     json.RawMessage `json:"entry"`     // The original log entry as raw JSON
	Signature string          `json:"signature"` // Hex-encoded HMAC-SHA256 signature
	KeyID     string          `json:"key_id"`    // Key identifier for verification
	Timestamp string          `json:"timestamp"` // ISO8601 timestamp when signed
}

// ComputeSignature computes HMAC-SHA256 of the entry's JSON representation.
// Returns hex-encoded signature string.
// The entry is JSON-marshaled before computing the HMAC to ensure deterministic input.
func ComputeSignature(entry any, secretKey []byte) (string, error) {
	if len(secretKey) < MinKeyLength {
		return "", ErrKeyTooShort
	}

	// Marshal entry to JSON for deterministic input
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(data)
	signature := mac.Sum(nil)

	// Return hex-encoded signature (32 bytes -> 64 chars)
	return hex.EncodeToString(signature), nil
}

// VerifySignature verifies the HMAC-SHA256 signature of an entry.
// Uses constant-time comparison to prevent timing attacks.
// Returns (true, nil) if signature is valid, (false, nil) if invalid,
// or (false, error) if there's a problem computing the expected signature.
func VerifySignature(entry any, signature string, secretKey []byte) (bool, error) {
	// Compute expected signature
	expected, err := ComputeSignature(entry, secretKey)
	if err != nil {
		return false, err
	}

	// Decode provided signature from hex
	providedBytes, err := hex.DecodeString(signature)
	if err != nil {
		// Invalid hex is treated as invalid signature, not error
		return false, nil
	}

	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		// This should never happen since we just computed it
		return false, err
	}

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(providedBytes, expectedBytes) == 1 {
		return true, nil
	}
	return false, nil
}

// NewSignedEntry creates a signed entry with current timestamp.
func NewSignedEntry(entry any, config *SignatureConfig) (*SignedEntry, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Marshal entry to JSON first - this is the canonical form we'll sign
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	timestamp := iso8601.Format(time.Now())

	// Create the signed entry with raw JSON
	signed := &SignedEntry{
		Entry:     entryJSON,
		KeyID:     config.KeyID,
		Timestamp: timestamp,
	}

	// Compute signature over the signable content
	signature, err := signed.computeSignature(config.SecretKey)
	if err != nil {
		return nil, err
	}

	signed.Signature = signature
	return signed, nil
}

// computeSignature computes the HMAC-SHA256 signature for this entry.
func (s *SignedEntry) computeSignature(secretKey []byte) (string, error) {
	// Create wrapper with entry, timestamp, and key_id
	wrapper := struct {
		Entry     json.RawMessage `json:"entry"`
		Timestamp string          `json:"timestamp"`
		KeyID     string          `json:"key_id"`
	}{
		Entry:     s.Entry,
		Timestamp: s.Timestamp,
		KeyID:     s.KeyID,
	}

	return ComputeSignature(wrapper, secretKey)
}

// Verify checks the signature of a SignedEntry.
// Returns (true, nil) if valid, (false, nil) if invalid, or (false, error) on error.
func (s *SignedEntry) Verify(secretKey []byte) (bool, error) {
	// Compute expected signature
	expected, err := s.computeSignature(secretKey)
	if err != nil {
		return false, err
	}

	// Decode provided signature from hex
	providedBytes, err := hex.DecodeString(s.Signature)
	if err != nil {
		// Invalid hex is treated as invalid signature, not error
		return false, nil
	}

	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		// This should never happen since we just computed it
		return false, err
	}

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(providedBytes, expectedBytes) == 1 {
		return true, nil
	}
	return false, nil
}

// GetEntry unmarshals the entry JSON into the provided destination.
// This is useful when you need to access the original entry data.
func (s *SignedEntry) GetEntry(dest any) error {
	return json.Unmarshal(s.Entry, dest)
}
