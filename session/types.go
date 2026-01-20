// Package session defines Sentinel's server session tracking schema.
// Server sessions track active credential-serving instances in server mode,
// enabling visibility, monitoring, and revocation of ongoing credential sessions.
//
// # Session State Machine
//
// Valid state transitions:
//   - active -> revoked (by admin or security)
//   - active -> expired (by TTL)
//
// Terminal states (revoked, expired) cannot transition.
// Sessions start active when the server begins serving credentials.
//
// # Session ID Format
//
// Session IDs are 16-character lowercase hexadecimal strings (64 bits of entropy),
// providing uniqueness and correlation across session operations.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"time"
)

const (
	// SessionIDLength is the exact length for session IDs (16 hex chars).
	SessionIDLength = 16

	// DefaultSessionTTL is the cleanup buffer beyond credential expiry.
	// Sessions are kept for this duration to allow for auditing and review.
	DefaultSessionTTL = 1 * time.Hour
)

// SessionStatus represents the current state of a server session.
// It can be active, revoked, or expired.
type SessionStatus string

const (
	// StatusActive indicates the session is active and credentials are being served.
	StatusActive SessionStatus = "active"
	// StatusRevoked indicates the session was manually revoked by admin or security.
	StatusRevoked SessionStatus = "revoked"
	// StatusExpired indicates the session expired (TTL elapsed).
	StatusExpired SessionStatus = "expired"
)

// IsValid returns true if the SessionStatus is a known value.
func (s SessionStatus) IsValid() bool {
	switch s {
	case StatusActive, StatusRevoked, StatusExpired:
		return true
	}
	return false
}

// String returns the string representation of the SessionStatus.
func (s SessionStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the status is a terminal state that cannot transition.
func (s SessionStatus) IsTerminal() bool {
	switch s {
	case StatusRevoked, StatusExpired:
		return true
	}
	return false
}

// ServerSession represents an active server-mode credential session.
// It tracks who started the session, what profile is being served,
// and the current state of the session.
type ServerSession struct {
	// ID is the unique session identifier (16 lowercase hex chars).
	ID string `yaml:"id" json:"id"`

	// User is the AWS identity who started the session.
	User string `yaml:"user" json:"user"`

	// Profile is the AWS profile being served.
	Profile string `yaml:"profile" json:"profile"`

	// ServerInstanceID is a unique ID for this server instance.
	// Useful for multi-server scenarios to identify which server is serving.
	ServerInstanceID string `yaml:"server_instance_id" json:"server_instance_id"`

	// Status is the current state of the session.
	Status SessionStatus `yaml:"status" json:"status"`

	// StartedAt is when the server started serving credentials.
	StartedAt time.Time `yaml:"started_at" json:"started_at"`

	// LastAccessAt is when the last credential request was served.
	LastAccessAt time.Time `yaml:"last_access_at" json:"last_access_at"`

	// ExpiresAt is when the session auto-expires.
	ExpiresAt time.Time `yaml:"expires_at" json:"expires_at"`

	// RequestCount is the number of credential requests served.
	RequestCount int64 `yaml:"request_count" json:"request_count"`

	// SourceIdentity is the SourceIdentity being used for correlation.
	SourceIdentity string `yaml:"source_identity" json:"source_identity"`

	// CreatedAt is when the session record was created.
	CreatedAt time.Time `yaml:"created_at" json:"created_at"`

	// UpdatedAt is when the session was last modified.
	UpdatedAt time.Time `yaml:"updated_at" json:"updated_at"`

	// RevokedBy is who revoked the session (empty if not revoked).
	RevokedBy string `yaml:"revoked_by,omitempty" json:"revoked_by,omitempty"`

	// RevokedReason is why the session was revoked (empty if not revoked).
	RevokedReason string `yaml:"revoked_reason,omitempty" json:"revoked_reason,omitempty"`
}

// sessionIDRegex matches valid session IDs (16 lowercase hex chars).
var sessionIDRegex = regexp.MustCompile(`^[0-9a-f]{16}$`)

// NewSessionID generates a new 16-character lowercase hex session ID.
// It uses crypto/rand for cryptographic randomness.
//
// The session ID provides:
//   - Uniqueness per session
//   - Correlation across session operations
//   - No PII or sensitive data (just random identifier)
func NewSessionID() string {
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

// ValidateSessionID checks if the given string is a valid session ID.
// A valid session ID is exactly 16 lowercase hexadecimal characters.
func ValidateSessionID(id string) bool {
	return sessionIDRegex.MatchString(id)
}
