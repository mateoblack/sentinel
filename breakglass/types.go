// Package breakglass defines Sentinel's break-glass emergency access schema.
// Break-glass events represent emergency access bypasses where users invoke
// elevated privileges with mandatory justification and audit trail.
//
// # Break-Glass State Machine
//
// Valid state transitions:
//   - active -> closed (by invoker or security)
//   - active -> expired (by TTL)
//
// Terminal states (closed, expired) cannot transition.
// Unlike approval requests, break-glass events start active (no pending state).
//
// # Break-Glass ID Format
//
// Break-glass IDs are 16-character lowercase hexadecimal strings (64 bits of entropy),
// providing uniqueness and correlation across break-glass operations and CloudTrail.
package breakglass

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"time"
)

const (
	// DefaultBreakGlassTTL is how long break-glass access remains valid.
	// Shorter than approval requests - emergency access should be brief.
	DefaultBreakGlassTTL = 4 * time.Hour

	// MaxJustificationLength is the maximum length for justification text.
	// Longer than approval requests - incidents need detailed explanation.
	MaxJustificationLength = 1000

	// MinJustificationLength is the minimum length for justification text.
	// Requires meaningful explanation of the emergency.
	MinJustificationLength = 20

	// BreakGlassIDLength is the exact length for break-glass IDs (16 hex chars).
	BreakGlassIDLength = 16

	// MaxDuration is the maximum access duration for break-glass events.
	// Cap emergency access to limit exposure window.
	MaxDuration = 4 * time.Hour
)

// BreakGlassStatus represents the current state of a break-glass event.
// It can be active, closed, or expired.
type BreakGlassStatus string

const (
	// StatusActive indicates emergency access is currently in use.
	StatusActive BreakGlassStatus = "active"
	// StatusClosed indicates access was manually closed by invoker or security.
	StatusClosed BreakGlassStatus = "closed"
	// StatusExpired indicates access expired due to TTL elapsed.
	StatusExpired BreakGlassStatus = "expired"
)

// IsValid returns true if the BreakGlassStatus is a known value.
func (s BreakGlassStatus) IsValid() bool {
	switch s {
	case StatusActive, StatusClosed, StatusExpired:
		return true
	}
	return false
}

// String returns the string representation of the BreakGlassStatus.
func (s BreakGlassStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the status is a terminal state that cannot transition.
func (s BreakGlassStatus) IsTerminal() bool {
	switch s {
	case StatusClosed, StatusExpired:
		return true
	}
	return false
}

// ReasonCode represents predefined categories for break-glass justification.
// Users must select a reason code and provide detailed justification.
type ReasonCode string

const (
	// ReasonIncident indicates production incident response.
	ReasonIncident ReasonCode = "incident"
	// ReasonMaintenance indicates emergency maintenance.
	ReasonMaintenance ReasonCode = "maintenance"
	// ReasonSecurity indicates security incident response.
	ReasonSecurity ReasonCode = "security"
	// ReasonRecovery indicates disaster recovery.
	ReasonRecovery ReasonCode = "recovery"
	// ReasonOther indicates other reason (requires detailed justification).
	ReasonOther ReasonCode = "other"
)

// IsValid returns true if the ReasonCode is a known value.
func (r ReasonCode) IsValid() bool {
	switch r {
	case ReasonIncident, ReasonMaintenance, ReasonSecurity, ReasonRecovery, ReasonOther:
		return true
	}
	return false
}

// String returns the string representation of the ReasonCode.
func (r ReasonCode) String() string {
	return string(r)
}

// BreakGlassEvent represents an emergency access bypass event.
// It contains the invoker's information, why they invoked break-glass,
// and the current state of the emergency access.
type BreakGlassEvent struct {
	// ID is the unique break-glass identifier (16 lowercase hex chars).
	ID string `yaml:"id" json:"id"`

	// Invoker is the username who invoked break-glass.
	Invoker string `yaml:"invoker" json:"invoker"`

	// Profile is the AWS profile being accessed.
	Profile string `yaml:"profile" json:"profile"`

	// ReasonCode is the predefined category for the emergency.
	ReasonCode ReasonCode `yaml:"reason_code" json:"reason_code"`

	// Justification is the detailed explanation for the emergency access.
	Justification string `yaml:"justification" json:"justification"`

	// Duration is how long emergency access is requested for.
	Duration time.Duration `yaml:"duration" json:"duration"`

	// Status is the current state of the break-glass event.
	Status BreakGlassStatus `yaml:"status" json:"status"`

	// CreatedAt is when break-glass was invoked.
	CreatedAt time.Time `yaml:"created_at" json:"created_at"`

	// UpdatedAt is when the event was last modified.
	UpdatedAt time.Time `yaml:"updated_at" json:"updated_at"`

	// ExpiresAt is when emergency access expires.
	ExpiresAt time.Time `yaml:"expires_at" json:"expires_at"`

	// ClosedBy is who closed the break-glass event (empty if expired).
	ClosedBy string `yaml:"closed_by,omitempty" json:"closed_by,omitempty"`

	// ClosedReason is why it was closed early (empty if expired).
	ClosedReason string `yaml:"closed_reason,omitempty" json:"closed_reason,omitempty"`

	// RequestID is the Sentinel request ID for CloudTrail correlation.
	RequestID string `yaml:"request_id,omitempty" json:"request_id,omitempty"`
}

// breakGlassIDRegex matches valid break-glass IDs (16 lowercase hex chars).
var breakGlassIDRegex = regexp.MustCompile(`^[0-9a-f]{16}$`)

// NewBreakGlassID generates a new 16-character lowercase hex break-glass ID.
// It uses crypto/rand for cryptographic randomness.
//
// The break-glass ID provides:
//   - Uniqueness per break-glass event
//   - Correlation across break-glass operations
//   - CloudTrail audit trail linkage
//   - No PII or sensitive data (just random identifier)
func NewBreakGlassID() string {
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

// ValidateBreakGlassID checks if the given string is a valid break-glass ID.
// A valid break-glass ID is exactly 16 lowercase hexadecimal characters.
func ValidateBreakGlassID(id string) bool {
	return breakGlassIDRegex.MatchString(id)
}
