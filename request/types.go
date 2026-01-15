// Package request defines Sentinel's approval request schema.
// Requests represent user submissions for access to AWS profiles that require
// approval before credentials can be issued. Each request flows through a
// state machine from pending to terminal states (approved, denied, expired, cancelled).
//
// # Request State Machine
//
// Valid state transitions:
//   - pending -> approved (by approver)
//   - pending -> denied (by approver)
//   - pending -> expired (by TTL)
//   - pending -> cancelled (by requester)
//
// Terminal states (approved, denied, expired, cancelled) cannot transition.
//
// # Request ID Format
//
// Request IDs are 16-character lowercase hexadecimal strings (64 bits of entropy),
// providing uniqueness and correlation across approval workflow operations.
package request

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"time"
)

const (
	// DefaultRequestTTL is how long pending requests remain valid before expiring.
	DefaultRequestTTL = 24 * time.Hour

	// MaxJustificationLength is the maximum length for justification text.
	MaxJustificationLength = 500

	// MinJustificationLength is the minimum length for justification text.
	MinJustificationLength = 10

	// RequestIDLength is the exact length for request IDs (16 hex chars).
	RequestIDLength = 16

	// MaxDuration is the maximum access duration that can be requested.
	MaxDuration = 8 * time.Hour
)

// RequestStatus represents the current state of an approval request.
// It can be pending, approved, denied, expired, or cancelled.
type RequestStatus string

const (
	// StatusPending indicates the request is awaiting approval.
	StatusPending RequestStatus = "pending"
	// StatusApproved indicates the request was approved by an approver.
	StatusApproved RequestStatus = "approved"
	// StatusDenied indicates the request was denied by an approver.
	StatusDenied RequestStatus = "denied"
	// StatusExpired indicates the request expired before being actioned.
	StatusExpired RequestStatus = "expired"
	// StatusCancelled indicates the request was cancelled by the requester.
	StatusCancelled RequestStatus = "cancelled"
)

// IsValid returns true if the RequestStatus is a known value.
func (s RequestStatus) IsValid() bool {
	switch s {
	case StatusPending, StatusApproved, StatusDenied, StatusExpired, StatusCancelled:
		return true
	}
	return false
}

// String returns the string representation of the RequestStatus.
func (s RequestStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the status is a terminal state that cannot transition.
func (s RequestStatus) IsTerminal() bool {
	switch s {
	case StatusApproved, StatusDenied, StatusExpired, StatusCancelled:
		return true
	}
	return false
}

// Request represents an approval request for AWS profile access.
// It contains the requester's information, what they're requesting,
// why they need it, and the current state of the approval workflow.
type Request struct {
	// ID is the unique request identifier (16 lowercase hex chars).
	ID string `yaml:"id" json:"id"`

	// Requester is the username requesting access.
	Requester string `yaml:"requester" json:"requester"`

	// Profile is the AWS profile being requested.
	Profile string `yaml:"profile" json:"profile"`

	// Justification explains why access is needed.
	Justification string `yaml:"justification" json:"justification"`

	// Duration is how long access is requested for.
	Duration time.Duration `yaml:"duration" json:"duration"`

	// Status is the current state of the request (pending, approved, etc.).
	Status RequestStatus `yaml:"status" json:"status"`

	// CreatedAt is when the request was submitted.
	CreatedAt time.Time `yaml:"created_at" json:"created_at"`

	// UpdatedAt is when the request was last modified.
	UpdatedAt time.Time `yaml:"updated_at" json:"updated_at"`

	// ExpiresAt is when the pending request times out.
	ExpiresAt time.Time `yaml:"expires_at" json:"expires_at"`

	// Approver is who approved/denied the request (empty until actioned).
	Approver string `yaml:"approver,omitempty" json:"approver,omitempty"`

	// ApproverComment is an optional comment from the approver.
	ApproverComment string `yaml:"approver_comment,omitempty" json:"approver_comment,omitempty"`
}

// requestIDRegex matches valid request IDs (16 lowercase hex chars).
var requestIDRegex = regexp.MustCompile(`^[0-9a-f]{16}$`)

// NewRequestID generates a new 16-character lowercase hex request ID.
// It uses crypto/rand for cryptographic randomness.
//
// The request ID provides:
//   - Uniqueness per approval request
//   - Correlation across approval workflow operations
//   - No PII or sensitive data (just random identifier)
func NewRequestID() string {
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

// ValidateRequestID checks if the given string is a valid request ID.
// A valid request ID is exactly 16 lowercase hexadecimal characters.
func ValidateRequestID(id string) bool {
	return requestIDRegex.MatchString(id)
}
