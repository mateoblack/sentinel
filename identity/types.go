// Package identity provides types and functions for Sentinel's SourceIdentity
// stamping mechanism. SourceIdentity is stamped on AWS STS AssumeRole calls
// to make Sentinel's access decisions visible and enforceable inside AWS.
//
// # SourceIdentity Format
//
// The SourceIdentity format is: sentinel:<user>:<request-id>
//
// Components:
//   - "sentinel:" - Fixed prefix identifying Sentinel-issued credentials
//   - user - Sanitized username (alphanumeric only, max 20 chars)
//   - request-id - 8-character lowercase hex string (32 bits of entropy)
//
// Example: sentinel:alice:a1b2c3d4
//
// # AWS Constraints
//
// SourceIdentity in AWS has the following constraints:
//   - Maximum 64 characters total
//   - Allowed characters: alphanumeric and =,.@-
//   - Set once on AssumeRole, immutable for session lifetime
//   - Propagates through role chaining via session tags
//
// The format is designed to stay well under these limits:
//   - Prefix "sentinel:" = 9 chars
//   - User (max) = 20 chars
//   - Separator ":" = 1 char
//   - Request-ID = 8 chars
//   - Total max = 38 chars (well under 64)
package identity

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// Prefix is the fixed prefix for Sentinel SourceIdentity values.
	Prefix = "sentinel"

	// MaxUserLength is the maximum length for the user component.
	MaxUserLength = 20

	// RequestIDLength is the exact length for request-id (8 hex chars).
	RequestIDLength = 8

	// MaxSourceIdentityLength is AWS's maximum SourceIdentity length.
	MaxSourceIdentityLength = 64

	// separator is the delimiter between components.
	separator = ":"
)

var (
	// ErrEmptyUser indicates the user field is empty.
	ErrEmptyUser = errors.New("user cannot be empty")

	// ErrUserTooLong indicates the user exceeds MaxUserLength.
	ErrUserTooLong = errors.New("user exceeds maximum length of 20 characters")

	// ErrInvalidUserChars indicates the user contains non-alphanumeric characters.
	ErrInvalidUserChars = errors.New("user must contain only alphanumeric characters")

	// ErrInvalidRequestID indicates the request-id is not valid.
	ErrInvalidRequestID = errors.New("request-id must be exactly 8 lowercase hex characters")

	// ErrInvalidFormat indicates the SourceIdentity string format is invalid.
	ErrInvalidFormat = errors.New("invalid SourceIdentity format: expected sentinel:<user>:<request-id>")

	// ErrWrongPrefix indicates the SourceIdentity doesn't start with "sentinel:".
	ErrWrongPrefix = errors.New("SourceIdentity must start with 'sentinel:'")
)

// userRegex matches valid usernames (alphanumeric only).
var userRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

// requestIDRegex matches valid request-ids (8 lowercase hex chars).
var requestIDRegex = regexp.MustCompile(`^[0-9a-f]{8}$`)

// SourceIdentity represents a Sentinel-stamped identity for AWS STS.
// It contains the user who requested credentials and a unique request-id
// for correlation between Sentinel logs and CloudTrail events.
type SourceIdentity struct {
	// User is the sanitized username (alphanumeric, max 20 chars).
	User string

	// RequestID is the unique 8-character hex identifier for this request.
	RequestID string
}

// New creates a new SourceIdentity with the given user and request-id.
// It validates both fields before returning.
func New(user, requestID string) (*SourceIdentity, error) {
	si := &SourceIdentity{
		User:      user,
		RequestID: requestID,
	}

	if err := si.Validate(); err != nil {
		return nil, err
	}

	return si, nil
}

// Format returns the SourceIdentity as a string in the format:
// sentinel:<user>:<request-id>
func (si *SourceIdentity) Format() string {
	return fmt.Sprintf("%s%s%s%s%s", Prefix, separator, si.User, separator, si.RequestID)
}

// String returns the formatted SourceIdentity string.
// This implements the Stringer interface.
func (si *SourceIdentity) String() string {
	return si.Format()
}

// Validate checks if the SourceIdentity fields are valid.
// Returns nil if valid, or an error describing the validation failure.
func (si *SourceIdentity) Validate() error {
	// Validate user
	if si.User == "" {
		return ErrEmptyUser
	}
	if len(si.User) > MaxUserLength {
		return ErrUserTooLong
	}
	if !userRegex.MatchString(si.User) {
		return ErrInvalidUserChars
	}

	// Validate request-id
	if !ValidateRequestID(si.RequestID) {
		return ErrInvalidRequestID
	}

	return nil
}

// IsValid returns true if the SourceIdentity passes all validation checks.
func (si *SourceIdentity) IsValid() bool {
	return si.Validate() == nil
}

// Parse parses a SourceIdentity string into its components.
// Expected format: sentinel:<user>:<request-id>
func Parse(s string) (*SourceIdentity, error) {
	// Check prefix
	if !strings.HasPrefix(s, Prefix+separator) {
		return nil, ErrWrongPrefix
	}

	// Split into parts
	parts := strings.Split(s, separator)
	if len(parts) != 3 {
		return nil, ErrInvalidFormat
	}

	// parts[0] = "sentinel", parts[1] = user, parts[2] = request-id
	user := parts[1]
	requestID := parts[2]

	return New(user, requestID)
}

// SanitizeUser converts a username to a valid SourceIdentity user component.
// It removes non-alphanumeric characters and truncates to MaxUserLength.
// Returns an error if the result would be empty.
func SanitizeUser(username string) (string, error) {
	// Remove all non-alphanumeric characters
	var result strings.Builder
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			result.WriteRune(r)
		}
	}

	sanitized := result.String()

	// Truncate if necessary
	if len(sanitized) > MaxUserLength {
		sanitized = sanitized[:MaxUserLength]
	}

	// Check if result is valid
	if sanitized == "" {
		return "", ErrEmptyUser
	}

	return sanitized, nil
}
