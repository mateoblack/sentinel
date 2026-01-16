// Package audit provides types and functions for CloudTrail session verification.
// It enables querying CloudTrail to verify that AWS sessions have proper Sentinel
// SourceIdentity, detect missing enforcement, and identify potential bypasses.
package audit

import (
	"strings"
	"time"
)

// SessionInfo contains parsed information from a CloudTrail event.
// It represents the relevant details about an AWS session for verification purposes.
type SessionInfo struct {
	// SourceIdentity is the sts:SourceIdentity value (e.g., "sentinel:alice:a1b2c3d4")
	SourceIdentity string `json:"source_identity,omitempty"`
	// EventTime is when the event occurred
	EventTime time.Time `json:"event_time"`
	// EventID is the CloudTrail event ID
	EventID string `json:"event_id"`
	// EventName is the AWS API action (e.g., "AssumeRole")
	EventName string `json:"event_name"`
	// EventSource is the AWS service (e.g., "sts.amazonaws.com")
	EventSource string `json:"event_source"`
	// RoleARN is the target role ARN
	RoleARN string `json:"role_arn,omitempty"`
	// Username is the IAM username or principal
	Username string `json:"username,omitempty"`
	// IsSentinel is true if SourceIdentity starts with "sentinel:"
	IsSentinel bool `json:"is_sentinel"`
	// User is the parsed user from SourceIdentity (if Sentinel)
	User string `json:"user,omitempty"`
	// RequestID is the parsed request-id from SourceIdentity (if Sentinel)
	RequestID string `json:"request_id,omitempty"`
}

// VerificationResult contains the outcome of verifying sessions in a time window.
type VerificationResult struct {
	// StartTime is the query start time
	StartTime time.Time `json:"start_time"`
	// EndTime is the query end time
	EndTime time.Time `json:"end_time"`
	// TotalSessions is the total number of sessions examined
	TotalSessions int `json:"total_sessions"`
	// SentinelSessions is the count of sessions with valid Sentinel SourceIdentity
	SentinelSessions int `json:"sentinel_sessions"`
	// NonSentinelSessions is the count of sessions without Sentinel SourceIdentity
	NonSentinelSessions int `json:"non_sentinel_sessions"`
	// BreakGlassSessions is the count of sessions with break-glass markers (future use)
	BreakGlassSessions int `json:"break_glass_sessions"`
	// UnknownSessions is the count of sessions that couldn't be classified
	UnknownSessions int `json:"unknown_sessions"`
	// Issues lists problems found during verification
	Issues []SessionIssue `json:"issues,omitempty"`
}

// HasIssues returns true if any issues were found during verification.
func (r *VerificationResult) HasIssues() bool {
	return len(r.Issues) > 0
}

// PassRate returns the percentage of sessions with valid Sentinel SourceIdentity.
// Returns 100.0 if there are no sessions, 0.0 if all sessions are non-Sentinel.
func (r *VerificationResult) PassRate() float64 {
	if r.TotalSessions == 0 {
		return 100.0
	}
	return float64(r.SentinelSessions) / float64(r.TotalSessions) * 100.0
}

// SessionIssue represents a problem detected during verification.
type SessionIssue struct {
	// Severity indicates the issue severity ("warning" or "error")
	Severity IssueSeverity `json:"severity"`
	// Type indicates the issue type
	Type IssueType `json:"type"`
	// SessionInfo is the problematic session
	SessionInfo *SessionInfo `json:"session_info,omitempty"`
	// Message is a human-readable description
	Message string `json:"message"`
}

// IssueSeverity indicates the severity of a session issue.
type IssueSeverity string

const (
	// SeverityWarning indicates a non-critical issue that should be investigated
	SeverityWarning IssueSeverity = "warning"
	// SeverityError indicates a critical issue requiring immediate attention
	SeverityError IssueSeverity = "error"
)

// IsValid returns true if the IssueSeverity is a known value.
func (s IssueSeverity) IsValid() bool {
	return s == SeverityWarning || s == SeverityError
}

// String returns the string representation of the IssueSeverity.
func (s IssueSeverity) String() string {
	return string(s)
}

// IssueType indicates the type of issue detected during verification.
type IssueType string

const (
	// IssueTypeMissingSourceIdentity indicates a session without SourceIdentity
	IssueTypeMissingSourceIdentity IssueType = "missing_source_identity"
	// IssueTypeBypassDetected indicates a potential bypass of Sentinel enforcement
	IssueTypeBypassDetected IssueType = "bypass_detected"
	// IssueTypeUnexpectedSourceIdentity indicates a SourceIdentity that doesn't match Sentinel format
	IssueTypeUnexpectedSourceIdentity IssueType = "unexpected_source_identity"
)

// IsValid returns true if the IssueType is a known value.
func (t IssueType) IsValid() bool {
	return t == IssueTypeMissingSourceIdentity ||
		t == IssueTypeBypassDetected ||
		t == IssueTypeUnexpectedSourceIdentity
}

// String returns the string representation of the IssueType.
func (t IssueType) String() string {
	return string(t)
}

// VerifyInput contains parameters for session verification.
type VerifyInput struct {
	// StartTime is the beginning of the time window to query
	StartTime time.Time
	// EndTime is the end of the time window to query
	EndTime time.Time
	// RoleARN optionally filters by a specific role
	RoleARN string
	// Username optionally filters by a specific user
	Username string
}

// ParseSourceIdentity parses a SourceIdentity string into its components.
// Returns the user, requestID, and whether it's a valid Sentinel format.
//
// Sentinel SourceIdentity format: "sentinel:<user>:<request-id>"
// Example: "sentinel:alice:a1b2c3d4" -> ("alice", "a1b2c3d4", true)
//
// Non-Sentinel format returns empty strings and false.
func ParseSourceIdentity(sourceIdentity string) (user string, requestID string, isSentinel bool) {
	if sourceIdentity == "" {
		return "", "", false
	}

	// Must start with "sentinel:"
	if !strings.HasPrefix(sourceIdentity, "sentinel:") {
		return "", "", false
	}

	// Remove the "sentinel:" prefix
	remainder := strings.TrimPrefix(sourceIdentity, "sentinel:")

	// Split by ":" to get user and request-id
	parts := strings.SplitN(remainder, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	user = parts[0]
	requestID = parts[1]

	// Both user and requestID must be non-empty
	if user == "" || requestID == "" {
		return "", "", false
	}

	return user, requestID, true
}
