package audit

import (
	"context"
	"time"

	"github.com/byteness/aws-vault/v7/session"
)

// UntrackedSessionsInput contains the input for untracked session detection.
type UntrackedSessionsInput struct {
	// StartTime is the beginning of the time window to query.
	StartTime time.Time
	// EndTime is the end of the time window to query.
	EndTime time.Time
	// RoleARN optionally filters by a specific role ARN.
	RoleARN string
	// ProfileName optionally filters by profile (matched via SourceIdentity).
	ProfileName string
}

// UntrackedSession represents a CloudTrail event without a tracked session.
type UntrackedSession struct {
	// EventID is the CloudTrail event ID.
	EventID string `json:"event_id"`
	// EventTime is when the event occurred.
	EventTime time.Time `json:"event_time"`
	// RoleARN is the target role ARN.
	RoleARN string `json:"role_arn"`
	// PrincipalID is the principal ID of the caller.
	PrincipalID string `json:"principal_id"`
	// SourceIP is the source IP address of the caller.
	SourceIP string `json:"source_ip"`
	// UserAgent is the user agent string.
	UserAgent string `json:"user_agent"`
	// SourceIdentity is the SourceIdentity value (if any).
	SourceIdentity string `json:"source_identity,omitempty"`
	// Category indicates why this session is untracked.
	Category UntrackedCategory `json:"category"`
	// Reason is a human-readable explanation.
	Reason string `json:"reason"`
}

// UntrackedCategory indicates why a session is untracked.
type UntrackedCategory string

const (
	// CategoryNoSourceIdentity means no SourceIdentity was set on the AssumeRole call.
	CategoryNoSourceIdentity UntrackedCategory = "no_source_identity"
	// CategoryNonSentinel means SourceIdentity is not in Sentinel format.
	CategoryNonSentinel UntrackedCategory = "non_sentinel_format"
	// CategoryOrphaned means Sentinel SourceIdentity format but session not found in DynamoDB.
	CategoryOrphaned UntrackedCategory = "orphaned"
)

// UntrackedSessionsResult contains the results of untracked session detection.
type UntrackedSessionsResult struct {
	// StartTime is the query start time.
	StartTime time.Time `json:"start_time"`
	// EndTime is the query end time.
	EndTime time.Time `json:"end_time"`
	// TotalEvents is the total number of AssumeRole events examined.
	TotalEvents int `json:"total_events"`
	// TrackedEvents is the count of events with corresponding DynamoDB sessions.
	TrackedEvents int `json:"tracked_events"`
	// UntrackedEvents is the count of events that bypassed session tracking.
	UntrackedEvents int `json:"untracked_events"`
	// OrphanedEvents is the count of Sentinel-format sessions not found in DynamoDB.
	OrphanedEvents int `json:"orphaned_events"`
	// UntrackedSessions lists the untracked and orphaned sessions.
	UntrackedSessions []UntrackedSession `json:"untracked_sessions"`
}

// ComplianceRate returns the percentage of events that were properly tracked.
// Returns 100.0 if there are no events (no issues = success).
func (r *UntrackedSessionsResult) ComplianceRate() float64 {
	if r.TotalEvents == 0 {
		return 100.0
	}
	return float64(r.TrackedEvents) / float64(r.TotalEvents) * 100
}

// UntrackedSessionsDetector defines the interface for untracked session detection.
// Both Detector and TestDetector implement this interface.
type UntrackedSessionsDetector interface {
	Detect(ctx context.Context, input *UntrackedSessionsInput) (*UntrackedSessionsResult, error)
}

// sessionStore interface for DynamoDB session queries.
// This enables testing with mock implementations.
type sessionStore interface {
	GetBySourceIdentity(ctx context.Context, sourceIdentity string) (*session.ServerSession, error)
}
