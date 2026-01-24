package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
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

// Detector implements UntrackedSessionsDetector using CloudTrail and DynamoDB.
type Detector struct {
	cloudtrail cloudtrailAPI
	sessions   sessionStore
}

// NewDetector creates a new Detector with CloudTrail and session store.
func NewDetector(cfg aws.Config, store sessionStore) *Detector {
	return &Detector{
		cloudtrail: cloudtrail.NewFromConfig(cfg),
		sessions:   store,
	}
}

// newDetectorWithClient creates a Detector with a custom CloudTrail client.
// This is primarily used for testing with mock clients.
func newDetectorWithClient(client cloudtrailAPI, store sessionStore) *Detector {
	return &Detector{
		cloudtrail: client,
		sessions:   store,
	}
}

// Detect finds untracked sessions by cross-referencing CloudTrail with DynamoDB.
func (d *Detector) Detect(ctx context.Context, input *UntrackedSessionsInput) (*UntrackedSessionsResult, error) {
	result := &UntrackedSessionsResult{
		StartTime:         input.StartTime,
		EndTime:           input.EndTime,
		UntrackedSessions: []UntrackedSession{},
	}

	// Query CloudTrail for AssumeRole events
	events, err := d.queryCloudTrail(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query CloudTrail: %w", err)
	}

	result.TotalEvents = len(events)

	// Cross-reference each event with session store
	for _, event := range events {
		sourceIdentity := extractSourceIdentityFromEvent(event)

		if sourceIdentity == "" {
			// No SourceIdentity - untracked
			result.UntrackedEvents++
			result.UntrackedSessions = append(result.UntrackedSessions, UntrackedSession{
				EventID:     aws.ToString(event.EventId),
				EventTime:   aws.ToTime(event.EventTime),
				RoleARN:     extractRoleARNFromEvent(event),
				PrincipalID: extractPrincipalIDFromEvent(event),
				SourceIP:    extractSourceIPFromEvent(event),
				UserAgent:   extractUserAgentFromEvent(event),
				Category:    CategoryNoSourceIdentity,
				Reason:      "No SourceIdentity set on AssumeRole call",
			})
			continue
		}

		// Check if SourceIdentity is in Sentinel format
		if !isSentinelSourceIdentity(sourceIdentity) {
			result.UntrackedEvents++
			result.UntrackedSessions = append(result.UntrackedSessions, UntrackedSession{
				EventID:        aws.ToString(event.EventId),
				EventTime:      aws.ToTime(event.EventTime),
				RoleARN:        extractRoleARNFromEvent(event),
				PrincipalID:    extractPrincipalIDFromEvent(event),
				SourceIP:       extractSourceIPFromEvent(event),
				UserAgent:      extractUserAgentFromEvent(event),
				SourceIdentity: sourceIdentity,
				Category:       CategoryNonSentinel,
				Reason:         "SourceIdentity not in Sentinel format",
			})
			continue
		}

		// Check if session exists in DynamoDB
		sess, err := d.sessions.GetBySourceIdentity(ctx, sourceIdentity)
		if err != nil || sess == nil {
			result.OrphanedEvents++
			result.UntrackedSessions = append(result.UntrackedSessions, UntrackedSession{
				EventID:        aws.ToString(event.EventId),
				EventTime:      aws.ToTime(event.EventTime),
				RoleARN:        extractRoleARNFromEvent(event),
				PrincipalID:    extractPrincipalIDFromEvent(event),
				SourceIP:       extractSourceIPFromEvent(event),
				UserAgent:      extractUserAgentFromEvent(event),
				SourceIdentity: sourceIdentity,
				Category:       CategoryOrphaned,
				Reason:         "Sentinel SourceIdentity but session not found (expired/deleted)",
			})
			continue
		}

		// Tracked session found
		result.TrackedEvents++
	}

	return result, nil
}

// queryCloudTrail queries CloudTrail for AssumeRole events in the time window.
func (d *Detector) queryCloudTrail(ctx context.Context, input *UntrackedSessionsInput) ([]types.Event, error) {
	var events []types.Event

	// Build lookup attributes for filtering
	lookupAttributes := []types.LookupAttribute{
		{
			AttributeKey:   types.LookupAttributeKeyEventName,
			AttributeValue: aws.String("AssumeRole"),
		},
	}

	// Paginate through all events
	var nextToken *string
	for {
		lookupInput := &cloudtrail.LookupEventsInput{
			StartTime:        aws.Time(input.StartTime),
			EndTime:          aws.Time(input.EndTime),
			LookupAttributes: lookupAttributes,
			NextToken:        nextToken,
		}

		output, err := d.cloudtrail.LookupEvents(ctx, lookupInput)
		if err != nil {
			return nil, fmt.Errorf("lookup events: %w", err)
		}

		// Filter by role ARN if specified
		for _, event := range output.Events {
			if input.RoleARN != "" {
				roleARN := extractRoleARNFromEvent(event)
				if roleARN != input.RoleARN {
					continue
				}
			}
			events = append(events, event)
		}

		// Check for more pages
		nextToken = output.NextToken
		if nextToken == nil {
			break
		}
	}

	return events, nil
}

// isSentinelSourceIdentity checks if a SourceIdentity matches Sentinel format.
// Sentinel format: sentinel:<user>:<marker>:<request-id>
// Where marker is either "direct" or an approval ID.
func isSentinelSourceIdentity(s string) bool {
	if !strings.HasPrefix(s, "sentinel:") {
		return false
	}
	// Parse the remaining parts
	remainder := strings.TrimPrefix(s, "sentinel:")
	parts := strings.Split(remainder, ":")
	// Valid formats have 2 parts (legacy) or 3 parts (new format)
	return len(parts) >= 2 && len(parts) <= 3
}

// cloudTrailEventPayloadForDetector represents the parsed JSON from CloudTrailEvent field.
type cloudTrailEventPayloadForDetector struct {
	UserIdentity struct {
		SourceIdentity string `json:"sourceIdentity"`
		ARN            string `json:"arn"`
		PrincipalID    string `json:"principalId"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	UserAgent       string `json:"userAgent"`
	SourceIPAddress string `json:"sourceIPAddress"`
}

// extractSourceIdentityFromEvent extracts the SourceIdentity from a CloudTrail event.
func extractSourceIdentityFromEvent(event types.Event) string {
	if event.CloudTrailEvent == nil {
		return ""
	}
	var payload cloudTrailEventPayloadForDetector
	if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &payload); err != nil {
		return ""
	}
	return payload.UserIdentity.SourceIdentity
}

// extractRoleARNFromEvent extracts the role ARN from a CloudTrail event.
func extractRoleARNFromEvent(event types.Event) string {
	if event.CloudTrailEvent == nil {
		return ""
	}
	var payload cloudTrailEventPayloadForDetector
	if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &payload); err != nil {
		return ""
	}
	return payload.UserIdentity.SessionContext.SessionIssuer.ARN
}

// extractPrincipalIDFromEvent extracts the principal ID from a CloudTrail event.
func extractPrincipalIDFromEvent(event types.Event) string {
	if event.CloudTrailEvent == nil {
		return ""
	}
	var payload cloudTrailEventPayloadForDetector
	if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &payload); err != nil {
		return ""
	}
	return payload.UserIdentity.PrincipalID
}

// extractUserAgentFromEvent extracts the user agent from a CloudTrail event.
func extractUserAgentFromEvent(event types.Event) string {
	if event.CloudTrailEvent == nil {
		return ""
	}
	var payload cloudTrailEventPayloadForDetector
	if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &payload); err != nil {
		return ""
	}
	return payload.UserAgent
}

// extractSourceIPFromEvent extracts the source IP address from a CloudTrail event.
func extractSourceIPFromEvent(event types.Event) string {
	if event.CloudTrailEvent == nil {
		return ""
	}
	var payload cloudTrailEventPayloadForDetector
	if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &payload); err != nil {
		return ""
	}
	return payload.SourceIPAddress
}

// DetectFunc is a function type for custom detect implementations (used for testing).
type DetectFunc func(ctx context.Context, input *UntrackedSessionsInput) (*UntrackedSessionsResult, error)

// TestDetector wraps a DetectFunc for testing purposes.
// Use NewDetectorForTest to create instances.
type TestDetector struct {
	detectFunc DetectFunc
}

// NewDetectorForTest creates a TestDetector that uses a custom detect function.
// This is used for testing CLI commands without actual AWS calls.
func NewDetectorForTest(fn DetectFunc) *TestDetector {
	return &TestDetector{
		detectFunc: fn,
	}
}

// Detect calls the custom detect function.
func (d *TestDetector) Detect(ctx context.Context, input *UntrackedSessionsInput) (*UntrackedSessionsResult, error) {
	return d.detectFunc(ctx, input)
}
