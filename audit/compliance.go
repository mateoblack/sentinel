package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/session"
)

// SessionComplianceInput contains the input for compliance reporting.
type SessionComplianceInput struct {
	StartTime   time.Time
	EndTime     time.Time
	ProfileName string // Optional: specific profile to check
	PolicyPath  string // Optional: policy file for requirement checking
}

// ProfileCompliance represents compliance metrics for a single profile.
type ProfileCompliance struct {
	Profile        string  `json:"profile"`
	PolicyRequired bool    `json:"policy_required"` // Does policy require session tracking?
	TrackedCount   int     `json:"tracked_count"`
	UntrackedCount int     `json:"untracked_count"`
	ComplianceRate float64 `json:"compliance_rate"`
	HasGap         bool    `json:"has_gap"` // PolicyRequired && UntrackedCount > 0
}

// SessionComplianceResult contains the full compliance report.
type SessionComplianceResult struct {
	StartTime              time.Time           `json:"start_time"`
	EndTime                time.Time           `json:"end_time"`
	Profiles               []ProfileCompliance `json:"profiles"`
	RequiredProfiles       int                 `json:"required_profiles"`        // Profiles with require_server_session
	FullyCompliantProfiles int                 `json:"fully_compliant_profiles"` // Required profiles with 100% tracking
	ProfilesWithGaps       int                 `json:"profiles_with_gaps"`       // Required profiles with untracked access
}

// HasComplianceGaps returns true if any required profile has untracked sessions.
func (r *SessionComplianceResult) HasComplianceGaps() bool {
	return r.ProfilesWithGaps > 0
}

// ComplianceReporter generates session compliance reports.
type ComplianceReporter interface {
	Report(ctx context.Context, input *SessionComplianceInput) (*SessionComplianceResult, error)
}

// complianceSessionStore interface for session queries used by compliance reporting.
type complianceSessionStore interface {
	GetBySourceIdentity(ctx context.Context, sourceIdentity string) (*session.ServerSession, error)
}

// Reporter implements ComplianceReporter.
type Reporter struct {
	cloudtrail cloudtrailAPI
	sessions   complianceSessionStore
	policy     *policy.Policy // Optional: for checking requirements
}

// NewReporter creates a new compliance Reporter.
func NewReporter(cfg aws.Config, store complianceSessionStore, pol *policy.Policy) *Reporter {
	return &Reporter{
		cloudtrail: cloudtrail.NewFromConfig(cfg),
		sessions:   store,
		policy:     pol,
	}
}

// newReporterWithClient creates a Reporter with a custom CloudTrail client (for testing).
func newReporterWithClient(client cloudtrailAPI, store complianceSessionStore, pol *policy.Policy) *Reporter {
	return &Reporter{
		cloudtrail: client,
		sessions:   store,
		policy:     pol,
	}
}

// Report generates a compliance report for session tracking.
func (r *Reporter) Report(ctx context.Context, input *SessionComplianceInput) (*SessionComplianceResult, error) {
	result := &SessionComplianceResult{
		StartTime: input.StartTime,
		EndTime:   input.EndTime,
		Profiles:  []ProfileCompliance{},
	}

	// Query CloudTrail for AssumeRole events in time window
	events, err := r.queryCloudTrailEvents(ctx, input.StartTime, input.EndTime)
	if err != nil {
		return nil, fmt.Errorf("failed to query CloudTrail: %w", err)
	}

	// Group events by profile (extracted from role ARN or SourceIdentity)
	profileEvents := r.groupEventsByProfile(ctx, events)

	// Build profile list, optionally filtered to single profile
	profiles := getProfileListForCompliance(profileEvents, input.ProfileName)

	// Calculate compliance for each profile
	for _, profileName := range profiles {
		evts := profileEvents[profileName]

		// Check if policy requires session tracking for this profile
		policyRequired := r.profileRequiresTracking(profileName)

		// Count tracked vs untracked events
		tracked, untracked := r.countTrackedEvents(ctx, evts)

		complianceRate := 100.0
		total := tracked + untracked
		if total > 0 {
			complianceRate = float64(tracked) / float64(total) * 100
		}

		pc := ProfileCompliance{
			Profile:        profileName,
			PolicyRequired: policyRequired,
			TrackedCount:   tracked,
			UntrackedCount: untracked,
			ComplianceRate: complianceRate,
			HasGap:         policyRequired && untracked > 0,
		}

		result.Profiles = append(result.Profiles, pc)

		// Update summary counts
		if policyRequired {
			result.RequiredProfiles++
			if untracked == 0 {
				result.FullyCompliantProfiles++
			} else {
				result.ProfilesWithGaps++
			}
		}
	}

	return result, nil
}

// queryCloudTrailEvents queries CloudTrail for AssumeRole events in the time window.
func (r *Reporter) queryCloudTrailEvents(ctx context.Context, startTime, endTime time.Time) ([]types.Event, error) {
	var events []types.Event

	// Build lookup attributes for AssumeRole filtering
	lookupAttributes := []types.LookupAttribute{
		{
			AttributeKey:   types.LookupAttributeKeyEventName,
			AttributeValue: aws.String("AssumeRole"),
		},
	}

	// Paginate through all events
	var nextToken *string
	for {
		output, err := r.cloudtrail.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime:        aws.Time(startTime),
			EndTime:          aws.Time(endTime),
			LookupAttributes: lookupAttributes,
			NextToken:        nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("lookup events: %w", err)
		}

		events = append(events, output.Events...)

		nextToken = output.NextToken
		if nextToken == nil {
			break
		}
	}

	return events, nil
}

// groupEventsByProfile groups CloudTrail events by the AWS profile.
func (r *Reporter) groupEventsByProfile(ctx context.Context, events []types.Event) map[string][]types.Event {
	result := make(map[string][]types.Event)

	for _, event := range events {
		profileName := r.extractProfileFromEvent(ctx, event)
		result[profileName] = append(result[profileName], event)
	}

	return result
}

// extractProfileFromEvent extracts the AWS profile name from a CloudTrail event.
// First tries SourceIdentity (if Sentinel format), then falls back to role name.
func (r *Reporter) extractProfileFromEvent(ctx context.Context, event types.Event) string {
	// Try to extract profile from SourceIdentity via session lookup
	sourceIdentity := extractSourceIdentityFromEvent(event)
	if isSentinelSourceIdentity(sourceIdentity) {
		// Look up the session to get the profile
		sess, err := r.sessions.GetBySourceIdentity(ctx, sourceIdentity)
		if err == nil && sess != nil {
			return sess.Profile
		}
	}

	// Fall back to extracting role name from the assumed role ARN
	roleARN := extractRoleARNFromEvent(event)
	if roleARN != "" {
		// arn:aws:iam::123456789012:role/role-name -> role-name
		return extractRoleNameFromARN(roleARN)
	}

	return "unknown"
}

// cloudTrailEventPayloadForCompliance represents the parsed JSON for request params.
type cloudTrailEventPayloadForCompliance struct {
	RequestParameters struct {
		RoleARN string `json:"roleArn"`
	} `json:"requestParameters"`
	UserIdentity struct {
		SourceIdentity string `json:"sourceIdentity"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
}

// extractRoleNameFromARN extracts the role name from a role ARN.
func extractRoleNameFromARN(roleARN string) string {
	// arn:aws:iam::123456789012:role/role-name -> role-name
	for i := len(roleARN) - 1; i >= 0; i-- {
		if roleARN[i] == '/' {
			return roleARN[i+1:]
		}
	}
	return roleARN
}

// extractRequestedRoleARN extracts the role ARN being assumed from requestParameters.
func extractRequestedRoleARN(event types.Event) string {
	if event.CloudTrailEvent == nil {
		return ""
	}
	var payload cloudTrailEventPayloadForCompliance
	if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &payload); err != nil {
		return ""
	}
	return payload.RequestParameters.RoleARN
}

// getProfileListForCompliance returns a sorted list of profiles to report on.
func getProfileListForCompliance(profileEvents map[string][]types.Event, filterProfile string) []string {
	if filterProfile != "" {
		return []string{filterProfile}
	}

	profiles := make([]string, 0, len(profileEvents))
	for p := range profileEvents {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)
	return profiles
}

// profileRequiresTracking checks if policy requires session tracking for a profile.
func (r *Reporter) profileRequiresTracking(profile string) bool {
	if r.policy == nil {
		return false // No policy loaded, can't determine requirement
	}

	// Evaluate policy for this profile (minimal request)
	req := policy.Request{
		Profile:          profile,
		Mode:             policy.ModeServer, // Check server mode rule
		SessionTableName: "",                // No session table to trigger requirement check
		Time:             time.Now(),
	}

	decision := policy.Evaluate(r.policy, &req)
	return decision.Effect == policy.EffectRequireServerSession ||
		decision.RequiresSessionTracking
}

// countTrackedEvents counts tracked vs untracked events for a profile.
func (r *Reporter) countTrackedEvents(ctx context.Context, events []types.Event) (tracked, untracked int) {
	for _, event := range events {
		sourceIdentity := extractSourceIdentityFromEvent(event)

		if sourceIdentity == "" || !isSentinelSourceIdentity(sourceIdentity) {
			untracked++
			continue
		}

		// Check if session exists in DynamoDB
		sess, _ := r.sessions.GetBySourceIdentity(ctx, sourceIdentity)
		if sess != nil {
			tracked++
		} else {
			untracked++ // Orphaned counts as untracked for compliance
		}
	}
	return
}

// LoadPolicyFile loads a policy from a file path.
func LoadPolicyFile(path string) (*policy.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return policy.ParsePolicy(data)
}

// ComplianceReportFunc is a function type for custom report implementations (used for testing).
type ComplianceReportFunc func(ctx context.Context, input *SessionComplianceInput) (*SessionComplianceResult, error)

// TestReporter wraps a ComplianceReportFunc for testing purposes.
type TestReporter struct {
	reportFunc ComplianceReportFunc
}

// NewReporterForTest creates a TestReporter that uses a custom report function.
func NewReporterForTest(fn ComplianceReportFunc) *TestReporter {
	return &TestReporter{
		reportFunc: fn,
	}
}

// Report calls the custom report function.
func (r *TestReporter) Report(ctx context.Context, input *SessionComplianceInput) (*SessionComplianceResult, error) {
	return r.reportFunc(ctx, input)
}
