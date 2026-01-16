package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// cloudtrailAPI defines the CloudTrail operations used by Verifier.
// This interface enables testing with mock implementations.
type cloudtrailAPI interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// Verifier queries CloudTrail and analyzes sessions for Sentinel enforcement.
type Verifier struct {
	client cloudtrailAPI
}

// NewVerifier creates a new Verifier using the provided AWS configuration.
func NewVerifier(cfg aws.Config) *Verifier {
	return &Verifier{
		client: cloudtrail.NewFromConfig(cfg),
	}
}

// newVerifierWithClient creates a Verifier with a custom client.
// This is primarily used for testing with mock clients.
func newVerifierWithClient(client cloudtrailAPI) *Verifier {
	return &Verifier{
		client: client,
	}
}

// Verify queries CloudTrail for sessions in the given time window and analyzes them
// for Sentinel enforcement. It identifies sessions with and without Sentinel SourceIdentity.
func (v *Verifier) Verify(ctx context.Context, input *VerifyInput) (*VerificationResult, error) {
	result := &VerificationResult{
		StartTime: input.StartTime,
		EndTime:   input.EndTime,
	}

	// Build lookup attributes for filtering
	var lookupAttributes []types.LookupAttribute
	if input.Username != "" {
		lookupAttributes = append(lookupAttributes, types.LookupAttribute{
			AttributeKey:   types.LookupAttributeKeyUsername,
			AttributeValue: aws.String(input.Username),
		})
	}

	// Paginate through all events
	var nextToken *string
	for {
		lookupInput := &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(input.StartTime),
			EndTime:   aws.Time(input.EndTime),
			NextToken: nextToken,
		}
		if len(lookupAttributes) > 0 {
			lookupInput.LookupAttributes = lookupAttributes
		}

		output, err := v.client.LookupEvents(ctx, lookupInput)
		if err != nil {
			return nil, fmt.Errorf("lookup events: %w", err)
		}

		// Process each event
		for _, event := range output.Events {
			sessionInfo, err := parseCloudTrailEvent(event)
			if err != nil {
				// Log parsing error but continue processing
				result.UnknownSessions++
				continue
			}

			// Skip if filtering by RoleARN and this event doesn't match
			if input.RoleARN != "" && sessionInfo.RoleARN != input.RoleARN {
				continue
			}

			result.TotalSessions++

			if sessionInfo.IsSentinel {
				result.SentinelSessions++
			} else {
				result.NonSentinelSessions++

				// Create an issue for non-Sentinel session
				issue := SessionIssue{
					Severity:    SeverityWarning,
					Type:        IssueTypeMissingSourceIdentity,
					SessionInfo: sessionInfo,
					Message:     fmt.Sprintf("Session without Sentinel SourceIdentity: %s (event: %s)", sessionInfo.Username, sessionInfo.EventName),
				}
				result.Issues = append(result.Issues, issue)
			}
		}

		// Check for more pages
		nextToken = output.NextToken
		if nextToken == nil {
			break
		}
	}

	return result, nil
}

// cloudTrailEventPayload represents the parsed JSON from CloudTrailEvent field.
type cloudTrailEventPayload struct {
	UserIdentity struct {
		SourceIdentity string `json:"sourceIdentity"`
		ARN            string `json:"arn"`
		Type           string `json:"type"`
		UserName       string `json:"userName"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	EventTime   string `json:"eventTime"`
	EventName   string `json:"eventName"`
	EventSource string `json:"eventSource"`
	EventID     string `json:"eventID"`
}

// parseCloudTrailEvent parses a CloudTrail event and extracts session information.
func parseCloudTrailEvent(event types.Event) (*SessionInfo, error) {
	info := &SessionInfo{}

	// Get EventID from the event object
	if event.EventId != nil {
		info.EventID = *event.EventId
	}

	// Get EventName from the event object
	if event.EventName != nil {
		info.EventName = *event.EventName
	}

	// Get EventSource from the event object
	if event.EventSource != nil {
		info.EventSource = *event.EventSource
	}

	// Get EventTime from the event object
	if event.EventTime != nil {
		info.EventTime = *event.EventTime
	}

	// Get Username from the event object
	if event.Username != nil {
		info.Username = *event.Username
	}

	// Parse the CloudTrailEvent JSON for additional details
	if event.CloudTrailEvent != nil {
		var payload cloudTrailEventPayload
		if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &payload); err != nil {
			return nil, fmt.Errorf("unmarshal cloudtrail event: %w", err)
		}

		// Extract SourceIdentity from userIdentity
		info.SourceIdentity = payload.UserIdentity.SourceIdentity

		// Extract RoleARN from sessionContext.sessionIssuer.arn
		if payload.UserIdentity.SessionContext.SessionIssuer.ARN != "" {
			info.RoleARN = payload.UserIdentity.SessionContext.SessionIssuer.ARN
		}

		// Fallback username from payload if not in event object
		if info.Username == "" && payload.UserIdentity.UserName != "" {
			info.Username = payload.UserIdentity.UserName
		}
	}

	// Parse SourceIdentity to determine if it's a Sentinel session
	user, requestID, isSentinel := ParseSourceIdentity(info.SourceIdentity)
	info.IsSentinel = isSentinel
	if isSentinel {
		info.User = user
		info.RequestID = requestID
	}

	return info, nil
}
