package audit

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// mockCloudTrailClient implements cloudtrailAPI for testing.
type mockCloudTrailClient struct {
	lookupEventsFunc func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

func (m *mockCloudTrailClient) LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	if m.lookupEventsFunc != nil {
		return m.lookupEventsFunc(ctx, params, optFns...)
	}
	return &cloudtrail.LookupEventsOutput{}, nil
}

func TestVerifier_Verify_WithSentinelSessions(t *testing.T) {
	now := time.Now()
	eventTime := now.Add(-30 * time.Minute)

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						EventId:     aws.String("event-1"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("alice"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sourceIdentity": "sentinel:alice:abc12345",
								"sessionContext": {
									"sessionIssuer": {
										"arn": "arn:aws:iam::123456789012:role/TestRole"
									}
								}
							},
							"eventName": "AssumeRole",
							"eventSource": "sts.amazonaws.com"
						}`),
					},
					{
						EventId:     aws.String("event-2"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("bob"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sourceIdentity": "sentinel:bob:def67890",
								"sessionContext": {
									"sessionIssuer": {
										"arn": "arn:aws:iam::123456789012:role/TestRole"
									}
								}
							},
							"eventName": "AssumeRole",
							"eventSource": "sts.amazonaws.com"
						}`),
					},
				},
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.TotalSessions != 2 {
		t.Errorf("TotalSessions = %d, want 2", result.TotalSessions)
	}
	if result.SentinelSessions != 2 {
		t.Errorf("SentinelSessions = %d, want 2", result.SentinelSessions)
	}
	if result.NonSentinelSessions != 0 {
		t.Errorf("NonSentinelSessions = %d, want 0", result.NonSentinelSessions)
	}
	if result.HasIssues() {
		t.Errorf("HasIssues() = true, want false")
	}
	if result.PassRate() != 100.0 {
		t.Errorf("PassRate() = %f, want 100.0", result.PassRate())
	}
}

func TestVerifier_Verify_WithNonSentinelSessions(t *testing.T) {
	now := time.Now()
	eventTime := now.Add(-30 * time.Minute)

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						EventId:     aws.String("event-1"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("attacker"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sessionContext": {
									"sessionIssuer": {
										"arn": "arn:aws:iam::123456789012:role/TestRole"
									}
								}
							},
							"eventName": "AssumeRole",
							"eventSource": "sts.amazonaws.com"
						}`),
					},
				},
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.TotalSessions != 1 {
		t.Errorf("TotalSessions = %d, want 1", result.TotalSessions)
	}
	if result.SentinelSessions != 0 {
		t.Errorf("SentinelSessions = %d, want 0", result.SentinelSessions)
	}
	if result.NonSentinelSessions != 1 {
		t.Errorf("NonSentinelSessions = %d, want 1", result.NonSentinelSessions)
	}
	if !result.HasIssues() {
		t.Errorf("HasIssues() = false, want true")
	}
	if len(result.Issues) != 1 {
		t.Errorf("len(Issues) = %d, want 1", len(result.Issues))
	}
	if result.Issues[0].Type != IssueTypeMissingSourceIdentity {
		t.Errorf("Issue.Type = %q, want %q", result.Issues[0].Type, IssueTypeMissingSourceIdentity)
	}
	if result.PassRate() != 0.0 {
		t.Errorf("PassRate() = %f, want 0.0", result.PassRate())
	}
}

func TestVerifier_Verify_MixedSessions(t *testing.T) {
	now := time.Now()
	eventTime := now.Add(-30 * time.Minute)

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						EventId:     aws.String("event-1"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("alice"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sourceIdentity": "sentinel:alice:abc12345"
							}
						}`),
					},
					{
						EventId:     aws.String("event-2"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("bob"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {}
						}`),
					},
					{
						EventId:     aws.String("event-3"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("carol"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sourceIdentity": "sentinel:carol:def67890"
							}
						}`),
					},
					{
						EventId:     aws.String("event-4"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("dave"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sourceIdentity": "other:format:xyz"
							}
						}`),
					},
				},
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.TotalSessions != 4 {
		t.Errorf("TotalSessions = %d, want 4", result.TotalSessions)
	}
	if result.SentinelSessions != 2 {
		t.Errorf("SentinelSessions = %d, want 2", result.SentinelSessions)
	}
	if result.NonSentinelSessions != 2 {
		t.Errorf("NonSentinelSessions = %d, want 2", result.NonSentinelSessions)
	}
	if len(result.Issues) != 2 {
		t.Errorf("len(Issues) = %d, want 2", len(result.Issues))
	}
	if result.PassRate() != 50.0 {
		t.Errorf("PassRate() = %f, want 50.0", result.PassRate())
	}
}

func TestVerifier_Verify_Pagination(t *testing.T) {
	now := time.Now()
	eventTime := now.Add(-30 * time.Minute)
	callCount := 0

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			callCount++
			if callCount == 1 {
				// First page
				return &cloudtrail.LookupEventsOutput{
					Events: []types.Event{
						{
							EventId:     aws.String("event-1"),
							EventName:   aws.String("AssumeRole"),
							EventSource: aws.String("sts.amazonaws.com"),
							EventTime:   aws.Time(eventTime),
							Username:    aws.String("alice"),
							CloudTrailEvent: aws.String(`{
								"userIdentity": {
									"sourceIdentity": "sentinel:alice:abc12345"
								}
							}`),
						},
					},
					NextToken: aws.String("page2"),
				}, nil
			}
			// Second page (no more pages)
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						EventId:     aws.String("event-2"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("bob"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sourceIdentity": "sentinel:bob:def67890"
							}
						}`),
					},
				},
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if callCount != 2 {
		t.Errorf("API call count = %d, want 2", callCount)
	}
	if result.TotalSessions != 2 {
		t.Errorf("TotalSessions = %d, want 2", result.TotalSessions)
	}
	if result.SentinelSessions != 2 {
		t.Errorf("SentinelSessions = %d, want 2", result.SentinelSessions)
	}
}

func TestVerifier_Verify_FilterByUsername(t *testing.T) {
	now := time.Now()
	var capturedInput *cloudtrail.LookupEventsInput

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			capturedInput = params
			return &cloudtrail.LookupEventsOutput{}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	_, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
		Username:  "alice",
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if capturedInput == nil {
		t.Fatal("capturedInput is nil")
	}
	if len(capturedInput.LookupAttributes) != 1 {
		t.Errorf("len(LookupAttributes) = %d, want 1", len(capturedInput.LookupAttributes))
	}
	if capturedInput.LookupAttributes[0].AttributeKey != types.LookupAttributeKeyUsername {
		t.Errorf("AttributeKey = %q, want Username", capturedInput.LookupAttributes[0].AttributeKey)
	}
	if *capturedInput.LookupAttributes[0].AttributeValue != "alice" {
		t.Errorf("AttributeValue = %q, want alice", *capturedInput.LookupAttributes[0].AttributeValue)
	}
}

func TestVerifier_Verify_FilterByRoleARN(t *testing.T) {
	now := time.Now()
	eventTime := now.Add(-30 * time.Minute)
	targetRoleARN := "arn:aws:iam::123456789012:role/TargetRole"

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						EventId:     aws.String("event-1"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("alice"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sourceIdentity": "sentinel:alice:abc12345",
								"sessionContext": {
									"sessionIssuer": {
										"arn": "arn:aws:iam::123456789012:role/TargetRole"
									}
								}
							}
						}`),
					},
					{
						EventId:     aws.String("event-2"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("bob"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sourceIdentity": "sentinel:bob:def67890",
								"sessionContext": {
									"sessionIssuer": {
										"arn": "arn:aws:iam::123456789012:role/OtherRole"
									}
								}
							}
						}`),
					},
				},
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
		RoleARN:   targetRoleARN,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	// Should only count the event matching the target role
	if result.TotalSessions != 1 {
		t.Errorf("TotalSessions = %d, want 1", result.TotalSessions)
	}
	if result.SentinelSessions != 1 {
		t.Errorf("SentinelSessions = %d, want 1", result.SentinelSessions)
	}
}

func TestParseCloudTrailEvent(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name            string
		event           types.Event
		wantIsSentinel  bool
		wantUser        string
		wantRequestID   string
		wantRoleARN     string
		wantErrContains string
	}{
		{
			name: "sentinel session with full details",
			event: types.Event{
				EventId:     aws.String("event-123"),
				EventName:   aws.String("AssumeRole"),
				EventSource: aws.String("sts.amazonaws.com"),
				EventTime:   aws.Time(now),
				Username:    aws.String("alice"),
				CloudTrailEvent: aws.String(`{
					"userIdentity": {
						"sourceIdentity": "sentinel:alice:abc12345",
						"sessionContext": {
							"sessionIssuer": {
								"arn": "arn:aws:iam::123456789012:role/TestRole"
							}
						}
					}
				}`),
			},
			wantIsSentinel: true,
			wantUser:       "alice",
			wantRequestID:  "abc12345",
			wantRoleARN:    "arn:aws:iam::123456789012:role/TestRole",
		},
		{
			name: "non-sentinel session",
			event: types.Event{
				EventId:     aws.String("event-456"),
				EventName:   aws.String("AssumeRole"),
				EventSource: aws.String("sts.amazonaws.com"),
				EventTime:   aws.Time(now),
				Username:    aws.String("external"),
				CloudTrailEvent: aws.String(`{
					"userIdentity": {
						"sourceIdentity": "",
						"sessionContext": {}
					}
				}`),
			},
			wantIsSentinel: false,
			wantUser:       "",
			wantRequestID:  "",
		},
		{
			name: "no sourceIdentity field",
			event: types.Event{
				EventId:     aws.String("event-789"),
				EventName:   aws.String("AssumeRole"),
				EventSource: aws.String("sts.amazonaws.com"),
				EventTime:   aws.Time(now),
				Username:    aws.String("external"),
				CloudTrailEvent: aws.String(`{
					"userIdentity": {
						"sessionContext": {}
					}
				}`),
			},
			wantIsSentinel: false,
		},
		{
			name: "nil CloudTrailEvent",
			event: types.Event{
				EventId:     aws.String("event-nil"),
				EventName:   aws.String("DescribeInstances"),
				EventSource: aws.String("ec2.amazonaws.com"),
				EventTime:   aws.Time(now),
				Username:    aws.String("user"),
			},
			wantIsSentinel: false,
		},
		{
			name: "invalid JSON in CloudTrailEvent",
			event: types.Event{
				EventId:         aws.String("event-bad"),
				EventName:       aws.String("AssumeRole"),
				CloudTrailEvent: aws.String(`{invalid json`),
			},
			wantErrContains: "unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseCloudTrailEvent(tt.event)

			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseCloudTrailEvent() error = %v", err)
			}

			if info.IsSentinel != tt.wantIsSentinel {
				t.Errorf("IsSentinel = %v, want %v", info.IsSentinel, tt.wantIsSentinel)
			}
			if info.User != tt.wantUser {
				t.Errorf("User = %q, want %q", info.User, tt.wantUser)
			}
			if info.RequestID != tt.wantRequestID {
				t.Errorf("RequestID = %q, want %q", info.RequestID, tt.wantRequestID)
			}
			if tt.wantRoleARN != "" && info.RoleARN != tt.wantRoleARN {
				t.Errorf("RoleARN = %q, want %q", info.RoleARN, tt.wantRoleARN)
			}
		})
	}
}

func TestVerifier_Verify_EmptyResult(t *testing.T) {
	now := time.Now()

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.TotalSessions != 0 {
		t.Errorf("TotalSessions = %d, want 0", result.TotalSessions)
	}
	if result.PassRate() != 100.0 {
		t.Errorf("PassRate() = %f, want 100.0 for empty result", result.PassRate())
	}
	if result.HasIssues() {
		t.Errorf("HasIssues() = true, want false for empty result")
	}
}

// CloudTrail JSON parsing edge case tests

func TestParseCloudTrailEvent_DeeplyNestedJSON(t *testing.T) {
	now := time.Now()
	// Test deeply nested userIdentity with extra levels
	event := types.Event{
		EventId:     aws.String("event-nested"),
		EventName:   aws.String("AssumeRole"),
		EventSource: aws.String("sts.amazonaws.com"),
		EventTime:   aws.Time(now),
		CloudTrailEvent: aws.String(`{
			"userIdentity": {
				"sourceIdentity": "sentinel:alice:abc123",
				"type": "AssumedRole",
				"arn": "arn:aws:sts::123456789012:assumed-role/TestRole/alice",
				"sessionContext": {
					"sessionIssuer": {
						"type": "Role",
						"arn": "arn:aws:iam::123456789012:role/TestRole",
						"accountId": "123456789012"
					},
					"webIdFederationData": {},
					"attributes": {
						"mfaAuthenticated": "true",
						"creationDate": "2025-01-15T10:00:00Z"
					}
				}
			},
			"eventName": "AssumeRole"
		}`),
	}

	info, err := parseCloudTrailEvent(event)
	if err != nil {
		t.Fatalf("parseCloudTrailEvent() error = %v", err)
	}
	if !info.IsSentinel {
		t.Error("IsSentinel = false, want true")
	}
	if info.RoleARN != "arn:aws:iam::123456789012:role/TestRole" {
		t.Errorf("RoleARN = %q, want arn:aws:iam::123456789012:role/TestRole", info.RoleARN)
	}
}

func TestParseCloudTrailEvent_MalformedJSON(t *testing.T) {
	tests := []struct {
		name            string
		cloudTrailEvent string
		wantErrContains string
	}{
		{
			name:            "truncated JSON",
			cloudTrailEvent: `{"userIdentity": {"source`,
			wantErrContains: "unmarshal",
		},
		{
			name:            "extra opening brace",
			cloudTrailEvent: `{{"userIdentity": {}}}`,
			wantErrContains: "unmarshal",
		},
		{
			name:            "missing closing brace",
			cloudTrailEvent: `{"userIdentity": {"sourceIdentity": "sentinel:alice:abc123"}`,
			wantErrContains: "unmarshal",
		},
		{
			name:            "empty string",
			cloudTrailEvent: ``,
			wantErrContains: "unmarshal",
		},
		{
			name:            "just whitespace",
			cloudTrailEvent: `   `,
			wantErrContains: "unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := types.Event{
				EventId:         aws.String("event-test"),
				CloudTrailEvent: aws.String(tt.cloudTrailEvent),
			}

			_, err := parseCloudTrailEvent(event)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrContains)
			}
		})
	}
}

func TestParseCloudTrailEvent_UnknownFields(t *testing.T) {
	now := time.Now()
	// JSON with unknown fields should be ignored gracefully
	event := types.Event{
		EventId:     aws.String("event-unknown"),
		EventName:   aws.String("AssumeRole"),
		EventSource: aws.String("sts.amazonaws.com"),
		EventTime:   aws.Time(now),
		CloudTrailEvent: aws.String(`{
			"userIdentity": {
				"sourceIdentity": "sentinel:alice:abc123",
				"unknownField1": "value1",
				"unknownNestedField": {"deep": {"nested": "value"}},
				"sessionContext": {
					"sessionIssuer": {
						"arn": "arn:aws:iam::123456789012:role/TestRole",
						"extraField": 12345
					}
				}
			},
			"futureField": true,
			"anotherFutureField": [1, 2, 3]
		}`),
	}

	info, err := parseCloudTrailEvent(event)
	if err != nil {
		t.Fatalf("parseCloudTrailEvent() error = %v", err)
	}
	if !info.IsSentinel {
		t.Error("IsSentinel = false, want true")
	}
	if info.User != "alice" {
		t.Errorf("User = %q, want alice", info.User)
	}
}

func TestParseCloudTrailEvent_NullValues(t *testing.T) {
	now := time.Now()
	// JSON with null values for expected fields
	event := types.Event{
		EventId:     aws.String("event-null"),
		EventName:   aws.String("AssumeRole"),
		EventSource: aws.String("sts.amazonaws.com"),
		EventTime:   aws.Time(now),
		CloudTrailEvent: aws.String(`{
			"userIdentity": {
				"sourceIdentity": null,
				"userName": null,
				"sessionContext": null
			}
		}`),
	}

	info, err := parseCloudTrailEvent(event)
	if err != nil {
		t.Fatalf("parseCloudTrailEvent() error = %v", err)
	}
	if info.IsSentinel {
		t.Error("IsSentinel = true, want false for null sourceIdentity")
	}
}

func TestParseCloudTrailEvent_WrongTypes(t *testing.T) {
	now := time.Now()
	// Test JSON where fields have wrong types (string vs object) - should fail gracefully
	event := types.Event{
		EventId:     aws.String("event-wrongtype"),
		EventName:   aws.String("AssumeRole"),
		EventSource: aws.String("sts.amazonaws.com"),
		EventTime:   aws.Time(now),
		CloudTrailEvent: aws.String(`{
			"userIdentity": "this-should-be-an-object"
		}`),
	}

	_, err := parseCloudTrailEvent(event)
	// Should error because userIdentity is a string instead of object
	if err == nil {
		t.Fatal("expected error for wrong type, got nil")
	}
}

func TestParseCloudTrailEvent_AllFieldsNil(t *testing.T) {
	// Event with all nil fields should not panic
	event := types.Event{}

	info, err := parseCloudTrailEvent(event)
	if err != nil {
		t.Fatalf("parseCloudTrailEvent() error = %v", err)
	}
	// Should return empty SessionInfo without panic
	if info.IsSentinel {
		t.Error("IsSentinel = true, want false")
	}
	if info.EventID != "" {
		t.Errorf("EventID = %q, want empty", info.EventID)
	}
}

func TestParseCloudTrailEvent_PartialFields(t *testing.T) {
	now := time.Now()
	// Event with partial fields populated
	event := types.Event{
		EventId:   aws.String("event-partial"),
		EventTime: aws.Time(now),
		// EventName, EventSource, Username, CloudTrailEvent are nil
	}

	info, err := parseCloudTrailEvent(event)
	if err != nil {
		t.Fatalf("parseCloudTrailEvent() error = %v", err)
	}
	if info.EventID != "event-partial" {
		t.Errorf("EventID = %q, want event-partial", info.EventID)
	}
	if info.EventName != "" {
		t.Errorf("EventName = %q, want empty", info.EventName)
	}
	if !info.EventTime.Equal(now) {
		t.Errorf("EventTime = %v, want %v", info.EventTime, now)
	}
}

func TestParseCloudTrailEvent_UsernameFallback(t *testing.T) {
	now := time.Now()
	// Username from payload when event.Username is nil
	event := types.Event{
		EventId:     aws.String("event-fallback"),
		EventName:   aws.String("AssumeRole"),
		EventSource: aws.String("sts.amazonaws.com"),
		EventTime:   aws.Time(now),
		// Username is nil
		CloudTrailEvent: aws.String(`{
			"userIdentity": {
				"userName": "alice-from-payload",
				"sourceIdentity": "sentinel:alice:abc123"
			}
		}`),
	}

	info, err := parseCloudTrailEvent(event)
	if err != nil {
		t.Fatalf("parseCloudTrailEvent() error = %v", err)
	}
	if info.Username != "alice-from-payload" {
		t.Errorf("Username = %q, want alice-from-payload", info.Username)
	}
}

func TestParseCloudTrailEvent_UsernameFromEvent(t *testing.T) {
	now := time.Now()
	// Username from event takes precedence over payload
	event := types.Event{
		EventId:     aws.String("event-priority"),
		EventName:   aws.String("AssumeRole"),
		EventSource: aws.String("sts.amazonaws.com"),
		EventTime:   aws.Time(now),
		Username:    aws.String("alice-from-event"),
		CloudTrailEvent: aws.String(`{
			"userIdentity": {
				"userName": "alice-from-payload",
				"sourceIdentity": "sentinel:alice:abc123"
			}
		}`),
	}

	info, err := parseCloudTrailEvent(event)
	if err != nil {
		t.Fatalf("parseCloudTrailEvent() error = %v", err)
	}
	if info.Username != "alice-from-event" {
		t.Errorf("Username = %q, want alice-from-event", info.Username)
	}
}

// Verifier error handling tests

func TestVerifier_Verify_APIError(t *testing.T) {
	now := time.Now()

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return nil, fmt.Errorf("access denied: insufficient permissions")
		},
	}

	verifier := newVerifierWithClient(client)
	_, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "lookup events") {
		t.Errorf("error = %q, want to contain 'lookup events'", err.Error())
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("error = %q, want to contain 'access denied'", err.Error())
	}
}

func TestVerifier_Verify_ContextCancellation(t *testing.T) {
	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	callCount := 0

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			callCount++
			if callCount == 1 {
				// First call succeeds but returns pagination token
				return &cloudtrail.LookupEventsOutput{
					Events:    []types.Event{},
					NextToken: aws.String("page2"),
				}, nil
			}
			// Cancel context before second call completes
			cancel()
			return nil, ctx.Err()
		},
	}

	verifier := newVerifierWithClient(client)
	_, err := verifier.Verify(ctx, &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}

func TestVerifier_Verify_EmptyEventsArray(t *testing.T) {
	now := time.Now()

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{}, // Explicitly empty
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.TotalSessions != 0 {
		t.Errorf("TotalSessions = %d, want 0", result.TotalSessions)
	}
	if result.UnknownSessions != 0 {
		t.Errorf("UnknownSessions = %d, want 0", result.UnknownSessions)
	}
}

func TestVerifier_Verify_SingleEventParseError(t *testing.T) {
	now := time.Now()
	eventTime := now.Add(-30 * time.Minute)

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						EventId:         aws.String("event-good"),
						EventName:       aws.String("AssumeRole"),
						EventSource:     aws.String("sts.amazonaws.com"),
						EventTime:       aws.Time(eventTime),
						Username:        aws.String("alice"),
						CloudTrailEvent: aws.String(`{"userIdentity": {"sourceIdentity": "sentinel:alice:abc123"}}`),
					},
					{
						EventId:         aws.String("event-bad"),
						EventName:       aws.String("AssumeRole"),
						CloudTrailEvent: aws.String(`{invalid json`),
					},
					{
						EventId:         aws.String("event-good2"),
						EventName:       aws.String("AssumeRole"),
						EventSource:     aws.String("sts.amazonaws.com"),
						EventTime:       aws.Time(eventTime),
						Username:        aws.String("bob"),
						CloudTrailEvent: aws.String(`{"userIdentity": {"sourceIdentity": "sentinel:bob:def456"}}`),
					},
				},
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	// Should have processed 2 good events
	if result.TotalSessions != 2 {
		t.Errorf("TotalSessions = %d, want 2", result.TotalSessions)
	}
	if result.SentinelSessions != 2 {
		t.Errorf("SentinelSessions = %d, want 2", result.SentinelSessions)
	}
	// The bad event should increment UnknownSessions
	if result.UnknownSessions != 1 {
		t.Errorf("UnknownSessions = %d, want 1", result.UnknownSessions)
	}
}

// Issue classification tests

func TestVerifier_IssueClassification_NonSentinelSourceIdentity(t *testing.T) {
	now := time.Now()
	eventTime := now.Add(-30 * time.Minute)

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						EventId:     aws.String("event-1"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("external-user"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {
								"sourceIdentity": "other:format:xyz"
							}
						}`),
					},
				},
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("len(Issues) = %d, want 1", len(result.Issues))
	}

	issue := result.Issues[0]
	// Non-Sentinel SourceIdentity creates IssueTypeMissingSourceIdentity
	if issue.Type != IssueTypeMissingSourceIdentity {
		t.Errorf("Issue.Type = %q, want %q", issue.Type, IssueTypeMissingSourceIdentity)
	}
}

func TestVerifier_IssueClassification_MissingSourceIdentity(t *testing.T) {
	now := time.Now()
	eventTime := now.Add(-30 * time.Minute)

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						EventId:     aws.String("event-1"),
						EventName:   aws.String("AssumeRole"),
						EventSource: aws.String("sts.amazonaws.com"),
						EventTime:   aws.Time(eventTime),
						Username:    aws.String("missing-user"),
						CloudTrailEvent: aws.String(`{
							"userIdentity": {}
						}`),
					},
				},
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("len(Issues) = %d, want 1", len(result.Issues))
	}

	issue := result.Issues[0]
	// Missing SourceIdentity creates correct message
	if !strings.Contains(issue.Message, "missing-user") {
		t.Errorf("Issue.Message = %q, want to contain 'missing-user'", issue.Message)
	}
	if !strings.Contains(issue.Message, "AssumeRole") {
		t.Errorf("Issue.Message = %q, want to contain 'AssumeRole'", issue.Message)
	}
}

func TestVerifier_IssueClassification_SeverityIsWarning(t *testing.T) {
	now := time.Now()
	eventTime := now.Add(-30 * time.Minute)

	client := &mockCloudTrailClient{
		lookupEventsFunc: func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
			return &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						EventId:         aws.String("event-1"),
						EventName:       aws.String("AssumeRole"),
						EventSource:     aws.String("sts.amazonaws.com"),
						EventTime:       aws.Time(eventTime),
						Username:        aws.String("user1"),
						CloudTrailEvent: aws.String(`{"userIdentity": {}}`),
					},
					{
						EventId:         aws.String("event-2"),
						EventName:       aws.String("AssumeRole"),
						EventSource:     aws.String("sts.amazonaws.com"),
						EventTime:       aws.Time(eventTime),
						Username:        aws.String("user2"),
						CloudTrailEvent: aws.String(`{"userIdentity": {"sourceIdentity": "other:format"}}`),
					},
				},
			}, nil
		},
	}

	verifier := newVerifierWithClient(client)
	result, err := verifier.Verify(context.Background(), &VerifyInput{
		StartTime: now.Add(-1 * time.Hour),
		EndTime:   now,
	})

	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	// All issues should have warning severity for missing SourceIdentity
	for i, issue := range result.Issues {
		if issue.Severity != SeverityWarning {
			t.Errorf("Issue[%d].Severity = %q, want %q", i, issue.Severity, SeverityWarning)
		}
	}
}
