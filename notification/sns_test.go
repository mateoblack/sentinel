package notification

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/byteness/aws-vault/v7/request"
)

// mockSNSClient implements snsAPI for testing.
type mockSNSClient struct {
	publishFn func(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error)
}

func (m *mockSNSClient) Publish(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error) {
	if m.publishFn != nil {
		return m.publishFn(ctx, params, optFns...)
	}
	return &sns.PublishOutput{}, nil
}

func TestSNSNotifier_Notify(t *testing.T) {
	ctx := context.Background()
	topicARN := "arn:aws:sns:us-east-1:123456789012:test-topic"

	event := &Event{
		Type: EventRequestCreated,
		Request: &request.Request{
			ID:            "req-123",
			Requester:     "alice",
			Profile:       "production",
			Justification: "Deploy hotfix",
			Duration:      time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(24 * time.Hour),
		},
		Timestamp: time.Now(),
		Actor:     "alice",
	}

	var capturedInput *sns.PublishInput

	mockClient := &mockSNSClient{
		publishFn: func(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error) {
			capturedInput = params
			return &sns.PublishOutput{
				MessageId: ptrString("msg-12345"),
			}, nil
		},
	}

	notifier := newSNSNotifierWithClient(mockClient, topicARN)

	err := notifier.Notify(ctx, event)
	if err != nil {
		t.Fatalf("Notify failed: %v", err)
	}

	// Verify TopicArn
	if capturedInput.TopicArn == nil || *capturedInput.TopicArn != topicARN {
		t.Errorf("TopicArn = %v, want %s", capturedInput.TopicArn, topicARN)
	}

	// Verify Message contains event JSON
	if capturedInput.Message == nil {
		t.Fatal("Message is nil")
	}
	var parsedEvent Event
	if err := json.Unmarshal([]byte(*capturedInput.Message), &parsedEvent); err != nil {
		t.Fatalf("Message is not valid JSON: %v", err)
	}
	if parsedEvent.Type != event.Type {
		t.Errorf("Event.Type = %s, want %s", parsedEvent.Type, event.Type)
	}
	if parsedEvent.Actor != event.Actor {
		t.Errorf("Event.Actor = %s, want %s", parsedEvent.Actor, event.Actor)
	}
	if parsedEvent.Request.ID != event.Request.ID {
		t.Errorf("Event.Request.ID = %s, want %s", parsedEvent.Request.ID, event.Request.ID)
	}

	// Verify MessageAttributes has event_type
	eventTypeAttr, ok := capturedInput.MessageAttributes["event_type"]
	if !ok {
		t.Fatal("MessageAttributes missing 'event_type'")
	}
	if eventTypeAttr.DataType == nil || *eventTypeAttr.DataType != "String" {
		t.Errorf("event_type.DataType = %v, want String", eventTypeAttr.DataType)
	}
	if eventTypeAttr.StringValue == nil || *eventTypeAttr.StringValue != string(EventRequestCreated) {
		t.Errorf("event_type.StringValue = %v, want %s", eventTypeAttr.StringValue, EventRequestCreated)
	}
}

func TestSNSNotifier_Notify_Error(t *testing.T) {
	ctx := context.Background()
	topicARN := "arn:aws:sns:us-east-1:123456789012:test-topic"

	event := &Event{
		Type: EventRequestApproved,
		Request: &request.Request{
			ID: "req-456",
		},
		Timestamp: time.Now(),
		Actor:     "bob",
	}

	mockClient := &mockSNSClient{
		publishFn: func(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error) {
			return nil, errors.New("sns: access denied")
		},
	}

	notifier := newSNSNotifierWithClient(mockClient, topicARN)

	err := notifier.Notify(ctx, event)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !errors.Is(err, err) {
		t.Errorf("Error = %v, expected wrapped error", err)
	}
}

// ptrString returns a pointer to the string value.
func ptrString(s string) *string {
	return &s
}
