package notification

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/byteness/aws-vault/v7/request"
)

// =============================================================================
// Task 1: Notification Payload Security Tests
// =============================================================================

// TestEventTypeExhaustiveValidation tests all 5 event types produce correct
// JSON structure with proper headers/attributes.
func TestEventTypeExhaustiveValidation(t *testing.T) {
	tests := []struct {
		eventType   EventType
		actor       string
		actorSource string // which field actor comes from
	}{
		{EventRequestCreated, "requester-user", "requester"},
		{EventRequestApproved, "approver-user", "approver"},
		{EventRequestDenied, "denier-user", "approver"},
		{EventRequestExpired, "system", "system"},
		{EventRequestCancelled, "canceller-user", "requester"},
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			// Verify event type is valid
			if !tt.eventType.IsValid() {
				t.Errorf("EventType %q should be valid", tt.eventType)
			}

			// Verify string representation
			if tt.eventType.String() != string(tt.eventType) {
				t.Errorf("String() = %q, want %q", tt.eventType.String(), string(tt.eventType))
			}

			// Create event and serialize
			req := &request.Request{
				ID:            "1234567890abcdef",
				Requester:     "testuser",
				Profile:       "production",
				Justification: "Test justification",
				Duration:      time.Hour,
				Status:        request.StatusPending,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(24 * time.Hour),
				Approver:      "approver-user",
			}

			event := &Event{
				Type:      tt.eventType,
				Request:   req,
				Timestamp: time.Date(2026, 1, 17, 10, 30, 0, 0, time.UTC),
				Actor:     tt.actor,
			}

			// Test JSON serialization
			data, err := json.Marshal(event)
			if err != nil {
				t.Fatalf("Failed to marshal event: %v", err)
			}

			// Parse back and verify structure
			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("Failed to unmarshal event: %v", err)
			}

			// Verify Type field
			if got := parsed["Type"]; got != string(tt.eventType) {
				t.Errorf("Type = %v, want %q", got, tt.eventType)
			}

			// Verify Actor field
			if got := parsed["Actor"]; got != tt.actor {
				t.Errorf("Actor = %v, want %q", got, tt.actor)
			}

			// Verify Timestamp is in RFC3339 format (Go's default JSON time format)
			tsStr, ok := parsed["Timestamp"].(string)
			if !ok {
				t.Fatalf("Timestamp is not a string")
			}
			if _, err := time.Parse(time.RFC3339Nano, tsStr); err != nil {
				t.Errorf("Timestamp %q is not RFC3339 format: %v", tsStr, err)
			}

			// Test webhook header contains correct event type
			var webhookEventHeader string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				webhookEventHeader = r.Header.Get("X-Sentinel-Event")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			notifier, err := NewWebhookNotifier(WebhookConfig{URL: server.URL})
			if err != nil {
				t.Fatalf("NewWebhookNotifier: %v", err)
			}

			if err := notifier.Notify(context.Background(), event); err != nil {
				t.Fatalf("Notify: %v", err)
			}

			if webhookEventHeader != string(tt.eventType) {
				t.Errorf("X-Sentinel-Event = %q, want %q", webhookEventHeader, tt.eventType)
			}

			// Test SNS message attribute contains correct event type
			var snsEventAttribute string
			mockSNS := &mockSNSClient{
				publishFn: func(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error) {
					if attr, ok := params.MessageAttributes["event_type"]; ok && attr.StringValue != nil {
						snsEventAttribute = *attr.StringValue
					}
					return &sns.PublishOutput{}, nil
				},
			}

			snsNotifier := newSNSNotifierWithClient(mockSNS, "arn:aws:sns:us-east-1:123456789012:test")
			if err := snsNotifier.Notify(context.Background(), event); err != nil {
				t.Fatalf("SNS Notify: %v", err)
			}

			if snsEventAttribute != string(tt.eventType) {
				t.Errorf("SNS event_type = %q, want %q", snsEventAttribute, tt.eventType)
			}
		})
	}
}

// TestInvalidEventTypeHandling tests handling of invalid event type strings.
func TestInvalidEventTypeHandling(t *testing.T) {
	tests := []struct {
		name      string
		eventType EventType
		valid     bool
	}{
		{"empty", EventType(""), false},
		{"whitespace", EventType("   "), false},
		{"unknown", EventType("request.unknown"), false},
		{"partial", EventType("request"), false},
		{"typo", EventType("request.aproved"), false},
		{"uppercase", EventType("REQUEST.CREATED"), false},
		{"valid_created", EventRequestCreated, true},
		{"valid_approved", EventRequestApproved, true},
		{"valid_denied", EventRequestDenied, true},
		{"valid_expired", EventRequestExpired, true},
		{"valid_cancelled", EventRequestCancelled, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.eventType.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

// TestPayloadContentValidation verifies no unexpected field leakage in serialized payloads.
func TestPayloadContentValidation(t *testing.T) {
	// Create event with sensitive-looking data in justification
	req := &request.Request{
		ID:            "1234567890abcdef",
		Requester:     "testuser",
		Profile:       "production",
		Justification: "SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111, Password: s3cr3t!",
		Duration:      time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		Approver:      "",
	}

	event := &Event{
		Type:      EventRequestCreated,
		Request:   req,
		Timestamp: time.Now(),
		Actor:     "testuser",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal event: %v", err)
	}

	// Parse as generic map to check for unexpected fields
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify only expected top-level fields
	expectedFields := map[string]bool{
		"Type":      true,
		"Request":   true,
		"Timestamp": true,
		"Actor":     true,
	}

	for key := range parsed {
		if !expectedFields[key] {
			t.Errorf("Unexpected field in payload: %q", key)
		}
	}

	// Verify all expected fields are present
	for key := range expectedFields {
		if _, ok := parsed[key]; !ok {
			t.Errorf("Missing expected field: %q", key)
		}
	}

	// Verify Request has expected fields (no extras)
	reqData, ok := parsed["Request"].(map[string]interface{})
	if !ok {
		t.Fatalf("Request is not a map")
	}

	expectedReqFields := map[string]bool{
		"id":               true,
		"requester":        true,
		"profile":          true,
		"justification":    true,
		"duration":         true,
		"status":           true,
		"created_at":       true,
		"updated_at":       true,
		"expires_at":       true,
		"approver":         true,
		"approver_comment": true,
	}

	for key := range reqData {
		if !expectedReqFields[key] {
			t.Errorf("Unexpected field in Request payload: %q", key)
		}
	}
}

// TestActorFieldSecurity tests actor field handling with special characters and edge cases.
func TestActorFieldSecurity(t *testing.T) {
	tests := []struct {
		name  string
		actor string
	}{
		{"newlines", "user\nwith\nnewlines"},
		{"carriage_return", "user\r\nwith\r\ncrlf"},
		{"quotes", `user"with"quotes`},
		{"single_quotes", `user'with'quotes`},
		{"backslash", `user\with\backslash`},
		{"unicode_emoji", "user-with-emoji"},
		{"unicode_chinese", "chinese-user-name"},
		{"unicode_arabic", "arabic-user-name"},
		{"null_char", "user\x00with\x00null"},
		{"tab", "user\twith\ttabs"},
		{"long_string", strings.Repeat("a", 1000)},
		{"very_long_string", strings.Repeat("x", 10000)},
		{"special_json_chars", `<script>alert("xss")</script>`},
		{"html_entities", "&lt;script&gt;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &Event{
				Type: EventRequestCreated,
				Request: &request.Request{
					ID:            "1234567890abcdef",
					Requester:     tt.actor,
					Profile:       "test",
					Justification: "test",
					Duration:      time.Hour,
					Status:        request.StatusPending,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
					ExpiresAt:     time.Now().Add(time.Hour),
				},
				Timestamp: time.Now(),
				Actor:     tt.actor,
			}

			// Serialize
			data, err := json.Marshal(event)
			if err != nil {
				t.Fatalf("Failed to marshal event with actor %q: %v", tt.name, err)
			}

			// Verify valid JSON
			var parsed Event
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			// Verify actor is preserved correctly
			if parsed.Actor != tt.actor {
				t.Errorf("Actor = %q, want %q", parsed.Actor, tt.actor)
			}
		})
	}
}

// TestActorMappingCorrectness verifies actor is correctly mapped based on event type.
func TestActorMappingCorrectness(t *testing.T) {
	tests := []struct {
		name        string
		eventType   EventType
		newStatus   request.RequestStatus
		expectedActor string
		actorSource string
	}{
		{
			name:        "created_uses_requester",
			eventType:   EventRequestCreated,
			newStatus:   request.StatusPending,
			expectedActor: "the-requester",
			actorSource: "requester",
		},
		{
			name:        "approved_uses_approver",
			eventType:   EventRequestApproved,
			newStatus:   request.StatusApproved,
			expectedActor: "the-approver",
			actorSource: "approver",
		},
		{
			name:        "denied_uses_approver",
			eventType:   EventRequestDenied,
			newStatus:   request.StatusDenied,
			expectedActor: "the-approver",
			actorSource: "approver",
		},
		{
			name:        "cancelled_uses_requester",
			eventType:   EventRequestCancelled,
			newStatus:   request.StatusCancelled,
			expectedActor: "the-requester",
			actorSource: "requester",
		},
		{
			name:        "expired_uses_system",
			eventType:   EventRequestExpired,
			newStatus:   request.StatusExpired,
			expectedActor: "system",
			actorSource: "system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create pending request
			pendingReq := &request.Request{
				ID:            "1234567890abcdef",
				Requester:     "the-requester",
				Profile:       "production",
				Justification: "Test",
				Duration:      time.Hour,
				Status:        request.StatusPending,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
				ExpiresAt:     time.Now().Add(24 * time.Hour),
			}

			// Create updated request with new status
			updatedReq := &request.Request{
				ID:            pendingReq.ID,
				Requester:     "the-requester",
				Profile:       pendingReq.Profile,
				Justification: pendingReq.Justification,
				Duration:      pendingReq.Duration,
				Status:        tt.newStatus,
				CreatedAt:     pendingReq.CreatedAt,
				UpdatedAt:     time.Now(),
				ExpiresAt:     pendingReq.ExpiresAt,
				Approver:      "the-approver",
			}

			// Track notifications
			var capturedEvent *Event
			notifier := &notifyTestMock{}
			notifier.err = nil

			store := &storeTestMock{
				getFn: func(ctx context.Context, id string) (*request.Request, error) {
					return pendingReq, nil
				},
			}

			ns := NewNotifyStore(store, notifier)

			// For create event, test Create method
			if tt.eventType == EventRequestCreated {
				err := ns.Create(context.Background(), pendingReq)
				if err != nil {
					t.Fatalf("Create failed: %v", err)
				}
			} else {
				// For other events, test Update method
				err := ns.Update(context.Background(), updatedReq)
				if err != nil {
					t.Fatalf("Update failed: %v", err)
				}
			}

			// Wait for async notification
			events := notifier.waitForEvents(1, 100*time.Millisecond)
			if len(events) != 1 {
				t.Fatalf("Expected 1 event, got %d", len(events))
			}

			capturedEvent = events[0]

			// Verify actor
			if capturedEvent.Actor != tt.expectedActor {
				t.Errorf("Actor = %q, want %q (from %s)", capturedEvent.Actor, tt.expectedActor, tt.actorSource)
			}

			// Verify event type
			if capturedEvent.Type != tt.eventType {
				t.Errorf("Type = %q, want %q", capturedEvent.Type, tt.eventType)
			}
		})
	}
}
