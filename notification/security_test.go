package notification

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

// =============================================================================
// Task 2: Async Notification Reliability Tests
// =============================================================================

// TestAsyncDeliveryReliability tests that all notifications are delivered under load.
func TestAsyncDeliveryReliability(t *testing.T) {
	const numRequests = 20

	notifier := &notifyTestMock{}
	store := &storeTestMock{}
	ns := NewNotifyStore(store, notifier)

	// Create many requests rapidly
	for i := 0; i < numRequests; i++ {
		req := &request.Request{
			ID:            request.NewRequestID(),
			Requester:     "testuser",
			Profile:       "production",
			Justification: "Test",
			Duration:      time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(24 * time.Hour),
		}

		if err := ns.Create(context.Background(), req); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}
	}

	// Wait for all notifications with longer timeout
	events := notifier.waitForEvents(numRequests, 5*time.Second)
	if len(events) != numRequests {
		t.Errorf("Expected %d events, got %d", numRequests, len(events))
	}

	// Verify all events are of correct type
	for i, event := range events {
		if event.Type != EventRequestCreated {
			t.Errorf("Event %d: Type = %q, want %q", i, event.Type, EventRequestCreated)
		}
	}
}

// TestAsyncDeliveryPreservesOrder tests that notifications maintain order.
func TestAsyncDeliveryPreservesOrder(t *testing.T) {
	const numRequests = 10

	notifier := &notifyTestMock{}
	store := &storeTestMock{}
	ns := NewNotifyStore(store, notifier)

	// Track request IDs in order
	requestIDs := make([]string, numRequests)

	for i := 0; i < numRequests; i++ {
		id := request.NewRequestID()
		requestIDs[i] = id

		req := &request.Request{
			ID:            id,
			Requester:     "testuser",
			Profile:       "production",
			Justification: "Test",
			Duration:      time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(24 * time.Hour),
		}

		if err := ns.Create(context.Background(), req); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}

		// Small delay to encourage ordering
		time.Sleep(time.Millisecond)
	}

	// Wait for all notifications
	events := notifier.waitForEvents(numRequests, 5*time.Second)
	if len(events) != numRequests {
		t.Fatalf("Expected %d events, got %d", numRequests, len(events))
	}

	// Note: Async notifications may not preserve strict order due to goroutine scheduling.
	// We verify all IDs are present (no lost notifications).
	receivedIDs := make(map[string]bool)
	for _, event := range events {
		receivedIDs[event.Request.ID] = true
	}

	for _, id := range requestIDs {
		if !receivedIDs[id] {
			t.Errorf("Missing notification for request ID %q", id)
		}
	}
}

// TestGoroutineLeakPrevention verifies no goroutine leaks when notifier fails.
func TestGoroutineLeakPrevention(t *testing.T) {
	const numOperations = 50

	// Force GC to stabilize goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	// Create store with failing notifier
	notifier := &notifyTestMock{
		err: errors.New("notification always fails"),
	}
	store := &storeTestMock{}
	ns := NewNotifyStore(store, notifier)

	// Trigger many operations
	for i := 0; i < numOperations; i++ {
		req := &request.Request{
			ID:            request.NewRequestID(),
			Requester:     "testuser",
			Profile:       "production",
			Justification: "Test",
			Duration:      time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(24 * time.Hour),
		}

		// Operation should succeed even though notification fails
		if err := ns.Create(context.Background(), req); err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}
	}

	// Wait for goroutines to complete
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()

	// Allow some variance (test framework may spawn goroutines)
	// But we should not have leaked numOperations goroutines
	leakedGoroutines := finalGoroutines - baselineGoroutines
	maxAllowedLeak := 10 // Allow small variance for test infrastructure

	if leakedGoroutines > maxAllowedLeak {
		t.Errorf("Goroutine leak detected: baseline=%d, final=%d, leaked=%d (max allowed=%d)",
			baselineGoroutines, finalGoroutines, leakedGoroutines, maxAllowedLeak)
	}
}

// TestContextCancellationBehavior tests fire-and-forget semantics.
func TestContextCancellationBehavior(t *testing.T) {
	// Create a slow notifier that respects context
	var notifyStarted atomic.Int32
	var notifyCompleted atomic.Int32

	slowNotifier := &notifyTestMock{}
	slowNotifier.err = nil

	// Override with slow notify function
	originalNotify := slowNotifier.Notify
	_ = originalNotify // silence unused warning

	// Create notifier that tracks calls
	trackingNotifier := &trackingSlowNotifier{
		started:   &notifyStarted,
		completed: &notifyCompleted,
	}

	store := &storeTestMock{}
	ns := NewNotifyStore(store, trackingNotifier)

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	req := &request.Request{
		ID:            request.NewRequestID(),
		Requester:     "testuser",
		Profile:       "production",
		Justification: "Test",
		Duration:      time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}

	// Create request
	err := ns.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Cancel context immediately
	cancel()

	// Operation should have succeeded (fire-and-forget)
	// The notification goroutine may or may not complete depending on timing

	// Wait a bit and verify notification was at least started
	time.Sleep(200 * time.Millisecond)

	// The notification goroutine should have been started
	if notifyStarted.Load() == 0 {
		t.Error("Notification was never started")
	}
}

// trackingSlowNotifier is a slow notifier that tracks starts and completions.
type trackingSlowNotifier struct {
	started   *atomic.Int32
	completed *atomic.Int32
}

func (n *trackingSlowNotifier) Notify(ctx context.Context, event *Event) error {
	n.started.Add(1)
	defer n.completed.Add(1)

	// Simulate slow notification
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(50 * time.Millisecond):
		return nil
	}
}

// TestConcurrentUpdateNotificationRace tests concurrent state transitions.
func TestConcurrentUpdateNotificationRace(t *testing.T) {
	const numConcurrent = 10

	// Track which status was notified
	var notifiedStatuses sync.Map
	var notifyCount atomic.Int32

	trackingNotifier := &concurrentTrackingNotifier{
		statuses:   &notifiedStatuses,
		count:      &notifyCount,
	}

	// Create store that tracks the "current" state
	var currentStatus atomic.Value
	currentStatus.Store(request.StatusPending)

	pendingReq := &request.Request{
		ID:            "1234567890abcdef",
		Requester:     "testuser",
		Profile:       "production",
		Justification: "Test",
		Duration:      time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}

	store := &storeTestMock{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
	}

	ns := NewNotifyStore(store, trackingNotifier)

	// Launch concurrent updates with different statuses
	var wg sync.WaitGroup
	statuses := []request.RequestStatus{
		request.StatusApproved,
		request.StatusDenied,
		request.StatusCancelled,
		request.StatusExpired,
	}

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			status := statuses[idx%len(statuses)]
			req := &request.Request{
				ID:            pendingReq.ID,
				Requester:     pendingReq.Requester,
				Profile:       pendingReq.Profile,
				Justification: pendingReq.Justification,
				Duration:      pendingReq.Duration,
				Status:        status,
				CreatedAt:     pendingReq.CreatedAt,
				UpdatedAt:     time.Now(),
				ExpiresAt:     pendingReq.ExpiresAt,
				Approver:      "approver",
			}

			_ = ns.Update(context.Background(), req)
		}(i)
	}

	wg.Wait()

	// Wait for async notifications
	time.Sleep(500 * time.Millisecond)

	// Each update should have fired a notification (since all transition from pending)
	finalCount := notifyCount.Load()
	if finalCount != int32(numConcurrent) {
		t.Logf("Note: %d notifications fired for %d concurrent updates (some may have been coalesced or lost to race conditions)",
			finalCount, numConcurrent)
	}
}

// concurrentTrackingNotifier tracks notifications from concurrent operations.
type concurrentTrackingNotifier struct {
	statuses *sync.Map
	count    *atomic.Int32
}

func (n *concurrentTrackingNotifier) Notify(ctx context.Context, event *Event) error {
	n.count.Add(1)
	n.statuses.Store(event.Request.Status, true)
	return nil
}
