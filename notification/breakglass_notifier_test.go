package notification

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/byteness/aws-vault/v7/breakglass"
)

// ============================================================================
// SNSBreakGlassNotifier Tests
// ============================================================================

func TestSNSBreakGlassNotifier_NotifyBreakGlass(t *testing.T) {
	ctx := context.Background()
	topicARN := "arn:aws:sns:us-east-1:123456789012:breakglass-topic"

	bgEvent := &breakglass.BreakGlassEvent{
		ID:            "bg-123456789abc",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Database outage requiring immediate access",
		Duration:      time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
		RequestID:     "req-123456789abc",
	}

	event := NewBreakGlassEvent(EventBreakGlassInvoked, bgEvent, "alice")

	var capturedInput *sns.PublishInput

	mockClient := &mockSNSClient{
		publishFn: func(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error) {
			capturedInput = params
			return &sns.PublishOutput{
				MessageId: ptrString("msg-breakglass-123"),
			}, nil
		},
	}

	notifier := newSNSBreakGlassNotifierWithClient(mockClient, topicARN)

	err := notifier.NotifyBreakGlass(ctx, event)
	if err != nil {
		t.Fatalf("NotifyBreakGlass failed: %v", err)
	}

	// Verify TopicArn
	if capturedInput.TopicArn == nil || *capturedInput.TopicArn != topicARN {
		t.Errorf("TopicArn = %v, want %s", capturedInput.TopicArn, topicARN)
	}

	// Verify Message contains event JSON
	if capturedInput.Message == nil {
		t.Fatal("Message is nil")
	}
	var parsedEvent BreakGlassEvent
	if err := json.Unmarshal([]byte(*capturedInput.Message), &parsedEvent); err != nil {
		t.Fatalf("Message is not valid JSON: %v", err)
	}
	if parsedEvent.Type != EventBreakGlassInvoked {
		t.Errorf("Event.Type = %s, want %s", parsedEvent.Type, EventBreakGlassInvoked)
	}
	if parsedEvent.Actor != "alice" {
		t.Errorf("Event.Actor = %s, want %s", parsedEvent.Actor, "alice")
	}
	if parsedEvent.BreakGlass.ID != bgEvent.ID {
		t.Errorf("Event.BreakGlass.ID = %s, want %s", parsedEvent.BreakGlass.ID, bgEvent.ID)
	}

	// Verify MessageAttributes has event_type
	eventTypeAttr, ok := capturedInput.MessageAttributes["event_type"]
	if !ok {
		t.Fatal("MessageAttributes missing 'event_type'")
	}
	if eventTypeAttr.DataType == nil || *eventTypeAttr.DataType != "String" {
		t.Errorf("event_type.DataType = %v, want String", eventTypeAttr.DataType)
	}
	if eventTypeAttr.StringValue == nil || *eventTypeAttr.StringValue != string(EventBreakGlassInvoked) {
		t.Errorf("event_type.StringValue = %v, want %s", eventTypeAttr.StringValue, EventBreakGlassInvoked)
	}
}

func TestSNSBreakGlassNotifier_NotifyBreakGlass_Error(t *testing.T) {
	ctx := context.Background()
	topicARN := "arn:aws:sns:us-east-1:123456789012:breakglass-topic"

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-error-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassClosed, bgEvent, "bob")

	mockClient := &mockSNSClient{
		publishFn: func(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error) {
			return nil, errors.New("sns: access denied")
		},
	}

	notifier := newSNSBreakGlassNotifierWithClient(mockClient, topicARN)

	err := notifier.NotifyBreakGlass(ctx, event)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !errors.Is(err, err) {
		t.Errorf("Error = %v, expected wrapped error", err)
	}
}

// ============================================================================
// WebhookBreakGlassNotifier Tests
// ============================================================================

func TestWebhookBreakGlassNotifier_NotifyBreakGlass(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	var receivedEventHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		receivedEventHeader = r.Header.Get("X-Sentinel-Event")

		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = buf

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, err := NewWebhookBreakGlassNotifier(WebhookConfig{
		URL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewWebhookBreakGlassNotifier: %v", err)
	}

	bgEvent := &breakglass.BreakGlassEvent{
		ID:            "bg-webhook-test",
		Invoker:       "testuser",
		Profile:       "staging",
		ReasonCode:    breakglass.ReasonMaintenance,
		Justification: "Scheduled maintenance window",
		Status:        breakglass.StatusActive,
	}
	event := NewBreakGlassEvent(EventBreakGlassInvoked, bgEvent, "testuser")

	err = notifier.NotifyBreakGlass(context.Background(), event)
	if err != nil {
		t.Fatalf("NotifyBreakGlass: %v", err)
	}

	// Verify Content-Type header
	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", receivedContentType, "application/json")
	}

	// Verify X-Sentinel-Event header
	if receivedEventHeader != string(EventBreakGlassInvoked) {
		t.Errorf("X-Sentinel-Event = %q, want %q", receivedEventHeader, EventBreakGlassInvoked)
	}

	// Verify body is valid JSON
	var decoded BreakGlassEvent
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Errorf("Body is not valid JSON: %v", err)
	}
	if decoded.Type != EventBreakGlassInvoked {
		t.Errorf("decoded.Type = %q, want %q", decoded.Type, EventBreakGlassInvoked)
	}
}

func TestWebhookBreakGlassNotifier_NotifyBreakGlass_Retry(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, err := NewWebhookBreakGlassNotifier(WebhookConfig{
		URL:               server.URL,
		MaxRetries:        3,
		RetryDelaySeconds: 0,
	})
	if err != nil {
		t.Fatalf("NewWebhookBreakGlassNotifier: %v", err)
	}
	notifier.retryDelay = 1 * time.Millisecond

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-retry-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassInvoked, bgEvent, "retrier")

	err = notifier.NotifyBreakGlass(context.Background(), event)
	if err != nil {
		t.Fatalf("NotifyBreakGlass should succeed after retries: %v", err)
	}

	finalAttempts := atomic.LoadInt32(&attempts)
	if finalAttempts != 3 {
		t.Errorf("attempts = %d, want 3", finalAttempts)
	}
}

func TestWebhookBreakGlassNotifier_NotifyBreakGlass_AllRetriesFail(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier, err := NewWebhookBreakGlassNotifier(WebhookConfig{
		URL:        server.URL,
		MaxRetries: 2,
	})
	if err != nil {
		t.Fatalf("NewWebhookBreakGlassNotifier: %v", err)
	}
	notifier.retryDelay = 1 * time.Millisecond

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-fail-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassExpired, bgEvent, "system")

	err = notifier.NotifyBreakGlass(context.Background(), event)
	if err == nil {
		t.Fatal("NotifyBreakGlass should return error after all retries fail")
	}

	finalAttempts := atomic.LoadInt32(&attempts)
	expected := int32(3) // 1 initial + 2 retries
	if finalAttempts != expected {
		t.Errorf("attempts = %d, want %d", finalAttempts, expected)
	}
}

func TestNewWebhookBreakGlassNotifier_InvalidURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"invalid format", "not-a-url"},
		{"missing scheme", "example.com/webhook"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWebhookBreakGlassNotifier(WebhookConfig{URL: tt.url})
			if err == nil {
				t.Error("NewWebhookBreakGlassNotifier should return error for invalid URL")
			}
		})
	}
}

func TestWebhookBreakGlassNotifier_NotifyBreakGlass_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier, err := NewWebhookBreakGlassNotifier(WebhookConfig{
		URL:        server.URL,
		MaxRetries: 5,
	})
	if err != nil {
		t.Fatalf("NewWebhookBreakGlassNotifier: %v", err)
	}
	notifier.retryDelay = 100 * time.Millisecond

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-cancel-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassInvoked, bgEvent, "canceller")

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err = notifier.NotifyBreakGlass(ctx, event)
	if err == nil {
		t.Fatal("NotifyBreakGlass should return error when context is cancelled")
	}
	if err != context.Canceled {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestWebhookBreakGlassNotifier_NotifyBreakGlass_ClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	notifier, err := NewWebhookBreakGlassNotifier(WebhookConfig{
		URL:        server.URL,
		MaxRetries: 3,
	})
	if err != nil {
		t.Fatalf("NewWebhookBreakGlassNotifier: %v", err)
	}

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-client-error-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassClosed, bgEvent, "closer")

	err = notifier.NotifyBreakGlass(context.Background(), event)
	if err == nil {
		t.Fatal("NotifyBreakGlass should return error for 4xx response")
	}
}

func TestWebhookBreakGlassNotifier_Defaults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, err := NewWebhookBreakGlassNotifier(WebhookConfig{
		URL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewWebhookBreakGlassNotifier: %v", err)
	}

	if notifier.maxRetries != 3 {
		t.Errorf("maxRetries = %d, want 3", notifier.maxRetries)
	}
	if notifier.retryDelay != 1*time.Second {
		t.Errorf("retryDelay = %v, want 1s", notifier.retryDelay)
	}
	if notifier.client.Timeout != 10*time.Second {
		t.Errorf("client.Timeout = %v, want 10s", notifier.client.Timeout)
	}
}

// ============================================================================
// MultiBreakGlassNotifier Tests
// ============================================================================

func TestMultiBreakGlassNotifier_NotifyBreakGlass(t *testing.T) {
	var called1, called2 bool

	notifier1 := &mockBreakGlassNotifier{
		notifyFn: func(ctx context.Context, event *BreakGlassEvent) error {
			called1 = true
			return nil
		},
	}
	notifier2 := &mockBreakGlassNotifier{
		notifyFn: func(ctx context.Context, event *BreakGlassEvent) error {
			called2 = true
			return nil
		},
	}

	multi := NewMultiBreakGlassNotifier(notifier1, notifier2)

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-multi-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassInvoked, bgEvent, "multi-user")

	err := multi.NotifyBreakGlass(context.Background(), event)
	if err != nil {
		t.Fatalf("NotifyBreakGlass failed: %v", err)
	}

	if !called1 {
		t.Error("notifier1 was not called")
	}
	if !called2 {
		t.Error("notifier2 was not called")
	}
}

func TestMultiBreakGlassNotifier_FiltersNil(t *testing.T) {
	var called bool
	notifier := &mockBreakGlassNotifier{
		notifyFn: func(ctx context.Context, event *BreakGlassEvent) error {
			called = true
			return nil
		},
	}

	multi := NewMultiBreakGlassNotifier(nil, notifier, nil)

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-filter-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassInvoked, bgEvent, "filter-user")

	err := multi.NotifyBreakGlass(context.Background(), event)
	if err != nil {
		t.Fatalf("NotifyBreakGlass failed: %v", err)
	}

	if !called {
		t.Error("notifier was not called")
	}

	// Verify only non-nil notifiers are stored
	if len(multi.notifiers) != 1 {
		t.Errorf("expected 1 notifier, got %d", len(multi.notifiers))
	}
}

func TestMultiBreakGlassNotifier_ErrorAggregation(t *testing.T) {
	notifier1 := &mockBreakGlassNotifier{
		notifyFn: func(ctx context.Context, event *BreakGlassEvent) error {
			return errors.New("error from notifier 1")
		},
	}
	notifier2 := &mockBreakGlassNotifier{
		notifyFn: func(ctx context.Context, event *BreakGlassEvent) error {
			return errors.New("error from notifier 2")
		},
	}

	multi := NewMultiBreakGlassNotifier(notifier1, notifier2)

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-error-agg-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassExpired, bgEvent, "system")

	err := multi.NotifyBreakGlass(context.Background(), event)
	if err == nil {
		t.Fatal("Expected combined error, got nil")
	}

	// errors.Join produces a joined error
	errStr := err.Error()
	if errStr != "error from notifier 1\nerror from notifier 2" {
		t.Errorf("unexpected error format: %q", errStr)
	}
}

func TestMultiBreakGlassNotifier_PartialFailure(t *testing.T) {
	var called1, called2 bool

	notifier1 := &mockBreakGlassNotifier{
		notifyFn: func(ctx context.Context, event *BreakGlassEvent) error {
			called1 = true
			return errors.New("error from notifier 1")
		},
	}
	notifier2 := &mockBreakGlassNotifier{
		notifyFn: func(ctx context.Context, event *BreakGlassEvent) error {
			called2 = true
			return nil
		},
	}

	multi := NewMultiBreakGlassNotifier(notifier1, notifier2)

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-partial-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassInvoked, bgEvent, "partial-user")

	err := multi.NotifyBreakGlass(context.Background(), event)
	if err == nil {
		t.Fatal("Expected error from failed notifier")
	}

	// Both notifiers should still be called
	if !called1 {
		t.Error("notifier1 was not called")
	}
	if !called2 {
		t.Error("notifier2 was not called")
	}
}

// ============================================================================
// NoopBreakGlassNotifier Tests
// ============================================================================

func TestNoopBreakGlassNotifier_NotifyBreakGlass(t *testing.T) {
	notifier := &NoopBreakGlassNotifier{}

	bgEvent := &breakglass.BreakGlassEvent{
		ID:      "bg-noop-test",
		Profile: "production",
	}
	event := NewBreakGlassEvent(EventBreakGlassInvoked, bgEvent, "noop-user")

	err := notifier.NotifyBreakGlass(context.Background(), event)
	if err != nil {
		t.Errorf("NoopBreakGlassNotifier.NotifyBreakGlass() = %v, want nil", err)
	}
}

// ============================================================================
// Test Helpers
// ============================================================================

// mockBreakGlassNotifier implements BreakGlassNotifier for testing.
type mockBreakGlassNotifier struct {
	notifyFn func(ctx context.Context, event *BreakGlassEvent) error
}

func (m *mockBreakGlassNotifier) NotifyBreakGlass(ctx context.Context, event *BreakGlassEvent) error {
	if m.notifyFn != nil {
		return m.notifyFn(ctx, event)
	}
	return nil
}
