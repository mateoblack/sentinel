package notification

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/request"
)

func TestWebhookNotifier_Notify(t *testing.T) {
	// Track received request
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

	notifier, err := NewWebhookNotifier(WebhookConfig{
		URL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}

	event := &Event{
		Type:      EventRequestCreated,
		Request:   &request.Request{ID: "test-123"},
		Timestamp: time.Now(),
		Actor:     "testuser",
	}

	err = notifier.Notify(context.Background(), event)
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	// Verify Content-Type header
	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", receivedContentType, "application/json")
	}

	// Verify X-Sentinel-Event header
	if receivedEventHeader != string(EventRequestCreated) {
		t.Errorf("X-Sentinel-Event = %q, want %q", receivedEventHeader, EventRequestCreated)
	}

	// Verify body is valid JSON
	var decoded Event
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Errorf("Body is not valid JSON: %v", err)
	}
	if decoded.Type != EventRequestCreated {
		t.Errorf("decoded.Type = %q, want %q", decoded.Type, EventRequestCreated)
	}
}

func TestWebhookNotifier_Notify_Retry(t *testing.T) {
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

	notifier, err := NewWebhookNotifier(WebhookConfig{
		URL:               server.URL,
		MaxRetries:        3,
		RetryDelaySeconds: 0, // Use minimal delay for tests
	})
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}
	// Override retry delay for faster tests
	notifier.retryDelay = 1 * time.Millisecond

	event := &Event{
		Type:      EventRequestApproved,
		Request:   &request.Request{ID: "retry-test"},
		Timestamp: time.Now(),
		Actor:     "approver",
	}

	err = notifier.Notify(context.Background(), event)
	if err != nil {
		t.Fatalf("Notify should succeed after retries: %v", err)
	}

	// Verify request was retried
	finalAttempts := atomic.LoadInt32(&attempts)
	if finalAttempts != 3 {
		t.Errorf("attempts = %d, want 3", finalAttempts)
	}
}

func TestWebhookNotifier_Notify_AllRetriesFail(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier, err := NewWebhookNotifier(WebhookConfig{
		URL:        server.URL,
		MaxRetries: 2,
	})
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}
	notifier.retryDelay = 1 * time.Millisecond

	event := &Event{
		Type:      EventRequestDenied,
		Request:   &request.Request{ID: "fail-test"},
		Timestamp: time.Now(),
		Actor:     "admin",
	}

	err = notifier.Notify(context.Background(), event)
	if err == nil {
		t.Fatal("Notify should return error after all retries fail")
	}

	// Verify all attempts were made (initial + retries)
	finalAttempts := atomic.LoadInt32(&attempts)
	expected := int32(3) // 1 initial + 2 retries
	if finalAttempts != expected {
		t.Errorf("attempts = %d, want %d", finalAttempts, expected)
	}
}

func TestNewWebhookNotifier_InvalidURL(t *testing.T) {
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
			_, err := NewWebhookNotifier(WebhookConfig{URL: tt.url})
			if err == nil {
				t.Error("NewWebhookNotifier should return error for invalid URL")
			}
		})
	}
}

func TestWebhookNotifier_Notify_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always fail to trigger retry
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier, err := NewWebhookNotifier(WebhookConfig{
		URL:        server.URL,
		MaxRetries: 5, // Allow many retries
	})
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}
	notifier.retryDelay = 100 * time.Millisecond

	event := &Event{
		Type:      EventRequestExpired,
		Request:   &request.Request{ID: "cancel-test"},
		Timestamp: time.Now(),
		Actor:     "system",
	}

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err = notifier.Notify(ctx, event)
	if err == nil {
		t.Fatal("Notify should return error when context is cancelled")
	}
	if err != context.Canceled {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestWebhookNotifier_Notify_ClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	notifier, err := NewWebhookNotifier(WebhookConfig{
		URL:        server.URL,
		MaxRetries: 3,
	})
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}

	event := &Event{
		Type:      EventRequestCancelled,
		Request:   &request.Request{ID: "client-error-test"},
		Timestamp: time.Now(),
		Actor:     "user",
	}

	err = notifier.Notify(context.Background(), event)
	if err == nil {
		t.Fatal("Notify should return error for 4xx response")
	}
}

func TestWebhookConfig_Defaults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create with only URL, all other fields should use defaults
	notifier, err := NewWebhookNotifier(WebhookConfig{
		URL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewWebhookNotifier: %v", err)
	}

	// Verify defaults were applied
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
