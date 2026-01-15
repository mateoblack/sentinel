package notification

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/request"
)

func TestEventTypeIsValid(t *testing.T) {
	tests := []struct {
		name     string
		et       EventType
		expected bool
	}{
		{"valid created", EventRequestCreated, true},
		{"valid approved", EventRequestApproved, true},
		{"valid denied", EventRequestDenied, true},
		{"valid expired", EventRequestExpired, true},
		{"valid cancelled", EventRequestCancelled, true},
		{"invalid empty", EventType(""), false},
		{"invalid unknown", EventType("unknown"), false},
		{"invalid typo", EventType("request.create"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.et.IsValid()
			if got != tc.expected {
				t.Errorf("EventType(%q).IsValid() = %v, want %v", tc.et, got, tc.expected)
			}
		})
	}
}

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		et       EventType
		expected string
	}{
		{EventRequestCreated, "request.created"},
		{EventRequestApproved, "request.approved"},
		{EventRequestDenied, "request.denied"},
		{EventRequestExpired, "request.expired"},
		{EventRequestCancelled, "request.cancelled"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			got := tc.et.String()
			if got != tc.expected {
				t.Errorf("EventType.String() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestNewEvent(t *testing.T) {
	req := &request.Request{
		ID:        "abc1234567890123",
		Requester: "alice",
		Profile:   "production",
		Status:    request.StatusPending,
	}

	before := time.Now()
	event := NewEvent(EventRequestCreated, req, "alice")
	after := time.Now()

	if event.Type != EventRequestCreated {
		t.Errorf("Event.Type = %v, want %v", event.Type, EventRequestCreated)
	}
	if event.Request != req {
		t.Error("Event.Request does not match input request")
	}
	if event.Actor != "alice" {
		t.Errorf("Event.Actor = %q, want %q", event.Actor, "alice")
	}
	if event.Timestamp.Before(before) || event.Timestamp.After(after) {
		t.Errorf("Event.Timestamp = %v, want between %v and %v", event.Timestamp, before, after)
	}
}

func TestNewEventApproved(t *testing.T) {
	req := &request.Request{
		ID:        "def1234567890123",
		Requester: "bob",
		Profile:   "staging",
		Status:    request.StatusApproved,
		Approver:  "charlie",
	}

	event := NewEvent(EventRequestApproved, req, "charlie")

	if event.Type != EventRequestApproved {
		t.Errorf("Event.Type = %v, want %v", event.Type, EventRequestApproved)
	}
	if event.Actor != "charlie" {
		t.Errorf("Event.Actor = %q, want %q", event.Actor, "charlie")
	}
}

func TestNewEventExpired(t *testing.T) {
	req := &request.Request{
		ID:        "ghi1234567890123",
		Requester: "dave",
		Profile:   "production",
		Status:    request.StatusExpired,
	}

	event := NewEvent(EventRequestExpired, req, "system")

	if event.Type != EventRequestExpired {
		t.Errorf("Event.Type = %v, want %v", event.Type, EventRequestExpired)
	}
	if event.Actor != "system" {
		t.Errorf("Event.Actor = %q, want %q", event.Actor, "system")
	}
}

// mockNotifier is a test notifier that records calls and can return errors.
type mockNotifier struct {
	calls  []*Event
	err    error
	called bool
}

func (m *mockNotifier) Notify(_ context.Context, event *Event) error {
	m.called = true
	m.calls = append(m.calls, event)
	return m.err
}

func TestMultiNotifierSingle(t *testing.T) {
	mock := &mockNotifier{}
	multi := NewMultiNotifier(mock)

	req := &request.Request{ID: "test1234567890123"}
	event := NewEvent(EventRequestCreated, req, "test")

	err := multi.Notify(context.Background(), event)

	if err != nil {
		t.Errorf("MultiNotifier.Notify() error = %v, want nil", err)
	}
	if !mock.called {
		t.Error("mock notifier was not called")
	}
	if len(mock.calls) != 1 {
		t.Errorf("mock.calls = %d, want 1", len(mock.calls))
	}
	if mock.calls[0] != event {
		t.Error("mock received different event")
	}
}

func TestMultiNotifierMultiple(t *testing.T) {
	mock1 := &mockNotifier{}
	mock2 := &mockNotifier{}
	multi := NewMultiNotifier(mock1, mock2)

	req := &request.Request{ID: "test1234567890123"}
	event := NewEvent(EventRequestDenied, req, "approver")

	err := multi.Notify(context.Background(), event)

	if err != nil {
		t.Errorf("MultiNotifier.Notify() error = %v, want nil", err)
	}
	if !mock1.called || !mock2.called {
		t.Error("not all mock notifiers were called")
	}
}

func TestMultiNotifierWithNil(t *testing.T) {
	mock := &mockNotifier{}
	multi := NewMultiNotifier(nil, mock, nil)

	req := &request.Request{ID: "test1234567890123"}
	event := NewEvent(EventRequestCancelled, req, "user")

	err := multi.Notify(context.Background(), event)

	if err != nil {
		t.Errorf("MultiNotifier.Notify() error = %v, want nil", err)
	}
	if !mock.called {
		t.Error("mock notifier was not called")
	}
}

func TestMultiNotifierEmpty(t *testing.T) {
	multi := NewMultiNotifier()

	req := &request.Request{ID: "test1234567890123"}
	event := NewEvent(EventRequestCreated, req, "user")

	err := multi.Notify(context.Background(), event)

	if err != nil {
		t.Errorf("empty MultiNotifier.Notify() error = %v, want nil", err)
	}
}

func TestMultiNotifierWithError(t *testing.T) {
	errFailed := errors.New("notification failed")
	mock1 := &mockNotifier{err: errFailed}
	mock2 := &mockNotifier{}
	multi := NewMultiNotifier(mock1, mock2)

	req := &request.Request{ID: "test1234567890123"}
	event := NewEvent(EventRequestApproved, req, "approver")

	err := multi.Notify(context.Background(), event)

	// Should return error
	if err == nil {
		t.Error("MultiNotifier.Notify() error = nil, want error")
	}
	// Both should still be called
	if !mock1.called || !mock2.called {
		t.Error("not all mock notifiers were called despite error")
	}
	// Error should contain the original error
	if !errors.Is(err, errFailed) {
		t.Errorf("error does not wrap errFailed: %v", err)
	}
}

func TestMultiNotifierWithMultipleErrors(t *testing.T) {
	err1 := errors.New("error 1")
	err2 := errors.New("error 2")
	mock1 := &mockNotifier{err: err1}
	mock2 := &mockNotifier{err: err2}
	multi := NewMultiNotifier(mock1, mock2)

	req := &request.Request{ID: "test1234567890123"}
	event := NewEvent(EventRequestCreated, req, "user")

	err := multi.Notify(context.Background(), event)

	if err == nil {
		t.Error("MultiNotifier.Notify() error = nil, want error")
	}
	if !errors.Is(err, err1) {
		t.Errorf("error does not wrap err1: %v", err)
	}
	if !errors.Is(err, err2) {
		t.Errorf("error does not wrap err2: %v", err)
	}
}

func TestNoopNotifier(t *testing.T) {
	noop := &NoopNotifier{}

	req := &request.Request{ID: "test1234567890123"}
	event := NewEvent(EventRequestCreated, req, "user")

	err := noop.Notify(context.Background(), event)

	if err != nil {
		t.Errorf("NoopNotifier.Notify() error = %v, want nil", err)
	}
}

func TestNoopNotifierMultipleCalls(t *testing.T) {
	noop := &NoopNotifier{}

	for i := 0; i < 100; i++ {
		req := &request.Request{ID: "test1234567890123"}
		event := NewEvent(EventRequestCreated, req, "user")
		err := noop.Notify(context.Background(), event)
		if err != nil {
			t.Errorf("NoopNotifier.Notify() call %d error = %v, want nil", i, err)
		}
	}
}
