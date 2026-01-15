package notification

import (
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
)

func TestBreakGlassEventTypeIsValid(t *testing.T) {
	tests := []struct {
		name     string
		et       BreakGlassEventType
		expected bool
	}{
		{"valid invoked", EventBreakGlassInvoked, true},
		{"valid closed", EventBreakGlassClosed, true},
		{"valid expired", EventBreakGlassExpired, true},
		{"invalid empty", BreakGlassEventType(""), false},
		{"invalid unknown", BreakGlassEventType("unknown"), false},
		{"invalid typo", BreakGlassEventType("breakglass.invoke"), false},
		{"invalid request type", BreakGlassEventType("request.created"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.et.IsValid()
			if got != tc.expected {
				t.Errorf("BreakGlassEventType(%q).IsValid() = %v, want %v", tc.et, got, tc.expected)
			}
		})
	}
}

func TestBreakGlassEventTypeString(t *testing.T) {
	tests := []struct {
		et       BreakGlassEventType
		expected string
	}{
		{EventBreakGlassInvoked, "breakglass.invoked"},
		{EventBreakGlassClosed, "breakglass.closed"},
		{EventBreakGlassExpired, "breakglass.expired"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			got := tc.et.String()
			if got != tc.expected {
				t.Errorf("BreakGlassEventType.String() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestNewBreakGlassEvent(t *testing.T) {
	bg := &breakglass.BreakGlassEvent{
		ID:            "abc1234567890123",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Production database is down, need emergency access",
		Status:        breakglass.StatusActive,
	}

	before := time.Now()
	event := NewBreakGlassEvent(EventBreakGlassInvoked, bg, "alice")
	after := time.Now()

	if event.Type != EventBreakGlassInvoked {
		t.Errorf("BreakGlassEvent.Type = %v, want %v", event.Type, EventBreakGlassInvoked)
	}
	if event.BreakGlass != bg {
		t.Error("BreakGlassEvent.BreakGlass does not match input break-glass event")
	}
	if event.Actor != "alice" {
		t.Errorf("BreakGlassEvent.Actor = %q, want %q", event.Actor, "alice")
	}
	if event.Timestamp.Before(before) || event.Timestamp.After(after) {
		t.Errorf("BreakGlassEvent.Timestamp = %v, want between %v and %v", event.Timestamp, before, after)
	}
}

func TestNewBreakGlassEventClosed(t *testing.T) {
	bg := &breakglass.BreakGlassEvent{
		ID:           "def1234567890123",
		Invoker:      "bob",
		Profile:      "staging",
		Status:       breakglass.StatusClosed,
		ClosedBy:     "security-team",
		ClosedReason: "Incident resolved",
	}

	event := NewBreakGlassEvent(EventBreakGlassClosed, bg, "security-team")

	if event.Type != EventBreakGlassClosed {
		t.Errorf("BreakGlassEvent.Type = %v, want %v", event.Type, EventBreakGlassClosed)
	}
	if event.Actor != "security-team" {
		t.Errorf("BreakGlassEvent.Actor = %q, want %q", event.Actor, "security-team")
	}
}

func TestNewBreakGlassEventExpired(t *testing.T) {
	bg := &breakglass.BreakGlassEvent{
		ID:      "ghi1234567890123",
		Invoker: "dave",
		Profile: "production",
		Status:  breakglass.StatusExpired,
	}

	event := NewBreakGlassEvent(EventBreakGlassExpired, bg, "system")

	if event.Type != EventBreakGlassExpired {
		t.Errorf("BreakGlassEvent.Type = %v, want %v", event.Type, EventBreakGlassExpired)
	}
	if event.Actor != "system" {
		t.Errorf("BreakGlassEvent.Actor = %q, want %q", event.Actor, "system")
	}
}

func TestBreakGlassEventHoldsData(t *testing.T) {
	bg := &breakglass.BreakGlassEvent{
		ID:            "jkl1234567890123",
		Invoker:       "charlie",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonSecurity,
		Justification: "Suspected breach, need to investigate logs",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	event := NewBreakGlassEvent(EventBreakGlassInvoked, bg, "charlie")

	// Verify all break-glass data is accessible through the event
	if event.BreakGlass.ID != "jkl1234567890123" {
		t.Errorf("BreakGlassEvent.BreakGlass.ID = %q, want %q", event.BreakGlass.ID, "jkl1234567890123")
	}
	if event.BreakGlass.Invoker != "charlie" {
		t.Errorf("BreakGlassEvent.BreakGlass.Invoker = %q, want %q", event.BreakGlass.Invoker, "charlie")
	}
	if event.BreakGlass.Profile != "production" {
		t.Errorf("BreakGlassEvent.BreakGlass.Profile = %q, want %q", event.BreakGlass.Profile, "production")
	}
	if event.BreakGlass.ReasonCode != breakglass.ReasonSecurity {
		t.Errorf("BreakGlassEvent.BreakGlass.ReasonCode = %v, want %v", event.BreakGlass.ReasonCode, breakglass.ReasonSecurity)
	}
	if event.BreakGlass.Justification != "Suspected breach, need to investigate logs" {
		t.Errorf("BreakGlassEvent.BreakGlass.Justification = %q, want %q", event.BreakGlass.Justification, "Suspected breach, need to investigate logs")
	}
	if event.BreakGlass.Duration != 2*time.Hour {
		t.Errorf("BreakGlassEvent.BreakGlass.Duration = %v, want %v", event.BreakGlass.Duration, 2*time.Hour)
	}
	if event.BreakGlass.Status != breakglass.StatusActive {
		t.Errorf("BreakGlassEvent.BreakGlass.Status = %v, want %v", event.BreakGlass.Status, breakglass.StatusActive)
	}
}
