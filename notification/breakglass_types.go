// Package notification provides event types for Sentinel's notification system.
// This file contains break-glass notification event types for security alerts
// when emergency access is invoked, closed, or expires.

package notification

import (
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
)

// BreakGlassEventType represents the type of break-glass notification event.
// Events correspond to break-glass lifecycle state changes.
type BreakGlassEventType string

const (
	// EventBreakGlassInvoked is emitted when break-glass emergency access is invoked.
	EventBreakGlassInvoked BreakGlassEventType = "breakglass.invoked"
	// EventBreakGlassClosed is emitted when break-glass access is manually closed.
	EventBreakGlassClosed BreakGlassEventType = "breakglass.closed"
	// EventBreakGlassExpired is emitted when break-glass access expires due to TTL.
	EventBreakGlassExpired BreakGlassEventType = "breakglass.expired"
)

// IsValid returns true if the BreakGlassEventType is a known value.
func (t BreakGlassEventType) IsValid() bool {
	switch t {
	case EventBreakGlassInvoked, EventBreakGlassClosed, EventBreakGlassExpired:
		return true
	}
	return false
}

// String returns the string representation of the BreakGlassEventType.
func (t BreakGlassEventType) String() string {
	return string(t)
}

// BreakGlassEvent represents a notification event triggered by a break-glass state change.
// It contains the event type, the break-glass event that triggered it, when it occurred,
// and who triggered the event.
type BreakGlassEvent struct {
	// Type is the event type (invoked, closed, expired).
	Type BreakGlassEventType

	// BreakGlass is the break-glass event that triggered this notification.
	BreakGlass *breakglass.BreakGlassEvent

	// Timestamp is when the event occurred.
	Timestamp time.Time

	// Actor is who triggered the event:
	//   - invoker username for invoked
	//   - closer username for closed
	//   - "system" for expired
	Actor string
}

// NewBreakGlassEvent creates a new break-glass notification event.
// The timestamp is set to the current time.
func NewBreakGlassEvent(eventType BreakGlassEventType, bg *breakglass.BreakGlassEvent, actor string) *BreakGlassEvent {
	return &BreakGlassEvent{
		Type:       eventType,
		BreakGlass: bg,
		Timestamp:  time.Now(),
		Actor:      actor,
	}
}
