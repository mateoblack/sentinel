// Package notification provides event types and interfaces for Sentinel's
// notification system. It enables pluggable notification delivery on request
// lifecycle events such as creation, approval, denial, expiration, and cancellation.
//
// # Event Types
//
// Events are emitted when request state changes:
//   - request.created: A new access request was submitted
//   - request.approved: A request was approved by an approver
//   - request.denied: A request was denied by an approver
//   - request.expired: A pending request timed out
//   - request.cancelled: A request was cancelled by the requester
//
// # Notification Delivery
//
// The Notifier interface allows pluggable notification backends (Slack, email,
// webhooks, etc.). MultiNotifier composes multiple backends for fanout delivery.
package notification

import (
	"time"

	"github.com/byteness/aws-vault/v7/request"
)

// EventType represents the type of notification event.
// Events correspond to request lifecycle state changes.
type EventType string

const (
	// EventRequestCreated is emitted when a new access request is submitted.
	EventRequestCreated EventType = "request.created"
	// EventRequestApproved is emitted when a request is approved by an approver.
	EventRequestApproved EventType = "request.approved"
	// EventRequestDenied is emitted when a request is denied by an approver.
	EventRequestDenied EventType = "request.denied"
	// EventRequestExpired is emitted when a pending request times out.
	EventRequestExpired EventType = "request.expired"
	// EventRequestCancelled is emitted when a request is cancelled by the requester.
	EventRequestCancelled EventType = "request.cancelled"
)

// IsValid returns true if the EventType is a known value.
func (t EventType) IsValid() bool {
	switch t {
	case EventRequestCreated, EventRequestApproved, EventRequestDenied,
		EventRequestExpired, EventRequestCancelled:
		return true
	}
	return false
}

// String returns the string representation of the EventType.
func (t EventType) String() string {
	return string(t)
}

// Event represents a notification event triggered by a request state change.
// It contains the event type, the request that triggered it, when it occurred,
// and who triggered the event.
type Event struct {
	// Type is the event type (created, approved, denied, expired, cancelled).
	Type EventType

	// Request is the request that triggered this event.
	Request *request.Request

	// Timestamp is when the event occurred.
	Timestamp time.Time

	// Actor is who triggered the event:
	//   - requester username for created/cancelled
	//   - approver username for approved/denied
	//   - "system" for expired
	Actor string
}

// NewEvent creates a new notification event.
// The timestamp is set to the current time.
func NewEvent(eventType EventType, req *request.Request, actor string) *Event {
	return &Event{
		Type:      eventType,
		Request:   req,
		Timestamp: time.Now(),
		Actor:     actor,
	}
}
