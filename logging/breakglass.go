package logging

import (
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/iso8601"
)

// Break-glass event type constants for audit logging.
const (
	// BreakGlassEventInvoked is logged when break-glass access is invoked.
	BreakGlassEventInvoked = "breakglass.invoked"
	// BreakGlassEventClosed is logged when break-glass access is manually closed.
	BreakGlassEventClosed = "breakglass.closed"
	// BreakGlassEventExpired is logged when break-glass access expires due to TTL.
	BreakGlassEventExpired = "breakglass.expired"
)

// BreakGlassLogEntry captures all context for a break-glass emergency access event.
// Events include: breakglass.invoked, breakglass.closed, breakglass.expired.
type BreakGlassLogEntry struct {
	Timestamp     string `json:"timestamp"`               // ISO8601 format
	Event         string `json:"event"`                   // "breakglass.invoked", "breakglass.closed", "breakglass.expired"
	EventID       string `json:"event_id"`                // 16-char hex break-glass event ID
	RequestID     string `json:"request_id"`              // 16-char hex request ID for CloudTrail correlation
	Invoker       string `json:"invoker"`                 // Who invoked break-glass
	Profile       string `json:"profile"`                 // AWS profile accessed
	ReasonCode    string `json:"reason_code"`             // Incident category (incident, maintenance, security, recovery, other)
	Justification string `json:"justification"`           // Mandatory detailed explanation (20-1000 chars)
	Status        string `json:"status"`                  // Current status (active, closed, expired)
	Duration      int    `json:"duration_seconds"`        // Requested duration in seconds
	ExpiresAt     string `json:"expires_at"`              // ISO8601 expiration time
	ClosedBy      string `json:"closed_by,omitempty"`     // Who closed (for closed events)
	ClosedReason  string `json:"closed_reason,omitempty"` // Why closed early
}

// NewBreakGlassLogEntry creates a BreakGlassLogEntry from a break-glass event.
// It populates fields based on the event type:
//   - breakglass.invoked: all mandatory fields, no closed fields
//   - breakglass.closed: includes closed_by and closed_reason
//   - breakglass.expired: includes status as expired, no closed_by/closed_reason
func NewBreakGlassLogEntry(event string, bg *breakglass.BreakGlassEvent) BreakGlassLogEntry {
	entry := BreakGlassLogEntry{
		Timestamp:     iso8601.Format(time.Now()),
		Event:         event,
		EventID:       bg.ID,
		RequestID:     bg.RequestID,
		Invoker:       bg.Invoker,
		Profile:       bg.Profile,
		ReasonCode:    string(bg.ReasonCode),
		Justification: bg.Justification,
		Status:        string(bg.Status),
		Duration:      int(bg.Duration.Seconds()),
		ExpiresAt:     iso8601.Format(bg.ExpiresAt),
	}

	// Populate closed fields only for closed/expired events
	switch event {
	case BreakGlassEventClosed:
		entry.ClosedBy = bg.ClosedBy
		entry.ClosedReason = bg.ClosedReason
	case BreakGlassEventExpired:
		// Expired events don't have ClosedBy/ClosedReason (system expired)
		// Status is already set from bg.Status
	}

	return entry
}
