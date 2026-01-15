package logging

import (
	"time"

	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/request"
)

// ApprovalLogEntry captures all context for an approval workflow event.
// Events include: request.created, request.approved, request.denied,
// request.expired, request.cancelled.
type ApprovalLogEntry struct {
	Timestamp       string `json:"timestamp"`                     // ISO8601 format
	Event           string `json:"event"`                         // "request.created", "request.approved", etc.
	RequestID       string `json:"request_id"`                    // 16-char hex request ID
	Requester       string `json:"requester"`                     // Who requested access
	Profile         string `json:"profile"`                       // AWS profile requested
	Status          string `json:"status"`                        // Current status after event
	Actor           string `json:"actor"`                         // Who triggered event (requester, approver, or "system")
	Justification   string `json:"justification,omitempty"`       // Reason for request (on create)
	Duration        int    `json:"duration_seconds,omitempty"`    // Requested duration (on create)
	Approver        string `json:"approver,omitempty"`            // Who approved/denied
	ApproverComment string `json:"approver_comment,omitempty"`    // Comment from approver
	AutoApproved    bool   `json:"auto_approved,omitempty"`       // True if auto-approved by policy
}

// NewApprovalLogEntry creates an ApprovalLogEntry from a notification event.
// It populates fields based on the event type:
//   - request.created: includes justification, duration
//   - request.approved/denied: includes approver, approver_comment, auto_approved
//   - request.expired/cancelled: no additional optional fields
func NewApprovalLogEntry(event notification.EventType, req *request.Request, actor string) ApprovalLogEntry {
	entry := ApprovalLogEntry{
		Timestamp: iso8601.Format(time.Now()),
		Event:     string(event),
		RequestID: req.ID,
		Requester: req.Requester,
		Profile:   req.Profile,
		Status:    string(req.Status),
		Actor:     actor,
	}

	// Populate optional fields based on event type
	switch event {
	case notification.EventRequestCreated:
		entry.Justification = req.Justification
		if req.Duration > 0 {
			entry.Duration = int(req.Duration.Seconds())
		}

	case notification.EventRequestApproved, notification.EventRequestDenied:
		entry.Approver = req.Approver
		entry.ApproverComment = req.ApproverComment
		// Auto-approved if actor equals requester (self-approval via policy)
		if actor == req.Requester {
			entry.AutoApproved = true
		}
	}

	return entry
}
