package logging

import (
	"time"

	"github.com/byteness/aws-vault/v7/device"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/policy"
)

// DecisionLogEntry captures all context for an access decision.
type DecisionLogEntry struct {
	Timestamp         string `json:"timestamp"`                          // ISO8601 format
	User              string `json:"user"`                               // Username making the request
	Profile           string `json:"profile"`                            // AWS profile requested
	Effect            string `json:"effect"`                             // "allow" or "deny"
	Rule              string `json:"rule"`                               // Matched rule name (empty if default deny)
	RuleIndex         int    `json:"rule_index"`                         // Position of matched rule (-1 if no match)
	Reason            string `json:"reason"`                             // Rule's reason or "no matching rule"
	PolicyPath        string `json:"policy_path"`                        // SSM parameter path
	RequestID         string `json:"request_id,omitempty"`               // 8-char hex request identifier
	SourceIdentity    string `json:"source_identity,omitempty"`          // Full sentinel:user:request-id string
	RoleARN           string `json:"role_arn,omitempty"`                 // Target role ARN if applicable
	SessionDuration   int    `json:"session_duration_seconds,omitempty"` // Session duration in seconds
	ApprovedRequestID string `json:"approved_request_id,omitempty"`      // ID of approved request that overrode policy deny
	BreakGlassEventID string `json:"break_glass_event_id,omitempty"`     // ID of break-glass event that overrode policy deny
	DriftStatus       string `json:"drift_status,omitempty"`             // Sentinel enforcement drift status: "ok", "partial", "none", "unknown"
	DriftMessage      string `json:"drift_message,omitempty"`            // Human-readable explanation of drift status

	// Device posture context (populated when device posture is evaluated)
	DeviceID          string `json:"device_id,omitempty"`           // Device identifier
	DeviceStatus      string `json:"device_status,omitempty"`       // compliant, non_compliant, unknown
	DeviceDiskEncrypt bool   `json:"device_disk_encrypted,omitempty"` // Disk encryption status
	DeviceMDMEnrolled bool   `json:"device_mdm_enrolled,omitempty"`   // MDM enrollment status
	DeviceOSType      string `json:"device_os_type,omitempty"`        // darwin, windows, linux
	DeviceOSVersion   string `json:"device_os_version,omitempty"`     // OS version string
}

// NewDecisionLogEntry creates a DecisionLogEntry from policy evaluation results.
func NewDecisionLogEntry(req *policy.Request, decision policy.Decision, policyPath string) DecisionLogEntry {
	return DecisionLogEntry{
		Timestamp:  iso8601.Format(time.Now()),
		User:       req.User,
		Profile:    req.Profile,
		Effect:     string(decision.Effect),
		Rule:       decision.MatchedRule,
		RuleIndex:  decision.RuleIndex,
		Reason:     decision.Reason,
		PolicyPath: policyPath,
	}
}

// CredentialIssuanceFields contains fields populated when credentials are issued.
type CredentialIssuanceFields struct {
	RequestID         string
	SourceIdentity    string // Full sentinel:user:request-id string
	RoleARN           string
	SessionDuration   time.Duration
	ApprovedRequestID string // ID of approved request that overrode policy deny (empty if policy allowed)
	BreakGlassEventID string // ID of break-glass event that overrode policy deny (empty if not break-glass)
	DriftStatus       string // Drift check result: "ok", "partial", "none", "unknown"
	DriftMessage      string // Human-readable explanation of drift status

	// DevicePosture contains device posture data (nil if not evaluated)
	DevicePosture *device.DevicePosture
}

// NewEnhancedDecisionLogEntry creates a DecisionLogEntry with credential issuance details.
// Use this when credentials are being issued (allow decisions with credential context).
func NewEnhancedDecisionLogEntry(req *policy.Request, decision policy.Decision, policyPath string, creds *CredentialIssuanceFields) DecisionLogEntry {
	entry := NewDecisionLogEntry(req, decision, policyPath)

	if creds != nil {
		entry.RequestID = creds.RequestID
		entry.SourceIdentity = creds.SourceIdentity
		entry.RoleARN = creds.RoleARN
		if creds.SessionDuration > 0 {
			entry.SessionDuration = int(creds.SessionDuration.Seconds())
		}
		entry.ApprovedRequestID = creds.ApprovedRequestID
		entry.BreakGlassEventID = creds.BreakGlassEventID
		entry.DriftStatus = creds.DriftStatus
		entry.DriftMessage = creds.DriftMessage

		// Populate device posture fields if present
		if creds.DevicePosture != nil {
			entry.DeviceID = creds.DevicePosture.DeviceID
			entry.DeviceStatus = string(creds.DevicePosture.Status)
			if creds.DevicePosture.DiskEncrypted != nil {
				entry.DeviceDiskEncrypt = *creds.DevicePosture.DiskEncrypted
			}
			if creds.DevicePosture.MDMEnrolled != nil {
				entry.DeviceMDMEnrolled = *creds.DevicePosture.MDMEnrolled
			}
			entry.DeviceOSType = creds.DevicePosture.OSType
			entry.DeviceOSVersion = creds.DevicePosture.OSVersion
		}
	}

	return entry
}
