package logging

import (
	"time"

	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/policy"
)

// DecisionLogEntry captures all context for an access decision.
type DecisionLogEntry struct {
	Timestamp       string `json:"timestamp"`                          // ISO8601 format
	User            string `json:"user"`                               // Username making the request
	Profile         string `json:"profile"`                            // AWS profile requested
	Effect          string `json:"effect"`                             // "allow" or "deny"
	Rule            string `json:"rule"`                               // Matched rule name (empty if default deny)
	RuleIndex       int    `json:"rule_index"`                         // Position of matched rule (-1 if no match)
	Reason          string `json:"reason"`                             // Rule's reason or "no matching rule"
	PolicyPath      string `json:"policy_path"`                        // SSM parameter path
	RequestID       string `json:"request_id,omitempty"`               // 8-char hex request identifier
	SourceIdentity  string `json:"source_identity,omitempty"`          // Full sentinel:user:request-id string
	RoleARN         string `json:"role_arn,omitempty"`                 // Target role ARN if applicable
	SessionDuration int    `json:"session_duration_seconds,omitempty"` // Session duration in seconds
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
