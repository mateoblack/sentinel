// Package policy defines Sentinel's access control policy schema.
//
// # Approval Workflow
//
// Access policy rules determine if a profile needs approval (effect: require_approval).
// Approval policy rules determine who can approve requests and auto-approve conditions.
//
// This separation allows:
//   - Access policy to be simple (allow/deny/require_approval)
//   - Approval routing to be complex (different approvers per profile, time-based auto-approve)
//
// When a request matches a rule with effect "require_approval":
//  1. Request is created with pending status
//  2. Approval policy is consulted to determine approvers
//  3. If auto-approve conditions match, request is automatically approved
//  4. Otherwise, designated approvers must explicitly approve
package policy

import "time"

// ApprovalPolicy defines approval routing and auto-approve rules.
// It contains a version identifier and a list of approval rules that determine
// who can approve requests for specific profiles.
type ApprovalPolicy struct {
	Version string         `yaml:"version" json:"version"`
	Rules   []ApprovalRule `yaml:"rules" json:"rules"`
}

// ApprovalRule defines who can approve requests for matching profiles.
// Rules are evaluated to find designated approvers and auto-approve conditions.
type ApprovalRule struct {
	// Name identifies this approval rule for logging and debugging.
	Name string `yaml:"name" json:"name"`

	// Profiles lists which AWS profiles this rule applies to.
	// If empty, the rule applies to all profiles requiring approval.
	Profiles []string `yaml:"profiles,omitempty" json:"profiles,omitempty"`

	// Approvers lists usernames who can approve requests matching this rule.
	Approvers []string `yaml:"approvers" json:"approvers"`

	// AutoApprove defines conditions for automatic approval.
	// If nil, requests require explicit approval from designated approvers.
	AutoApprove *AutoApproveCondition `yaml:"auto_approve,omitempty" json:"auto_approve,omitempty"`
}

// AutoApproveCondition defines when requests can be auto-approved.
// If conditions match, the request is automatically approved without
// requiring an explicit approver action.
type AutoApproveCondition struct {
	// Users who can self-approve (empty = no self-approval).
	// When a user in this list makes a request, it can be auto-approved
	// if other conditions (Time, MaxDuration) are also satisfied.
	Users []string `yaml:"users,omitempty" json:"users,omitempty"`

	// Time window when auto-approve is allowed (nil = any time).
	// Useful for allowing self-approval only during business hours.
	Time *TimeWindow `yaml:"time,omitempty" json:"time,omitempty"`

	// MaxDuration caps the duration for auto-approved requests.
	// Requests for longer durations require explicit approval.
	// Zero means no duration cap for auto-approval.
	MaxDuration time.Duration `yaml:"max_duration,omitempty" json:"max_duration,omitempty"`
}
