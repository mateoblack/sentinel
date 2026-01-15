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

import (
	"fmt"
	"time"

	"github.com/byteness/aws-vault/v7/request"
)

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

// Validate checks if the ApprovalPolicy is semantically correct.
// It verifies at least one rule exists and all rules are valid.
func (p *ApprovalPolicy) Validate() error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("approval policy must have at least one rule")
	}

	for i, rule := range p.Rules {
		if err := rule.validate(i); err != nil {
			return err
		}
	}

	return nil
}

// validate checks if an ApprovalRule is semantically correct.
// It verifies name is present, at least one approver exists,
// and any auto-approve condition is valid.
func (r *ApprovalRule) validate(index int) error {
	if r.Name == "" {
		return fmt.Errorf("approval rule at index %d missing name", index)
	}

	if len(r.Approvers) == 0 {
		return fmt.Errorf("approval rule '%s' must have at least one approver", r.Name)
	}

	if r.AutoApprove != nil {
		if err := r.AutoApprove.validate(r.Name); err != nil {
			return err
		}
	}

	return nil
}

// validate checks if an AutoApproveCondition is semantically correct.
// At least one condition must be set (users, time, or max_duration).
func (a *AutoApproveCondition) validate(ruleName string) error {
	hasCondition := len(a.Users) > 0 || a.Time != nil || a.MaxDuration > 0

	if !hasCondition {
		return fmt.Errorf("auto_approve in rule '%s' must have at least one condition (users, time, or max_duration)", ruleName)
	}

	if a.Time != nil {
		if err := a.Time.validate(ruleName); err != nil {
			return err
		}
	}

	if a.MaxDuration > 0 && a.MaxDuration > request.MaxDuration {
		return fmt.Errorf("auto_approve max_duration in rule '%s' exceeds maximum of %v", ruleName, request.MaxDuration)
	}

	return nil
}
