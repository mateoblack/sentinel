// Rate limiting types and validation for break-glass abuse prevention.
// Follows the ApprovalPolicy pattern from policy/approval.go.

package breakglass

import (
	"fmt"
	"time"
)

// RateLimitPolicy defines cooldown and quota rules for break-glass events.
// It contains a version identifier and a list of rate limit rules that
// prevent abuse while allowing legitimate emergency access.
type RateLimitPolicy struct {
	Version string          `yaml:"version" json:"version"`
	Rules   []RateLimitRule `yaml:"rules" json:"rules"`
}

// RateLimitRule defines rate limits for matching profiles.
// Rules are evaluated to enforce cooldowns, quotas, and escalation thresholds.
type RateLimitRule struct {
	// Name identifies this rate limit rule for logging and debugging.
	Name string `yaml:"name" json:"name"`

	// Profiles lists which AWS profiles this rule applies to.
	// If empty, the rule applies to all profiles (wildcard).
	Profiles []string `yaml:"profiles,omitempty" json:"profiles,omitempty"`

	// Cooldown is the minimum time between break-glass events per user+profile.
	// Zero means no cooldown requirement.
	Cooldown time.Duration `yaml:"cooldown,omitempty" json:"cooldown,omitempty"`

	// MaxPerUser is the maximum break-glass events per user within QuotaWindow.
	// Zero means no per-user quota.
	MaxPerUser int `yaml:"max_per_user,omitempty" json:"max_per_user,omitempty"`

	// MaxPerProfile is the maximum break-glass events per profile within QuotaWindow.
	// Zero means no per-profile quota.
	MaxPerProfile int `yaml:"max_per_profile,omitempty" json:"max_per_profile,omitempty"`

	// QuotaWindow is the time window for quota counting (e.g., 24h).
	// Required if MaxPerUser > 0 or MaxPerProfile > 0.
	QuotaWindow time.Duration `yaml:"quota_window,omitempty" json:"quota_window,omitempty"`

	// EscalationThreshold triggers escalated notification when user exceeds this count.
	// Zero means no escalation notifications.
	EscalationThreshold int `yaml:"escalation_threshold,omitempty" json:"escalation_threshold,omitempty"`
}

// Validate checks if the RateLimitPolicy is semantically correct.
// It verifies at least one rule exists and all rules are valid.
func (p *RateLimitPolicy) Validate() error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("rate limit policy must have at least one rule")
	}

	for i, rule := range p.Rules {
		if err := rule.validate(i); err != nil {
			return err
		}
	}

	return nil
}

// validate checks if a RateLimitRule is semantically correct.
func (r *RateLimitRule) validate(index int) error {
	if r.Name == "" {
		return fmt.Errorf("rate limit rule at index %d missing name", index)
	}

	if r.Cooldown < 0 {
		return fmt.Errorf("rate limit rule '%s' has negative cooldown", r.Name)
	}

	if r.MaxPerUser < 0 {
		return fmt.Errorf("rate limit rule '%s' has negative max_per_user", r.Name)
	}

	if r.MaxPerProfile < 0 {
		return fmt.Errorf("rate limit rule '%s' has negative max_per_profile", r.Name)
	}

	// QuotaWindow must be > 0 if any quota is set
	hasQuota := r.MaxPerUser > 0 || r.MaxPerProfile > 0
	if hasQuota && r.QuotaWindow <= 0 {
		return fmt.Errorf("rate limit rule '%s' has quota limits but missing or invalid quota_window", r.Name)
	}

	// At least one limit must be set
	hasLimit := r.Cooldown > 0 || r.MaxPerUser > 0 || r.MaxPerProfile > 0
	if !hasLimit {
		return fmt.Errorf("rate limit rule '%s' must have at least one limit (cooldown, max_per_user, or max_per_profile)", r.Name)
	}

	if r.EscalationThreshold < 0 {
		return fmt.Errorf("rate limit rule '%s' has negative escalation_threshold", r.Name)
	}

	return nil
}

// FindRateLimitRule returns the first rule matching the given profile.
// An empty Profiles list in a rule acts as a wildcard and matches any profile.
// Returns nil if no rule matches or if policy is nil.
func FindRateLimitRule(policy *RateLimitPolicy, profile string) *RateLimitRule {
	if policy == nil {
		return nil
	}
	for i := range policy.Rules {
		rule := &policy.Rules[i]
		if containsOrEmpty(rule.Profiles, profile) {
			return rule
		}
	}
	return nil
}

// containsOrEmpty returns true if the slice is empty (wildcard) or contains the value.
func containsOrEmpty(slice []string, value string) bool {
	if len(slice) == 0 {
		return true // empty slice = wildcard
	}
	for _, s := range slice {
		if s == value {
			return true
		}
	}
	return false
}
