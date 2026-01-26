// Break-glass policy types and validation for authorization rules.
// Follows the ApprovalPolicy pattern from policy/approval.go.

package breakglass

import (
	"fmt"
	"time"

	"github.com/byteness/aws-vault/v7/mfa"
	"github.com/byteness/aws-vault/v7/policy"
)

// BreakGlassPolicy defines authorization rules for break-glass invocation.
// It contains a version identifier and a list of rules that determine
// who can invoke break-glass for which profiles.
type BreakGlassPolicy struct {
	Version string                 `yaml:"version" json:"version"`
	Rules   []BreakGlassPolicyRule `yaml:"rules" json:"rules"`
}

// MFARequirement specifies MFA enforcement for break-glass.
type MFARequirement struct {
	// Required enables MFA verification before break-glass access.
	// If true, users must complete MFA challenge before invoking break-glass.
	Required bool `yaml:"required" json:"required"`

	// Methods lists allowed MFA methods (empty = all methods allowed).
	// Valid values: "totp", "sms"
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}

// BreakGlassPolicyRule defines who can invoke break-glass for matching profiles.
// Rules are evaluated to authorize users and enforce restrictions.
type BreakGlassPolicyRule struct {
	// Name identifies this policy rule for logging and debugging.
	Name string `yaml:"name" json:"name"`

	// Profiles lists which AWS profiles this rule applies to.
	// If empty, the rule applies to all profiles (wildcard).
	Profiles []string `yaml:"profiles,omitempty" json:"profiles,omitempty"`

	// Users lists who is authorized to invoke break-glass for matching profiles.
	// At least one user must be specified.
	Users []string `yaml:"users" json:"users"`

	// AllowedReasonCodes restricts which reason codes can be used.
	// If empty, all reason codes are allowed.
	AllowedReasonCodes []ReasonCode `yaml:"allowed_reason_codes,omitempty" json:"allowed_reason_codes,omitempty"`

	// Time restricts when break-glass can be invoked (nil = any time).
	Time *policy.TimeWindow `yaml:"time,omitempty" json:"time,omitempty"`

	// MaxDuration caps the duration for this rule (0 = use system default).
	MaxDuration time.Duration `yaml:"max_duration,omitempty" json:"max_duration,omitempty"`

	// MFA specifies multi-factor authentication requirements.
	// If nil, MFA is not required for this rule.
	MFA *MFARequirement `yaml:"mfa,omitempty" json:"mfa,omitempty"`
}

// Validate checks if the BreakGlassPolicy is semantically correct.
// It verifies at least one rule exists and all rules are valid.
func (p *BreakGlassPolicy) Validate() error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("break-glass policy must have at least one rule")
	}

	for i, rule := range p.Rules {
		if err := rule.validate(i); err != nil {
			return err
		}
	}

	return nil
}

// validate checks if a BreakGlassPolicyRule is semantically correct.
// It verifies name is present, at least one user exists, and all
// optional constraints are valid.
func (r *BreakGlassPolicyRule) validate(index int) error {
	if r.Name == "" {
		return fmt.Errorf("break-glass policy rule at index %d missing name", index)
	}

	if len(r.Users) == 0 {
		return fmt.Errorf("break-glass policy rule '%s' must have at least one user", r.Name)
	}

	// Validate reason codes if specified
	for _, rc := range r.AllowedReasonCodes {
		if !rc.IsValid() {
			return fmt.Errorf("break-glass policy rule '%s' has invalid reason code '%s'", r.Name, rc)
		}
	}

	// Validate time window if specified
	if r.Time != nil {
		if err := validateTimeWindow(r.Time, r.Name); err != nil {
			return err
		}
	}

	// Validate MaxDuration
	if r.MaxDuration < 0 {
		return fmt.Errorf("break-glass policy rule '%s' has negative max_duration", r.Name)
	}

	if r.MaxDuration > MaxDuration {
		return fmt.Errorf("break-glass policy rule '%s' max_duration exceeds maximum of %v", r.Name, MaxDuration)
	}

	// Validate MFA requirements if specified
	if r.MFA != nil && r.MFA.Required && len(r.MFA.Methods) > 0 {
		for _, method := range r.MFA.Methods {
			if !mfa.MFAMethod(method).IsValid() {
				return fmt.Errorf("break-glass policy rule '%s' has invalid MFA method '%s'", r.Name, method)
			}
		}
	}

	return nil
}

// validateTimeWindow validates a TimeWindow for a rule.
// Replicates policy.TimeWindow.validate logic since it's not exported.
func validateTimeWindow(tw *policy.TimeWindow, ruleName string) error {
	for _, day := range tw.Days {
		if !day.IsValid() {
			return fmt.Errorf("invalid weekday '%s' in rule '%s'", day, ruleName)
		}
	}

	if tw.Timezone != "" {
		if _, err := time.LoadLocation(tw.Timezone); err != nil {
			return fmt.Errorf("invalid timezone '%s' in rule '%s'", tw.Timezone, ruleName)
		}
	}

	if tw.Hours != nil {
		if err := tw.Hours.Validate(); err != nil {
			return fmt.Errorf("in rule '%s': %w", ruleName, err)
		}
	}

	return nil
}

// FindBreakGlassPolicyRule returns the first rule matching the given profile.
// An empty Profiles list in a rule acts as a wildcard and matches any profile.
// Returns nil if no rule matches or if policy is nil.
func FindBreakGlassPolicyRule(p *BreakGlassPolicy, profile string) *BreakGlassPolicyRule {
	if p == nil {
		return nil
	}
	for i := range p.Rules {
		rule := &p.Rules[i]
		if containsOrEmpty(rule.Profiles, profile) {
			return rule
		}
	}
	return nil
}

// CanInvokeBreakGlass returns true if the given user is authorized to invoke
// break-glass for the profile matched by this rule.
// Returns false if rule is nil or user is not in the Users list.
func CanInvokeBreakGlass(rule *BreakGlassPolicyRule, user string) bool {
	if rule == nil {
		return false
	}
	for _, u := range rule.Users {
		if u == user {
			return true
		}
	}
	return false
}

// IsBreakGlassAllowed performs a comprehensive authorization check.
// It verifies:
//   - User is in rule.Users (via CanInvokeBreakGlass)
//   - ReasonCode is in AllowedReasonCodes (empty = all allowed)
//   - requestTime falls within Time window (nil = any time)
//   - duration is <= MaxDuration (0 = no cap)
//
// Returns false if rule is nil.
func IsBreakGlassAllowed(rule *BreakGlassPolicyRule, user string, reasonCode ReasonCode, requestTime time.Time, duration time.Duration) bool {
	if rule == nil {
		return false
	}

	// Check user authorization
	if !CanInvokeBreakGlass(rule, user) {
		return false
	}

	// Check reason code (empty = all allowed)
	if len(rule.AllowedReasonCodes) > 0 {
		found := false
		for _, rc := range rule.AllowedReasonCodes {
			if rc == reasonCode {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check time window (nil = any time)
	if rule.Time != nil {
		if !matchesTimeWindow(rule.Time, requestTime) {
			return false
		}
	}

	// Check duration cap (0 = no cap)
	if rule.MaxDuration > 0 && duration > rule.MaxDuration {
		return false
	}

	return true
}

// matchesTimeWindow checks if the request time falls within the time window.
// Replicates policy.matchesTimeWindow logic since it's not exported.
func matchesTimeWindow(tw *policy.TimeWindow, t time.Time) bool {
	if tw == nil {
		return true
	}

	// Convert time to the rule's timezone if specified
	evalTime := t
	if tw.Timezone != "" {
		loc, err := time.LoadLocation(tw.Timezone)
		if err == nil {
			evalTime = t.In(loc)
		}
	}

	// Check day of week constraint
	if !matchesDays(tw.Days, evalTime) {
		return false
	}

	// Check hour range constraint
	if !matchesHours(tw.Hours, evalTime) {
		return false
	}

	return true
}

// matchesDays checks if the time falls on one of the specified days.
// An empty days list matches any day.
func matchesDays(days []policy.Weekday, t time.Time) bool {
	if len(days) == 0 {
		return true
	}

	goDay := t.Weekday()
	requestDay := goWeekdayToWeekday(goDay)

	for _, d := range days {
		if d == requestDay {
			return true
		}
	}
	return false
}

// goWeekdayToWeekday converts Go's time.Weekday to policy.Weekday.
func goWeekdayToWeekday(d time.Weekday) policy.Weekday {
	switch d {
	case time.Monday:
		return policy.Monday
	case time.Tuesday:
		return policy.Tuesday
	case time.Wednesday:
		return policy.Wednesday
	case time.Thursday:
		return policy.Thursday
	case time.Friday:
		return policy.Friday
	case time.Saturday:
		return policy.Saturday
	case time.Sunday:
		return policy.Sunday
	default:
		return ""
	}
}

// matchesHours checks if the time falls within the hour range.
// A nil hour range matches any time of day.
func matchesHours(hr *policy.HourRange, t time.Time) bool {
	if hr == nil {
		return true
	}

	startHour, startMin := parseHourMinute(hr.Start)
	endHour, endMin := parseHourMinute(hr.End)

	reqHour := t.Hour()
	reqMin := t.Minute()

	// Convert to minutes since midnight for easier comparison
	reqMinutes := reqHour*60 + reqMin
	startMinutes := startHour*60 + startMin
	endMinutes := endHour*60 + endMin

	// Check if request time is in range [start, end)
	return reqMinutes >= startMinutes && reqMinutes < endMinutes
}

// parseHourMinute parses a HH:MM string and returns hour and minute.
func parseHourMinute(s string) (hour, minute int) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0
	}
	hour = int(s[0]-'0')*10 + int(s[1]-'0')
	minute = int(s[3]-'0')*10 + int(s[4]-'0')
	return hour, minute
}

// RequiresMFA returns true if the rule requires MFA verification.
func (r *BreakGlassPolicyRule) RequiresMFA() bool {
	return r.MFA != nil && r.MFA.Required
}

// IsMethodAllowed returns true if the given MFA method is allowed by the rule.
// Returns true if no method restrictions (empty Methods list).
func (r *BreakGlassPolicyRule) IsMethodAllowed(method string) bool {
	if r.MFA == nil || len(r.MFA.Methods) == 0 {
		return true
	}
	for _, m := range r.MFA.Methods {
		if m == method {
			return true
		}
	}
	return false
}
