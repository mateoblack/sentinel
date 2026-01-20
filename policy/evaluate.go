package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Request represents a credential request to be evaluated.
type Request struct {
	User    string
	Profile string
	Time    time.Time
	Mode    CredentialMode // Credential delivery mode (server, cli, credential_process)
}

// Decision represents the outcome of policy evaluation.
type Decision struct {
	Effect             Effect
	MatchedRule        string
	Reason             string
	RuleIndex          int           // Position of matched rule in policy (0-based, -1 if no match)
	Conditions         *Condition    // Copy of matched rule's conditions for logging (nil for default deny)
	EvaluatedAt        time.Time     // Timestamp when evaluation occurred
	MaxServerDuration  time.Duration // Policy-imposed cap on server mode session duration (0 = no cap)
	RequiresServerMode bool          // True when EffectRequireServer matched but mode was not server
}

// String returns a human-readable representation of the decision.
func (d Decision) String() string {
	if d.MatchedRule == "" {
		return "DENY (no matching rule)"
	}
	return fmt.Sprintf("%s by rule '%s' (index %d)", strings.ToUpper(string(d.Effect)), d.MatchedRule, d.RuleIndex)
}

// defaultDeny returns the default deny decision when no rules match.
func defaultDeny(evaluatedAt time.Time) Decision {
	return Decision{
		Effect:      EffectDeny,
		MatchedRule: "",
		Reason:      "no matching rule",
		RuleIndex:   -1,
		Conditions:  nil,
		EvaluatedAt: evaluatedAt,
	}
}

// Evaluate evaluates a credential request against a policy.
// It returns the decision for the first matching rule, or default deny if no rules match.
func Evaluate(policy *Policy, req *Request) Decision {
	evaluatedAt := time.Now()

	if policy == nil || req == nil {
		return defaultDeny(evaluatedAt)
	}

	for i, rule := range policy.Rules {
		if matchesConditions(&rule.Conditions, req) {
			// Copy conditions to avoid reference to original
			conditionsCopy := rule.Conditions
			return Decision{
				Effect:            rule.Effect,
				MatchedRule:       rule.Name,
				Reason:            rule.Reason,
				RuleIndex:         i,
				Conditions:        &conditionsCopy,
				EvaluatedAt:       evaluatedAt,
				MaxServerDuration: rule.MaxServerDuration,
			}
		}
	}

	return defaultDeny(evaluatedAt)
}

// matchesConditions checks if all conditions in a rule match the request.
// All specified conditions must match for the rule to apply.
// Empty or nil conditions are considered to match any request.
func matchesConditions(c *Condition, req *Request) bool {
	if !matchesProfiles(c.Profiles, req.Profile) {
		return false
	}
	if !matchesUsers(c.Users, req.User) {
		return false
	}
	if !matchesTimeWindow(c.Time, req.Time) {
		return false
	}
	if !matchesMode(c.Mode, req.Mode) {
		return false
	}
	return true
}

// matchesMode checks if the request mode matches the condition.
// An empty mode list matches any mode.
func matchesMode(modes []CredentialMode, mode CredentialMode) bool {
	if len(modes) == 0 {
		return true
	}
	for _, m := range modes {
		if m == mode {
			return true
		}
	}
	return false
}

// matchesProfiles checks if the request profile matches the condition.
// An empty profiles list matches any profile.
func matchesProfiles(profiles []string, profile string) bool {
	return containsOrEmpty(profiles, profile)
}

// matchesUsers checks if the request user matches the condition.
// An empty users list matches any user.
func matchesUsers(users []string, user string) bool {
	return containsOrEmpty(users, user)
}

// containsOrEmpty returns true if the list is empty or contains the value.
// An empty list matches any value (acts as wildcard).
func containsOrEmpty(list []string, value string) bool {
	if len(list) == 0 {
		return true
	}
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// matchesTimeWindow checks if the request time falls within the time window.
// A nil time window matches any time.
func matchesTimeWindow(tw *TimeWindow, t time.Time) bool {
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
func matchesDays(days []Weekday, t time.Time) bool {
	if len(days) == 0 {
		return true
	}

	// Convert Go's time.Weekday to our Weekday type
	goDay := t.Weekday()
	requestDay := goWeekdayToWeekday(goDay)

	for _, d := range days {
		if d == requestDay {
			return true
		}
	}
	return false
}

// goWeekdayToWeekday converts Go's time.Weekday to our Weekday type.
func goWeekdayToWeekday(d time.Weekday) Weekday {
	switch d {
	case time.Monday:
		return Monday
	case time.Tuesday:
		return Tuesday
	case time.Wednesday:
		return Wednesday
	case time.Thursday:
		return Thursday
	case time.Friday:
		return Friday
	case time.Saturday:
		return Saturday
	case time.Sunday:
		return Sunday
	default:
		return ""
	}
}

// matchesHours checks if the time falls within the hour range.
// A nil hour range matches any time of day.
// The range is inclusive of start and exclusive of end: [start, end).
func matchesHours(hr *HourRange, t time.Time) bool {
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
// Assumes the format has already been validated by hourFormatRegex.
func parseHourMinute(s string) (hour, minute int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0
	}
	hour, _ = strconv.Atoi(parts[0])
	minute, _ = strconv.Atoi(parts[1])
	return hour, minute
}
