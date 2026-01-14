// Package policy defines Sentinel's access control policy schema.
// Policies contain rules that determine whether credential requests
// should be allowed or denied based on conditions like user, profile,
// and time constraints.
package policy

// Policy is the top-level container for access rules.
// It contains a version identifier and a list of rules that are
// evaluated in order to determine access decisions.
type Policy struct {
	Version string `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

// Rule defines a single access control rule.
// Rules are evaluated in order, and the first matching rule determines
// the access decision. Each rule specifies an effect (allow/deny),
// conditions that must match, and an optional reason for logging.
type Rule struct {
	Name       string    `yaml:"name" json:"name"`
	Effect     Effect    `yaml:"effect" json:"effect"`
	Conditions Condition `yaml:"conditions" json:"conditions"`
	Reason     string    `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// Effect is the outcome of a matched rule.
// It can be either "allow" (grant access) or "deny" (reject access).
type Effect string

const (
	// EffectAllow grants access when a rule matches.
	EffectAllow Effect = "allow"
	// EffectDeny rejects access when a rule matches.
	EffectDeny Effect = "deny"
)

// Condition defines matching criteria for a rule.
// All specified conditions must match for the rule to apply.
// Empty or nil conditions are considered to match any request.
type Condition struct {
	Profiles []string    `yaml:"profiles,omitempty" json:"profiles,omitempty"`
	Users    []string    `yaml:"users,omitempty" json:"users,omitempty"`
	Time     *TimeWindow `yaml:"time,omitempty" json:"time,omitempty"`
}

// TimeWindow restricts when a rule applies.
// It allows limiting access to specific days of the week,
// hours of the day, and timezones.
type TimeWindow struct {
	Days     []Weekday  `yaml:"days,omitempty" json:"days,omitempty"`
	Hours    *HourRange `yaml:"hours,omitempty" json:"hours,omitempty"`
	Timezone string     `yaml:"timezone,omitempty" json:"timezone,omitempty"`
}

// Weekday represents a day of the week.
// Days are specified as lowercase strings (monday, tuesday, etc.).
type Weekday string

const (
	// Monday represents Monday.
	Monday Weekday = "monday"
	// Tuesday represents Tuesday.
	Tuesday Weekday = "tuesday"
	// Wednesday represents Wednesday.
	Wednesday Weekday = "wednesday"
	// Thursday represents Thursday.
	Thursday Weekday = "thursday"
	// Friday represents Friday.
	Friday Weekday = "friday"
	// Saturday represents Saturday.
	Saturday Weekday = "saturday"
	// Sunday represents Sunday.
	Sunday Weekday = "sunday"
)

// HourRange defines a daily time window.
// Start and End times are specified in 24-hour format (HH:MM).
type HourRange struct {
	Start string `yaml:"start" json:"start"` // Format: "HH:MM" (24-hour)
	End   string `yaml:"end" json:"end"`     // Format: "HH:MM" (24-hour)
}

// IsValid returns true if the Effect is a known value.
func (e Effect) IsValid() bool {
	return e == EffectAllow || e == EffectDeny
}

// String returns the string representation of the Effect.
func (e Effect) String() string {
	return string(e)
}

// IsValid returns true if the Weekday is a known value.
func (w Weekday) IsValid() bool {
	switch w {
	case Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday:
		return true
	}
	return false
}

// String returns the string representation of the Weekday.
func (w Weekday) String() string {
	return string(w)
}

// AllWeekdays returns all valid weekday values.
func AllWeekdays() []Weekday {
	return []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday}
}
