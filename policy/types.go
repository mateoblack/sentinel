// Package policy defines Sentinel's access control policy schema.
// Policies contain rules that determine whether credential requests
// should be allowed or denied based on conditions like user, profile,
// and time constraints.
package policy

import "time"

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
	Name              string        `yaml:"name" json:"name"`
	Effect            Effect        `yaml:"effect" json:"effect"`
	Conditions        Condition     `yaml:"conditions" json:"conditions"`
	Reason            string        `yaml:"reason,omitempty" json:"reason,omitempty"`
	MaxServerDuration time.Duration `yaml:"max_server_duration,omitempty" json:"max_server_duration,omitempty"`
	// SessionTable specifies the DynamoDB table name for session tracking when
	// using require_server_session effect. If empty, uses the --session-table CLI flag.
	SessionTable string `yaml:"session_table,omitempty" json:"session_table,omitempty"`
}

// Effect is the outcome of a matched rule.
// It can be either "allow" (grant access) or "deny" (reject access).
type Effect string

const (
	// EffectAllow grants access when a rule matches.
	EffectAllow Effect = "allow"
	// EffectDeny rejects access when a rule matches.
	EffectDeny Effect = "deny"
	// EffectRequireApproval triggers approval workflow when a rule matches.
	// Instead of direct credential issuance, the request needs approval.
	EffectRequireApproval Effect = "require_approval"
	// EffectRequireServer allows access only when credentials are requested via server mode.
	// If the request mode is not 'server', access is denied with a clear error indicating
	// server mode is required.
	EffectRequireServer Effect = "require_server"
	// EffectRequireServerSession allows access only when credentials are requested via server mode
	// WITH session tracking enabled. If either condition is not met, access is denied with a clear
	// error indicating server mode with session tracking is required.
	EffectRequireServerSession Effect = "require_server_session"
)

// Condition defines matching criteria for a rule.
// All specified conditions must match for the rule to apply.
// Empty or nil conditions are considered to match any request.
type Condition struct {
	Profiles []string         `yaml:"profiles,omitempty" json:"profiles,omitempty"`
	Users    []string         `yaml:"users,omitempty" json:"users,omitempty"`
	Time     *TimeWindow      `yaml:"time,omitempty" json:"time,omitempty"`
	Mode     []CredentialMode `yaml:"mode,omitempty" json:"mode,omitempty"` // Empty = match any mode
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
	return e == EffectAllow || e == EffectDeny || e == EffectRequireApproval || e == EffectRequireServer || e == EffectRequireServerSession
}

// String returns the string representation of the Effect.
func (e Effect) String() string {
	return string(e)
}

// CredentialMode identifies how credentials are being requested.
// Server mode evaluates policy per-request, CLI mode evaluates once.
type CredentialMode string

const (
	// ModeServer indicates credentials served via credential server (per-request evaluation).
	ModeServer CredentialMode = "server"
	// ModeCLI indicates credentials served via exec command (one-time evaluation).
	ModeCLI CredentialMode = "cli"
	// ModeCredentialProcess indicates credentials served via credential_process (one-time evaluation).
	ModeCredentialProcess CredentialMode = "credential_process"
)

// IsValid returns true if the CredentialMode is a known value.
func (m CredentialMode) IsValid() bool {
	return m == ModeServer || m == ModeCLI || m == ModeCredentialProcess
}

// String returns the string representation of the CredentialMode.
func (m CredentialMode) String() string {
	return string(m)
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
