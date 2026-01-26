package breakglass

import (
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/policy"
)

// TestBreakGlassPolicyValidate tests validation of BreakGlassPolicy.
func TestBreakGlassPolicyValidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  BreakGlassPolicy
		wantErr string
	}{
		{
			name: "valid policy with one rule",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "default",
						Users: []string{"admin"},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid policy with multiple rules",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:     "prod-rule",
						Profiles: []string{"prod"},
						Users:    []string{"oncall", "sre"},
					},
					{
						Name:  "default",
						Users: []string{"admin"},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid policy with all constraints",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:               "restricted-rule",
						Profiles:           []string{"prod"},
						Users:              []string{"oncall"},
						AllowedReasonCodes: []ReasonCode{ReasonIncident, ReasonSecurity},
						Time: &policy.TimeWindow{
							Days:     []policy.Weekday{policy.Monday, policy.Tuesday},
							Hours:    &policy.HourRange{Start: "09:00", End: "18:00"},
							Timezone: "America/New_York",
						},
						MaxDuration: 2 * time.Hour,
					},
				},
			},
			wantErr: "",
		},
		{
			name: "empty rules",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules:   []BreakGlassPolicyRule{},
			},
			wantErr: "at least one rule",
		},
		{
			name: "nil rules",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules:   nil,
			},
			wantErr: "at least one rule",
		},
		{
			name: "rule missing name",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "",
						Users: []string{"admin"},
					},
				},
			},
			wantErr: "missing name",
		},
		{
			name: "rule missing users",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "test",
						Users: []string{},
					},
				},
			},
			wantErr: "at least one user",
		},
		{
			name: "rule with nil users",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "test",
						Users: nil,
					},
				},
			},
			wantErr: "at least one user",
		},
		{
			name: "invalid reason code",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:               "test",
						Users:              []string{"admin"},
						AllowedReasonCodes: []ReasonCode{ReasonCode("invalid")},
					},
				},
			},
			wantErr: "invalid reason code",
		},
		{
			name: "invalid weekday in time window",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "test",
						Users: []string{"admin"},
						Time: &policy.TimeWindow{
							Days: []policy.Weekday{policy.Weekday("notaday")},
						},
					},
				},
			},
			wantErr: "invalid weekday",
		},
		{
			name: "invalid timezone in time window",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "test",
						Users: []string{"admin"},
						Time: &policy.TimeWindow{
							Days:     []policy.Weekday{policy.Monday},
							Timezone: "Invalid/Zone",
						},
					},
				},
			},
			wantErr: "invalid timezone",
		},
		{
			name: "invalid hour format",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "test",
						Users: []string{"admin"},
						Time: &policy.TimeWindow{
							Days:  []policy.Weekday{policy.Monday},
							Hours: &policy.HourRange{Start: "9:00", End: "18:00"},
						},
					},
				},
			},
			wantErr: "invalid hour format",
		},
		{
			name: "negative max_duration",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:        "test",
						Users:       []string{"admin"},
						MaxDuration: -1 * time.Hour,
					},
				},
			},
			wantErr: "negative max_duration",
		},
		{
			name: "max_duration exceeds system max",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:        "test",
						Users:       []string{"admin"},
						MaxDuration: 5 * time.Hour, // MaxDuration is 4h
					},
				},
			},
			wantErr: "exceeds maximum",
		},
		{
			name: "max_duration equals system max is valid",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:        "test",
						Users:       []string{"admin"},
						MaxDuration: MaxDuration, // exactly 4h
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid with wildcard profiles",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:     "wildcard-rule",
						Profiles: []string{}, // empty = wildcard
						Users:    []string{"admin"},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid with all reason codes",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:               "all-reasons",
						Users:              []string{"admin"},
						AllowedReasonCodes: []ReasonCode{ReasonIncident, ReasonMaintenance, ReasonSecurity, ReasonRecovery, ReasonOther},
					},
				},
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()

			if tc.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestFindBreakGlassPolicyRule tests rule lookup by profile.
func TestFindBreakGlassPolicyRule(t *testing.T) {
	tests := []struct {
		name     string
		policy   *BreakGlassPolicy
		profile  string
		wantRule string // expected rule name, or "" for nil
	}{
		{
			name:     "nil policy returns nil",
			policy:   nil,
			profile:  "prod",
			wantRule: "",
		},
		{
			name: "no matching rule returns nil",
			policy: &BreakGlassPolicy{
				Rules: []BreakGlassPolicyRule{
					{Name: "prod-rule", Profiles: []string{"prod"}},
				},
			},
			profile:  "staging",
			wantRule: "",
		},
		{
			name: "exact profile match",
			policy: &BreakGlassPolicy{
				Rules: []BreakGlassPolicyRule{
					{Name: "prod-rule", Profiles: []string{"prod", "production"}},
				},
			},
			profile:  "prod",
			wantRule: "prod-rule",
		},
		{
			name: "first matching rule returned",
			policy: &BreakGlassPolicy{
				Rules: []BreakGlassPolicyRule{
					{Name: "first", Profiles: []string{"prod"}},
					{Name: "second", Profiles: []string{"prod"}},
				},
			},
			profile:  "prod",
			wantRule: "first",
		},
		{
			name: "wildcard rule (empty profiles) matches any",
			policy: &BreakGlassPolicy{
				Rules: []BreakGlassPolicyRule{
					{Name: "wildcard", Profiles: []string{}},
				},
			},
			profile:  "any-profile",
			wantRule: "wildcard",
		},
		{
			name: "specific rule before wildcard",
			policy: &BreakGlassPolicy{
				Rules: []BreakGlassPolicyRule{
					{Name: "specific", Profiles: []string{"prod"}},
					{Name: "wildcard", Profiles: []string{}},
				},
			},
			profile:  "prod",
			wantRule: "specific",
		},
		{
			name: "wildcard catches non-specific profile",
			policy: &BreakGlassPolicy{
				Rules: []BreakGlassPolicyRule{
					{Name: "specific", Profiles: []string{"prod"}},
					{Name: "wildcard", Profiles: []string{}},
				},
			},
			profile:  "staging",
			wantRule: "wildcard",
		},
		{
			name: "multiple profiles in rule",
			policy: &BreakGlassPolicy{
				Rules: []BreakGlassPolicyRule{
					{Name: "multi", Profiles: []string{"prod", "staging", "dev"}},
				},
			},
			profile:  "staging",
			wantRule: "multi",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := FindBreakGlassPolicyRule(tc.policy, tc.profile)

			if tc.wantRule == "" {
				if rule != nil {
					t.Errorf("expected nil, got rule %q", rule.Name)
				}
				return
			}

			if rule == nil {
				t.Errorf("expected rule %q, got nil", tc.wantRule)
				return
			}

			if rule.Name != tc.wantRule {
				t.Errorf("expected rule %q, got %q", tc.wantRule, rule.Name)
			}
		})
	}
}

// TestCanInvokeBreakGlass tests user authorization check.
func TestCanInvokeBreakGlass(t *testing.T) {
	tests := []struct {
		name string
		rule *BreakGlassPolicyRule
		user string
		want bool
	}{
		{
			name: "nil rule returns false",
			rule: nil,
			user: "anyone",
			want: false,
		},
		{
			name: "user in list returns true",
			rule: &BreakGlassPolicyRule{
				Users: []string{"alice", "bob", "charlie"},
			},
			user: "bob",
			want: true,
		},
		{
			name: "user not in list returns false",
			rule: &BreakGlassPolicyRule{
				Users: []string{"alice", "bob"},
			},
			user: "eve",
			want: false,
		},
		{
			name: "empty users list returns false",
			rule: &BreakGlassPolicyRule{
				Users: []string{},
			},
			user: "anyone",
			want: false,
		},
		{
			name: "case-sensitive comparison",
			rule: &BreakGlassPolicyRule{
				Users: []string{"Alice"},
			},
			user: "alice",
			want: false,
		},
		{
			name: "first user in list",
			rule: &BreakGlassPolicyRule{
				Users: []string{"oncall", "sre", "admin"},
			},
			user: "oncall",
			want: true,
		},
		{
			name: "last user in list",
			rule: &BreakGlassPolicyRule{
				Users: []string{"oncall", "sre", "admin"},
			},
			user: "admin",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CanInvokeBreakGlass(tc.rule, tc.user)
			if got != tc.want {
				t.Errorf("CanInvokeBreakGlass() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsBreakGlassAllowed tests comprehensive authorization check.
func TestIsBreakGlassAllowed(t *testing.T) {
	// Monday 10:30 AM in America/New_York (for time window tests)
	// 2026-01-19 is a Monday
	businessHours := time.Date(2026, 1, 19, 10, 30, 0, 0, mustLoadLocation("America/New_York"))
	outsideHours := time.Date(2026, 1, 19, 22, 30, 0, 0, mustLoadLocation("America/New_York"))
	weekend := time.Date(2026, 1, 17, 10, 30, 0, 0, mustLoadLocation("America/New_York")) // Saturday

	tests := []struct {
		name        string
		rule        *BreakGlassPolicyRule
		user        string
		reasonCode  ReasonCode
		requestTime time.Time
		duration    time.Duration
		want        bool
	}{
		{
			name:        "nil rule returns false",
			rule:        nil,
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "user not authorized returns false",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"bob"},
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "all conditions match returns true",
			rule: &BreakGlassPolicyRule{
				Name:               "test",
				Users:              []string{"alice", "bob"},
				AllowedReasonCodes: []ReasonCode{ReasonIncident, ReasonSecurity},
				Time: &policy.TimeWindow{
					Days:     []policy.Weekday{policy.Monday, policy.Tuesday, policy.Wednesday, policy.Thursday, policy.Friday},
					Hours:    &policy.HourRange{Start: "09:00", End: "18:00"},
					Timezone: "America/New_York",
				},
				MaxDuration: 2 * time.Hour,
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "reason code not in allowed list returns false",
			rule: &BreakGlassPolicyRule{
				Name:               "test",
				Users:              []string{"alice"},
				AllowedReasonCodes: []ReasonCode{ReasonIncident, ReasonSecurity},
			},
			user:        "alice",
			reasonCode:  ReasonMaintenance,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "empty allowed reason codes means all allowed",
			rule: &BreakGlassPolicyRule{
				Name:               "test",
				Users:              []string{"alice"},
				AllowedReasonCodes: []ReasonCode{},
			},
			user:        "alice",
			reasonCode:  ReasonMaintenance,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "nil allowed reason codes means all allowed",
			rule: &BreakGlassPolicyRule{
				Name:               "test",
				Users:              []string{"alice"},
				AllowedReasonCodes: nil,
			},
			user:        "alice",
			reasonCode:  ReasonOther,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "outside time window returns false",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"alice"},
				Time: &policy.TimeWindow{
					Days:     []policy.Weekday{policy.Monday, policy.Tuesday, policy.Wednesday, policy.Thursday, policy.Friday},
					Hours:    &policy.HourRange{Start: "09:00", End: "18:00"},
					Timezone: "America/New_York",
				},
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: outsideHours,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "on weekend when only weekdays allowed returns false",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"alice"},
				Time: &policy.TimeWindow{
					Days:     []policy.Weekday{policy.Monday, policy.Tuesday, policy.Wednesday, policy.Thursday, policy.Friday},
					Hours:    &policy.HourRange{Start: "09:00", End: "18:00"},
					Timezone: "America/New_York",
				},
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: weekend,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "nil time window means any time",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"alice"},
				Time:  nil,
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: outsideHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "duration exceeds MaxDuration returns false",
			rule: &BreakGlassPolicyRule{
				Name:        "test",
				Users:       []string{"alice"},
				MaxDuration: 1 * time.Hour,
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: businessHours,
			duration:    2 * time.Hour,
			want:        false,
		},
		{
			name: "duration equals MaxDuration returns true",
			rule: &BreakGlassPolicyRule{
				Name:        "test",
				Users:       []string{"alice"},
				MaxDuration: 1 * time.Hour,
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "MaxDuration 0 means no cap",
			rule: &BreakGlassPolicyRule{
				Name:        "test",
				Users:       []string{"alice"},
				MaxDuration: 0,
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: businessHours,
			duration:    24 * time.Hour,
			want:        true,
		},
		{
			name: "minimal rule - only users constraint",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"oncall"},
			},
			user:        "oncall",
			reasonCode:  ReasonRecovery,
			requestTime: weekend,
			duration:    4 * time.Hour,
			want:        true,
		},
		{
			name: "reason code exactly matches first in list",
			rule: &BreakGlassPolicyRule{
				Name:               "test",
				Users:              []string{"alice"},
				AllowedReasonCodes: []ReasonCode{ReasonIncident, ReasonSecurity},
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "reason code exactly matches last in list",
			rule: &BreakGlassPolicyRule{
				Name:               "test",
				Users:              []string{"alice"},
				AllowedReasonCodes: []ReasonCode{ReasonIncident, ReasonSecurity},
			},
			user:        "alice",
			reasonCode:  ReasonSecurity,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "time window with only days (no hours)",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"alice"},
				Time: &policy.TimeWindow{
					Days:     []policy.Weekday{policy.Monday},
					Timezone: "America/New_York",
				},
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: businessHours, // Monday
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "time window with only hours (no days)",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"alice"},
				Time: &policy.TimeWindow{
					Hours:    &policy.HourRange{Start: "09:00", End: "18:00"},
					Timezone: "America/New_York",
				},
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "empty time window allows any time",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"alice"},
				Time:  &policy.TimeWindow{},
			},
			user:        "alice",
			reasonCode:  ReasonIncident,
			requestTime: weekend,
			duration:    1 * time.Hour,
			want:        true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsBreakGlassAllowed(tc.rule, tc.user, tc.reasonCode, tc.requestTime, tc.duration)
			if got != tc.want {
				t.Errorf("IsBreakGlassAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBreakGlassPolicyRuleValidate tests individual rule validation.
func TestBreakGlassPolicyRuleValidate(t *testing.T) {
	tests := []struct {
		name    string
		rule    BreakGlassPolicyRule
		wantErr string
	}{
		{
			name: "valid rule with minimal fields",
			rule: BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
			},
			wantErr: "",
		},
		{
			name: "missing name",
			rule: BreakGlassPolicyRule{
				Name:  "",
				Users: []string{"admin"},
			},
			wantErr: "missing name",
		},
		{
			name: "empty users",
			rule: BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{},
			},
			wantErr: "at least one user",
		},
		{
			name: "invalid reason code",
			rule: BreakGlassPolicyRule{
				Name:               "test",
				Users:              []string{"admin"},
				AllowedReasonCodes: []ReasonCode{ReasonCode("bad")},
			},
			wantErr: "invalid reason code",
		},
		{
			name: "negative MaxDuration",
			rule: BreakGlassPolicyRule{
				Name:        "test",
				Users:       []string{"admin"},
				MaxDuration: -time.Hour,
			},
			wantErr: "negative max_duration",
		},
		{
			name: "MaxDuration exceeds max",
			rule: BreakGlassPolicyRule{
				Name:        "test",
				Users:       []string{"admin"},
				MaxDuration: 10 * time.Hour,
			},
			wantErr: "exceeds maximum",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rule.validate(0)

			if tc.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateTimeWindow tests time window validation in break-glass policy context.
func TestValidateTimeWindow(t *testing.T) {
	tests := []struct {
		name     string
		tw       *policy.TimeWindow
		ruleName string
		wantErr  string
	}{
		{
			name:     "nil time window is valid",
			tw:       nil,
			ruleName: "test",
			wantErr:  "",
		},
		{
			name: "valid time window",
			tw: &policy.TimeWindow{
				Days:     []policy.Weekday{policy.Monday, policy.Tuesday},
				Hours:    &policy.HourRange{Start: "09:00", End: "17:00"},
				Timezone: "America/New_York",
			},
			ruleName: "test",
			wantErr:  "",
		},
		{
			name: "invalid weekday",
			tw: &policy.TimeWindow{
				Days: []policy.Weekday{policy.Weekday("invalid")},
			},
			ruleName: "test",
			wantErr:  "invalid weekday",
		},
		{
			name: "invalid timezone",
			tw: &policy.TimeWindow{
				Timezone: "Not/A/Zone",
			},
			ruleName: "test",
			wantErr:  "invalid timezone",
		},
		{
			name: "invalid hour format",
			tw: &policy.TimeWindow{
				Hours: &policy.HourRange{Start: "9:00", End: "17:00"},
			},
			ruleName: "test",
			wantErr:  "invalid hour format",
		},
		{
			name: "empty time window is valid",
			tw: &policy.TimeWindow{
				Days:     []policy.Weekday{},
				Timezone: "",
			},
			ruleName: "test",
			wantErr:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.tw != nil {
				err = validateTimeWindow(tc.tw, tc.ruleName)
			}

			if tc.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestMatchesTimeWindow tests time window matching logic.
func TestMatchesTimeWindow(t *testing.T) {
	// Monday 10:30 AM in America/New_York
	mondayMorning := time.Date(2026, 1, 19, 10, 30, 0, 0, mustLoadLocation("America/New_York"))
	// Saturday 10:30 AM in America/New_York
	saturdayMorning := time.Date(2026, 1, 17, 10, 30, 0, 0, mustLoadLocation("America/New_York"))
	// Monday 22:30 in America/New_York
	mondayEvening := time.Date(2026, 1, 19, 22, 30, 0, 0, mustLoadLocation("America/New_York"))

	tests := []struct {
		name string
		tw   *policy.TimeWindow
		t    time.Time
		want bool
	}{
		{
			name: "nil time window matches any time",
			tw:   nil,
			t:    mondayMorning,
			want: true,
		},
		{
			name: "empty time window matches any time",
			tw:   &policy.TimeWindow{},
			t:    saturdayMorning,
			want: true,
		},
		{
			name: "matching day only",
			tw: &policy.TimeWindow{
				Days:     []policy.Weekday{policy.Monday, policy.Tuesday},
				Timezone: "America/New_York",
			},
			t:    mondayMorning,
			want: true,
		},
		{
			name: "non-matching day",
			tw: &policy.TimeWindow{
				Days:     []policy.Weekday{policy.Monday, policy.Tuesday},
				Timezone: "America/New_York",
			},
			t:    saturdayMorning,
			want: false,
		},
		{
			name: "matching hours only",
			tw: &policy.TimeWindow{
				Hours:    &policy.HourRange{Start: "09:00", End: "18:00"},
				Timezone: "America/New_York",
			},
			t:    mondayMorning,
			want: true,
		},
		{
			name: "non-matching hours",
			tw: &policy.TimeWindow{
				Hours:    &policy.HourRange{Start: "09:00", End: "18:00"},
				Timezone: "America/New_York",
			},
			t:    mondayEvening,
			want: false,
		},
		{
			name: "matching day and hours",
			tw: &policy.TimeWindow{
				Days:     []policy.Weekday{policy.Monday},
				Hours:    &policy.HourRange{Start: "09:00", End: "18:00"},
				Timezone: "America/New_York",
			},
			t:    mondayMorning,
			want: true,
		},
		{
			name: "matching day but not hours",
			tw: &policy.TimeWindow{
				Days:     []policy.Weekday{policy.Monday},
				Hours:    &policy.HourRange{Start: "09:00", End: "18:00"},
				Timezone: "America/New_York",
			},
			t:    mondayEvening,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesTimeWindow(tc.tw, tc.t)
			if got != tc.want {
				t.Errorf("matchesTimeWindow() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseHourMinute tests hour:minute parsing.
func TestParseHourMinute(t *testing.T) {
	tests := []struct {
		input      string
		wantHour   int
		wantMinute int
	}{
		{"09:00", 9, 0},
		{"18:30", 18, 30},
		{"00:00", 0, 0},
		{"23:59", 23, 59},
		{"12:05", 12, 5},
		{"invalid", 0, 0},
		{"9:00", 0, 0},  // wrong format
		{"", 0, 0},      // empty
		{"0900", 0, 0},  // no colon
		{"09-00", 0, 0}, // wrong separator
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			gotHour, gotMinute := parseHourMinute(tc.input)
			if gotHour != tc.wantHour || gotMinute != tc.wantMinute {
				t.Errorf("parseHourMinute(%q) = (%d, %d), want (%d, %d)",
					tc.input, gotHour, gotMinute, tc.wantHour, tc.wantMinute)
			}
		})
	}
}

// mustLoadLocation is a helper that panics if location loading fails.
func mustLoadLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return loc
}

// ============================================================================
// MFA Requirement Tests
// ============================================================================

// TestBreakGlassPolicyMFAValidation tests MFA requirement validation.
func TestBreakGlassPolicyMFAValidation(t *testing.T) {
	tests := []struct {
		name    string
		policy  BreakGlassPolicy
		wantErr string
	}{
		{
			name: "valid policy with MFA required",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "mfa-required",
						Users: []string{"admin"},
						MFA: &MFARequirement{
							Required: true,
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid policy with MFA required and totp method",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "mfa-totp",
						Users: []string{"admin"},
						MFA: &MFARequirement{
							Required: true,
							Methods:  []string{"totp"},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid policy with MFA required and sms method",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "mfa-sms",
						Users: []string{"admin"},
						MFA: &MFARequirement{
							Required: true,
							Methods:  []string{"sms"},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid policy with MFA required and both methods",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "mfa-both",
						Users: []string{"admin"},
						MFA: &MFARequirement{
							Required: true,
							Methods:  []string{"totp", "sms"},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid policy with MFA not required (methods ignored)",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "mfa-disabled",
						Users: []string{"admin"},
						MFA: &MFARequirement{
							Required: false,
							Methods:  []string{"invalid"},
						},
					},
				},
			},
			wantErr: "", // Invalid methods ignored when Required=false
		},
		{
			name: "valid policy with nil MFA",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "no-mfa",
						Users: []string{"admin"},
						MFA:   nil,
					},
				},
			},
			wantErr: "",
		},
		{
			name: "invalid MFA method",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "invalid-method",
						Users: []string{"admin"},
						MFA: &MFARequirement{
							Required: true,
							Methods:  []string{"invalid"},
						},
					},
				},
			},
			wantErr: "invalid MFA method",
		},
		{
			name: "invalid MFA method among valid ones",
			policy: BreakGlassPolicy{
				Version: "1",
				Rules: []BreakGlassPolicyRule{
					{
						Name:  "mixed-methods",
						Users: []string{"admin"},
						MFA: &MFARequirement{
							Required: true,
							Methods:  []string{"totp", "email"},
						},
					},
				},
			},
			wantErr: "invalid MFA method",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()

			if tc.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestRequiresMFA tests the RequiresMFA helper function.
func TestRequiresMFA(t *testing.T) {
	tests := []struct {
		name string
		rule *BreakGlassPolicyRule
		want bool
	}{
		{
			name: "nil MFA returns false",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA:   nil,
			},
			want: false,
		},
		{
			name: "MFA not required returns false",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: false,
				},
			},
			want: false,
		},
		{
			name: "MFA required returns true",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: true,
				},
			},
			want: true,
		},
		{
			name: "MFA required with methods returns true",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: true,
					Methods:  []string{"totp"},
				},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.rule.RequiresMFA()
			if got != tc.want {
				t.Errorf("RequiresMFA() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsMethodAllowed tests the IsMethodAllowed helper function.
func TestIsMethodAllowed(t *testing.T) {
	tests := []struct {
		name   string
		rule   *BreakGlassPolicyRule
		method string
		want   bool
	}{
		{
			name: "nil MFA allows any method",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA:   nil,
			},
			method: "totp",
			want:   true,
		},
		{
			name: "empty methods list allows any method",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: true,
					Methods:  []string{},
				},
			},
			method: "sms",
			want:   true,
		},
		{
			name: "nil methods list allows any method",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: true,
					Methods:  nil,
				},
			},
			method: "totp",
			want:   true,
		},
		{
			name: "method in list allowed",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: true,
					Methods:  []string{"totp", "sms"},
				},
			},
			method: "totp",
			want:   true,
		},
		{
			name: "method not in list denied",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: true,
					Methods:  []string{"totp"},
				},
			},
			method: "sms",
			want:   false,
		},
		{
			name: "first method in list",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: true,
					Methods:  []string{"sms", "totp"},
				},
			},
			method: "sms",
			want:   true,
		},
		{
			name: "last method in list",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: true,
					Methods:  []string{"sms", "totp"},
				},
			},
			method: "totp",
			want:   true,
		},
		{
			name: "case-sensitive method matching",
			rule: &BreakGlassPolicyRule{
				Name:  "test",
				Users: []string{"admin"},
				MFA: &MFARequirement{
					Required: true,
					Methods:  []string{"totp"},
				},
			},
			method: "TOTP",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.rule.IsMethodAllowed(tc.method)
			if got != tc.want {
				t.Errorf("IsMethodAllowed(%q) = %v, want %v", tc.method, got, tc.want)
			}
		})
	}
}
