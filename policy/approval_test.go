package policy

import (
	"strings"
	"testing"
	"time"
)

func TestApprovalPolicyValidate(t *testing.T) {
	var testCases = []struct {
		name    string
		policy  ApprovalPolicy
		wantErr string
	}{
		{
			name: "valid policy with one rule",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "default",
						Approvers: []string{"admin"},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid policy with multiple rules",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "prod-rule",
						Profiles:  []string{"prod"},
						Approvers: []string{"admin", "lead"},
					},
					{
						Name:      "default",
						Approvers: []string{"team-lead"},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid policy with auto-approve",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "dev-rule",
						Profiles:  []string{"dev"},
						Approvers: []string{"admin"},
						AutoApprove: &AutoApproveCondition{
							Users:       []string{"dev1", "dev2"},
							MaxDuration: 1 * time.Hour,
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "empty rules",
			policy: ApprovalPolicy{
				Version: "1",
				Rules:   []ApprovalRule{},
			},
			wantErr: "at least one rule",
		},
		{
			name: "nil rules",
			policy: ApprovalPolicy{
				Version: "1",
				Rules:   nil,
			},
			wantErr: "at least one rule",
		},
		{
			name: "rule missing name",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "",
						Approvers: []string{"admin"},
					},
				},
			},
			wantErr: "missing name",
		},
		{
			name: "rule missing approvers",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "test",
						Approvers: []string{},
					},
				},
			},
			wantErr: "at least one approver",
		},
		{
			name: "rule with nil approvers",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "test",
						Approvers: nil,
					},
				},
			},
			wantErr: "at least one approver",
		},
		{
			name: "auto-approve with no conditions",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:        "test",
						Approvers:   []string{"admin"},
						AutoApprove: &AutoApproveCondition{},
					},
				},
			},
			wantErr: "must have at least one condition",
		},
		{
			name: "auto-approve with invalid time window",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "test",
						Approvers: []string{"admin"},
						AutoApprove: &AutoApproveCondition{
							Time: &TimeWindow{
								Days: []Weekday{Weekday("notaday")},
							},
						},
					},
				},
			},
			wantErr: "invalid weekday",
		},
		{
			name: "auto-approve with invalid timezone",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "test",
						Approvers: []string{"admin"},
						AutoApprove: &AutoApproveCondition{
							Time: &TimeWindow{
								Days:     []Weekday{Monday},
								Timezone: "Invalid/Zone",
							},
						},
					},
				},
			},
			wantErr: "invalid timezone",
		},
		{
			name: "auto-approve with MaxDuration > 8h",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "test",
						Approvers: []string{"admin"},
						AutoApprove: &AutoApproveCondition{
							MaxDuration: 9 * time.Hour,
						},
					},
				},
			},
			wantErr: "exceeds maximum",
		},
		{
			name: "auto-approve with MaxDuration = 8h (valid)",
			policy: ApprovalPolicy{
				Version: "1",
				Rules: []ApprovalRule{
					{
						Name:      "test",
						Approvers: []string{"admin"},
						AutoApprove: &AutoApproveCondition{
							MaxDuration: 8 * time.Hour,
						},
					},
				},
			},
			wantErr: "",
		},
	}

	for _, tc := range testCases {
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

func TestFindApprovalRule(t *testing.T) {
	var testCases = []struct {
		name     string
		policy   *ApprovalPolicy
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
			policy: &ApprovalPolicy{
				Rules: []ApprovalRule{
					{Name: "prod-rule", Profiles: []string{"prod"}},
				},
			},
			profile:  "staging",
			wantRule: "",
		},
		{
			name: "exact profile match",
			policy: &ApprovalPolicy{
				Rules: []ApprovalRule{
					{Name: "prod-rule", Profiles: []string{"prod", "production"}},
				},
			},
			profile:  "prod",
			wantRule: "prod-rule",
		},
		{
			name: "first matching rule returned",
			policy: &ApprovalPolicy{
				Rules: []ApprovalRule{
					{Name: "first", Profiles: []string{"prod"}},
					{Name: "second", Profiles: []string{"prod"}},
				},
			},
			profile:  "prod",
			wantRule: "first",
		},
		{
			name: "wildcard rule (empty profiles) matches any",
			policy: &ApprovalPolicy{
				Rules: []ApprovalRule{
					{Name: "wildcard", Profiles: []string{}},
				},
			},
			profile:  "any-profile",
			wantRule: "wildcard",
		},
		{
			name: "specific rule before wildcard",
			policy: &ApprovalPolicy{
				Rules: []ApprovalRule{
					{Name: "specific", Profiles: []string{"prod"}},
					{Name: "wildcard", Profiles: []string{}},
				},
			},
			profile:  "prod",
			wantRule: "specific",
		},
		{
			name: "wildcard catches non-specific profile",
			policy: &ApprovalPolicy{
				Rules: []ApprovalRule{
					{Name: "specific", Profiles: []string{"prod"}},
					{Name: "wildcard", Profiles: []string{}},
				},
			},
			profile:  "staging",
			wantRule: "wildcard",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := FindApprovalRule(tc.policy, tc.profile)

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

func TestCanApprove(t *testing.T) {
	var testCases = []struct {
		name     string
		rule     *ApprovalRule
		approver string
		want     bool
	}{
		{
			name:     "nil rule returns false",
			rule:     nil,
			approver: "anyone",
			want:     false,
		},
		{
			name: "approver in list returns true",
			rule: &ApprovalRule{
				Approvers: []string{"alice", "bob", "charlie"},
			},
			approver: "bob",
			want:     true,
		},
		{
			name: "approver not in list returns false",
			rule: &ApprovalRule{
				Approvers: []string{"alice", "bob"},
			},
			approver: "eve",
			want:     false,
		},
		{
			name: "empty approvers list returns false",
			rule: &ApprovalRule{
				Approvers: []string{},
			},
			approver: "anyone",
			want:     false,
		},
		{
			name: "case-sensitive comparison",
			rule: &ApprovalRule{
				Approvers: []string{"Alice"},
			},
			approver: "alice",
			want:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := CanApprove(tc.rule, tc.approver)
			if got != tc.want {
				t.Errorf("CanApprove() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldAutoApprove(t *testing.T) {
	// Monday 10:30 AM in America/New_York (for time window tests)
	// 2026-01-19 is a Monday
	businessHours := time.Date(2026, 1, 19, 10, 30, 0, 0, mustLoadLocation("America/New_York"))
	outsideHours := time.Date(2026, 1, 19, 22, 30, 0, 0, mustLoadLocation("America/New_York"))
	weekend := time.Date(2026, 1, 17, 10, 30, 0, 0, mustLoadLocation("America/New_York")) // Saturday

	var testCases = []struct {
		name        string
		rule        *ApprovalRule
		requester   string
		requestTime time.Time
		duration    time.Duration
		want        bool
	}{
		{
			name:        "nil rule returns false",
			rule:        nil,
			requester:   "alice",
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "nil AutoApprove returns false",
			rule: &ApprovalRule{
				Name:        "test",
				AutoApprove: nil,
			},
			requester:   "alice",
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "all conditions match returns true",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					Users: []string{"alice", "bob"},
					Time: &TimeWindow{
						Days:     []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
						Hours:    &HourRange{Start: "09:00", End: "18:00"},
						Timezone: "America/New_York",
					},
					MaxDuration: 2 * time.Hour,
				},
			},
			requester:   "alice",
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "user not in list returns false",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					Users: []string{"alice", "bob"},
				},
			},
			requester:   "eve",
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "empty users list means any user can auto-approve",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					Users:       []string{},
					MaxDuration: 2 * time.Hour,
				},
			},
			requester:   "anyone",
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "outside time window returns false",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					Users: []string{"alice"},
					Time: &TimeWindow{
						Days:     []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
						Hours:    &HourRange{Start: "09:00", End: "18:00"},
						Timezone: "America/New_York",
					},
				},
			},
			requester:   "alice",
			requestTime: outsideHours,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "on weekend when only weekdays allowed returns false",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					Users: []string{"alice"},
					Time: &TimeWindow{
						Days:     []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
						Hours:    &HourRange{Start: "09:00", End: "18:00"},
						Timezone: "America/New_York",
					},
				},
			},
			requester:   "alice",
			requestTime: weekend,
			duration:    1 * time.Hour,
			want:        false,
		},
		{
			name: "nil time means any time",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					Users: []string{"alice"},
					Time:  nil,
				},
			},
			requester:   "alice",
			requestTime: outsideHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "duration exceeds MaxDuration returns false",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					Users:       []string{"alice"},
					MaxDuration: 1 * time.Hour,
				},
			},
			requester:   "alice",
			requestTime: businessHours,
			duration:    2 * time.Hour,
			want:        false,
		},
		{
			name: "duration equals MaxDuration returns true",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					Users:       []string{"alice"},
					MaxDuration: 1 * time.Hour,
				},
			},
			requester:   "alice",
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
		{
			name: "MaxDuration 0 means no cap",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					Users:       []string{"alice"},
					MaxDuration: 0,
				},
			},
			requester:   "alice",
			requestTime: businessHours,
			duration:    24 * time.Hour,
			want:        true,
		},
		{
			name: "only MaxDuration condition set",
			rule: &ApprovalRule{
				Name: "test",
				AutoApprove: &AutoApproveCondition{
					MaxDuration: 2 * time.Hour,
				},
			},
			requester:   "anyone",
			requestTime: businessHours,
			duration:    1 * time.Hour,
			want:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShouldAutoApprove(tc.rule, tc.requester, tc.requestTime, tc.duration)
			if got != tc.want {
				t.Errorf("ShouldAutoApprove() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetApprovers(t *testing.T) {
	policy := &ApprovalPolicy{
		Rules: []ApprovalRule{
			{
				Name:      "prod-rule",
				Profiles:  []string{"prod"},
				Approvers: []string{"admin", "lead"},
			},
			{
				Name:      "default",
				Profiles:  []string{},
				Approvers: []string{"manager"},
			},
		},
	}

	var testCases = []struct {
		name    string
		policy  *ApprovalPolicy
		profile string
		want    []string
	}{
		{
			name:    "nil policy returns nil",
			policy:  nil,
			profile: "prod",
			want:    nil,
		},
		{
			name:    "matching profile returns approvers",
			policy:  policy,
			profile: "prod",
			want:    []string{"admin", "lead"},
		},
		{
			name:    "non-matching profile falls through to wildcard",
			policy:  policy,
			profile: "staging",
			want:    []string{"manager"},
		},
		{
			name: "no matching rule returns nil",
			policy: &ApprovalPolicy{
				Rules: []ApprovalRule{
					{Name: "specific", Profiles: []string{"specific-only"}},
				},
			},
			profile: "other",
			want:    nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := GetApprovers(tc.policy, tc.profile)

			if tc.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}

			if len(got) != len(tc.want) {
				t.Errorf("expected %v, got %v", tc.want, got)
				return
			}

			for i, v := range tc.want {
				if got[i] != v {
					t.Errorf("expected %v, got %v", tc.want, got)
					break
				}
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
