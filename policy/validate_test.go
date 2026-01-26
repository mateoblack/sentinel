package policy

import (
	"strings"
	"testing"
)

func TestPolicyValidate(t *testing.T) {
	var testCases = []struct {
		name    string
		policy  Policy
		wantErr string
	}{
		{
			name: "valid policy with one allow rule",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-all",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid policy with time conditions",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "business-hours",
						Effect: EffectAllow,
						Conditions: Condition{
							Time: &TimeWindow{
								Days:     []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
								Hours:    &HourRange{Start: "09:00", End: "17:00"},
								Timezone: "America/New_York",
							},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "empty rules",
			policy: Policy{
				Version: "1",
				Rules:   []Rule{},
			},
			wantErr: "at least one rule",
		},
		{
			name: "nil rules",
			policy: Policy{
				Version: "1",
				Rules:   nil,
			},
			wantErr: "at least one rule",
		},
		{
			name: "rule with invalid effect",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "invalid-rule",
						Effect: Effect("invalid"),
						Conditions: Condition{
							Profiles: []string{"test"},
						},
					},
				},
			},
			wantErr: "invalid effect",
		},
		{
			name: "rule missing name",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"test"},
						},
					},
				},
			},
			wantErr: "missing name",
		},
		{
			name: "rule with no conditions",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:       "empty-rule",
						Effect:     EffectAllow,
						Conditions: Condition{},
					},
				},
			},
			wantErr: "no conditions",
		},
		{
			name: "rule with invalid weekday",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "bad-weekday",
						Effect: EffectAllow,
						Conditions: Condition{
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
			name: "rule with invalid hour format - out of range",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "bad-hours",
						Effect: EffectAllow,
						Conditions: Condition{
							Time: &TimeWindow{
								Days:  []Weekday{Monday},
								Hours: &HourRange{Start: "25:00", End: "17:00"},
							},
						},
					},
				},
			},
			wantErr: "invalid hour format",
		},
		{
			name: "rule with invalid hour format - bad format",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "bad-format",
						Effect: EffectAllow,
						Conditions: Condition{
							Time: &TimeWindow{
								Days:  []Weekday{Monday},
								Hours: &HourRange{Start: "9am", End: "5pm"},
							},
						},
					},
				},
			},
			wantErr: "invalid hour format",
		},
		{
			name: "rule with invalid timezone",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "bad-timezone",
						Effect: EffectAllow,
						Conditions: Condition{
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

func TestRuleValidate(t *testing.T) {
	var testCases = []struct {
		name    string
		rule    Rule
		index   int
		wantErr string
	}{
		{
			name: "valid rule",
			rule: Rule{
				Name:   "test",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
			index:   0,
			wantErr: "",
		},
		{
			name: "missing name",
			rule: Rule{
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
			index:   2,
			wantErr: "rule at index 2 missing name",
		},
		{
			name: "invalid effect",
			rule: Rule{
				Name:   "bad-effect",
				Effect: Effect("maybe"),
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
			index:   0,
			wantErr: "invalid effect 'maybe' in rule 'bad-effect'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rule.validate(tc.index)

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

func TestTimeWindowValidate(t *testing.T) {
	var testCases = []struct {
		name    string
		tw      TimeWindow
		rule    string
		wantErr string
	}{
		{
			name: "valid time window with all fields",
			tw: TimeWindow{
				Days:     []Weekday{Monday, Tuesday},
				Hours:    &HourRange{Start: "09:00", End: "17:00"},
				Timezone: "America/New_York",
			},
			rule:    "test-rule",
			wantErr: "",
		},
		{
			name: "valid time window with only days",
			tw: TimeWindow{
				Days: []Weekday{Saturday, Sunday},
			},
			rule:    "test-rule",
			wantErr: "",
		},
		{
			name: "invalid weekday",
			tw: TimeWindow{
				Days: []Weekday{Weekday("funday")},
			},
			rule:    "test-rule",
			wantErr: "invalid weekday 'funday' in rule 'test-rule'",
		},
		{
			name: "invalid timezone",
			tw: TimeWindow{
				Days:     []Weekday{Monday},
				Timezone: "Not/ATimezone",
			},
			rule:    "test-rule",
			wantErr: "invalid timezone 'Not/ATimezone'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.tw.validate(tc.rule)

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

func TestHourRangeValidate(t *testing.T) {
	var testCases = []struct {
		name    string
		hr      HourRange
		wantErr string
	}{
		{
			name:    "valid hour range",
			hr:      HourRange{Start: "09:00", End: "17:00"},
			wantErr: "",
		},
		{
			name:    "valid midnight to midnight",
			hr:      HourRange{Start: "00:00", End: "23:59"},
			wantErr: "",
		},
		{
			name:    "invalid start hour - out of range",
			hr:      HourRange{Start: "25:00", End: "17:00"},
			wantErr: "invalid hour format '25:00'",
		},
		{
			name:    "invalid end minute - out of range",
			hr:      HourRange{Start: "09:00", End: "17:60"},
			wantErr: "invalid hour format '17:60'",
		},
		{
			name:    "invalid format - no colon",
			hr:      HourRange{Start: "0900", End: "1700"},
			wantErr: "invalid hour format '0900'",
		},
		{
			name:    "invalid format - am/pm",
			hr:      HourRange{Start: "9am", End: "5pm"},
			wantErr: "invalid hour format '9am'",
		},
		{
			name:    "invalid format - single digit",
			hr:      HourRange{Start: "9:00", End: "17:00"},
			wantErr: "invalid hour format '9:00'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.hr.Validate()

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

func TestPolicy_Validate_UnsupportedVersion(t *testing.T) {
	policy := Policy{
		Version: Version("99"),
		Rules: []Rule{
			{
				Name:   "test-rule",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
		},
	}

	err := policy.Validate()
	if err == nil {
		t.Error("expected error for unsupported version, got nil")
		return
	}

	if !strings.Contains(err.Error(), "unsupported policy version") {
		t.Errorf("error %q does not contain 'unsupported policy version'", err.Error())
	}
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error %q does not contain version '99'", err.Error())
	}
}

func TestPolicy_Validate_ValidVersion(t *testing.T) {
	policy := Policy{
		Version: Version("1"),
		Rules: []Rule{
			{
				Name:   "test-rule",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
		},
	}

	err := policy.Validate()
	if err != nil {
		t.Errorf("unexpected error for valid version: %v", err)
	}
}

func TestPolicy_Validate_EmptyVersion(t *testing.T) {
	policy := Policy{
		Version: Version(""),
		Rules: []Rule{
			{
				Name:   "test-rule",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
		},
	}

	err := policy.Validate()
	if err == nil {
		t.Error("expected error for empty version, got nil")
		return
	}

	if !strings.Contains(err.Error(), "unsupported policy version") {
		t.Errorf("error %q does not contain 'unsupported policy version'", err.Error())
	}
}
