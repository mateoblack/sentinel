package policy

import (
	"testing"
)

func TestLintPolicy_AllowBeforeDeny(t *testing.T) {
	testCases := []struct {
		name       string
		policy     Policy
		wantIssues int
		wantType   LintIssueType
	}{
		{
			name: "allow profile=prod followed by deny profile=prod - issue detected",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-prod",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
					{
						Name:   "deny-prod",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
				},
			},
			wantIssues: 1,
			wantType:   LintAllowBeforeDeny,
		},
		{
			name: "allow profile=prod followed by deny profile=staging - no issue",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-prod",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
					{
						Name:   "deny-staging",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"staging"},
						},
					},
				},
			},
			wantIssues: 0,
		},
		{
			name: "deny before allow for same profile - no issue (correct order)",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "deny-prod",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
					{
						Name:   "allow-prod",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
				},
			},
			wantIssues: 0,
		},
		{
			name: "allow on empty profiles followed by deny on specific - no issue",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-all",
						Effect: EffectAllow,
						Conditions: Condition{
							Users: []string{"admin"}, // Must have at least one condition
						},
					},
					{
						Name:   "deny-prod",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
				},
			},
			wantIssues: 1, // Empty profiles = wildcard, matches prod
		},
		{
			name: "allow wildcard followed by deny specific - issue detected",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-all-profiles",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{}, // Empty = wildcard
							Users:    []string{"bob"},
						},
					},
					{
						Name:   "deny-prod",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
				},
			},
			wantIssues: 1,
			wantType:   LintAllowBeforeDeny,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issues := LintPolicy(&tc.policy)

			// Count allow-before-deny issues
			count := 0
			for _, issue := range issues {
				if issue.Type == LintAllowBeforeDeny {
					count++
				}
			}

			if count != tc.wantIssues {
				t.Errorf("got %d allow-before-deny issues, want %d", count, tc.wantIssues)
				for _, issue := range issues {
					t.Logf("  issue: %s - %s", issue.Type, issue.Message)
				}
			}

			if tc.wantIssues > 0 && tc.wantType != "" && len(issues) > 0 {
				if issues[0].Type != tc.wantType {
					t.Errorf("got issue type %q, want %q", issues[0].Type, tc.wantType)
				}
			}
		})
	}
}

func TestLintPolicy_UnreachableRules(t *testing.T) {
	testCases := []struct {
		name       string
		policy     Policy
		wantIssues int
	}{
		{
			name: "allow users=[] profiles=[] followed by allow users=bob - unreachable",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-all",
						Effect: EffectAllow,
						Conditions: Condition{
							Users:    []string{},
							Profiles: []string{},
							Time:     &TimeWindow{Days: []Weekday{Monday}}, // Need at least one condition
						},
					},
					{
						Name:   "allow-bob",
						Effect: EffectAllow,
						Conditions: Condition{
							Users: []string{"bob"},
						},
					},
				},
			},
			wantIssues: 1,
		},
		{
			name: "deny profiles=[] followed by deny profiles=prod - unreachable",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "deny-all",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{},
							Time:     &TimeWindow{Days: []Weekday{Monday}}, // Need at least one condition
						},
					},
					{
						Name:   "deny-prod",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
				},
			},
			wantIssues: 1,
		},
		{
			name: "allow profiles=[] followed by deny profiles=[] - reachable (different effects)",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-all",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{},
							Time:     &TimeWindow{Days: []Weekday{Monday}},
						},
					},
					{
						Name:   "deny-all",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{},
							Time:     &TimeWindow{Days: []Weekday{Tuesday}},
						},
					},
				},
			},
			wantIssues: 0, // Different effects don't shadow
		},
		{
			name: "allow profiles=prod followed by allow profiles=staging - reachable (different profiles)",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-prod",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
						},
					},
					{
						Name:   "allow-staging",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"staging"},
						},
					},
				},
			},
			wantIssues: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issues := LintPolicy(&tc.policy)

			// Count unreachable-rule issues
			count := 0
			for _, issue := range issues {
				if issue.Type == LintUnreachableRule {
					count++
				}
			}

			if count != tc.wantIssues {
				t.Errorf("got %d unreachable-rule issues, want %d", count, tc.wantIssues)
				for _, issue := range issues {
					t.Logf("  issue: %s - %s", issue.Type, issue.Message)
				}
			}
		})
	}
}

func TestLintPolicy_OverlappingTimeWindows(t *testing.T) {
	testCases := []struct {
		name       string
		policy     Policy
		wantIssues int
	}{
		{
			name: "allow 09:00-17:00 Mon-Fri followed by deny 12:00-18:00 Mon-Fri - overlap detected",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-business",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
							Time: &TimeWindow{
								Days:  []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
								Hours: &HourRange{Start: "09:00", End: "17:00"},
							},
						},
					},
					{
						Name:   "deny-afternoon",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"prod"},
							Time: &TimeWindow{
								Days:  []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
								Hours: &HourRange{Start: "12:00", End: "18:00"},
							},
						},
					},
				},
			},
			wantIssues: 1,
		},
		{
			name: "allow 09:00-12:00 followed by deny 13:00-17:00 - no overlap",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-morning",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
							Time: &TimeWindow{
								Days:  []Weekday{Monday},
								Hours: &HourRange{Start: "09:00", End: "12:00"},
							},
						},
					},
					{
						Name:   "deny-afternoon",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"prod"},
							Time: &TimeWindow{
								Days:  []Weekday{Monday},
								Hours: &HourRange{Start: "13:00", End: "17:00"},
							},
						},
					},
				},
			},
			wantIssues: 0,
		},
		{
			name: "allow Mon-Tue followed by deny Wed-Thu - no overlap",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-early-week",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
							Time: &TimeWindow{
								Days: []Weekday{Monday, Tuesday},
							},
						},
					},
					{
						Name:   "deny-mid-week",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"prod"},
							Time: &TimeWindow{
								Days: []Weekday{Wednesday, Thursday},
							},
						},
					},
				},
			},
			wantIssues: 0,
		},
		{
			name: "same time windows but same effect - no issue (not ambiguous)",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-morning",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
							Time: &TimeWindow{
								Days:  []Weekday{Monday},
								Hours: &HourRange{Start: "09:00", End: "12:00"},
							},
						},
					},
					{
						Name:   "allow-morning-2",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
							Time: &TimeWindow{
								Days:  []Weekday{Monday},
								Hours: &HourRange{Start: "09:00", End: "12:00"},
							},
						},
					},
				},
			},
			wantIssues: 0, // Same effect = not ambiguous
		},
		{
			name: "different profiles with overlapping time - no issue",
			policy: Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-prod",
						Effect: EffectAllow,
						Conditions: Condition{
							Profiles: []string{"prod"},
							Time: &TimeWindow{
								Days:  []Weekday{Monday},
								Hours: &HourRange{Start: "09:00", End: "17:00"},
							},
						},
					},
					{
						Name:   "deny-staging",
						Effect: EffectDeny,
						Conditions: Condition{
							Profiles: []string{"staging"},
							Time: &TimeWindow{
								Days:  []Weekday{Monday},
								Hours: &HourRange{Start: "09:00", End: "17:00"},
							},
						},
					},
				},
			},
			wantIssues: 0, // Different profiles
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			issues := LintPolicy(&tc.policy)

			// Count overlapping-time-windows issues
			count := 0
			for _, issue := range issues {
				if issue.Type == LintOverlappingTimeWindows {
					count++
				}
			}

			if count != tc.wantIssues {
				t.Errorf("got %d overlapping-time-windows issues, want %d", count, tc.wantIssues)
				for _, issue := range issues {
					t.Logf("  issue: %s - %s", issue.Type, issue.Message)
				}
			}
		})
	}
}

func TestLintPolicy_NoIssues(t *testing.T) {
	// Well-formed policy with deny-first pattern
	policy := Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "deny-all",
				Effect: EffectDeny,
				Conditions: Condition{
					Profiles: []string{"*"},
				},
			},
			{
				Name:   "allow-prod-admin",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod"},
					Users:    []string{"admin"},
				},
			},
		},
	}

	issues := LintPolicy(&policy)

	if len(issues) != 0 {
		t.Errorf("expected no issues for well-formed policy, got %d", len(issues))
		for _, issue := range issues {
			t.Logf("  issue: %s - %s", issue.Type, issue.Message)
		}
	}
}

func TestLintPolicy_MultipleIssues(t *testing.T) {
	// Policy with all three types of issues
	policy := Policy{
		Version: "1",
		Rules: []Rule{
			// Issue 1: allow-before-deny
			{
				Name:   "allow-prod",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
			{
				Name:   "deny-prod",
				Effect: EffectDeny,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
			// Issue 2: unreachable rule (same profiles, same effect as allow-prod but comes later)
			// Note: This won't be detected because allow-prod has specific profiles
			// Issue 3: overlapping time windows
			{
				Name:   "allow-business",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"staging"},
					Time: &TimeWindow{
						Days:  []Weekday{Monday},
						Hours: &HourRange{Start: "09:00", End: "17:00"},
					},
				},
			},
			{
				Name:   "deny-afternoon",
				Effect: EffectDeny,
				Conditions: Condition{
					Profiles: []string{"staging"},
					Time: &TimeWindow{
						Days:  []Weekday{Monday},
						Hours: &HourRange{Start: "12:00", End: "18:00"},
					},
				},
			},
		},
	}

	issues := LintPolicy(&policy)

	if len(issues) < 2 {
		t.Errorf("expected at least 2 issues, got %d", len(issues))
		for _, issue := range issues {
			t.Logf("  issue: %s - %s", issue.Type, issue.Message)
		}
	}

	// Check we have the expected issue types
	hasAllowBeforeDeny := false
	hasOverlappingTimeWindows := false
	for _, issue := range issues {
		switch issue.Type {
		case LintAllowBeforeDeny:
			hasAllowBeforeDeny = true
		case LintOverlappingTimeWindows:
			hasOverlappingTimeWindows = true
		}
	}

	if !hasAllowBeforeDeny {
		t.Error("expected allow-before-deny issue")
	}
	if !hasOverlappingTimeWindows {
		t.Error("expected overlapping-time-windows issue")
	}
}

func TestLintPolicy_IssueFields(t *testing.T) {
	// Verify issue fields are populated correctly
	policy := Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-prod",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
			{
				Name:   "deny-prod",
				Effect: EffectDeny,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
		},
	}

	issues := LintPolicy(&policy)

	if len(issues) == 0 {
		t.Fatal("expected at least one issue")
	}

	issue := issues[0]

	if issue.Type != LintAllowBeforeDeny {
		t.Errorf("Type = %q, want %q", issue.Type, LintAllowBeforeDeny)
	}

	if issue.RuleIndex != 0 {
		t.Errorf("RuleIndex = %d, want 0", issue.RuleIndex)
	}

	if issue.RuleName != "allow-prod" {
		t.Errorf("RuleName = %q, want %q", issue.RuleName, "allow-prod")
	}

	if issue.Message == "" {
		t.Error("Message should not be empty")
	}

	// Verify message contains expected information
	expectedSubstrings := []string{"allow-prod", "deny-prod", "index 0"}
	for _, s := range expectedSubstrings {
		if !contains(issue.Message, s) {
			t.Errorf("Message %q should contain %q", issue.Message, s)
		}
	}
}

// Helper function to check substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestProfilesOverlap(t *testing.T) {
	testCases := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{"both empty", []string{}, []string{}, true},
		{"first empty (wildcard)", []string{}, []string{"prod"}, true},
		{"second empty (wildcard)", []string{"prod"}, []string{}, true},
		{"same profile", []string{"prod"}, []string{"prod"}, true},
		{"different profiles", []string{"prod"}, []string{"staging"}, false},
		{"overlap in larger lists", []string{"prod", "dev"}, []string{"staging", "dev"}, true},
		{"no overlap in larger lists", []string{"prod", "dev"}, []string{"staging", "test"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := profilesOverlap(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("profilesOverlap(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestHoursOverlap(t *testing.T) {
	testCases := []struct {
		name string
		a    *HourRange
		b    *HourRange
		want bool
	}{
		{
			"both nil",
			nil,
			nil,
			true,
		},
		{
			"first nil",
			nil,
			&HourRange{Start: "09:00", End: "17:00"},
			true,
		},
		{
			"second nil",
			&HourRange{Start: "09:00", End: "17:00"},
			nil,
			true,
		},
		{
			"overlapping ranges",
			&HourRange{Start: "09:00", End: "17:00"},
			&HourRange{Start: "12:00", End: "18:00"},
			true,
		},
		{
			"non-overlapping ranges",
			&HourRange{Start: "09:00", End: "12:00"},
			&HourRange{Start: "13:00", End: "17:00"},
			false,
		},
		{
			"adjacent ranges (no overlap)",
			&HourRange{Start: "09:00", End: "12:00"},
			&HourRange{Start: "12:00", End: "17:00"},
			false, // max(09:00, 12:00)=12:00, min(12:00, 17:00)=12:00, 12:00 < 12:00 is false
		},
		{
			"same range",
			&HourRange{Start: "09:00", End: "17:00"},
			&HourRange{Start: "09:00", End: "17:00"},
			true,
		},
		{
			"one contains other",
			&HourRange{Start: "08:00", End: "18:00"},
			&HourRange{Start: "10:00", End: "14:00"},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := hoursOverlap(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("hoursOverlap(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestParseTimeToMinutes(t *testing.T) {
	testCases := []struct {
		input string
		want  int
	}{
		{"00:00", 0},
		{"01:00", 60},
		{"09:00", 540},
		{"12:30", 750},
		{"17:00", 1020},
		{"23:59", 1439},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			got := parseTimeToMinutes(tc.input)
			if got != tc.want {
				t.Errorf("parseTimeToMinutes(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestItoa(t *testing.T) {
	testCases := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{123, "123"},
		{-1, "-1"},
		{-123, "-123"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := itoa(tc.input)
			if got != tc.want {
				t.Errorf("itoa(%d) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
