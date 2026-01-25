package policy

import (
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/device"
)

func TestEvaluate(t *testing.T) {
	t.Run("allow rule with matching profile", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-production",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
					},
					Reason: "production access allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow, got %v", decision.Effect)
		}
		if decision.MatchedRule != "allow-production" {
			t.Errorf("expected MatchedRule 'allow-production', got %q", decision.MatchedRule)
		}
		if decision.Reason != "production access allowed" {
			t.Errorf("expected Reason 'production access allowed', got %q", decision.Reason)
		}
	})

	t.Run("deny rule with matching user", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "deny-bob",
					Effect: EffectDeny,
					Conditions: Condition{
						Users: []string{"bob"},
					},
					Reason: "bob is not allowed",
				},
			},
		}
		req := &Request{
			User:    "bob",
			Profile: "staging",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny, got %v", decision.Effect)
		}
		if decision.MatchedRule != "deny-bob" {
			t.Errorf("expected MatchedRule 'deny-bob', got %q", decision.MatchedRule)
		}
	})

	t.Run("multiple rules first match wins", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-alice",
					Effect: EffectAllow,
					Conditions: Condition{
						Users: []string{"alice"},
					},
					Reason: "alice always allowed",
				},
				{
					Name:   "deny-all",
					Effect: EffectDeny,
					Conditions: Condition{
						Profiles: []string{"production"},
					},
					Reason: "production denied by default",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		// First matching rule (allow-alice) should win
		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (first match wins), got %v", decision.Effect)
		}
		if decision.MatchedRule != "allow-alice" {
			t.Errorf("expected MatchedRule 'allow-alice', got %q", decision.MatchedRule)
		}
	})

	t.Run("empty profiles condition matches any profile", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-alice-any-profile",
					Effect: EffectAllow,
					Conditions: Condition{
						Users:    []string{"alice"},
						Profiles: []string{}, // empty = matches any
					},
					Reason: "alice allowed on any profile",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "random-profile",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (empty profiles matches any), got %v", decision.Effect)
		}
	})

	t.Run("empty users condition matches any user", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-staging",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"staging"},
						Users:    []string{}, // empty = matches any
					},
					Reason: "staging allowed for all users",
				},
			},
		}
		req := &Request{
			User:    "random-user",
			Profile: "staging",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (empty users matches any), got %v", decision.Effect)
		}
	})

	t.Run("no matching rules returns default deny", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-production",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
					},
					Reason: "production allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "staging", // doesn't match production
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (default), got %v", decision.Effect)
		}
		if decision.MatchedRule != "" {
			t.Errorf("expected empty MatchedRule for default deny, got %q", decision.MatchedRule)
		}
		if decision.Reason != "no matching rule" {
			t.Errorf("expected Reason 'no matching rule', got %q", decision.Reason)
		}
	})

	t.Run("user not in condition list does not match", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-team",
					Effect: EffectAllow,
					Conditions: Condition{
						Users: []string{"alice", "bob"},
					},
					Reason: "team members allowed",
				},
			},
		}
		req := &Request{
			User:    "charlie", // not in list
			Profile: "production",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (user not in list), got %v", decision.Effect)
		}
	})

	t.Run("profile not in condition list does not match", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-nonprod",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"staging", "development"},
					},
					Reason: "non-prod allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production", // not in list
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (profile not in list), got %v", decision.Effect)
		}
	})
}

func TestEvaluate_TimeWindow(t *testing.T) {
	// Use a fixed time for deterministic tests
	// Tuesday, January 14, 2025 at 10:30 AM UTC
	fixedTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)

	t.Run("day matches allows rule", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "weekday-only",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Days: []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
						},
					},
					Reason: "weekdays allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    fixedTime, // Tuesday
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (Tuesday is a weekday), got %v", decision.Effect)
		}
	})

	t.Run("day does not match skips rule", func(t *testing.T) {
		// Saturday, January 18, 2025 at 10:30 AM UTC
		saturdayTime := time.Date(2025, time.January, 18, 10, 30, 0, 0, time.UTC)

		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "weekday-only",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Days: []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
						},
					},
					Reason: "weekdays allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    saturdayTime, // Saturday
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (Saturday not in weekday list), got %v", decision.Effect)
		}
		if decision.MatchedRule != "" {
			t.Errorf("expected empty MatchedRule, got %q", decision.MatchedRule)
		}
	})

	t.Run("hour within range allows rule", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "business-hours",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
						},
					},
					Reason: "business hours allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    fixedTime, // 10:30 - within 09:00-17:00
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (10:30 is within 09:00-17:00), got %v", decision.Effect)
		}
	})

	t.Run("hour outside range skips rule", func(t *testing.T) {
		// 20:30 (8:30 PM) - outside business hours
		eveningTime := time.Date(2025, time.January, 14, 20, 30, 0, 0, time.UTC)

		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "business-hours",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
						},
					},
					Reason: "business hours allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    eveningTime, // 20:30 - outside 09:00-17:00
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (20:30 is outside 09:00-17:00), got %v", decision.Effect)
		}
	})

	t.Run("hour at exact start boundary matches", func(t *testing.T) {
		startTime := time.Date(2025, time.January, 14, 9, 0, 0, 0, time.UTC)

		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "business-hours",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
						},
					},
					Reason: "business hours allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    startTime, // exactly 09:00
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (09:00 is at start boundary), got %v", decision.Effect)
		}
	})

	t.Run("hour at exact end boundary does not match", func(t *testing.T) {
		// 17:00 exactly should NOT match (end is exclusive)
		endTime := time.Date(2025, time.January, 14, 17, 0, 0, 0, time.UTC)

		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "business-hours",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
						},
					},
					Reason: "business hours allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    endTime, // exactly 17:00
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (17:00 is at end boundary, exclusive), got %v", decision.Effect)
		}
	})

	t.Run("timezone conversion affects matching", func(t *testing.T) {
		// 10:30 UTC = 05:30 EST (America/New_York in winter)
		// Should NOT match 09:00-17:00 in America/New_York
		utcTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)

		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "business-hours-nyc",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
							Timezone: "America/New_York",
						},
					},
					Reason: "NYC business hours",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    utcTime, // 10:30 UTC = 05:30 EST
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (05:30 EST is before 09:00), got %v", decision.Effect)
		}
	})

	t.Run("timezone conversion allows when in range", func(t *testing.T) {
		// 15:30 UTC = 10:30 EST (America/New_York in winter)
		// Should match 09:00-17:00 in America/New_York
		utcTime := time.Date(2025, time.January, 14, 15, 30, 0, 0, time.UTC)

		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "business-hours-nyc",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
							Timezone: "America/New_York",
						},
					},
					Reason: "NYC business hours",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    utcTime, // 15:30 UTC = 10:30 EST
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (10:30 EST is within 09:00-17:00), got %v", decision.Effect)
		}
	})

	t.Run("empty days list matches any day", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "hours-only",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Days: []Weekday{}, // empty = any day
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
						},
					},
					Reason: "any day during business hours",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    fixedTime, // 10:30 on Tuesday
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (empty days matches any), got %v", decision.Effect)
		}
	})

	t.Run("nil hours matches any time of day", func(t *testing.T) {
		// Saturday
		saturdayTime := time.Date(2025, time.January, 18, 23, 59, 0, 0, time.UTC)

		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "weekend-only",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Days:  []Weekday{Saturday, Sunday},
							Hours: nil, // nil = any hour
						},
					},
					Reason: "weekends any time",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    saturdayTime, // 23:59 on Saturday
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (nil hours matches any time), got %v", decision.Effect)
		}
	})

	t.Run("combined day and hour constraints", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "weekday-business-hours",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Days: []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
						},
					},
					Reason: "weekday business hours",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    fixedTime, // Tuesday 10:30
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (Tuesday 10:30 matches weekday + business hours), got %v", decision.Effect)
		}
	})

	t.Run("day matches but hour does not skips rule", func(t *testing.T) {
		// Tuesday at 20:30
		tuesdayEvening := time.Date(2025, time.January, 14, 20, 30, 0, 0, time.UTC)

		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "weekday-business-hours",
					Effect: EffectAllow,
					Conditions: Condition{
						Time: &TimeWindow{
							Days: []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
						},
					},
					Reason: "weekday business hours",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    tuesdayEvening, // Tuesday 20:30
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (day matches but hour does not), got %v", decision.Effect)
		}
	})
}

func TestEvaluate_CombinedConditions(t *testing.T) {
	fixedTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)

	t.Run("all conditions must match for rule to apply", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "strict-rule",
					Effect: EffectAllow,
					Conditions: Condition{
						Users:    []string{"alice"},
						Profiles: []string{"production"},
						Time: &TimeWindow{
							Days: []Weekday{Tuesday},
						},
					},
					Reason: "all conditions met",
				},
			},
		}

		// All conditions match
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    fixedTime, // Tuesday
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow (all conditions match), got %v", decision.Effect)
		}
	})

	t.Run("user mismatch prevents rule match", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "strict-rule",
					Effect: EffectAllow,
					Conditions: Condition{
						Users:    []string{"alice"},
						Profiles: []string{"production"},
						Time: &TimeWindow{
							Days: []Weekday{Tuesday},
						},
					},
					Reason: "all conditions met",
				},
			},
		}

		// User mismatch
		req := &Request{
			User:    "bob", // wrong user
			Profile: "production",
			Time:    fixedTime, // Tuesday
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (user mismatch), got %v", decision.Effect)
		}
	})

	t.Run("profile mismatch prevents rule match", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "strict-rule",
					Effect: EffectAllow,
					Conditions: Condition{
						Users:    []string{"alice"},
						Profiles: []string{"production"},
						Time: &TimeWindow{
							Days: []Weekday{Tuesday},
						},
					},
					Reason: "all conditions met",
				},
			},
		}

		// Profile mismatch
		req := &Request{
			User:    "alice",
			Profile: "staging", // wrong profile
			Time:    fixedTime, // Tuesday
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (profile mismatch), got %v", decision.Effect)
		}
	})

	t.Run("time mismatch prevents rule match", func(t *testing.T) {
		saturdayTime := time.Date(2025, time.January, 18, 10, 30, 0, 0, time.UTC)

		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "strict-rule",
					Effect: EffectAllow,
					Conditions: Condition{
						Users:    []string{"alice"},
						Profiles: []string{"production"},
						Time: &TimeWindow{
							Days: []Weekday{Tuesday},
						},
					},
					Reason: "all conditions met",
				},
			},
		}

		// Time mismatch
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    saturdayTime, // Saturday, not Tuesday
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (time mismatch), got %v", decision.Effect)
		}
	})
}

func TestDecisionContext_MatchedRule(t *testing.T) {
	t.Run("RuleIndex is set correctly for first rule", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-staging",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"staging"},
					},
					Reason: "staging allowed",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "staging",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.RuleIndex != 0 {
			t.Errorf("expected RuleIndex 0, got %d", decision.RuleIndex)
		}
	})

	t.Run("RuleIndex is set correctly for second rule", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "deny-prod",
					Effect: EffectDeny,
					Conditions: Condition{
						Profiles: []string{"production"},
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
		}
		req := &Request{
			User:    "alice",
			Profile: "staging",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.RuleIndex != 1 {
			t.Errorf("expected RuleIndex 1, got %d", decision.RuleIndex)
		}
	})

	t.Run("Conditions populated from matched rule", func(t *testing.T) {
		expectedProfiles := []string{"staging", "development"}
		expectedUsers := []string{"alice", "bob"}
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-nonprod-team",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: expectedProfiles,
						Users:    expectedUsers,
					},
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "staging",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Conditions == nil {
			t.Fatal("expected Conditions to be non-nil")
		}
		if len(decision.Conditions.Profiles) != len(expectedProfiles) {
			t.Errorf("expected %d profiles, got %d", len(expectedProfiles), len(decision.Conditions.Profiles))
		}
		for i, p := range expectedProfiles {
			if decision.Conditions.Profiles[i] != p {
				t.Errorf("expected profile %q at index %d, got %q", p, i, decision.Conditions.Profiles[i])
			}
		}
		if len(decision.Conditions.Users) != len(expectedUsers) {
			t.Errorf("expected %d users, got %d", len(expectedUsers), len(decision.Conditions.Users))
		}
	})

	t.Run("Conditions includes time window when present", func(t *testing.T) {
		// 15:30 UTC = 10:30 EST, which is within 09:00-17:00 in America/New_York
		fixedTime := time.Date(2025, time.January, 14, 15, 30, 0, 0, time.UTC)
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "business-hours",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Time: &TimeWindow{
							Days: []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
							Hours: &HourRange{
								Start: "09:00",
								End:   "17:00",
							},
							Timezone: "America/New_York",
						},
					},
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    fixedTime,
		}

		decision := Evaluate(policy, req)

		if decision.Conditions == nil {
			t.Fatal("expected Conditions to be non-nil")
		}
		if decision.Conditions.Time == nil {
			t.Fatal("expected Conditions.Time to be non-nil")
		}
		if len(decision.Conditions.Time.Days) != 5 {
			t.Errorf("expected 5 days, got %d", len(decision.Conditions.Time.Days))
		}
		if decision.Conditions.Time.Hours == nil {
			t.Fatal("expected Hours to be non-nil")
		}
		if decision.Conditions.Time.Hours.Start != "09:00" {
			t.Errorf("expected Start '09:00', got %q", decision.Conditions.Time.Hours.Start)
		}
		if decision.Conditions.Time.Timezone != "America/New_York" {
			t.Errorf("expected Timezone 'America/New_York', got %q", decision.Conditions.Time.Timezone)
		}
	})
}

func TestDecisionContext_DefaultDeny(t *testing.T) {
	t.Run("RuleIndex is -1 for default deny", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-prod",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
					},
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "staging", // no matching rule
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.RuleIndex != -1 {
			t.Errorf("expected RuleIndex -1 for default deny, got %d", decision.RuleIndex)
		}
	})

	t.Run("Conditions is nil for default deny", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules:   []Rule{},
		}
		req := &Request{
			User:    "alice",
			Profile: "staging",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Conditions != nil {
			t.Errorf("expected Conditions to be nil for default deny, got %+v", decision.Conditions)
		}
	})

	t.Run("RuleIndex is -1 for nil policy", func(t *testing.T) {
		req := &Request{
			User:    "alice",
			Profile: "staging",
			Time:    time.Now(),
		}

		decision := Evaluate(nil, req)

		if decision.RuleIndex != -1 {
			t.Errorf("expected RuleIndex -1 for nil policy, got %d", decision.RuleIndex)
		}
		if decision.Conditions != nil {
			t.Errorf("expected Conditions to be nil for nil policy, got %+v", decision.Conditions)
		}
	})

	t.Run("RuleIndex is -1 for nil request", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-all",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{},
					},
				},
			},
		}

		decision := Evaluate(policy, nil)

		if decision.RuleIndex != -1 {
			t.Errorf("expected RuleIndex -1 for nil request, got %d", decision.RuleIndex)
		}
	})
}

func TestDecisionContext_EvaluatedAt(t *testing.T) {
	t.Run("EvaluatedAt is reasonable for matched rule", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-staging",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"staging"},
					},
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "staging",
			Time:    time.Now(),
		}

		before := time.Now()
		decision := Evaluate(policy, req)
		after := time.Now()

		if decision.EvaluatedAt.Before(before) {
			t.Errorf("EvaluatedAt %v is before test start %v", decision.EvaluatedAt, before)
		}
		if decision.EvaluatedAt.After(after) {
			t.Errorf("EvaluatedAt %v is after test end %v", decision.EvaluatedAt, after)
		}
	})

	t.Run("EvaluatedAt is reasonable for default deny", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules:   []Rule{},
		}
		req := &Request{
			User:    "alice",
			Profile: "staging",
			Time:    time.Now(),
		}

		before := time.Now()
		decision := Evaluate(policy, req)
		after := time.Now()

		if decision.EvaluatedAt.Before(before) {
			t.Errorf("EvaluatedAt %v is before test start %v", decision.EvaluatedAt, before)
		}
		if decision.EvaluatedAt.After(after) {
			t.Errorf("EvaluatedAt %v is after test end %v", decision.EvaluatedAt, after)
		}
	})

	t.Run("EvaluatedAt is set even for nil policy", func(t *testing.T) {
		req := &Request{
			User:    "alice",
			Profile: "staging",
			Time:    time.Now(),
		}

		before := time.Now()
		decision := Evaluate(nil, req)
		after := time.Now()

		if decision.EvaluatedAt.IsZero() {
			t.Error("EvaluatedAt should not be zero for nil policy")
		}
		if decision.EvaluatedAt.Before(before) || decision.EvaluatedAt.After(after) {
			t.Errorf("EvaluatedAt %v is outside test window [%v, %v]", decision.EvaluatedAt, before, after)
		}
	})
}

func TestDecision_String(t *testing.T) {
	t.Run("ALLOW format with rule name and index", func(t *testing.T) {
		decision := Decision{
			Effect:      EffectAllow,
			MatchedRule: "allow-staging",
			RuleIndex:   0,
		}

		result := decision.String()

		expected := "ALLOW by rule 'allow-staging' (index 0)"
		if result != expected {
			t.Errorf("expected %q, got %q", expected, result)
		}
	})

	t.Run("DENY format with rule name and index", func(t *testing.T) {
		decision := Decision{
			Effect:      EffectDeny,
			MatchedRule: "deny-prod",
			RuleIndex:   2,
		}

		result := decision.String()

		expected := "DENY by rule 'deny-prod' (index 2)"
		if result != expected {
			t.Errorf("expected %q, got %q", expected, result)
		}
	})

	t.Run("default deny format", func(t *testing.T) {
		decision := Decision{
			Effect:      EffectDeny,
			MatchedRule: "",
			RuleIndex:   -1,
		}

		result := decision.String()

		expected := "DENY (no matching rule)"
		if result != expected {
			t.Errorf("expected %q, got %q", expected, result)
		}
	})

	t.Run("String output from Evaluate for allow", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-dev",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"development"},
					},
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "development",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)
		result := decision.String()

		expected := "ALLOW by rule 'allow-dev' (index 0)"
		if result != expected {
			t.Errorf("expected %q, got %q", expected, result)
		}
	})

	t.Run("String output from Evaluate for default deny", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules:   []Rule{},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)
		result := decision.String()

		expected := "DENY (no matching rule)"
		if result != expected {
			t.Errorf("expected %q, got %q", expected, result)
		}
	})
}

func TestGoWeekdayToWeekday_AllDays(t *testing.T) {
	tests := []struct {
		name     string
		goDay    time.Weekday
		expected Weekday
	}{
		{"Sunday", time.Sunday, Sunday},
		{"Monday", time.Monday, Monday},
		{"Tuesday", time.Tuesday, Tuesday},
		{"Wednesday", time.Wednesday, Wednesday},
		{"Thursday", time.Thursday, Thursday},
		{"Friday", time.Friday, Friday},
		{"Saturday", time.Saturday, Saturday},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := goWeekdayToWeekday(tt.goDay)
			if result != tt.expected {
				t.Errorf("goWeekdayToWeekday(%v) = %q, want %q", tt.goDay, result, tt.expected)
			}
		})
	}
}

func TestGoWeekdayToWeekday_InvalidDay(t *testing.T) {
	// Test that an invalid weekday value returns empty string (the default case)
	// time.Weekday is an int, so we can cast an invalid value
	invalidDay := time.Weekday(99)
	result := goWeekdayToWeekday(invalidDay)
	if result != "" {
		t.Errorf("goWeekdayToWeekday(%v) = %q, want empty string", invalidDay, result)
	}
}

func TestParseHourMinute_EdgeCases(t *testing.T) {
	// parseHourMinute is a private function, so we test it indirectly via matchesHours.
	// However, since matchesHours requires time parsing, we use a direct approach
	// by testing parseHourMinute directly from within the same package.

	tests := []struct {
		name         string
		input        string
		expectedHour int
		expectedMin  int
	}{
		{"Normal HH:MM", "09:00", 9, 0},
		{"Afternoon", "17:30", 17, 30},
		{"Midnight", "00:00", 0, 0},
		{"End of day", "23:59", 23, 59},
		{"Empty string", "", 0, 0},              // len(parts) != 2
		{"No colon", "0900", 0, 0},              // len(parts) != 2
		{"Multiple colons", "09:00:00", 0, 0},   // len(parts) != 2
		{"Just hour", "09", 0, 0},               // len(parts) != 2
		{"Colon only", ":", 0, 0},               // parts[0] and parts[1] empty
		{"Leading colon", ":30", 0, 30},         // hour parse fails -> 0
		{"Trailing colon", "09:", 9, 0},         // minute parse fails -> 0
		{"Invalid hour chars", "ab:30", 0, 30},  // hour parse fails -> 0
		{"Invalid minute chars", "09:cd", 9, 0}, // minute parse fails -> 0
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hour, minute := parseHourMinute(tt.input)
			if hour != tt.expectedHour || minute != tt.expectedMin {
				t.Errorf("parseHourMinute(%q) = (%d, %d), want (%d, %d)",
					tt.input, hour, minute, tt.expectedHour, tt.expectedMin)
			}
		})
	}
}

func TestEvaluate_EdgeCases(t *testing.T) {
	t.Run("empty policy returns default deny", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules:   []Rule{},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (empty rules), got %v", decision.Effect)
		}
		if decision.Reason != "no matching rule" {
			t.Errorf("expected Reason 'no matching rule', got %q", decision.Reason)
		}
	})

	t.Run("nil policy returns default deny", func(t *testing.T) {
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := Evaluate(nil, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (nil policy), got %v", decision.Effect)
		}
	})

	t.Run("nil request returns default deny", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-all",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
					},
				},
			},
		}

		decision := Evaluate(policy, nil)

		if decision.Effect != EffectDeny {
			t.Errorf("expected EffectDeny (nil request), got %v", decision.Effect)
		}
	})

	t.Run("multiple matching rules returns first match", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "first-match",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
					},
					Reason: "first rule",
				},
				{
					Name:   "second-match",
					Effect: EffectDeny,
					Conditions: Condition{
						Profiles: []string{"production"},
					},
					Reason: "second rule",
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := Evaluate(policy, req)

		if decision.MatchedRule != "first-match" {
			t.Errorf("expected first matching rule 'first-match', got %q", decision.MatchedRule)
		}
		if decision.Effect != EffectAllow {
			t.Errorf("expected EffectAllow from first rule, got %v", decision.Effect)
		}
	})
}

func TestMatchesMode(t *testing.T) {
	tests := []struct {
		name     string
		modes    []CredentialMode
		mode     CredentialMode
		expected bool
	}{
		{"empty list matches any mode", nil, ModeServer, true},
		{"empty list matches cli", nil, ModeCLI, true},
		{"server matches server", []CredentialMode{ModeServer}, ModeServer, true},
		{"server does not match cli", []CredentialMode{ModeServer}, ModeCLI, false},
		{"multiple modes - server matches", []CredentialMode{ModeServer, ModeCLI}, ModeServer, true},
		{"multiple modes - cli matches", []CredentialMode{ModeServer, ModeCLI}, ModeCLI, true},
		{"multiple modes - credential_process no match", []CredentialMode{ModeServer, ModeCLI}, ModeCredentialProcess, false},
		{"credential_process matches", []CredentialMode{ModeCredentialProcess}, ModeCredentialProcess, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesMode(tt.modes, tt.mode)
			if result != tt.expected {
				t.Errorf("matchesMode(%v, %v) = %v, want %v", tt.modes, tt.mode, result, tt.expected)
			}
		})
	}
}

func TestEvaluate_ModeCondition(t *testing.T) {
	tests := []struct {
		name       string
		policy     *Policy
		request    *Request
		wantEffect Effect
		wantRule   string
	}{
		{
			name: "server-only rule matches server mode",
			policy: &Policy{
				Version: "1",
				Rules: []Rule{
					{Name: "server-only", Effect: EffectAllow, Conditions: Condition{Mode: []CredentialMode{ModeServer}}},
				},
			},
			request:    &Request{User: "alice", Profile: "prod", Time: time.Now(), Mode: ModeServer},
			wantEffect: EffectAllow,
			wantRule:   "server-only",
		},
		{
			name: "server-only rule denies cli mode",
			policy: &Policy{
				Version: "1",
				Rules: []Rule{
					{Name: "server-only", Effect: EffectAllow, Conditions: Condition{Mode: []CredentialMode{ModeServer}}},
				},
			},
			request:    &Request{User: "alice", Profile: "prod", Time: time.Now(), Mode: ModeCLI},
			wantEffect: EffectDeny,
			wantRule:   "", // default deny
		},
		{
			name: "no mode condition matches any mode",
			policy: &Policy{
				Version: "1",
				Rules: []Rule{
					{Name: "any-mode", Effect: EffectAllow, Conditions: Condition{Users: []string{"alice"}}},
				},
			},
			request:    &Request{User: "alice", Profile: "prod", Time: time.Now(), Mode: ModeCredentialProcess},
			wantEffect: EffectAllow,
			wantRule:   "any-mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := Evaluate(tt.policy, tt.request)
			if decision.Effect != tt.wantEffect {
				t.Errorf("Effect = %v, want %v", decision.Effect, tt.wantEffect)
			}
			if decision.MatchedRule != tt.wantRule {
				t.Errorf("MatchedRule = %v, want %v", decision.MatchedRule, tt.wantRule)
			}
		})
	}
}

func TestEvaluate_MaxServerDuration(t *testing.T) {
	t.Run("Decision includes MaxServerDuration from matched rule", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:              "allow-with-duration-cap",
					Effect:            EffectAllow,
					Conditions:        Condition{Profiles: []string{"production"}},
					MaxServerDuration: 10 * time.Minute,
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
			Mode:    ModeServer,
		}

		decision := Evaluate(policy, req)

		if decision.MaxServerDuration != 10*time.Minute {
			t.Errorf("expected MaxServerDuration 10m, got %v", decision.MaxServerDuration)
		}
	})

	t.Run("Decision MaxServerDuration is 0 when rule has no cap", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:       "allow-no-cap",
					Effect:     EffectAllow,
					Conditions: Condition{Profiles: []string{"staging"}},
					// MaxServerDuration not set (defaults to 0)
				},
			},
		}
		req := &Request{
			User:    "alice",
			Profile: "staging",
			Time:    time.Now(),
			Mode:    ModeServer,
		}

		decision := Evaluate(policy, req)

		if decision.MaxServerDuration != 0 {
			t.Errorf("expected MaxServerDuration 0 (no cap), got %v", decision.MaxServerDuration)
		}
	})

	t.Run("Default deny has 0 MaxServerDuration", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules:   []Rule{}, // No rules - default deny
		}
		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
			Mode:    ModeServer,
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("expected default deny, got %v", decision.Effect)
		}
		if decision.MaxServerDuration != 0 {
			t.Errorf("expected MaxServerDuration 0 for default deny, got %v", decision.MaxServerDuration)
		}
	})

	t.Run("MaxServerDuration preserved with various durations", func(t *testing.T) {
		testCases := []struct {
			name     string
			duration time.Duration
		}{
			{"5 minutes", 5 * time.Minute},
			{"15 minutes", 15 * time.Minute},
			{"1 hour", 1 * time.Hour},
			{"30 seconds", 30 * time.Second},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				policy := &Policy{
					Version: "1",
					Rules: []Rule{
						{
							Name:              "allow-duration",
							Effect:            EffectAllow,
							MaxServerDuration: tc.duration,
						},
					},
				}
				req := &Request{
					User:    "alice",
					Profile: "production",
					Time:    time.Now(),
				}

				decision := Evaluate(policy, req)

				if decision.MaxServerDuration != tc.duration {
					t.Errorf("expected MaxServerDuration %v, got %v", tc.duration, decision.MaxServerDuration)
				}
			})
		}
	})
}

func TestCredentialMode_IsValid(t *testing.T) {
	tests := []struct {
		mode  CredentialMode
		valid bool
	}{
		{ModeServer, true},
		{ModeCLI, true},
		{ModeCredentialProcess, true},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := tt.mode.IsValid(); got != tt.valid {
				t.Errorf("CredentialMode(%q).IsValid() = %v, want %v", tt.mode, got, tt.valid)
			}
		})
	}
}

func TestEvaluate_RequireServerEffect(t *testing.T) {
	tests := []struct {
		name               string
		mode               CredentialMode
		wantEffect         Effect
		wantRequiresServer bool
	}{
		{
			name:               "server mode allowed",
			mode:               ModeServer,
			wantEffect:         EffectAllow,
			wantRequiresServer: false,
		},
		{
			name:               "cli mode denied",
			mode:               ModeCLI,
			wantEffect:         EffectDeny,
			wantRequiresServer: true,
		},
		{
			name:               "credential_process mode denied",
			mode:               ModeCredentialProcess,
			wantEffect:         EffectDeny,
			wantRequiresServer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "require-server",
						Effect: EffectRequireServer,
						Conditions: Condition{
							Profiles: []string{"production"},
						},
					},
				},
			}

			req := &Request{
				User:    "alice",
				Profile: "production",
				Time:    time.Now(),
				Mode:    tt.mode,
			}

			decision := Evaluate(policy, req)

			if decision.Effect != tt.wantEffect {
				t.Errorf("Effect = %v, want %v", decision.Effect, tt.wantEffect)
			}
			if decision.RequiresServerMode != tt.wantRequiresServer {
				t.Errorf("RequiresServerMode = %v, want %v", decision.RequiresServerMode, tt.wantRequiresServer)
			}
			if decision.MatchedRule != "require-server" {
				t.Errorf("MatchedRule = %v, want require-server", decision.MatchedRule)
			}
		})
	}
}

func TestEffectRequireServer_IsValid(t *testing.T) {
	if !EffectRequireServer.IsValid() {
		t.Error("EffectRequireServer.IsValid() = false, want true")
	}
}

func TestEvaluate_RequireServerSession(t *testing.T) {
	tests := []struct {
		name                     string
		mode                     CredentialMode
		sessionTableName         string
		wantEffect               Effect
		wantRequiresServerMode   bool
		wantRequiresSessionTrack bool
	}{
		{
			name:                     "server mode + session table = ALLOW",
			mode:                     ModeServer,
			sessionTableName:         "sentinel-sessions",
			wantEffect:               EffectAllow,
			wantRequiresServerMode:   false,
			wantRequiresSessionTrack: false,
		},
		{
			name:                     "server mode + NO session table = DENY",
			mode:                     ModeServer,
			sessionTableName:         "",
			wantEffect:               EffectDeny,
			wantRequiresServerMode:   false, // Mode is correct, only session tracking missing
			wantRequiresSessionTrack: true,
		},
		{
			name:                     "cli mode + session table = DENY",
			mode:                     ModeCLI,
			sessionTableName:         "sentinel-sessions",
			wantEffect:               EffectDeny,
			wantRequiresServerMode:   true,
			wantRequiresSessionTrack: true,
		},
		{
			name:                     "cli mode + NO session table = DENY (both flags true)",
			mode:                     ModeCLI,
			sessionTableName:         "",
			wantEffect:               EffectDeny,
			wantRequiresServerMode:   true,
			wantRequiresSessionTrack: true,
		},
		{
			name:                     "credential_process mode = DENY",
			mode:                     ModeCredentialProcess,
			sessionTableName:         "sentinel-sessions",
			wantEffect:               EffectDeny,
			wantRequiresServerMode:   true,
			wantRequiresSessionTrack: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "require-server-session",
						Effect: EffectRequireServerSession,
						Conditions: Condition{
							Profiles: []string{"production"},
						},
					},
				},
			}

			req := &Request{
				User:             "alice",
				Profile:          "production",
				Time:             time.Now(),
				Mode:             tt.mode,
				SessionTableName: tt.sessionTableName,
			}

			decision := Evaluate(policy, req)

			if decision.Effect != tt.wantEffect {
				t.Errorf("Effect = %v, want %v", decision.Effect, tt.wantEffect)
			}
			if decision.RequiresServerMode != tt.wantRequiresServerMode {
				t.Errorf("RequiresServerMode = %v, want %v", decision.RequiresServerMode, tt.wantRequiresServerMode)
			}
			if decision.RequiresSessionTracking != tt.wantRequiresSessionTrack {
				t.Errorf("RequiresSessionTracking = %v, want %v", decision.RequiresSessionTracking, tt.wantRequiresSessionTrack)
			}
			if decision.MatchedRule != "require-server-session" {
				t.Errorf("MatchedRule = %v, want require-server-session", decision.MatchedRule)
			}
		})
	}
}

func TestEffectRequireServerSession_IsValid(t *testing.T) {
	if !EffectRequireServerSession.IsValid() {
		t.Error("EffectRequireServerSession.IsValid() = false, want true")
	}
}

// TestEvaluate_SessionTablePropagation tests that SessionTableName from rules is propagated to decisions.
func TestEvaluate_SessionTablePropagation(t *testing.T) {
	t.Run("require_server_session with session_table specified", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:         "require-session",
					Effect:       EffectRequireServerSession,
					SessionTable: "policy-table",
					Conditions: Condition{
						Profiles: []string{"production"},
					},
				},
			},
		}

		req := &Request{
			User:             "alice",
			Profile:          "production",
			Time:             time.Now(),
			Mode:             ModeServer,
			SessionTableName: "cli-table", // CLI specified, but policy should override
		}

		decision := Evaluate(policy, req)

		if decision.SessionTableName != "policy-table" {
			t.Errorf("SessionTableName = %q, want 'policy-table'", decision.SessionTableName)
		}
	})

	t.Run("require_server_session without session_table", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:         "require-session",
					Effect:       EffectRequireServerSession,
					SessionTable: "", // Not specified in policy
					Conditions: Condition{
						Profiles: []string{"production"},
					},
				},
			},
		}

		req := &Request{
			User:             "alice",
			Profile:          "production",
			Time:             time.Now(),
			Mode:             ModeServer,
			SessionTableName: "cli-table",
		}

		decision := Evaluate(policy, req)

		// SessionTableName should be empty (CLI value used, not from policy)
		if decision.SessionTableName != "" {
			t.Errorf("SessionTableName = %q, want empty (use CLI value)", decision.SessionTableName)
		}
	})

	t.Run("allow effect with session_table", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:         "allow-with-audit",
					Effect:       EffectAllow,
					SessionTable: "audit-table",
					Conditions: Condition{
						Profiles: []string{"production"},
					},
				},
			},
		}

		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
			Mode:    ModeServer,
		}

		decision := Evaluate(policy, req)

		// session_table should be propagated regardless of effect
		if decision.SessionTableName != "audit-table" {
			t.Errorf("SessionTableName = %q, want 'audit-table'", decision.SessionTableName)
		}
	})

	t.Run("deny effect preserves session_table from rule", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:         "deny-with-table",
					Effect:       EffectDeny,
					SessionTable: "deny-audit-table",
					Conditions: Condition{
						Profiles: []string{"production"},
					},
				},
			},
		}

		req := &Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
			Mode:    ModeCLI,
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectDeny {
			t.Errorf("Effect = %v, want EffectDeny", decision.Effect)
		}
		// session_table should still be set even for deny rules
		if decision.SessionTableName != "deny-audit-table" {
			t.Errorf("SessionTableName = %q, want 'deny-audit-table'", decision.SessionTableName)
		}
	})
}

// ============================================================================
// Device Condition Tests
// ============================================================================

// boolPtr is a helper to create bool pointers for tests.
func boolPtr(b bool) *bool {
	return &b
}

func TestEvaluate_DeviceConditions(t *testing.T) {
	t.Run("rule with device conditions - posture matches - allow", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "require-mdm",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device: &DeviceCondition{
							RequireMDM: true,
						},
					},
					Reason: "MDM required for production",
				},
			},
		}

		posture := &device.DevicePosture{
			DeviceID:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			Status:      device.StatusCompliant,
			MDMEnrolled: boolPtr(true),
			CollectedAt: time.Now(),
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: posture,
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("Effect = %v, want EffectAllow (posture matches)", decision.Effect)
		}
		if decision.MatchedRule != "require-mdm" {
			t.Errorf("MatchedRule = %q, want 'require-mdm'", decision.MatchedRule)
		}
	})

	t.Run("rule with device conditions - posture fails - rule not matched, falls through", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "require-mdm",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device: &DeviceCondition{
							RequireMDM: true,
						},
					},
					Reason: "MDM required for production",
				},
			},
		}

		// Device is not MDM enrolled - posture fails
		posture := &device.DevicePosture{
			DeviceID:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			Status:      device.StatusNonCompliant,
			MDMEnrolled: boolPtr(false), // Not enrolled
			CollectedAt: time.Now(),
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: posture,
		}

		decision := Evaluate(policy, req)

		// Rule doesn't match, falls through to default deny
		if decision.Effect != EffectDeny {
			t.Errorf("Effect = %v, want EffectDeny (posture fails, rule not matched)", decision.Effect)
		}
		if decision.MatchedRule != "" {
			t.Errorf("MatchedRule = %q, want empty (no matching rule)", decision.MatchedRule)
		}
	})

	t.Run("rule with device conditions - nil posture - rule not matched", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "require-mdm",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device: &DeviceCondition{
							RequireMDM: true,
						},
					},
					Reason: "MDM required for production",
				},
			},
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: nil, // No device posture available
		}

		decision := Evaluate(policy, req)

		// Nil posture fails non-empty device condition, rule doesn't match
		if decision.Effect != EffectDeny {
			t.Errorf("Effect = %v, want EffectDeny (nil posture fails non-empty condition)", decision.Effect)
		}
		if decision.MatchedRule != "" {
			t.Errorf("MatchedRule = %q, want empty (no matching rule)", decision.MatchedRule)
		}
	})

	t.Run("rule without device conditions - any posture - matches (backward compatible)", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-production",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						// No Device condition
					},
					Reason: "production allowed",
				},
			},
		}

		// Even with non-compliant posture, rule matches (no device condition)
		posture := &device.DevicePosture{
			DeviceID:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			Status:      device.StatusNonCompliant,
			MDMEnrolled: boolPtr(false),
			CollectedAt: time.Now(),
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: posture,
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("Effect = %v, want EffectAllow (no device condition = backward compatible)", decision.Effect)
		}
		if decision.MatchedRule != "allow-production" {
			t.Errorf("MatchedRule = %q, want 'allow-production'", decision.MatchedRule)
		}
	})

	t.Run("multiple rules - first has device condition that fails, second allows", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "strict-production-mdm",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device: &DeviceCondition{
							RequireMDM: true,
						},
					},
					Reason: "MDM required for production",
				},
				{
					Name:   "fallback-production",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						// No device condition - fallback rule
					},
					Reason: "production allowed without MDM (fallback)",
				},
			},
		}

		// Device not enrolled - first rule fails, falls through to second
		posture := &device.DevicePosture{
			DeviceID:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			Status:      device.StatusNonCompliant,
			MDMEnrolled: boolPtr(false),
			CollectedAt: time.Now(),
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: posture,
		}

		decision := Evaluate(policy, req)

		// First rule doesn't match (device fails), second rule matches
		if decision.Effect != EffectAllow {
			t.Errorf("Effect = %v, want EffectAllow (second rule should match)", decision.Effect)
		}
		if decision.MatchedRule != "fallback-production" {
			t.Errorf("MatchedRule = %q, want 'fallback-production'", decision.MatchedRule)
		}
		if decision.RuleIndex != 1 {
			t.Errorf("RuleIndex = %d, want 1 (second rule)", decision.RuleIndex)
		}
	})

	t.Run("rule with empty device condition - matches any posture", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "allow-with-empty-device",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device:   &DeviceCondition{}, // Empty device condition
					},
					Reason: "empty device condition",
				},
			},
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: nil, // Even nil posture should match empty device condition
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("Effect = %v, want EffectAllow (empty device condition matches any)", decision.Effect)
		}
	})

	t.Run("require_encryption - posture has encryption", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "require-encryption",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device: &DeviceCondition{
							RequireEncryption: true,
						},
					},
				},
			},
		}

		posture := &device.DevicePosture{
			DeviceID:      "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			Status:        device.StatusCompliant,
			DiskEncrypted: boolPtr(true),
			CollectedAt:   time.Now(),
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: posture,
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("Effect = %v, want EffectAllow", decision.Effect)
		}
	})

	t.Run("require_encryption - posture lacks encryption", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "require-encryption",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device: &DeviceCondition{
							RequireEncryption: true,
						},
					},
				},
			},
		}

		posture := &device.DevicePosture{
			DeviceID:      "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			Status:        device.StatusNonCompliant,
			DiskEncrypted: boolPtr(false), // Not encrypted
			CollectedAt:   time.Now(),
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: posture,
		}

		decision := Evaluate(policy, req)

		// Rule doesn't match, default deny
		if decision.Effect != EffectDeny {
			t.Errorf("Effect = %v, want EffectDeny", decision.Effect)
		}
	})

	t.Run("require_mdm_compliant - posture is compliant", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "require-mdm-compliant",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device: &DeviceCondition{
							RequireMDMCompliant: true,
						},
					},
				},
			},
		}

		posture := &device.DevicePosture{
			DeviceID:     "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			Status:       device.StatusCompliant,
			MDMEnrolled:  boolPtr(true),
			MDMCompliant: boolPtr(true),
			CollectedAt:  time.Now(),
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: posture,
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("Effect = %v, want EffectAllow", decision.Effect)
		}
	})

	t.Run("require_mdm_compliant - posture is not compliant", func(t *testing.T) {
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "require-mdm-compliant",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device: &DeviceCondition{
							RequireMDMCompliant: true,
						},
					},
				},
			},
		}

		posture := &device.DevicePosture{
			DeviceID:     "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
			Status:       device.StatusNonCompliant,
			MDMEnrolled:  boolPtr(true),
			MDMCompliant: boolPtr(false), // Not compliant
			CollectedAt:  time.Now(),
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: posture,
		}

		decision := Evaluate(policy, req)

		// Rule doesn't match, default deny
		if decision.Effect != EffectDeny {
			t.Errorf("Effect = %v, want EffectDeny", decision.Effect)
		}
	})

	t.Run("device condition with nil posture - defaults to empty condition behavior", func(t *testing.T) {
		// Nil Device pointer should not panic
		policy := &Policy{
			Version: "1",
			Rules: []Rule{
				{
					Name:   "no-device-condition",
					Effect: EffectAllow,
					Conditions: Condition{
						Profiles: []string{"production"},
						Device:   nil, // Explicitly nil
					},
				},
			},
		}

		req := &Request{
			User:          "alice",
			Profile:       "production",
			Time:          time.Now(),
			DevicePosture: nil,
		}

		decision := Evaluate(policy, req)

		if decision.Effect != EffectAllow {
			t.Errorf("Effect = %v, want EffectAllow (nil device condition)", decision.Effect)
		}
	})
}
