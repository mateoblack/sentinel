package policy

import (
	"testing"
	"time"
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
