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
