// Security regression tests for policy evaluation denial paths.
// These tests serve as regression guards against future code changes that
// might inadvertently weaken security by allowing credential issuance
// when policy should deny.
//
// Test naming convention: TestSecurityRegression_<Category>_<Specific>
// Categories:
//   - DefaultDeny: Tests that default deny is enforced
//   - RuleBypass: Tests that rules cannot be bypassed
//   - TimeWindow: Tests time-based access control
//   - EffectIsolation: Tests that effects work correctly

package policy

import (
	"testing"
	"time"
)

// ============================================================================
// Default Deny Enforcement Tests
// ============================================================================

// TestSecurityRegression_DefaultDeny_EmptyPolicy verifies that an empty policy
// (no rules) always returns deny. This is the security foundation: no explicit
// allow = no credentials.
func TestSecurityRegression_DefaultDeny_EmptyPolicy(t *testing.T) {
	policy := &Policy{
		Version: "1",
		Rules:   []Rule{}, // No rules
	}
	req := &Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := Evaluate(policy, req)

	if decision.Effect != EffectDeny {
		t.Errorf("Empty policy MUST deny, got %v", decision.Effect)
	}
	if decision.MatchedRule != "" {
		t.Errorf("Empty policy should have no matched rule, got %q", decision.MatchedRule)
	}
	if decision.RuleIndex != -1 {
		t.Errorf("Empty policy should have RuleIndex -1, got %d", decision.RuleIndex)
	}
}

// TestSecurityRegression_DefaultDeny_NilPolicy verifies that a nil policy
// always returns deny. No policy = no credentials.
func TestSecurityRegression_DefaultDeny_NilPolicy(t *testing.T) {
	req := &Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := Evaluate(nil, req)

	if decision.Effect != EffectDeny {
		t.Errorf("Nil policy MUST deny, got %v", decision.Effect)
	}
	if decision.RuleIndex != -1 {
		t.Errorf("Nil policy should have RuleIndex -1, got %d", decision.RuleIndex)
	}
}

// TestSecurityRegression_DefaultDeny_NilRequest verifies that a nil request
// always returns deny. No valid request = no credentials.
func TestSecurityRegression_DefaultDeny_NilRequest(t *testing.T) {
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-all",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{}, // Wildcard - should match any
				},
			},
		},
	}

	decision := Evaluate(policy, nil)

	if decision.Effect != EffectDeny {
		t.Errorf("Nil request MUST deny, got %v", decision.Effect)
	}
}

// TestSecurityRegression_DefaultDeny_NoMatchingRules verifies that when
// no rules match the request, the decision is deny.
func TestSecurityRegression_DefaultDeny_NoMatchingRules(t *testing.T) {
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-production",
				Effect: EffectAllow,
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
		Profile: "development", // Neither production nor staging
		Time:    time.Now(),
	}

	decision := Evaluate(policy, req)

	if decision.Effect != EffectDeny {
		t.Errorf("No matching rules MUST deny, got %v", decision.Effect)
	}
	if decision.Reason != "no matching rule" {
		t.Errorf("Expected reason 'no matching rule', got %q", decision.Reason)
	}
}

// TestSecurityRegression_DefaultDeny_NoCodePathAllowsWithoutMatch ensures that
// no code path can return allow without an explicit rule match.
func TestSecurityRegression_DefaultDeny_NoCodePathAllowsWithoutMatch(t *testing.T) {
	tests := []struct {
		name    string
		policy  *Policy
		request *Request
	}{
		{
			name:   "nil policy",
			policy: nil,
			request: &Request{
				User:    "alice",
				Profile: "production",
				Time:    time.Now(),
			},
		},
		{
			name: "nil request",
			policy: &Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:       "allow-all",
						Effect:     EffectAllow,
						Conditions: Condition{},
					},
				},
			},
			request: nil,
		},
		{
			name: "empty rules",
			policy: &Policy{
				Version: "1",
				Rules:   []Rule{},
			},
			request: &Request{
				User:    "alice",
				Profile: "production",
				Time:    time.Now(),
			},
		},
		{
			name: "no matching user",
			policy: &Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "allow-bob",
						Effect: EffectAllow,
						Conditions: Condition{
							Users: []string{"bob"},
						},
					},
				},
			},
			request: &Request{
				User:    "alice",
				Profile: "production",
				Time:    time.Now(),
			},
		},
		{
			name: "no matching profile",
			policy: &Policy{
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
			},
			request: &Request{
				User:    "alice",
				Profile: "staging",
				Time:    time.Now(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := Evaluate(tt.policy, tt.request)
			if decision.Effect == EffectAllow {
				t.Errorf("SECURITY VIOLATION: %s returned Allow without explicit match", tt.name)
			}
		})
	}
}

// ============================================================================
// Rule Bypass Prevention Tests
// ============================================================================

// TestSecurityRegression_RuleBypass_UserCaseSensitive verifies that user
// matching is case-sensitive. "Admin" must NOT match "admin".
func TestSecurityRegression_RuleBypass_UserCaseSensitive(t *testing.T) {
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-admin",
				Effect: EffectAllow,
				Conditions: Condition{
					Users: []string{"admin"},
				},
			},
		},
	}

	tests := []struct {
		user     string
		expectDeny bool
	}{
		{"admin", false},     // Exact match - should allow
		{"Admin", true},      // Different case - MUST deny
		{"ADMIN", true},      // Different case - MUST deny
		{"aDmIn", true},      // Different case - MUST deny
		{"admin ", true},     // Trailing space - MUST deny
		{" admin", true},     // Leading space - MUST deny
		{"admin\n", true},    // Newline - MUST deny
		{"admin\t", true},    // Tab - MUST deny
	}

	for _, tt := range tests {
		t.Run(tt.user, func(t *testing.T) {
			req := &Request{
				User:    tt.user,
				Profile: "production",
				Time:    time.Now(),
			}
			decision := Evaluate(policy, req)

			if tt.expectDeny && decision.Effect == EffectAllow {
				t.Errorf("SECURITY VIOLATION: User %q should NOT match rule for 'admin'", tt.user)
			}
			if !tt.expectDeny && decision.Effect != EffectAllow {
				t.Errorf("User %q should match rule for 'admin', got %v", tt.user, decision.Effect)
			}
		})
	}
}

// TestSecurityRegression_RuleBypass_ProfileCaseSensitive verifies that profile
// matching is case-sensitive. "Prod" must NOT match "prod".
func TestSecurityRegression_RuleBypass_ProfileCaseSensitive(t *testing.T) {
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-prod",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod"},
				},
			},
		},
	}

	tests := []struct {
		profile    string
		expectDeny bool
	}{
		{"prod", false},      // Exact match - should allow
		{"Prod", true},       // Different case - MUST deny
		{"PROD", true},       // Different case - MUST deny
		{"pRoD", true},       // Different case - MUST deny
		{"prod ", true},      // Trailing space - MUST deny
		{" prod", true},      // Leading space - MUST deny
		{"production", true}, // Longer string - MUST deny
		{"pro", true},        // Shorter string - MUST deny
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			req := &Request{
				User:    "alice",
				Profile: tt.profile,
				Time:    time.Now(),
			}
			decision := Evaluate(policy, req)

			if tt.expectDeny && decision.Effect == EffectAllow {
				t.Errorf("SECURITY VIOLATION: Profile %q should NOT match rule for 'prod'", tt.profile)
			}
			if !tt.expectDeny && decision.Effect != EffectAllow {
				t.Errorf("Profile %q should match rule for 'prod', got %v", tt.profile, decision.Effect)
			}
		})
	}
}

// TestSecurityRegression_RuleBypass_PartialStringRejection verifies that
// partial string matches are rejected. "alice" must NOT match "alice@example.com".
func TestSecurityRegression_RuleBypass_PartialStringRejection(t *testing.T) {
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-alice-email",
				Effect: EffectAllow,
				Conditions: Condition{
					Users: []string{"alice@example.com"},
				},
			},
		},
	}

	partialMatches := []string{
		"alice",           // Prefix only
		"example.com",     // Suffix only
		"alice@example",   // Missing .com
		"@example.com",    // Missing alice
		"alice@",          // Missing domain
		"lice@example.com", // Missing first char
		"alice@example.co", // Missing last char
	}

	for _, user := range partialMatches {
		t.Run(user, func(t *testing.T) {
			req := &Request{
				User:    user,
				Profile: "production",
				Time:    time.Now(),
			}
			decision := Evaluate(policy, req)

			if decision.Effect == EffectAllow {
				t.Errorf("SECURITY VIOLATION: User %q should NOT match rule for 'alice@example.com'", user)
			}
		})
	}
}

// TestSecurityRegression_RuleBypass_EmptyUserInRequest verifies that an empty
// user in request evaluates correctly and does not match wildcard unexpectedly.
func TestSecurityRegression_RuleBypass_EmptyUserInRequest(t *testing.T) {
	// Policy with specific users - empty user should not match
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-specific-users",
				Effect: EffectAllow,
				Conditions: Condition{
					Users: []string{"alice", "bob"},
				},
			},
		},
	}

	req := &Request{
		User:    "", // Empty user
		Profile: "production",
		Time:    time.Now(),
	}

	decision := Evaluate(policy, req)

	if decision.Effect == EffectAllow {
		t.Errorf("Empty user should NOT match specific user list")
	}
}

// TestSecurityRegression_RuleBypass_EmptyProfileInRequest verifies that an empty
// profile in request evaluates correctly.
func TestSecurityRegression_RuleBypass_EmptyProfileInRequest(t *testing.T) {
	// Policy with specific profiles - empty profile should not match
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-specific-profiles",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"production", "staging"},
				},
			},
		},
	}

	req := &Request{
		User:    "alice",
		Profile: "", // Empty profile
		Time:    time.Now(),
	}

	decision := Evaluate(policy, req)

	if decision.Effect == EffectAllow {
		t.Errorf("Empty profile should NOT match specific profile list")
	}
}

// ============================================================================
// Time Window Bypass Prevention Tests
// ============================================================================

// TestSecurityRegression_TimeWindow_OneNanosecondBeforeStart verifies that
// requests at 1 nanosecond before window start are denied.
func TestSecurityRegression_TimeWindow_OneNanosecondBeforeStart(t *testing.T) {
	// Window: 09:00-17:00 UTC
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
			},
		},
	}

	// 08:59:59.999999999 - one nanosecond before 09:00
	beforeStart := time.Date(2025, time.January, 14, 8, 59, 59, 999999999, time.UTC)

	req := &Request{
		User:    "alice",
		Profile: "production",
		Time:    beforeStart,
	}

	decision := Evaluate(policy, req)

	if decision.Effect == EffectAllow {
		t.Errorf("SECURITY VIOLATION: Request at 08:59:59.999999999 should be denied (before 09:00 window)")
	}
}

// TestSecurityRegression_TimeWindow_OneNanosecondAfterEnd verifies that
// requests at 1 nanosecond after window end are denied.
func TestSecurityRegression_TimeWindow_OneNanosecondAfterEnd(t *testing.T) {
	// Window: 09:00-17:00 UTC (end is exclusive)
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
			},
		},
	}

	// 17:00:00.000000001 - one nanosecond after 17:00 (which is already excluded)
	afterEnd := time.Date(2025, time.January, 14, 17, 0, 0, 1, time.UTC)

	req := &Request{
		User:    "alice",
		Profile: "production",
		Time:    afterEnd,
	}

	decision := Evaluate(policy, req)

	if decision.Effect == EffectAllow {
		t.Errorf("SECURITY VIOLATION: Request at 17:00:00.000000001 should be denied (after 17:00 window)")
	}
}

// TestSecurityRegression_TimeWindow_ExactlyAtEnd verifies that requests
// at exactly the end time are denied (end is exclusive).
func TestSecurityRegression_TimeWindow_ExactlyAtEnd(t *testing.T) {
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
			},
		},
	}

	// Exactly 17:00:00.000000000
	exactEnd := time.Date(2025, time.January, 14, 17, 0, 0, 0, time.UTC)

	req := &Request{
		User:    "alice",
		Profile: "production",
		Time:    exactEnd,
	}

	decision := Evaluate(policy, req)

	if decision.Effect == EffectAllow {
		t.Errorf("SECURITY VIOLATION: Request at exactly 17:00 should be denied (end is exclusive)")
	}
}

// TestSecurityRegression_TimeWindow_WeekendDeniedOnWeekdays verifies that
// weekend requests are denied when only weekdays are allowed.
func TestSecurityRegression_TimeWindow_WeekendDeniedOnWeekdays(t *testing.T) {
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "weekdays-only",
				Effect: EffectAllow,
				Conditions: Condition{
					Time: &TimeWindow{
						Days: []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
					},
				},
			},
		},
	}

	// Saturday at midnight (00:00:00.000000000)
	saturdayMidnight := time.Date(2025, time.January, 18, 0, 0, 0, 0, time.UTC)
	// Sunday at 23:59:59.999999999
	sundayEndOfDay := time.Date(2025, time.January, 19, 23, 59, 59, 999999999, time.UTC)

	tests := []struct {
		name string
		time time.Time
	}{
		{"saturday_midnight", saturdayMidnight},
		{"sunday_end_of_day", sundayEndOfDay},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				User:    "alice",
				Profile: "production",
				Time:    tt.time,
			}
			decision := Evaluate(policy, req)

			if decision.Effect == EffectAllow {
				t.Errorf("SECURITY VIOLATION: Weekend request on %s should be denied", tt.name)
			}
		})
	}
}

// TestSecurityRegression_TimeWindow_MidnightBoundary verifies that the
// 23:59 to 00:00 boundary is handled correctly.
func TestSecurityRegression_TimeWindow_MidnightBoundary(t *testing.T) {
	// Policy that only allows access from 00:00 to 08:00
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "early-morning",
				Effect: EffectAllow,
				Conditions: Condition{
					Time: &TimeWindow{
						Hours: &HourRange{
							Start: "00:00",
							End:   "08:00",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name       string
		time       time.Time
		expectAllow bool
	}{
		{"00:00:00", time.Date(2025, 1, 14, 0, 0, 0, 0, time.UTC), true},
		{"07:59:59", time.Date(2025, 1, 14, 7, 59, 59, 0, time.UTC), true},
		{"08:00:00", time.Date(2025, 1, 14, 8, 0, 0, 0, time.UTC), false}, // End is exclusive
		{"23:59:59", time.Date(2025, 1, 14, 23, 59, 59, 0, time.UTC), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				User:    "alice",
				Profile: "production",
				Time:    tt.time,
			}
			decision := Evaluate(policy, req)

			if tt.expectAllow && decision.Effect != EffectAllow {
				t.Errorf("Request at %s should be allowed, got %v", tt.name, decision.Effect)
			}
			if !tt.expectAllow && decision.Effect == EffectAllow {
				t.Errorf("SECURITY VIOLATION: Request at %s should be denied", tt.name)
			}
		})
	}
}

// TestSecurityRegression_TimeWindow_TimezoneEdgeCases verifies that timezone
// handling works correctly at boundaries.
func TestSecurityRegression_TimeWindow_TimezoneEdgeCases(t *testing.T) {
	// Policy for America/New_York business hours
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "nyc-business-hours",
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
			},
		},
	}

	// Test: 14:00 UTC in winter = 09:00 EST (should be allowed - at start boundary)
	utc1400 := time.Date(2025, time.January, 14, 14, 0, 0, 0, time.UTC)
	// Test: 13:59 UTC in winter = 08:59 EST (should be denied - before start)
	utc1359 := time.Date(2025, time.January, 14, 13, 59, 59, 999999999, time.UTC)
	// Test: 22:00 UTC in winter = 17:00 EST (should be denied - at end, exclusive)
	utc2200 := time.Date(2025, time.January, 14, 22, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		time        time.Time
		expectAllow bool
	}{
		{"14:00 UTC (09:00 EST)", utc1400, true},
		{"13:59 UTC (08:59 EST)", utc1359, false},
		{"22:00 UTC (17:00 EST)", utc2200, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				User:    "alice",
				Profile: "production",
				Time:    tt.time,
			}
			decision := Evaluate(policy, req)

			if tt.expectAllow && decision.Effect != EffectAllow {
				t.Errorf("Request at %s should be allowed, got %v", tt.name, decision.Effect)
			}
			if !tt.expectAllow && decision.Effect == EffectAllow {
				t.Errorf("SECURITY VIOLATION: Request at %s should be denied", tt.name)
			}
		})
	}
}

// ============================================================================
// Effect Isolation Tests
// ============================================================================

// TestSecurityRegression_EffectIsolation_DenyStopsEvaluation verifies that
// EffectDeny is final and stops rule evaluation (first match wins).
func TestSecurityRegression_EffectIsolation_DenyStopsEvaluation(t *testing.T) {
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "deny-alice",
				Effect: EffectDeny,
				Conditions: Condition{
					Users: []string{"alice"},
				},
				Reason: "alice is denied",
			},
			{
				Name:   "allow-all",
				Effect: EffectAllow,
				Conditions: Condition{
					Users: []string{}, // Wildcard - would match alice
				},
				Reason: "everyone else allowed",
			},
		},
	}

	req := &Request{
		User:    "alice",
		Profile: "production",
		Time:    time.Now(),
	}

	decision := Evaluate(policy, req)

	if decision.Effect != EffectDeny {
		t.Errorf("SECURITY VIOLATION: Deny rule should win over later allow rule")
	}
	if decision.MatchedRule != "deny-alice" {
		t.Errorf("Expected matched rule 'deny-alice', got %q", decision.MatchedRule)
	}
}

// TestSecurityRegression_EffectIsolation_RequireApprovalNotAllow verifies that
// EffectRequireApproval returns that effect, not EffectAllow.
func TestSecurityRegression_EffectIsolation_RequireApprovalNotAllow(t *testing.T) {
	policy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "require-approval-for-prod",
				Effect: EffectRequireApproval,
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
	}

	decision := Evaluate(policy, req)

	if decision.Effect == EffectAllow {
		t.Errorf("SECURITY VIOLATION: EffectRequireApproval should NOT return EffectAllow")
	}
	if decision.Effect != EffectRequireApproval {
		t.Errorf("Expected EffectRequireApproval, got %v", decision.Effect)
	}
}

// TestSecurityRegression_EffectIsolation_InvalidEffectCannotProduceAllow tests that
// invalid effect strings cannot be used to bypass security.
func TestSecurityRegression_EffectIsolation_InvalidEffectCannotProduceAllow(t *testing.T) {
	// Note: This test documents that invalid effects should not produce allow.
	// The Effect type is a string, so we can test with invalid values.
	invalidEffects := []Effect{
		"",
		"Allow",  // Wrong case
		"ALLOW",  // Wrong case
		"permit",
		"grant",
		"yes",
		"true",
		"1",
		"allow ", // Trailing space
		" allow", // Leading space
	}

	for _, invalidEffect := range invalidEffects {
		t.Run(string(invalidEffect), func(t *testing.T) {
			if invalidEffect.IsValid() {
				t.Errorf("Invalid effect %q should not be considered valid", invalidEffect)
			}

			// If someone creates a policy with an invalid effect and it matches,
			// we need to ensure it doesn't accidentally grant access.
			// This tests the Effect type's safety.
			if invalidEffect == EffectAllow {
				t.Errorf("Invalid effect %q should not equal EffectAllow", invalidEffect)
			}
		})
	}
}

// TestSecurityRegression_EffectIsolation_FirstMatchWins verifies that the
// first matching rule's effect is used, regardless of later rules.
func TestSecurityRegression_EffectIsolation_FirstMatchWins(t *testing.T) {
	tests := []struct {
		name        string
		firstEffect Effect
		laterEffect Effect
		expected    Effect
	}{
		{"allow_then_deny", EffectAllow, EffectDeny, EffectAllow},
		{"deny_then_allow", EffectDeny, EffectAllow, EffectDeny},
		{"require_then_allow", EffectRequireApproval, EffectAllow, EffectRequireApproval},
		{"deny_then_require", EffectDeny, EffectRequireApproval, EffectDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &Policy{
				Version: "1",
				Rules: []Rule{
					{
						Name:   "first-rule",
						Effect: tt.firstEffect,
						Conditions: Condition{
							Profiles: []string{"production"},
						},
					},
					{
						Name:   "later-rule",
						Effect: tt.laterEffect,
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
			}

			decision := Evaluate(policy, req)

			if decision.Effect != tt.expected {
				t.Errorf("Expected first match effect %v, got %v", tt.expected, decision.Effect)
			}
			if decision.MatchedRule != "first-rule" {
				t.Errorf("Expected first rule to match, got %q", decision.MatchedRule)
			}
		})
	}
}

// ============================================================================
// Table-Driven Comprehensive Regression Tests
// ============================================================================

// TestSecurityRegression_ComprehensiveDenialPaths runs a comprehensive set of
// denial path tests to ensure no credentials leak through any code path.
func TestSecurityRegression_ComprehensiveDenialPaths(t *testing.T) {
	// Base policy for testing
	basePolicy := &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-alice-on-staging",
				Effect: EffectAllow,
				Conditions: Condition{
					Users:    []string{"alice"},
					Profiles: []string{"staging"},
					Time: &TimeWindow{
						Days: []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
						Hours: &HourRange{
							Start: "09:00",
							End:   "17:00",
						},
					},
				},
			},
		},
	}

	// Tuesday 10:00 - should be within business hours
	validTime := time.Date(2025, time.January, 14, 10, 0, 0, 0, time.UTC)
	// Saturday 10:00 - weekend
	weekendTime := time.Date(2025, time.January, 18, 10, 0, 0, 0, time.UTC)
	// Tuesday 20:00 - after hours
	afterHoursTime := time.Date(2025, time.January, 14, 20, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		user       string
		profile    string
		time       time.Time
		expectDeny bool
		reason     string
	}{
		// Valid request
		{"valid_request", "alice", "staging", validTime, false, "should allow"},

		// User mismatches
		{"wrong_user", "bob", "staging", validTime, true, "user mismatch"},
		{"user_case_mismatch", "Alice", "staging", validTime, true, "case sensitivity"},
		{"empty_user", "", "staging", validTime, true, "empty user"},

		// Profile mismatches
		{"wrong_profile", "alice", "production", validTime, true, "profile mismatch"},
		{"profile_case_mismatch", "alice", "Staging", validTime, true, "case sensitivity"},
		{"empty_profile", "alice", "", validTime, true, "empty profile"},

		// Time mismatches
		{"weekend_denied", "alice", "staging", weekendTime, true, "weekend"},
		{"after_hours", "alice", "staging", afterHoursTime, true, "after hours"},

		// Multiple mismatches
		{"all_wrong", "bob", "production", weekendTime, true, "everything wrong"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				User:    tt.user,
				Profile: tt.profile,
				Time:    tt.time,
			}

			decision := Evaluate(basePolicy, req)

			if tt.expectDeny && decision.Effect == EffectAllow {
				t.Errorf("SECURITY VIOLATION: %s (%s) should be denied but was allowed", tt.name, tt.reason)
			}
			if !tt.expectDeny && decision.Effect != EffectAllow {
				t.Errorf("%s should be allowed but got %v", tt.name, decision.Effect)
			}
		})
	}
}
