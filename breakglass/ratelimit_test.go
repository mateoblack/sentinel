package breakglass

import (
	"strings"
	"testing"
	"time"
)

func TestRateLimitPolicy_Validate_Valid(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:        "production-limits",
				Profiles:    []string{"production"},
				Cooldown:    time.Hour,
				MaxPerUser:  3,
				QuotaWindow: 24 * time.Hour,
			},
		},
	}

	if err := policy.Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil for valid policy", err)
	}
}

func TestRateLimitPolicy_Validate_EmptyRules(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules:   []RateLimitRule{},
	}

	err := policy.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for empty rules")
	}

	if !strings.Contains(err.Error(), "at least one rule") {
		t.Errorf("Validate() error = %q, want error about at least one rule", err)
	}
}

func TestRateLimitPolicy_Validate_MissingName(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:     "", // missing
				Cooldown: time.Hour,
			},
		},
	}

	err := policy.Validate()
	if err == nil {
		t.Fatal("Validate() should return error for missing rule name")
	}

	if !strings.Contains(err.Error(), "missing name") {
		t.Errorf("Validate() error = %q, want error about missing name", err)
	}
}

func TestRateLimitPolicy_Validate_NoLimitsSet(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:     "no-limits",
				Profiles: []string{"staging"},
				// No cooldown, max_per_user, or max_per_profile set
			},
		},
	}

	err := policy.Validate()
	if err == nil {
		t.Fatal("Validate() should return error when no limits set")
	}

	if !strings.Contains(err.Error(), "at least one limit") {
		t.Errorf("Validate() error = %q, want error about at least one limit", err)
	}
}

func TestRateLimitPolicy_Validate_InvalidQuotaWindow(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:        "invalid-quota",
				MaxPerUser:  5, // quota set
				QuotaWindow: 0, // but no window
			},
		},
	}

	err := policy.Validate()
	if err == nil {
		t.Fatal("Validate() should return error when quota set but no window")
	}

	if !strings.Contains(err.Error(), "quota_window") {
		t.Errorf("Validate() error = %q, want error about quota_window", err)
	}
}

func TestRateLimitPolicy_Validate_CooldownOnly(t *testing.T) {
	// Cooldown alone is valid (no quota window needed)
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:     "cooldown-only",
				Cooldown: 30 * time.Minute,
			},
		},
	}

	if err := policy.Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil for cooldown-only rule", err)
	}
}

func TestRateLimitPolicy_Validate_NegativeValues(t *testing.T) {
	tests := []struct {
		name    string
		rule    RateLimitRule
		wantErr string
	}{
		{
			name: "negative cooldown",
			rule: RateLimitRule{
				Name:     "neg-cooldown",
				Cooldown: -time.Hour,
			},
			wantErr: "negative cooldown",
		},
		{
			name: "negative max_per_user",
			rule: RateLimitRule{
				Name:        "neg-max-user",
				MaxPerUser:  -1,
				QuotaWindow: 24 * time.Hour,
			},
			wantErr: "negative max_per_user",
		},
		{
			name: "negative max_per_profile",
			rule: RateLimitRule{
				Name:          "neg-max-profile",
				MaxPerProfile: -1,
				QuotaWindow:   24 * time.Hour,
			},
			wantErr: "negative max_per_profile",
		},
		{
			name: "negative escalation_threshold",
			rule: RateLimitRule{
				Name:                "neg-escalation",
				Cooldown:            time.Hour,
				EscalationThreshold: -1,
			},
			wantErr: "negative escalation_threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &RateLimitPolicy{
				Version: "1.0",
				Rules:   []RateLimitRule{tt.rule},
			}

			err := policy.Validate()
			if err == nil {
				t.Fatal("Validate() should return error for negative value")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() error = %q, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestRateLimitPolicy_Validate_AllLimitsSet(t *testing.T) {
	// Policy with all limits set should be valid
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:                "all-limits",
				Profiles:            []string{"production", "staging"},
				Cooldown:            time.Hour,
				MaxPerUser:          5,
				MaxPerProfile:       20,
				QuotaWindow:         24 * time.Hour,
				EscalationThreshold: 3,
			},
		},
	}

	if err := policy.Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil for policy with all limits", err)
	}
}

func TestFindRateLimitRule_MatchingProfile(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:     "production-rule",
				Profiles: []string{"production"},
				Cooldown: time.Hour,
			},
			{
				Name:     "staging-rule",
				Profiles: []string{"staging"},
				Cooldown: 30 * time.Minute,
			},
		},
	}

	rule := FindRateLimitRule(policy, "production")
	if rule == nil {
		t.Fatal("FindRateLimitRule() returned nil, want production-rule")
	}
	if rule.Name != "production-rule" {
		t.Errorf("FindRateLimitRule().Name = %q, want %q", rule.Name, "production-rule")
	}

	rule = FindRateLimitRule(policy, "staging")
	if rule == nil {
		t.Fatal("FindRateLimitRule() returned nil, want staging-rule")
	}
	if rule.Name != "staging-rule" {
		t.Errorf("FindRateLimitRule().Name = %q, want %q", rule.Name, "staging-rule")
	}
}

func TestFindRateLimitRule_Wildcard(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:     "default-rule",
				Profiles: []string{}, // empty = wildcard
				Cooldown: time.Hour,
			},
		},
	}

	// Wildcard should match any profile
	rule := FindRateLimitRule(policy, "production")
	if rule == nil {
		t.Fatal("FindRateLimitRule() returned nil for wildcard match")
	}
	if rule.Name != "default-rule" {
		t.Errorf("FindRateLimitRule().Name = %q, want %q", rule.Name, "default-rule")
	}

	rule = FindRateLimitRule(policy, "unknown-profile")
	if rule == nil {
		t.Fatal("FindRateLimitRule() returned nil for wildcard match with unknown profile")
	}
}

func TestFindRateLimitRule_NoMatch(t *testing.T) {
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:     "production-only",
				Profiles: []string{"production"},
				Cooldown: time.Hour,
			},
		},
	}

	rule := FindRateLimitRule(policy, "staging")
	if rule != nil {
		t.Errorf("FindRateLimitRule() = %v, want nil for non-matching profile", rule)
	}
}

func TestFindRateLimitRule_NilPolicy(t *testing.T) {
	rule := FindRateLimitRule(nil, "production")
	if rule != nil {
		t.Errorf("FindRateLimitRule(nil, ...) = %v, want nil", rule)
	}
}

func TestFindRateLimitRule_FirstMatchWins(t *testing.T) {
	// When multiple rules could match, first one wins
	policy := &RateLimitPolicy{
		Version: "1.0",
		Rules: []RateLimitRule{
			{
				Name:     "first-rule",
				Profiles: []string{}, // wildcard - matches everything
				Cooldown: time.Hour,
			},
			{
				Name:     "second-rule",
				Profiles: []string{}, // also wildcard
				Cooldown: 2 * time.Hour,
			},
		},
	}

	rule := FindRateLimitRule(policy, "production")
	if rule == nil {
		t.Fatal("FindRateLimitRule() returned nil")
	}
	if rule.Name != "first-rule" {
		t.Errorf("FindRateLimitRule().Name = %q, want %q (first match wins)", rule.Name, "first-rule")
	}
}

func TestContainsOrEmpty(t *testing.T) {
	tests := []struct {
		name   string
		slice  []string
		value  string
		result bool
	}{
		{"empty slice matches anything", []string{}, "foo", true},
		{"contains value", []string{"foo", "bar"}, "foo", true},
		{"does not contain value", []string{"foo", "bar"}, "baz", false},
		{"single element match", []string{"foo"}, "foo", true},
		{"single element no match", []string{"foo"}, "bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsOrEmpty(tt.slice, tt.value)
			if got != tt.result {
				t.Errorf("containsOrEmpty(%v, %q) = %v, want %v", tt.slice, tt.value, got, tt.result)
			}
		})
	}
}
