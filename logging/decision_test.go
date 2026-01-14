package logging

import (
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/policy"
)

func TestNewDecisionLogEntry_Allow(t *testing.T) {
	t.Run("populates all fields correctly for allow decision", func(t *testing.T) {
		req := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Date(2026, time.January, 14, 10, 0, 0, 0, time.UTC),
		}

		decision := policy.Decision{
			Effect:      policy.EffectAllow,
			MatchedRule: "allow-production",
			RuleIndex:   0,
			Reason:      "production access allowed",
		}

		policyPath := "/sentinel/policies/default"

		entry := NewDecisionLogEntry(req, decision, policyPath)

		// Verify timestamp is set (non-empty)
		if entry.Timestamp == "" {
			t.Error("expected non-empty timestamp")
		}

		// Verify user
		if entry.User != "alice" {
			t.Errorf("expected user 'alice', got %q", entry.User)
		}

		// Verify profile
		if entry.Profile != "production" {
			t.Errorf("expected profile 'production', got %q", entry.Profile)
		}

		// Verify effect
		if entry.Effect != "allow" {
			t.Errorf("expected effect 'allow', got %q", entry.Effect)
		}

		// Verify rule
		if entry.Rule != "allow-production" {
			t.Errorf("expected rule 'allow-production', got %q", entry.Rule)
		}

		// Verify rule_index
		if entry.RuleIndex != 0 {
			t.Errorf("expected rule_index 0, got %d", entry.RuleIndex)
		}

		// Verify reason
		if entry.Reason != "production access allowed" {
			t.Errorf("expected reason 'production access allowed', got %q", entry.Reason)
		}

		// Verify policy_path
		if entry.PolicyPath != policyPath {
			t.Errorf("expected policy_path %q, got %q", policyPath, entry.PolicyPath)
		}
	})

	t.Run("timestamp is ISO8601 format", func(t *testing.T) {
		req := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Decision{
			Effect:      policy.EffectAllow,
			MatchedRule: "allow-all",
			RuleIndex:   0,
		}

		entry := NewDecisionLogEntry(req, decision, "/path")

		// Verify timestamp parses as RFC3339 (ISO8601)
		_, err := time.Parse(time.RFC3339, entry.Timestamp)
		if err != nil {
			t.Errorf("timestamp should be RFC3339/ISO8601 format, got error: %v", err)
		}
	})
}

func TestNewDecisionLogEntry_Deny(t *testing.T) {
	t.Run("populates fields correctly for explicit deny", func(t *testing.T) {
		req := &policy.Request{
			User:    "bob",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Decision{
			Effect:      policy.EffectDeny,
			MatchedRule: "deny-bob",
			RuleIndex:   1,
			Reason:      "bob not allowed",
		}

		entry := NewDecisionLogEntry(req, decision, "/sentinel/policies/strict")

		if entry.Effect != "deny" {
			t.Errorf("expected effect 'deny', got %q", entry.Effect)
		}
		if entry.Rule != "deny-bob" {
			t.Errorf("expected rule 'deny-bob', got %q", entry.Rule)
		}
		if entry.RuleIndex != 1 {
			t.Errorf("expected rule_index 1, got %d", entry.RuleIndex)
		}
	})

	t.Run("populates fields correctly for default deny", func(t *testing.T) {
		req := &policy.Request{
			User:    "charlie",
			Profile: "staging",
			Time:    time.Now(),
		}

		// Default deny: no matching rule
		decision := policy.Decision{
			Effect:      policy.EffectDeny,
			MatchedRule: "", // Empty for default deny
			RuleIndex:   -1, // -1 indicates no match
			Reason:      "no matching rule",
		}

		entry := NewDecisionLogEntry(req, decision, "/sentinel/policies/default")

		if entry.Effect != "deny" {
			t.Errorf("expected effect 'deny', got %q", entry.Effect)
		}
		if entry.Rule != "" {
			t.Errorf("expected empty rule for default deny, got %q", entry.Rule)
		}
		if entry.RuleIndex != -1 {
			t.Errorf("expected rule_index -1 for default deny, got %d", entry.RuleIndex)
		}
		if entry.Reason != "no matching rule" {
			t.Errorf("expected reason 'no matching rule', got %q", entry.Reason)
		}
	})
}

func TestNewDecisionLogEntry_PreservesRequestData(t *testing.T) {
	t.Run("preserves user from request", func(t *testing.T) {
		testUsers := []string{"alice", "bob", "admin", "user@domain.com"}

		for _, user := range testUsers {
			req := &policy.Request{
				User:    user,
				Profile: "test",
				Time:    time.Now(),
			}
			decision := policy.Decision{Effect: policy.EffectAllow}

			entry := NewDecisionLogEntry(req, decision, "/path")

			if entry.User != user {
				t.Errorf("expected user %q, got %q", user, entry.User)
			}
		}
	})

	t.Run("preserves profile from request", func(t *testing.T) {
		testProfiles := []string{"production", "staging", "development", "my-profile-name"}

		for _, profile := range testProfiles {
			req := &policy.Request{
				User:    "alice",
				Profile: profile,
				Time:    time.Now(),
			}
			decision := policy.Decision{Effect: policy.EffectAllow}

			entry := NewDecisionLogEntry(req, decision, "/path")

			if entry.Profile != profile {
				t.Errorf("expected profile %q, got %q", profile, entry.Profile)
			}
		}
	})
}
