package logging

import (
	"encoding/json"
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

func TestNewEnhancedDecisionLogEntry(t *testing.T) {
	t.Run("populates all fields with credential context", func(t *testing.T) {
		req := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Decision{
			Effect:      policy.EffectAllow,
			MatchedRule: "allow-production",
			RuleIndex:   0,
			Reason:      "production access allowed",
		}

		creds := &CredentialIssuanceFields{
			RequestID:       "a1b2c3d4",
			SourceIdentity:  "sentinel:alice:a1b2c3d4",
			RoleARN:         "arn:aws:iam::123456789012:role/ProductionRole",
			SessionDuration: 1 * time.Hour,
		}

		entry := NewEnhancedDecisionLogEntry(req, decision, "/sentinel/policies/default", creds)

		// Verify base fields
		if entry.User != "alice" {
			t.Errorf("expected user 'alice', got %q", entry.User)
		}
		if entry.Profile != "production" {
			t.Errorf("expected profile 'production', got %q", entry.Profile)
		}
		if entry.Effect != "allow" {
			t.Errorf("expected effect 'allow', got %q", entry.Effect)
		}

		// Verify new credential fields
		if entry.RequestID != "a1b2c3d4" {
			t.Errorf("expected request_id 'a1b2c3d4', got %q", entry.RequestID)
		}
		if entry.SourceIdentity != "sentinel:alice:a1b2c3d4" {
			t.Errorf("expected source_identity 'sentinel:alice:a1b2c3d4', got %q", entry.SourceIdentity)
		}
		if entry.RoleARN != "arn:aws:iam::123456789012:role/ProductionRole" {
			t.Errorf("expected role_arn 'arn:aws:iam::123456789012:role/ProductionRole', got %q", entry.RoleARN)
		}
		if entry.SessionDuration != 3600 {
			t.Errorf("expected session_duration_seconds 3600, got %d", entry.SessionDuration)
		}
	})

	t.Run("works like NewDecisionLogEntry with nil creds", func(t *testing.T) {
		req := &policy.Request{
			User:    "bob",
			Profile: "staging",
			Time:    time.Now(),
		}

		decision := policy.Decision{
			Effect:      policy.EffectDeny,
			MatchedRule: "",
			RuleIndex:   -1,
			Reason:      "no matching rule",
		}

		entry := NewEnhancedDecisionLogEntry(req, decision, "/sentinel/policies/default", nil)

		// Verify base fields are set
		if entry.User != "bob" {
			t.Errorf("expected user 'bob', got %q", entry.User)
		}
		if entry.Effect != "deny" {
			t.Errorf("expected effect 'deny', got %q", entry.Effect)
		}

		// Verify new fields are empty/zero
		if entry.RequestID != "" {
			t.Errorf("expected empty request_id, got %q", entry.RequestID)
		}
		if entry.SourceIdentity != "" {
			t.Errorf("expected empty source_identity, got %q", entry.SourceIdentity)
		}
		if entry.RoleARN != "" {
			t.Errorf("expected empty role_arn, got %q", entry.RoleARN)
		}
		if entry.SessionDuration != 0 {
			t.Errorf("expected session_duration_seconds 0, got %d", entry.SessionDuration)
		}
	})

	t.Run("zero session duration is not set", func(t *testing.T) {
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

		creds := &CredentialIssuanceFields{
			RequestID:       "a1b2c3d4",
			SourceIdentity:  "sentinel:alice:a1b2c3d4",
			SessionDuration: 0, // Zero duration
		}

		entry := NewEnhancedDecisionLogEntry(req, decision, "/path", creds)

		if entry.SessionDuration != 0 {
			t.Errorf("expected session_duration_seconds 0 for zero duration, got %d", entry.SessionDuration)
		}
	})
}

func TestDecisionLogEntry_JSONMarshal(t *testing.T) {
	t.Run("includes new fields when present", func(t *testing.T) {
		req := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Decision{
			Effect:      policy.EffectAllow,
			MatchedRule: "allow-production",
			RuleIndex:   0,
			Reason:      "allowed",
		}

		creds := &CredentialIssuanceFields{
			RequestID:       "a1b2c3d4",
			SourceIdentity:  "sentinel:alice:a1b2c3d4",
			RoleARN:         "arn:aws:iam::123456789012:role/MyRole",
			SessionDuration: 30 * time.Minute,
		}

		entry := NewEnhancedDecisionLogEntry(req, decision, "/path", creds)

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify new fields are in JSON
		if !containsSubstring(jsonStr, `"request_id":"a1b2c3d4"`) {
			t.Error("JSON should contain request_id field")
		}
		if !containsSubstring(jsonStr, `"source_identity":"sentinel:alice:a1b2c3d4"`) {
			t.Error("JSON should contain source_identity field")
		}
		if !containsSubstring(jsonStr, `"role_arn":"arn:aws:iam::123456789012:role/MyRole"`) {
			t.Error("JSON should contain role_arn field")
		}
		if !containsSubstring(jsonStr, `"session_duration_seconds":1800`) {
			t.Error("JSON should contain session_duration_seconds field")
		}
	})

	t.Run("omits new fields when empty (omitempty)", func(t *testing.T) {
		req := &policy.Request{
			User:    "bob",
			Profile: "staging",
			Time:    time.Now(),
		}

		decision := policy.Decision{
			Effect:      policy.EffectDeny,
			MatchedRule: "",
			RuleIndex:   -1,
			Reason:      "no matching rule",
		}

		// No creds - simulating a deny decision
		entry := NewEnhancedDecisionLogEntry(req, decision, "/path", nil)

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify new fields are NOT in JSON (omitempty)
		if containsSubstring(jsonStr, `"request_id"`) {
			t.Error("JSON should NOT contain request_id field when empty")
		}
		if containsSubstring(jsonStr, `"source_identity"`) {
			t.Error("JSON should NOT contain source_identity field when empty")
		}
		if containsSubstring(jsonStr, `"role_arn"`) {
			t.Error("JSON should NOT contain role_arn field when empty")
		}
		if containsSubstring(jsonStr, `"session_duration_seconds"`) {
			t.Error("JSON should NOT contain session_duration_seconds field when zero")
		}
	})

	t.Run("partial fields are handled correctly", func(t *testing.T) {
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

		// Only some fields populated
		creds := &CredentialIssuanceFields{
			RequestID:      "a1b2c3d4",
			SourceIdentity: "sentinel:alice:a1b2c3d4",
			// RoleARN and SessionDuration not set
		}

		entry := NewEnhancedDecisionLogEntry(req, decision, "/path", creds)

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Populated fields should be present
		if !containsSubstring(jsonStr, `"request_id":"a1b2c3d4"`) {
			t.Error("JSON should contain request_id field")
		}
		if !containsSubstring(jsonStr, `"source_identity":"sentinel:alice:a1b2c3d4"`) {
			t.Error("JSON should contain source_identity field")
		}

		// Empty fields should be omitted
		if containsSubstring(jsonStr, `"role_arn"`) {
			t.Error("JSON should NOT contain role_arn field when empty")
		}
		if containsSubstring(jsonStr, `"session_duration_seconds"`) {
			t.Error("JSON should NOT contain session_duration_seconds field when zero")
		}
	})
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstringHelper(s, substr))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
