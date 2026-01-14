package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONLogger_LogDecision(t *testing.T) {
	t.Run("outputs valid JSON with expected fields", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		entry := DecisionLogEntry{
			Timestamp:  "2026-01-14T10:00:00Z",
			User:       "alice",
			Profile:    "production",
			Effect:     "allow",
			Rule:       "allow-production",
			RuleIndex:  0,
			Reason:     "production access allowed",
			PolicyPath: "/sentinel/policies/default",
		}

		logger.LogDecision(entry)

		output := buf.String()

		// Verify newline-terminated (JSON Lines format)
		if !strings.HasSuffix(output, "\n") {
			t.Errorf("output should be newline-terminated, got: %q", output)
		}

		// Verify valid JSON
		var parsed DecisionLogEntry
		if err := json.Unmarshal([]byte(strings.TrimSuffix(output, "\n")), &parsed); err != nil {
			t.Fatalf("output should be valid JSON, got error: %v", err)
		}

		// Verify all fields match
		if parsed.Timestamp != entry.Timestamp {
			t.Errorf("expected timestamp %q, got %q", entry.Timestamp, parsed.Timestamp)
		}
		if parsed.User != entry.User {
			t.Errorf("expected user %q, got %q", entry.User, parsed.User)
		}
		if parsed.Profile != entry.Profile {
			t.Errorf("expected profile %q, got %q", entry.Profile, parsed.Profile)
		}
		if parsed.Effect != entry.Effect {
			t.Errorf("expected effect %q, got %q", entry.Effect, parsed.Effect)
		}
		if parsed.Rule != entry.Rule {
			t.Errorf("expected rule %q, got %q", entry.Rule, parsed.Rule)
		}
		if parsed.RuleIndex != entry.RuleIndex {
			t.Errorf("expected rule_index %d, got %d", entry.RuleIndex, parsed.RuleIndex)
		}
		if parsed.Reason != entry.Reason {
			t.Errorf("expected reason %q, got %q", entry.Reason, parsed.Reason)
		}
		if parsed.PolicyPath != entry.PolicyPath {
			t.Errorf("expected policy_path %q, got %q", entry.PolicyPath, parsed.PolicyPath)
		}
	})

	t.Run("multiple entries are newline separated", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		entry1 := DecisionLogEntry{
			Timestamp: "2026-01-14T10:00:00Z",
			User:      "alice",
			Profile:   "production",
			Effect:    "allow",
		}
		entry2 := DecisionLogEntry{
			Timestamp: "2026-01-14T10:01:00Z",
			User:      "bob",
			Profile:   "staging",
			Effect:    "deny",
		}

		logger.LogDecision(entry1)
		logger.LogDecision(entry2)

		output := buf.String()
		lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")

		if len(lines) != 2 {
			t.Errorf("expected 2 lines (JSON Lines format), got %d", len(lines))
		}

		// Verify each line is valid JSON
		for i, line := range lines {
			var parsed DecisionLogEntry
			if err := json.Unmarshal([]byte(line), &parsed); err != nil {
				t.Errorf("line %d should be valid JSON, got error: %v", i+1, err)
			}
		}
	})

	t.Run("handles empty strings in entry", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		entry := DecisionLogEntry{
			Timestamp:  "2026-01-14T10:00:00Z",
			User:       "alice",
			Profile:    "staging",
			Effect:     "deny",
			Rule:       "", // Empty for default deny
			RuleIndex:  -1,
			Reason:     "no matching rule",
			PolicyPath: "/sentinel/policies/default",
		}

		logger.LogDecision(entry)

		output := buf.String()

		// Verify valid JSON even with empty fields
		var parsed DecisionLogEntry
		if err := json.Unmarshal([]byte(strings.TrimSuffix(output, "\n")), &parsed); err != nil {
			t.Fatalf("output should be valid JSON, got error: %v", err)
		}

		if parsed.Rule != "" {
			t.Errorf("expected empty rule, got %q", parsed.Rule)
		}
		if parsed.RuleIndex != -1 {
			t.Errorf("expected rule_index -1, got %d", parsed.RuleIndex)
		}
	})
}

func TestNopLogger_LogDecision(t *testing.T) {
	t.Run("does not panic", func(t *testing.T) {
		logger := NewNopLogger()

		entry := DecisionLogEntry{
			Timestamp:  "2026-01-14T10:00:00Z",
			User:       "alice",
			Profile:    "production",
			Effect:     "allow",
			Rule:       "allow-production",
			RuleIndex:  0,
			Reason:     "production access allowed",
			PolicyPath: "/sentinel/policies/default",
		}

		// Should not panic
		logger.LogDecision(entry)
	})

	t.Run("discards entries silently", func(t *testing.T) {
		logger := NewNopLogger()

		// Log multiple entries - all should be discarded without error
		for i := 0; i < 100; i++ {
			entry := DecisionLogEntry{
				Timestamp: "2026-01-14T10:00:00Z",
				User:      "alice",
				Effect:    "allow",
			}
			logger.LogDecision(entry)
		}
		// If we get here without panic, test passes
	})
}
