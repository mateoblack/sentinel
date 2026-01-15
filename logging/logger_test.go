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

func TestJSONLogger_LogApproval(t *testing.T) {
	t.Run("outputs valid JSON with expected fields", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		entry := ApprovalLogEntry{
			Timestamp:       "2026-01-15T10:00:00Z",
			Event:           "request.created",
			RequestID:       "a1b2c3d4e5f67890",
			Requester:       "alice",
			Profile:         "production",
			Status:          "pending",
			Actor:           "alice",
			Justification:   "Deploy hotfix for critical bug",
			Duration:        7200,
		}

		logger.LogApproval(entry)

		output := buf.String()

		// Verify newline-terminated (JSON Lines format)
		if !strings.HasSuffix(output, "\n") {
			t.Errorf("output should be newline-terminated, got: %q", output)
		}

		// Verify valid JSON
		var parsed ApprovalLogEntry
		if err := json.Unmarshal([]byte(strings.TrimSuffix(output, "\n")), &parsed); err != nil {
			t.Fatalf("output should be valid JSON, got error: %v", err)
		}

		// Verify all fields match
		if parsed.Timestamp != entry.Timestamp {
			t.Errorf("expected timestamp %q, got %q", entry.Timestamp, parsed.Timestamp)
		}
		if parsed.Event != entry.Event {
			t.Errorf("expected event %q, got %q", entry.Event, parsed.Event)
		}
		if parsed.RequestID != entry.RequestID {
			t.Errorf("expected request_id %q, got %q", entry.RequestID, parsed.RequestID)
		}
		if parsed.Requester != entry.Requester {
			t.Errorf("expected requester %q, got %q", entry.Requester, parsed.Requester)
		}
		if parsed.Profile != entry.Profile {
			t.Errorf("expected profile %q, got %q", entry.Profile, parsed.Profile)
		}
		if parsed.Status != entry.Status {
			t.Errorf("expected status %q, got %q", entry.Status, parsed.Status)
		}
		if parsed.Actor != entry.Actor {
			t.Errorf("expected actor %q, got %q", entry.Actor, parsed.Actor)
		}
		if parsed.Justification != entry.Justification {
			t.Errorf("expected justification %q, got %q", entry.Justification, parsed.Justification)
		}
		if parsed.Duration != entry.Duration {
			t.Errorf("expected duration_seconds %d, got %d", entry.Duration, parsed.Duration)
		}
	})

	t.Run("multiple entries are newline separated", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		entry1 := ApprovalLogEntry{
			Timestamp: "2026-01-15T10:00:00Z",
			Event:     "request.created",
			RequestID: "aaaaaaaaaaaaaaaa",
			Requester: "alice",
			Profile:   "production",
			Status:    "pending",
			Actor:     "alice",
		}
		entry2 := ApprovalLogEntry{
			Timestamp: "2026-01-15T10:05:00Z",
			Event:     "request.approved",
			RequestID: "aaaaaaaaaaaaaaaa",
			Requester: "alice",
			Profile:   "production",
			Status:    "approved",
			Actor:     "bob",
			Approver:  "bob",
		}

		logger.LogApproval(entry1)
		logger.LogApproval(entry2)

		output := buf.String()
		lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")

		if len(lines) != 2 {
			t.Errorf("expected 2 lines (JSON Lines format), got %d", len(lines))
		}

		// Verify each line is valid JSON
		for i, line := range lines {
			var parsed ApprovalLogEntry
			if err := json.Unmarshal([]byte(line), &parsed); err != nil {
				t.Errorf("line %d should be valid JSON, got error: %v", i+1, err)
			}
		}
	})

	t.Run("handles entries with omitempty fields", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		// Expired event - no optional fields
		entry := ApprovalLogEntry{
			Timestamp: "2026-01-15T10:00:00Z",
			Event:     "request.expired",
			RequestID: "a1b2c3d4e5f67890",
			Requester: "alice",
			Profile:   "production",
			Status:    "expired",
			Actor:     "system",
		}

		logger.LogApproval(entry)

		output := buf.String()

		// Verify valid JSON even with empty optional fields
		var parsed ApprovalLogEntry
		if err := json.Unmarshal([]byte(strings.TrimSuffix(output, "\n")), &parsed); err != nil {
			t.Fatalf("output should be valid JSON, got error: %v", err)
		}

		if parsed.Justification != "" {
			t.Errorf("expected empty justification, got %q", parsed.Justification)
		}
		if parsed.Duration != 0 {
			t.Errorf("expected zero duration, got %d", parsed.Duration)
		}
		if parsed.Approver != "" {
			t.Errorf("expected empty approver, got %q", parsed.Approver)
		}
	})
}

func TestNopLogger_LogApproval(t *testing.T) {
	t.Run("does not panic", func(t *testing.T) {
		logger := NewNopLogger()

		entry := ApprovalLogEntry{
			Timestamp: "2026-01-15T10:00:00Z",
			Event:     "request.created",
			RequestID: "a1b2c3d4e5f67890",
			Requester: "alice",
			Profile:   "production",
			Status:    "pending",
			Actor:     "alice",
		}

		// Should not panic
		logger.LogApproval(entry)
	})

	t.Run("discards entries silently", func(t *testing.T) {
		logger := NewNopLogger()

		// Log multiple entries - all should be discarded without error
		for i := 0; i < 100; i++ {
			entry := ApprovalLogEntry{
				Timestamp: "2026-01-15T10:00:00Z",
				Event:     "request.created",
				RequestID: "a1b2c3d4e5f67890",
				Requester: "alice",
				Profile:   "production",
				Status:    "pending",
				Actor:     "alice",
			}
			logger.LogApproval(entry)
		}
		// If we get here without panic, test passes
	})
}

func TestJSONLogger_LogBreakGlass(t *testing.T) {
	t.Run("outputs valid JSON with expected fields", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		entry := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T10:00:00Z",
			Event:         BreakGlassEventInvoked,
			EventID:       "a1b2c3d4e5f67890",
			RequestID:     "fedcba0987654321",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Production database is down, need emergency access",
			Status:        "active",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
		}

		logger.LogBreakGlass(entry)

		output := buf.String()

		// Verify newline-terminated (JSON Lines format)
		if !strings.HasSuffix(output, "\n") {
			t.Errorf("output should be newline-terminated, got: %q", output)
		}

		// Verify valid JSON
		var parsed BreakGlassLogEntry
		if err := json.Unmarshal([]byte(strings.TrimSuffix(output, "\n")), &parsed); err != nil {
			t.Fatalf("output should be valid JSON, got error: %v", err)
		}

		// Verify all fields match
		if parsed.Timestamp != entry.Timestamp {
			t.Errorf("expected timestamp %q, got %q", entry.Timestamp, parsed.Timestamp)
		}
		if parsed.Event != entry.Event {
			t.Errorf("expected event %q, got %q", entry.Event, parsed.Event)
		}
		if parsed.EventID != entry.EventID {
			t.Errorf("expected event_id %q, got %q", entry.EventID, parsed.EventID)
		}
		if parsed.RequestID != entry.RequestID {
			t.Errorf("expected request_id %q, got %q", entry.RequestID, parsed.RequestID)
		}
		if parsed.Invoker != entry.Invoker {
			t.Errorf("expected invoker %q, got %q", entry.Invoker, parsed.Invoker)
		}
		if parsed.Profile != entry.Profile {
			t.Errorf("expected profile %q, got %q", entry.Profile, parsed.Profile)
		}
		if parsed.ReasonCode != entry.ReasonCode {
			t.Errorf("expected reason_code %q, got %q", entry.ReasonCode, parsed.ReasonCode)
		}
		if parsed.Justification != entry.Justification {
			t.Errorf("expected justification %q, got %q", entry.Justification, parsed.Justification)
		}
		if parsed.Status != entry.Status {
			t.Errorf("expected status %q, got %q", entry.Status, parsed.Status)
		}
		if parsed.Duration != entry.Duration {
			t.Errorf("expected duration_seconds %d, got %d", entry.Duration, parsed.Duration)
		}
		if parsed.ExpiresAt != entry.ExpiresAt {
			t.Errorf("expected expires_at %q, got %q", entry.ExpiresAt, parsed.ExpiresAt)
		}
	})

	t.Run("multiple entries are newline separated", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		entry1 := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T10:00:00Z",
			Event:         BreakGlassEventInvoked,
			EventID:       "aaaaaaaaaaaaaaaa",
			RequestID:     "bbbbbbbbbbbbbbbb",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Production incident in progress",
			Status:        "active",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
		}
		entry2 := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T11:00:00Z",
			Event:         BreakGlassEventClosed,
			EventID:       "aaaaaaaaaaaaaaaa",
			RequestID:     "bbbbbbbbbbbbbbbb",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Production incident in progress",
			Status:        "closed",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
			ClosedBy:      "alice",
			ClosedReason:  "Incident resolved",
		}

		logger.LogBreakGlass(entry1)
		logger.LogBreakGlass(entry2)

		output := buf.String()
		lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")

		if len(lines) != 2 {
			t.Errorf("expected 2 lines (JSON Lines format), got %d", len(lines))
		}

		// Verify each line is valid JSON
		for i, line := range lines {
			var parsed BreakGlassLogEntry
			if err := json.Unmarshal([]byte(line), &parsed); err != nil {
				t.Errorf("line %d should be valid JSON, got error: %v", i+1, err)
			}
		}
	})

	t.Run("handles entries with omitempty fields", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		// Invoked event - no closed fields
		entry := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T10:00:00Z",
			Event:         BreakGlassEventInvoked,
			EventID:       "a1b2c3d4e5f67890",
			RequestID:     "fedcba0987654321",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Emergency access needed",
			Status:        "active",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
		}

		logger.LogBreakGlass(entry)

		output := buf.String()

		// Verify valid JSON even with empty optional fields
		var parsed BreakGlassLogEntry
		if err := json.Unmarshal([]byte(strings.TrimSuffix(output, "\n")), &parsed); err != nil {
			t.Fatalf("output should be valid JSON, got error: %v", err)
		}

		if parsed.ClosedBy != "" {
			t.Errorf("expected empty closed_by, got %q", parsed.ClosedBy)
		}
		if parsed.ClosedReason != "" {
			t.Errorf("expected empty closed_reason, got %q", parsed.ClosedReason)
		}
	})

	t.Run("JSON contains expected field names", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewJSONLogger(&buf)

		entry := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T10:00:00Z",
			Event:         BreakGlassEventInvoked,
			EventID:       "a1b2c3d4e5f67890",
			RequestID:     "fedcba0987654321",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Emergency access needed",
			Status:        "active",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
		}

		logger.LogBreakGlass(entry)

		output := buf.String()

		// Verify expected JSON field names
		expectedFields := []string{
			`"timestamp"`,
			`"event"`,
			`"event_id"`,
			`"request_id"`,
			`"invoker"`,
			`"profile"`,
			`"reason_code"`,
			`"justification"`,
			`"status"`,
			`"duration_seconds"`,
			`"expires_at"`,
		}

		for _, field := range expectedFields {
			if !strings.Contains(output, field) {
				t.Errorf("expected JSON output to contain field %s", field)
			}
		}
	})
}

func TestNopLogger_LogBreakGlass(t *testing.T) {
	t.Run("does not panic", func(t *testing.T) {
		logger := NewNopLogger()

		entry := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T10:00:00Z",
			Event:         BreakGlassEventInvoked,
			EventID:       "a1b2c3d4e5f67890",
			RequestID:     "fedcba0987654321",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Production incident requires emergency access",
			Status:        "active",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
		}

		// Should not panic
		logger.LogBreakGlass(entry)
	})

	t.Run("discards entries silently", func(t *testing.T) {
		logger := NewNopLogger()

		// Log multiple entries - all should be discarded without error
		for i := 0; i < 100; i++ {
			entry := BreakGlassLogEntry{
				Timestamp:     "2026-01-15T10:00:00Z",
				Event:         BreakGlassEventInvoked,
				EventID:       "a1b2c3d4e5f67890",
				RequestID:     "fedcba0987654321",
				Invoker:       "alice",
				Profile:       "production",
				ReasonCode:    "incident",
				Justification: "Production incident requires emergency access",
				Status:        "active",
				Duration:      7200,
				ExpiresAt:     "2026-01-15T12:00:00Z",
			}
			logger.LogBreakGlass(entry)
		}
		// If we get here without panic, test passes
	})
}
