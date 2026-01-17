package logging

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
)

func TestNewBreakGlassLogEntry(t *testing.T) {
	t.Run("creates entry for invoked event", func(t *testing.T) {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Production database is down, need emergency access to investigate",
			Duration:      2 * time.Hour,
			Status:        breakglass.StatusActive,
			CreatedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(2 * time.Hour),
			RequestID:     "fedcba0987654321",
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		if entry.Event != BreakGlassEventInvoked {
			t.Errorf("expected event %q, got %q", BreakGlassEventInvoked, entry.Event)
		}
		if entry.EventID != bg.ID {
			t.Errorf("expected event_id %q, got %q", bg.ID, entry.EventID)
		}
		if entry.RequestID != bg.RequestID {
			t.Errorf("expected request_id %q, got %q", bg.RequestID, entry.RequestID)
		}
		if entry.Invoker != bg.Invoker {
			t.Errorf("expected invoker %q, got %q", bg.Invoker, entry.Invoker)
		}
		if entry.Profile != bg.Profile {
			t.Errorf("expected profile %q, got %q", bg.Profile, entry.Profile)
		}
		if entry.ReasonCode != string(bg.ReasonCode) {
			t.Errorf("expected reason_code %q, got %q", bg.ReasonCode, entry.ReasonCode)
		}
		if entry.Justification != bg.Justification {
			t.Errorf("expected justification %q, got %q", bg.Justification, entry.Justification)
		}
		if entry.Status != string(bg.Status) {
			t.Errorf("expected status %q, got %q", bg.Status, entry.Status)
		}
		if entry.Duration != 7200 {
			t.Errorf("expected duration_seconds 7200, got %d", entry.Duration)
		}
		// Verify ExpiresAt is ISO8601 formatted
		if entry.ExpiresAt == "" {
			t.Error("expected expires_at to be set")
		}
		// ClosedBy/ClosedReason should be empty for invoked events
		if entry.ClosedBy != "" {
			t.Errorf("expected empty closed_by for invoked event, got %q", entry.ClosedBy)
		}
		if entry.ClosedReason != "" {
			t.Errorf("expected empty closed_reason for invoked event, got %q", entry.ClosedReason)
		}
	})

	t.Run("creates entry for closed event", func(t *testing.T) {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Production database is down, need emergency access to investigate",
			Duration:      2 * time.Hour,
			Status:        breakglass.StatusClosed,
			CreatedAt:     time.Now().Add(-1 * time.Hour),
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			RequestID:     "fedcba0987654321",
			ClosedBy:      "bob",
			ClosedReason:  "Issue resolved, no longer need access",
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventClosed, bg)

		if entry.Event != BreakGlassEventClosed {
			t.Errorf("expected event %q, got %q", BreakGlassEventClosed, entry.Event)
		}
		if entry.Status != string(breakglass.StatusClosed) {
			t.Errorf("expected status %q, got %q", breakglass.StatusClosed, entry.Status)
		}
		if entry.ClosedBy != bg.ClosedBy {
			t.Errorf("expected closed_by %q, got %q", bg.ClosedBy, entry.ClosedBy)
		}
		if entry.ClosedReason != bg.ClosedReason {
			t.Errorf("expected closed_reason %q, got %q", bg.ClosedReason, entry.ClosedReason)
		}
	})

	t.Run("creates entry for expired event", func(t *testing.T) {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonMaintenance,
			Justification: "Emergency maintenance required for critical system update",
			Duration:      4 * time.Hour,
			Status:        breakglass.StatusExpired,
			CreatedAt:     time.Now().Add(-5 * time.Hour),
			ExpiresAt:     time.Now().Add(-1 * time.Hour),
			RequestID:     "fedcba0987654321",
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventExpired, bg)

		if entry.Event != BreakGlassEventExpired {
			t.Errorf("expected event %q, got %q", BreakGlassEventExpired, entry.Event)
		}
		if entry.Status != string(breakglass.StatusExpired) {
			t.Errorf("expected status %q, got %q", breakglass.StatusExpired, entry.Status)
		}
		// Expired events don't have ClosedBy/ClosedReason (system expired)
		if entry.ClosedBy != "" {
			t.Errorf("expected empty closed_by for expired event, got %q", entry.ClosedBy)
		}
		if entry.ClosedReason != "" {
			t.Errorf("expected empty closed_reason for expired event, got %q", entry.ClosedReason)
		}
	})

	t.Run("timestamp is set to current time", func(t *testing.T) {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Production issue requires immediate investigation",
			Duration:      1 * time.Hour,
			Status:        breakglass.StatusActive,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			RequestID:     "fedcba0987654321",
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		// Timestamp should be recent (within last second)
		if entry.Timestamp == "" {
			t.Error("expected timestamp to be set")
		}
		// Verify it's ISO8601 format (contains T and Z or timezone)
		if !strings.Contains(entry.Timestamp, "T") {
			t.Errorf("timestamp should be ISO8601 format, got %q", entry.Timestamp)
		}
	})

	t.Run("duration converted to seconds", func(t *testing.T) {
		testCases := []struct {
			duration        time.Duration
			expectedSeconds int
		}{
			{30 * time.Minute, 1800},
			{1 * time.Hour, 3600},
			{2 * time.Hour, 7200},
			{4 * time.Hour, 14400},
		}

		for _, tc := range testCases {
			bg := &breakglass.BreakGlassEvent{
				ID:            "a1b2c3d4e5f67890",
				Invoker:       "alice",
				Profile:       "production",
				ReasonCode:    breakglass.ReasonIncident,
				Justification: "Test justification for duration test",
				Duration:      tc.duration,
				Status:        breakglass.StatusActive,
				ExpiresAt:     time.Now().Add(tc.duration),
				RequestID:     "fedcba0987654321",
			}

			entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

			if entry.Duration != tc.expectedSeconds {
				t.Errorf("expected duration_seconds %d for %v, got %d", tc.expectedSeconds, tc.duration, entry.Duration)
			}
		}
	})
}

func TestBreakGlassLogEntry_JSONMarshal(t *testing.T) {
	t.Run("marshals to expected JSON field names", func(t *testing.T) {
		entry := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T10:00:00Z",
			Event:         BreakGlassEventInvoked,
			EventID:       "a1b2c3d4e5f67890",
			RequestID:     "fedcba0987654321",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Emergency access for production incident",
			Status:        "active",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
		}

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify expected field names are present
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
			if !strings.Contains(jsonStr, field) {
				t.Errorf("expected JSON to contain field %s, got: %s", field, jsonStr)
			}
		}
	})

	t.Run("omitempty works for ClosedBy and ClosedReason", func(t *testing.T) {
		// Entry without closed fields (invoked event)
		entry := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T10:00:00Z",
			Event:         BreakGlassEventInvoked,
			EventID:       "a1b2c3d4e5f67890",
			RequestID:     "fedcba0987654321",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Emergency access for production incident",
			Status:        "active",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
			// ClosedBy and ClosedReason are empty
		}

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify closed_by and closed_reason are NOT present (omitempty)
		if strings.Contains(jsonStr, `"closed_by"`) {
			t.Error("expected closed_by to be omitted when empty")
		}
		if strings.Contains(jsonStr, `"closed_reason"`) {
			t.Error("expected closed_reason to be omitted when empty")
		}
	})

	t.Run("includes ClosedBy and ClosedReason when set", func(t *testing.T) {
		// Entry with closed fields (closed event)
		entry := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T11:00:00Z",
			Event:         BreakGlassEventClosed,
			EventID:       "a1b2c3d4e5f67890",
			RequestID:     "fedcba0987654321",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Emergency access for production incident",
			Status:        "closed",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
			ClosedBy:      "bob",
			ClosedReason:  "Issue resolved",
		}

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify closed_by and closed_reason are present
		if !strings.Contains(jsonStr, `"closed_by":"bob"`) {
			t.Errorf("expected JSON to contain closed_by field, got: %s", jsonStr)
		}
		if !strings.Contains(jsonStr, `"closed_reason":"Issue resolved"`) {
			t.Errorf("expected JSON to contain closed_reason field, got: %s", jsonStr)
		}
	})

	t.Run("unmarshals back to equivalent struct", func(t *testing.T) {
		original := BreakGlassLogEntry{
			Timestamp:     "2026-01-15T10:00:00Z",
			Event:         BreakGlassEventInvoked,
			EventID:       "a1b2c3d4e5f67890",
			RequestID:     "fedcba0987654321",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    "incident",
			Justification: "Emergency access for production incident",
			Status:        "active",
			Duration:      7200,
			ExpiresAt:     "2026-01-15T12:00:00Z",
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		var parsed BreakGlassLogEntry
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("failed to unmarshal entry: %v", err)
		}

		if parsed != original {
			t.Errorf("expected parsed entry to equal original\noriginal: %+v\nparsed: %+v", original, parsed)
		}
	})
}

func TestBreakGlassEventConstants(t *testing.T) {
	t.Run("event type constants have expected values", func(t *testing.T) {
		if BreakGlassEventInvoked != "breakglass.invoked" {
			t.Errorf("expected BreakGlassEventInvoked to be 'breakglass.invoked', got %q", BreakGlassEventInvoked)
		}
		if BreakGlassEventClosed != "breakglass.closed" {
			t.Errorf("expected BreakGlassEventClosed to be 'breakglass.closed', got %q", BreakGlassEventClosed)
		}
		if BreakGlassEventExpired != "breakglass.expired" {
			t.Errorf("expected BreakGlassEventExpired to be 'breakglass.expired', got %q", BreakGlassEventExpired)
		}
	})

	t.Run("all event constants have breakglass prefix", func(t *testing.T) {
		events := []string{
			BreakGlassEventInvoked,
			BreakGlassEventClosed,
			BreakGlassEventExpired,
		}

		for _, event := range events {
			if !strings.HasPrefix(event, "breakglass.") {
				t.Errorf("expected event %q to have 'breakglass.' prefix", event)
			}
		}
	})
}

// =============================================================================
// Security Tests: Log Entry Completeness
// =============================================================================
// These tests verify that all mandatory audit fields are populated correctly
// for different event types.

func TestBreakGlassLogEntry_InvokedEvent_AllFieldsPopulated(t *testing.T) {
	// Create a break-glass event with all fields populated
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Production database is down, need emergency access to investigate",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(2 * time.Hour),
		RequestID:     "fedcba0987654321",
	}

	entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

	// Verify ALL mandatory fields are populated (not empty)
	mandatoryFields := map[string]string{
		"Timestamp":     entry.Timestamp,
		"Event":         entry.Event,
		"EventID":       entry.EventID,
		"RequestID":     entry.RequestID,
		"Invoker":       entry.Invoker,
		"Profile":       entry.Profile,
		"ReasonCode":    entry.ReasonCode,
		"Justification": entry.Justification,
		"Status":        entry.Status,
		"ExpiresAt":     entry.ExpiresAt,
	}

	for field, value := range mandatoryFields {
		if value == "" {
			t.Errorf("mandatory field %s is empty for invoked event", field)
		}
	}

	// Duration must be positive
	if entry.Duration <= 0 {
		t.Errorf("Duration should be positive, got %d", entry.Duration)
	}
}

func TestBreakGlassLogEntry_ClosedEvent_IncludesClosedFields(t *testing.T) {
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Production database is down, need emergency access to investigate",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusClosed,
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		RequestID:     "fedcba0987654321",
		ClosedBy:      "bob",
		ClosedReason:  "Issue resolved, no longer need access",
	}

	entry := NewBreakGlassLogEntry(BreakGlassEventClosed, bg)

	// ClosedBy and ClosedReason MUST be populated for closed events
	if entry.ClosedBy == "" {
		t.Error("ClosedBy should be populated for closed event")
	}
	if entry.ClosedReason == "" {
		t.Error("ClosedReason should be populated for closed event")
	}
	if entry.ClosedBy != "bob" {
		t.Errorf("expected ClosedBy 'bob', got %q", entry.ClosedBy)
	}
	if entry.ClosedReason != "Issue resolved, no longer need access" {
		t.Errorf("expected ClosedReason 'Issue resolved, no longer need access', got %q", entry.ClosedReason)
	}
}

func TestBreakGlassLogEntry_ExpiredEvent_NoClosedFields(t *testing.T) {
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonMaintenance,
		Justification: "Emergency maintenance required for critical system update",
		Duration:      4 * time.Hour,
		Status:        breakglass.StatusExpired,
		CreatedAt:     time.Now().Add(-5 * time.Hour),
		ExpiresAt:     time.Now().Add(-1 * time.Hour),
		RequestID:     "fedcba0987654321",
		// Explicitly set ClosedBy/ClosedReason - should NOT appear in entry
		ClosedBy:     "should-not-appear",
		ClosedReason: "should-not-appear",
	}

	entry := NewBreakGlassLogEntry(BreakGlassEventExpired, bg)

	// Expired events should NOT have ClosedBy/ClosedReason (system expired, not user closed)
	if entry.ClosedBy != "" {
		t.Errorf("ClosedBy should be empty for expired event, got %q", entry.ClosedBy)
	}
	if entry.ClosedReason != "" {
		t.Errorf("ClosedReason should be empty for expired event, got %q", entry.ClosedReason)
	}
}

func TestBreakGlassLogEntry_EventIDMatchesSource(t *testing.T) {
	testIDs := []string{
		"a1b2c3d4e5f67890",
		"0000000000000000",
		"ffffffffffffffff",
		"1234567890abcdef",
	}

	for _, id := range testIDs {
		bg := &breakglass.BreakGlassEvent{
			ID:            id,
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Test justification for ID matching",
			Duration:      1 * time.Hour,
			Status:        breakglass.StatusActive,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		if entry.EventID != id {
			t.Errorf("EventID mismatch: expected %q, got %q", id, entry.EventID)
		}
	}
}

func TestBreakGlassLogEntry_RequestIDMatchesSource(t *testing.T) {
	testIDs := []string{
		"fedcba0987654321",
		"0000000000000000",
		"ffffffffffffffff",
		"abcd1234efgh5678",
	}

	for _, id := range testIDs {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Test justification for RequestID matching",
			Duration:      1 * time.Hour,
			Status:        breakglass.StatusActive,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			RequestID:     id,
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		if entry.RequestID != id {
			t.Errorf("RequestID mismatch: expected %q, got %q", id, entry.RequestID)
		}
	}
}

func TestBreakGlassLogEntry_TimestampIsISO8601(t *testing.T) {
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test justification for timestamp format",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

	// Verify timestamp is valid ISO8601/RFC3339 format
	_, err := time.Parse(time.RFC3339, entry.Timestamp)
	if err != nil {
		t.Errorf("Timestamp is not valid ISO8601/RFC3339: %q, error: %v", entry.Timestamp, err)
	}

	// Additional format checks
	if !strings.Contains(entry.Timestamp, "T") {
		t.Errorf("ISO8601 timestamp should contain 'T' separator: %q", entry.Timestamp)
	}
	if !strings.HasSuffix(entry.Timestamp, "Z") && !strings.Contains(entry.Timestamp, "+") && !strings.Contains(entry.Timestamp, "-") {
		t.Errorf("ISO8601 timestamp should end with 'Z' or contain timezone offset: %q", entry.Timestamp)
	}
}

func TestBreakGlassLogEntry_DurationInSeconds(t *testing.T) {
	testCases := []struct {
		duration        time.Duration
		expectedSeconds int
	}{
		{15 * time.Minute, 900},
		{30 * time.Minute, 1800},
		{45 * time.Minute, 2700},
		{1 * time.Hour, 3600},
		{90 * time.Minute, 5400},
		{2 * time.Hour, 7200},
		{3 * time.Hour, 10800},
		{4 * time.Hour, 14400},
		{1*time.Hour + 30*time.Minute + 15*time.Second, 5415},
	}

	for _, tc := range testCases {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Test justification for duration test",
			Duration:      tc.duration,
			Status:        breakglass.StatusActive,
			ExpiresAt:     time.Now().Add(tc.duration),
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		if entry.Duration != tc.expectedSeconds {
			t.Errorf("Duration mismatch for %v: expected %d seconds, got %d", tc.duration, tc.expectedSeconds, entry.Duration)
		}
	}
}

// =============================================================================
// Security Tests: Event Type Consistency
// =============================================================================
// These tests verify event type handling is consistent and safe.

func TestBreakGlassEventConstants_Values(t *testing.T) {
	// Explicit value verification for security-critical constants
	if BreakGlassEventInvoked != "breakglass.invoked" {
		t.Errorf("BreakGlassEventInvoked value mismatch: expected 'breakglass.invoked', got %q", BreakGlassEventInvoked)
	}
	if BreakGlassEventClosed != "breakglass.closed" {
		t.Errorf("BreakGlassEventClosed value mismatch: expected 'breakglass.closed', got %q", BreakGlassEventClosed)
	}
	if BreakGlassEventExpired != "breakglass.expired" {
		t.Errorf("BreakGlassEventExpired value mismatch: expected 'breakglass.expired', got %q", BreakGlassEventExpired)
	}
}

func TestBreakGlassEventConstants_Prefix(t *testing.T) {
	// All break-glass events must have the "breakglass." namespace prefix
	// This ensures consistent filtering in audit logs
	events := []struct {
		name  string
		value string
	}{
		{"BreakGlassEventInvoked", BreakGlassEventInvoked},
		{"BreakGlassEventClosed", BreakGlassEventClosed},
		{"BreakGlassEventExpired", BreakGlassEventExpired},
	}

	for _, e := range events {
		if !strings.HasPrefix(e.value, "breakglass.") {
			t.Errorf("%s should have 'breakglass.' prefix for namespace consistency, got %q", e.name, e.value)
		}
	}
}

func TestNewBreakGlassLogEntry_EventTypePassthrough(t *testing.T) {
	// The event parameter should be set directly on the log entry
	// No validation, filtering, or transformation
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test justification for event passthrough",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	testEvents := []string{
		BreakGlassEventInvoked,
		BreakGlassEventClosed,
		BreakGlassEventExpired,
	}

	for _, event := range testEvents {
		entry := NewBreakGlassLogEntry(event, bg)

		if entry.Event != event {
			t.Errorf("Event passthrough failed: expected %q, got %q", event, entry.Event)
		}
	}
}

func TestNewBreakGlassLogEntry_InvalidEventType(t *testing.T) {
	// Unknown event types should still create log entries
	// Don't fail silently - audit ALL events, even unexpected ones
	// This ensures no audit bypasses through invalid event types
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test justification for invalid event type",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	invalidEvents := []string{
		"invalid.event",
		"breakglass.unknown",
		"random.string",
		"BREAKGLASS.INVOKED", // Case matters
		"",                   // Empty event
	}

	for _, event := range invalidEvents {
		entry := NewBreakGlassLogEntry(event, bg)

		// Entry should still be created
		if entry.EventID == "" {
			t.Errorf("Entry should be created even for invalid event type %q", event)
		}

		// Event type should be preserved as-is
		if entry.Event != event {
			t.Errorf("Invalid event should be preserved: expected %q, got %q", event, entry.Event)
		}

		// All other fields should still be populated
		if entry.Invoker == "" || entry.Profile == "" {
			t.Errorf("Other fields should still be populated for invalid event %q", event)
		}
	}
}

func TestNewBreakGlassLogEntry_EmptyEventType(t *testing.T) {
	// Empty event type should create log entry with empty Event field
	// Don't silently fail - audit even malformed requests
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test justification for empty event type",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	entry := NewBreakGlassLogEntry("", bg)

	// Entry should be created
	if entry.EventID == "" {
		t.Error("Entry should be created even with empty event type")
	}

	// Event field should be empty (as passed)
	if entry.Event != "" {
		t.Errorf("Event should be empty: expected '', got %q", entry.Event)
	}

	// All other mandatory fields should be populated
	if entry.Invoker == "" {
		t.Error("Invoker should still be populated")
	}
	if entry.Profile == "" {
		t.Error("Profile should still be populated")
	}
	if entry.Timestamp == "" {
		t.Error("Timestamp should still be populated")
	}
}

func TestBreakGlassLogEntry_StatusMatchesSource(t *testing.T) {
	// Status in log must exactly match bg.Status.String()
	testCases := []struct {
		status   breakglass.BreakGlassStatus
		expected string
	}{
		{breakglass.StatusActive, "active"},
		{breakglass.StatusClosed, "closed"},
		{breakglass.StatusExpired, "expired"},
	}

	for _, tc := range testCases {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Test justification for status matching",
			Duration:      1 * time.Hour,
			Status:        tc.status,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		if entry.Status != tc.expected {
			t.Errorf("Status mismatch: expected %q, got %q", tc.expected, entry.Status)
		}

		// Verify it matches the String() method
		if entry.Status != tc.status.String() {
			t.Errorf("Status should match String(): expected %q, got %q", tc.status.String(), entry.Status)
		}
	}
}

func TestBreakGlassLogEntry_ReasonCodeMatchesSource(t *testing.T) {
	// ReasonCode in log must exactly match string(bg.ReasonCode)
	testCases := []struct {
		reason   breakglass.ReasonCode
		expected string
	}{
		{breakglass.ReasonIncident, "incident"},
		{breakglass.ReasonMaintenance, "maintenance"},
		{breakglass.ReasonSecurity, "security"},
		{breakglass.ReasonRecovery, "recovery"},
		{breakglass.ReasonOther, "other"},
	}

	for _, tc := range testCases {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    tc.reason,
			Justification: "Test justification for reason code matching",
			Duration:      1 * time.Hour,
			Status:        breakglass.StatusActive,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		if entry.ReasonCode != tc.expected {
			t.Errorf("ReasonCode mismatch: expected %q, got %q", tc.expected, entry.ReasonCode)
		}

		// Verify it matches string conversion
		if entry.ReasonCode != string(tc.reason) {
			t.Errorf("ReasonCode should match string(): expected %q, got %q", string(tc.reason), entry.ReasonCode)
		}
	}
}

// =============================================================================
// Security Tests: Correlation and Traceability
// =============================================================================
// These tests verify ID formats, timestamps, and JSON serialization for audit
// log parsing and CloudTrail correlation.

func TestBreakGlassLogEntry_EventIDFormat(t *testing.T) {
	// EventID should be 16 lowercase hex characters (matches ValidateBreakGlassID format)
	validIDs := []string{
		"a1b2c3d4e5f67890",
		"0000000000000000",
		"ffffffffffffffff",
		"1234567890abcdef",
		"fedcba9876543210",
	}

	for _, id := range validIDs {
		bg := &breakglass.BreakGlassEvent{
			ID:            id,
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Test justification for EventID format",
			Duration:      1 * time.Hour,
			Status:        breakglass.StatusActive,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		// Verify EventID is exactly as provided
		if entry.EventID != id {
			t.Errorf("EventID mismatch: expected %q, got %q", id, entry.EventID)
		}

		// Verify it's 16 characters
		if len(entry.EventID) != 16 {
			t.Errorf("EventID should be 16 characters: got %d for %q", len(entry.EventID), entry.EventID)
		}

		// Verify it's lowercase hex using breakglass.ValidateBreakGlassID
		if !breakglass.ValidateBreakGlassID(entry.EventID) {
			t.Errorf("EventID should be valid break-glass ID format: %q", entry.EventID)
		}
	}
}

func TestBreakGlassLogEntry_RequestIDFormat(t *testing.T) {
	// RequestID should be 16 lowercase hex characters when populated
	validIDs := []string{
		"fedcba0987654321",
		"0000000000000000",
		"ffffffffffffffff",
		"1234567890abcdef",
	}

	for _, id := range validIDs {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Test justification for RequestID format",
			Duration:      1 * time.Hour,
			Status:        breakglass.StatusActive,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			RequestID:     id,
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		// Verify RequestID is exactly as provided
		if entry.RequestID != id {
			t.Errorf("RequestID mismatch: expected %q, got %q", id, entry.RequestID)
		}

		// Verify it's 16 characters
		if len(entry.RequestID) != 16 {
			t.Errorf("RequestID should be 16 characters: got %d for %q", len(entry.RequestID), entry.RequestID)
		}
	}
}

func TestBreakGlassLogEntry_RequestIDEmpty(t *testing.T) {
	// RequestID can be empty (for events before credential issuance)
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test justification for empty RequestID",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		RequestID:     "", // Empty - not yet issued credentials
	}

	entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

	// RequestID should be empty
	if entry.RequestID != "" {
		t.Errorf("RequestID should be empty when source is empty: got %q", entry.RequestID)
	}

	// Entry should still be valid
	if entry.EventID == "" {
		t.Error("Entry should still have EventID even with empty RequestID")
	}
}

func TestBreakGlassLogEntry_TimestampIsRecent(t *testing.T) {
	// Timestamp should be within 1 second of now (log entry created at call time)
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test justification for recent timestamp",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	beforeCall := time.Now().Add(-1 * time.Second)
	entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)
	afterCall := time.Now().Add(1 * time.Second)

	// Parse the timestamp
	ts, err := time.Parse(time.RFC3339, entry.Timestamp)
	if err != nil {
		t.Fatalf("Failed to parse timestamp %q: %v", entry.Timestamp, err)
	}

	// Timestamp should be between beforeCall and afterCall
	if ts.Before(beforeCall) {
		t.Errorf("Timestamp %v is before expected range (started %v)", ts, beforeCall)
	}
	if ts.After(afterCall) {
		t.Errorf("Timestamp %v is after expected range (ended %v)", ts, afterCall)
	}
}

func TestBreakGlassLogEntry_ExpiresAtMatchesSource(t *testing.T) {
	// ExpiresAt in log should match ISO8601 format of bg.ExpiresAt
	expiresAt := time.Now().Add(2 * time.Hour).UTC()

	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test justification for ExpiresAt matching",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		ExpiresAt:     expiresAt,
	}

	entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

	// Parse the ExpiresAt from entry
	parsedExpires, err := time.Parse(time.RFC3339, entry.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to parse ExpiresAt %q: %v", entry.ExpiresAt, err)
	}

	// Should be within 1 second of source (accounting for formatting precision)
	diff := parsedExpires.Sub(expiresAt)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("ExpiresAt mismatch: expected ~%v, got %v (diff: %v)", expiresAt, parsedExpires, diff)
	}
}

func TestBreakGlassLogEntry_DurationAccuracy(t *testing.T) {
	// Duration in seconds should match bg.Duration.Seconds() rounded
	testCases := []struct {
		duration        time.Duration
		expectedSeconds int
	}{
		{30 * time.Minute, 1800},
		{1 * time.Hour, 3600},
		{1*time.Hour + 30*time.Minute, 5400},
		{2 * time.Hour, 7200},
		{4 * time.Hour, 14400},
		// Sub-second precision should be truncated
		{1*time.Hour + 500*time.Millisecond, 3600},
	}

	for _, tc := range testCases {
		bg := &breakglass.BreakGlassEvent{
			ID:            "a1b2c3d4e5f67890",
			Invoker:       "alice",
			Profile:       "production",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Test justification for duration accuracy",
			Duration:      tc.duration,
			Status:        breakglass.StatusActive,
			ExpiresAt:     time.Now().Add(tc.duration),
		}

		entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

		if entry.Duration != tc.expectedSeconds {
			t.Errorf("Duration for %v: expected %d seconds, got %d", tc.duration, tc.expectedSeconds, entry.Duration)
		}

		// Verify conversion matches int(duration.Seconds())
		expected := int(tc.duration.Seconds())
		if entry.Duration != expected {
			t.Errorf("Duration should match int(duration.Seconds()): expected %d, got %d", expected, entry.Duration)
		}
	}
}

func TestBreakGlassLogEntry_JSONMarshalValid(t *testing.T) {
	// Log entry should marshal to valid JSON
	bg := &breakglass.BreakGlassEvent{
		ID:            "a1b2c3d4e5f67890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test justification for JSON marshal",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		RequestID:     "fedcba0987654321",
	}

	entry := NewBreakGlassLogEntry(BreakGlassEventInvoked, bg)

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to marshal entry to JSON: %v", err)
	}

	// Verify it's valid JSON by unmarshaling
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Marshaled JSON is not valid: %v", err)
	}

	// Verify key fields are present
	expectedKeys := []string{"timestamp", "event", "event_id", "request_id", "invoker", "profile", "reason_code", "justification", "status", "duration_seconds", "expires_at"}
	for _, key := range expectedKeys {
		if _, ok := parsed[key]; !ok {
			t.Errorf("Expected JSON key %q not found", key)
		}
	}
}

func TestBreakGlassLogEntry_JSONFieldNaming(t *testing.T) {
	// JSON field names should use snake_case
	entry := BreakGlassLogEntry{
		Timestamp:     "2026-01-15T10:00:00Z",
		Event:         BreakGlassEventInvoked,
		EventID:       "a1b2c3d4e5f67890",
		RequestID:     "fedcba0987654321",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    "incident",
		Justification: "Test justification",
		Status:        "active",
		Duration:      3600,
		ExpiresAt:     "2026-01-15T11:00:00Z",
		ClosedBy:      "bob",
		ClosedReason:  "resolved",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to marshal entry: %v", err)
	}

	jsonStr := string(data)

	// Verify snake_case field names
	snakeCaseFields := []string{
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
		`"closed_by"`,
		`"closed_reason"`,
	}

	for _, field := range snakeCaseFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Expected snake_case field %s in JSON", field)
		}
	}

	// Verify NO camelCase or PascalCase leaking
	invalidCaseFields := []string{
		`"EventID"`,
		`"RequestID"`,
		`"ReasonCode"`,
		`"ExpiresAt"`,
		`"ClosedBy"`,
		`"ClosedReason"`,
		`"eventId"`,
		`"requestId"`,
		`"reasonCode"`,
		`"expiresAt"`,
		`"closedBy"`,
		`"closedReason"`,
	}

	for _, field := range invalidCaseFields {
		if strings.Contains(jsonStr, field) {
			t.Errorf("Invalid case field %s should not be in JSON", field)
		}
	}
}

func TestBreakGlassLogEntry_JSONOmitempty(t *testing.T) {
	// ClosedBy and ClosedReason should be omitted from JSON when empty
	entry := BreakGlassLogEntry{
		Timestamp:     "2026-01-15T10:00:00Z",
		Event:         BreakGlassEventInvoked,
		EventID:       "a1b2c3d4e5f67890",
		RequestID:     "fedcba0987654321",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    "incident",
		Justification: "Test justification",
		Status:        "active",
		Duration:      3600,
		ExpiresAt:     "2026-01-15T11:00:00Z",
		// ClosedBy and ClosedReason intentionally left empty
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to marshal entry: %v", err)
	}

	jsonStr := string(data)

	// ClosedBy and ClosedReason should NOT appear in output
	if strings.Contains(jsonStr, "closed_by") {
		t.Error("closed_by should be omitted when empty (omitempty)")
	}
	if strings.Contains(jsonStr, "closed_reason") {
		t.Error("closed_reason should be omitted when empty (omitempty)")
	}

	// But all other fields should be present
	requiredFields := []string{"timestamp", "event", "event_id", "invoker", "profile"}
	for _, field := range requiredFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("Required field %s should be present", field)
		}
	}
}
