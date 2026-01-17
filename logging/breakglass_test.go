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
