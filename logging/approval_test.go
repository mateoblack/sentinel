package logging

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/request"
)

func TestNewApprovalLogEntry_RequestCreated(t *testing.T) {
	t.Run("populates all fields for request.created event", func(t *testing.T) {
		req := &request.Request{
			ID:            "a1b2c3d4e5f67890",
			Requester:     "alice",
			Profile:       "production",
			Justification: "Need to deploy hotfix for critical bug",
			Duration:      2 * time.Hour,
			Status:        request.StatusPending,
		}

		entry := NewApprovalLogEntry(notification.EventRequestCreated, req, "alice")

		// Verify timestamp is set
		if entry.Timestamp == "" {
			t.Error("expected non-empty timestamp")
		}

		// Verify event
		if entry.Event != "request.created" {
			t.Errorf("expected event 'request.created', got %q", entry.Event)
		}

		// Verify request_id
		if entry.RequestID != "a1b2c3d4e5f67890" {
			t.Errorf("expected request_id 'a1b2c3d4e5f67890', got %q", entry.RequestID)
		}

		// Verify requester
		if entry.Requester != "alice" {
			t.Errorf("expected requester 'alice', got %q", entry.Requester)
		}

		// Verify profile
		if entry.Profile != "production" {
			t.Errorf("expected profile 'production', got %q", entry.Profile)
		}

		// Verify status
		if entry.Status != "pending" {
			t.Errorf("expected status 'pending', got %q", entry.Status)
		}

		// Verify actor
		if entry.Actor != "alice" {
			t.Errorf("expected actor 'alice', got %q", entry.Actor)
		}

		// Verify justification (populated for created)
		if entry.Justification != "Need to deploy hotfix for critical bug" {
			t.Errorf("expected justification, got %q", entry.Justification)
		}

		// Verify duration (populated for created)
		if entry.Duration != 7200 {
			t.Errorf("expected duration_seconds 7200, got %d", entry.Duration)
		}

		// Verify approver fields are empty for created
		if entry.Approver != "" {
			t.Errorf("expected empty approver for created, got %q", entry.Approver)
		}
		if entry.ApproverComment != "" {
			t.Errorf("expected empty approver_comment for created, got %q", entry.ApproverComment)
		}
		if entry.AutoApproved {
			t.Error("expected auto_approved false for created")
		}
	})

	t.Run("timestamp is ISO8601 format", func(t *testing.T) {
		req := &request.Request{
			ID:        "1234567890abcdef",
			Requester: "bob",
			Profile:   "staging",
			Status:    request.StatusPending,
		}

		entry := NewApprovalLogEntry(notification.EventRequestCreated, req, "bob")

		// Verify timestamp parses as RFC3339 (ISO8601)
		_, err := time.Parse(time.RFC3339, entry.Timestamp)
		if err != nil {
			t.Errorf("timestamp should be RFC3339/ISO8601 format, got error: %v", err)
		}
	})
}

func TestNewApprovalLogEntry_RequestApproved(t *testing.T) {
	t.Run("populates approver fields for request.approved event", func(t *testing.T) {
		req := &request.Request{
			ID:              "a1b2c3d4e5f67890",
			Requester:       "alice",
			Profile:         "production",
			Justification:   "Deploy hotfix",
			Duration:        1 * time.Hour,
			Status:          request.StatusApproved,
			Approver:        "bob",
			ApproverComment: "Approved for emergency fix",
		}

		entry := NewApprovalLogEntry(notification.EventRequestApproved, req, "bob")

		// Verify event
		if entry.Event != "request.approved" {
			t.Errorf("expected event 'request.approved', got %q", entry.Event)
		}

		// Verify status
		if entry.Status != "approved" {
			t.Errorf("expected status 'approved', got %q", entry.Status)
		}

		// Verify actor (approver)
		if entry.Actor != "bob" {
			t.Errorf("expected actor 'bob', got %q", entry.Actor)
		}

		// Verify approver
		if entry.Approver != "bob" {
			t.Errorf("expected approver 'bob', got %q", entry.Approver)
		}

		// Verify approver_comment
		if entry.ApproverComment != "Approved for emergency fix" {
			t.Errorf("expected approver_comment 'Approved for emergency fix', got %q", entry.ApproverComment)
		}

		// Verify auto_approved is false (different actor than requester)
		if entry.AutoApproved {
			t.Error("expected auto_approved false when actor != requester")
		}

		// Verify justification not populated for approved
		if entry.Justification != "" {
			t.Errorf("expected empty justification for approved, got %q", entry.Justification)
		}
	})

	t.Run("sets auto_approved when actor equals requester", func(t *testing.T) {
		req := &request.Request{
			ID:        "1234567890abcdef",
			Requester: "alice",
			Profile:   "development",
			Status:    request.StatusApproved,
			Approver:  "alice",
		}

		// Self-approval via policy (actor is the requester)
		entry := NewApprovalLogEntry(notification.EventRequestApproved, req, "alice")

		if !entry.AutoApproved {
			t.Error("expected auto_approved true when actor equals requester")
		}
	})
}

func TestNewApprovalLogEntry_RequestDenied(t *testing.T) {
	t.Run("populates approver fields for request.denied event", func(t *testing.T) {
		req := &request.Request{
			ID:              "a1b2c3d4e5f67890",
			Requester:       "charlie",
			Profile:         "production",
			Status:          request.StatusDenied,
			Approver:        "admin",
			ApproverComment: "Not authorized for production",
		}

		entry := NewApprovalLogEntry(notification.EventRequestDenied, req, "admin")

		// Verify event
		if entry.Event != "request.denied" {
			t.Errorf("expected event 'request.denied', got %q", entry.Event)
		}

		// Verify status
		if entry.Status != "denied" {
			t.Errorf("expected status 'denied', got %q", entry.Status)
		}

		// Verify actor
		if entry.Actor != "admin" {
			t.Errorf("expected actor 'admin', got %q", entry.Actor)
		}

		// Verify approver
		if entry.Approver != "admin" {
			t.Errorf("expected approver 'admin', got %q", entry.Approver)
		}

		// Verify approver_comment
		if entry.ApproverComment != "Not authorized for production" {
			t.Errorf("expected approver_comment 'Not authorized for production', got %q", entry.ApproverComment)
		}

		// Verify auto_approved is false
		if entry.AutoApproved {
			t.Error("expected auto_approved false for denied")
		}
	})
}

func TestNewApprovalLogEntry_RequestExpired(t *testing.T) {
	t.Run("populates fields for request.expired event", func(t *testing.T) {
		req := &request.Request{
			ID:            "a1b2c3d4e5f67890",
			Requester:     "alice",
			Profile:       "production",
			Justification: "Deploy hotfix",
			Duration:      1 * time.Hour,
			Status:        request.StatusExpired,
		}

		entry := NewApprovalLogEntry(notification.EventRequestExpired, req, "system")

		// Verify event
		if entry.Event != "request.expired" {
			t.Errorf("expected event 'request.expired', got %q", entry.Event)
		}

		// Verify status
		if entry.Status != "expired" {
			t.Errorf("expected status 'expired', got %q", entry.Status)
		}

		// Verify actor is "system"
		if entry.Actor != "system" {
			t.Errorf("expected actor 'system', got %q", entry.Actor)
		}

		// Verify no approver fields for expired
		if entry.Approver != "" {
			t.Errorf("expected empty approver for expired, got %q", entry.Approver)
		}
		if entry.ApproverComment != "" {
			t.Errorf("expected empty approver_comment for expired, got %q", entry.ApproverComment)
		}
		if entry.AutoApproved {
			t.Error("expected auto_approved false for expired")
		}

		// Verify justification not populated for expired
		if entry.Justification != "" {
			t.Errorf("expected empty justification for expired, got %q", entry.Justification)
		}
	})
}

func TestNewApprovalLogEntry_RequestCancelled(t *testing.T) {
	t.Run("populates fields for request.cancelled event", func(t *testing.T) {
		req := &request.Request{
			ID:            "a1b2c3d4e5f67890",
			Requester:     "alice",
			Profile:       "production",
			Justification: "No longer needed",
			Duration:      1 * time.Hour,
			Status:        request.StatusCancelled,
		}

		entry := NewApprovalLogEntry(notification.EventRequestCancelled, req, "alice")

		// Verify event
		if entry.Event != "request.cancelled" {
			t.Errorf("expected event 'request.cancelled', got %q", entry.Event)
		}

		// Verify status
		if entry.Status != "cancelled" {
			t.Errorf("expected status 'cancelled', got %q", entry.Status)
		}

		// Verify actor is requester
		if entry.Actor != "alice" {
			t.Errorf("expected actor 'alice', got %q", entry.Actor)
		}

		// Verify no approver fields for cancelled
		if entry.Approver != "" {
			t.Errorf("expected empty approver for cancelled, got %q", entry.Approver)
		}
		if entry.ApproverComment != "" {
			t.Errorf("expected empty approver_comment for cancelled, got %q", entry.ApproverComment)
		}
		if entry.AutoApproved {
			t.Error("expected auto_approved false for cancelled")
		}

		// Verify justification not populated for cancelled
		if entry.Justification != "" {
			t.Errorf("expected empty justification for cancelled, got %q", entry.Justification)
		}
	})
}

func TestApprovalLogEntry_JSONMarshal(t *testing.T) {
	t.Run("includes all fields when present", func(t *testing.T) {
		req := &request.Request{
			ID:              "a1b2c3d4e5f67890",
			Requester:       "alice",
			Profile:         "production",
			Justification:   "Deploy hotfix",
			Duration:        2 * time.Hour,
			Status:          request.StatusApproved,
			Approver:        "bob",
			ApproverComment: "Approved",
		}

		entry := NewApprovalLogEntry(notification.EventRequestApproved, req, "bob")

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify required fields are present
		requiredFields := []string{
			`"timestamp":`,
			`"event":"request.approved"`,
			`"request_id":"a1b2c3d4e5f67890"`,
			`"requester":"alice"`,
			`"profile":"production"`,
			`"status":"approved"`,
			`"actor":"bob"`,
			`"approver":"bob"`,
			`"approver_comment":"Approved"`,
		}

		for _, field := range requiredFields {
			if !containsSubstring(jsonStr, field) {
				t.Errorf("JSON should contain %s, got: %s", field, jsonStr)
			}
		}
	})

	t.Run("omits empty optional fields (omitempty)", func(t *testing.T) {
		req := &request.Request{
			ID:        "a1b2c3d4e5f67890",
			Requester: "alice",
			Profile:   "production",
			Status:    request.StatusExpired,
		}

		entry := NewApprovalLogEntry(notification.EventRequestExpired, req, "system")

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify optional fields are NOT in JSON (omitempty)
		optionalFields := []string{
			`"justification"`,
			`"duration_seconds"`,
			`"approver"`,
			`"approver_comment"`,
			`"auto_approved"`,
		}

		for _, field := range optionalFields {
			if containsSubstring(jsonStr, field) {
				t.Errorf("JSON should NOT contain %s when empty, got: %s", field, jsonStr)
			}
		}

		// Verify required fields ARE present
		requiredFields := []string{
			`"timestamp":`,
			`"event":"request.expired"`,
			`"request_id":"a1b2c3d4e5f67890"`,
			`"requester":"alice"`,
			`"profile":"production"`,
			`"status":"expired"`,
			`"actor":"system"`,
		}

		for _, field := range requiredFields {
			if !containsSubstring(jsonStr, field) {
				t.Errorf("JSON should contain %s, got: %s", field, jsonStr)
			}
		}
	})

	t.Run("includes justification and duration for created", func(t *testing.T) {
		req := &request.Request{
			ID:            "1234567890abcdef",
			Requester:     "bob",
			Profile:       "staging",
			Justification: "Testing new feature",
			Duration:      30 * time.Minute,
			Status:        request.StatusPending,
		}

		entry := NewApprovalLogEntry(notification.EventRequestCreated, req, "bob")

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify justification is present
		if !containsSubstring(jsonStr, `"justification":"Testing new feature"`) {
			t.Errorf("JSON should contain justification, got: %s", jsonStr)
		}

		// Verify duration_seconds is 1800 (30 minutes)
		if !containsSubstring(jsonStr, `"duration_seconds":1800`) {
			t.Errorf("JSON should contain duration_seconds:1800, got: %s", jsonStr)
		}
	})

	t.Run("includes auto_approved when true", func(t *testing.T) {
		req := &request.Request{
			ID:        "1234567890abcdef",
			Requester: "alice",
			Profile:   "development",
			Status:    request.StatusApproved,
			Approver:  "alice",
		}

		// Self-approval
		entry := NewApprovalLogEntry(notification.EventRequestApproved, req, "alice")

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify auto_approved is present and true
		if !containsSubstring(jsonStr, `"auto_approved":true`) {
			t.Errorf("JSON should contain auto_approved:true, got: %s", jsonStr)
		}
	})

	t.Run("omits auto_approved when false", func(t *testing.T) {
		req := &request.Request{
			ID:        "1234567890abcdef",
			Requester: "alice",
			Profile:   "production",
			Status:    request.StatusApproved,
			Approver:  "bob",
		}

		// Different approver
		entry := NewApprovalLogEntry(notification.EventRequestApproved, req, "bob")

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal entry: %v", err)
		}

		jsonStr := string(data)

		// Verify auto_approved is NOT present (omitempty on false)
		if containsSubstring(jsonStr, `"auto_approved"`) {
			t.Errorf("JSON should NOT contain auto_approved when false, got: %s", jsonStr)
		}
	})
}

func TestApprovalLogEntry_JSONFieldNames(t *testing.T) {
	t.Run("verifies exact JSON field names match schema", func(t *testing.T) {
		req := &request.Request{
			ID:              "a1b2c3d4e5f67890",
			Requester:       "alice",
			Profile:         "production",
			Justification:   "Deploy",
			Duration:        1 * time.Hour,
			Status:          request.StatusApproved,
			Approver:        "alice",
			ApproverComment: "Self-approved",
		}

		// Use approved with self-approval to get all fields
		entry := NewApprovalLogEntry(notification.EventRequestApproved, req, "alice")
		// Manually set justification and duration for testing (normally not set for approved)
		entry.Justification = req.Justification
		entry.Duration = int(req.Duration.Seconds())

		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		jsonStr := string(data)

		// Verify exact field names (JSON tags)
		expectedFields := []string{
			`"timestamp":`,
			`"event":`,
			`"request_id":`,
			`"requester":`,
			`"profile":`,
			`"status":`,
			`"actor":`,
			`"justification":`,
			`"duration_seconds":`,
			`"approver":`,
			`"approver_comment":`,
			`"auto_approved":`,
		}

		for _, field := range expectedFields {
			if !containsSubstring(jsonStr, field) {
				t.Errorf("JSON should contain field %s, got: %s", field, jsonStr)
			}
		}
	})
}

func TestApprovalLogEntry_Constructor_AllEventTypes(t *testing.T) {
	// Verify constructor handles all 5 event types
	eventTypes := []struct {
		event         notification.EventType
		expectedEvent string
	}{
		{notification.EventRequestCreated, "request.created"},
		{notification.EventRequestApproved, "request.approved"},
		{notification.EventRequestDenied, "request.denied"},
		{notification.EventRequestExpired, "request.expired"},
		{notification.EventRequestCancelled, "request.cancelled"},
	}

	for _, tc := range eventTypes {
		t.Run(tc.expectedEvent, func(t *testing.T) {
			req := &request.Request{
				ID:        "1234567890abcdef",
				Requester: "alice",
				Profile:   "production",
				Status:    request.StatusPending,
			}

			entry := NewApprovalLogEntry(tc.event, req, "alice")

			if entry.Event != tc.expectedEvent {
				t.Errorf("expected event %q, got %q", tc.expectedEvent, entry.Event)
			}

			// Verify required fields are always set
			if entry.Timestamp == "" {
				t.Error("timestamp should never be empty")
			}
			if entry.RequestID != "1234567890abcdef" {
				t.Errorf("request_id should be '1234567890abcdef', got %q", entry.RequestID)
			}
			if entry.Requester != "alice" {
				t.Errorf("requester should be 'alice', got %q", entry.Requester)
			}
			if entry.Profile != "production" {
				t.Errorf("profile should be 'production', got %q", entry.Profile)
			}
			if entry.Actor != "alice" {
				t.Errorf("actor should be 'alice', got %q", entry.Actor)
			}
		})
	}
}

func TestApprovalLogEntry_PreservesRequestData(t *testing.T) {
	t.Run("preserves requester from request", func(t *testing.T) {
		testUsers := []string{"alice", "bob", "admin", "user@domain.com"}

		for _, user := range testUsers {
			req := &request.Request{
				ID:        "1234567890abcdef",
				Requester: user,
				Profile:   "test",
				Status:    request.StatusPending,
			}

			entry := NewApprovalLogEntry(notification.EventRequestCreated, req, user)

			if entry.Requester != user {
				t.Errorf("expected requester %q, got %q", user, entry.Requester)
			}
		}
	})

	t.Run("preserves profile from request", func(t *testing.T) {
		testProfiles := []string{"production", "staging", "development", "my-profile-name"}

		for _, profile := range testProfiles {
			req := &request.Request{
				ID:        "1234567890abcdef",
				Requester: "alice",
				Profile:   profile,
				Status:    request.StatusPending,
			}

			entry := NewApprovalLogEntry(notification.EventRequestCreated, req, "alice")

			if entry.Profile != profile {
				t.Errorf("expected profile %q, got %q", profile, entry.Profile)
			}
		}
	})

	t.Run("preserves request ID", func(t *testing.T) {
		testIDs := []string{"a1b2c3d4e5f67890", "0000000000000000", "ffffffffffffffff"}

		for _, id := range testIDs {
			req := &request.Request{
				ID:        id,
				Requester: "alice",
				Profile:   "test",
				Status:    request.StatusPending,
			}

			entry := NewApprovalLogEntry(notification.EventRequestCreated, req, "alice")

			if entry.RequestID != id {
				t.Errorf("expected request_id %q, got %q", id, entry.RequestID)
			}
		}
	})
}
