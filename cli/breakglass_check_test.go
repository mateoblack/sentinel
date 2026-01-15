package cli

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
)

// testableBreakGlassCheckCommand is a testable version that allows mock store injection.
func testableBreakGlassCheckCommand(ctx context.Context, input BreakGlassCheckCommandInput) (*BreakGlassCheckCommandOutput, error) {
	// 1. Validate event ID format
	if !breakglass.ValidateBreakGlassID(input.EventID) {
		return nil, errors.New("invalid event ID format")
	}

	// 2. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 3. Fetch event from store
	event, err := store.Get(ctx, input.EventID)
	if err != nil {
		return nil, err
	}

	// 4. Format duration as human-readable string
	duration := formatDuration(event.Duration)

	// 5. Return output
	return &BreakGlassCheckCommandOutput{
		ID:            event.ID,
		Invoker:       event.Invoker,
		Profile:       event.Profile,
		ReasonCode:    string(event.ReasonCode),
		Justification: event.Justification,
		Duration:      duration,
		Status:        string(event.Status),
		CreatedAt:     event.CreatedAt,
		UpdatedAt:     event.UpdatedAt,
		ExpiresAt:     event.ExpiresAt,
		ClosedBy:      event.ClosedBy,
		ClosedReason:  event.ClosedReason,
		RequestID:     event.RequestID,
	}, nil
}

func TestBreakGlassCheckCommand_Success(t *testing.T) {
	now := time.Now()
	expectedEvent := &breakglass.BreakGlassEvent{
		ID:            "abc123def4567890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Investigating incident INC-12345 - production database outage",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-30 * time.Minute),
		ExpiresAt:     now.Add(1 * time.Hour),
		RequestID:     "req123456789abcd",
	}

	var calledID string
	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			calledID = id
			return expectedEvent, nil
		},
	}

	input := BreakGlassCheckCommandInput{
		EventID: "abc123def4567890",
		Store:   store,
	}

	output, err := testableBreakGlassCheckCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Get was called with correct ID
	if calledID != "abc123def4567890" {
		t.Errorf("expected Get called with 'abc123def4567890', got %q", calledID)
	}

	// Verify output fields
	if output.ID != "abc123def4567890" {
		t.Errorf("expected ID 'abc123def4567890', got %q", output.ID)
	}
	if output.Invoker != "alice" {
		t.Errorf("expected Invoker 'alice', got %q", output.Invoker)
	}
	if output.Profile != "production" {
		t.Errorf("expected Profile 'production', got %q", output.Profile)
	}
	if output.Status != "active" {
		t.Errorf("expected Status 'active', got %q", output.Status)
	}
	if output.ReasonCode != "incident" {
		t.Errorf("expected ReasonCode 'incident', got %q", output.ReasonCode)
	}
	if output.RequestID != "req123456789abcd" {
		t.Errorf("expected RequestID 'req123456789abcd', got %q", output.RequestID)
	}
}

func TestBreakGlassCheckCommand_NotFound(t *testing.T) {
	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return nil, breakglass.ErrEventNotFound
		},
	}

	input := BreakGlassCheckCommandInput{
		EventID: "1234567890abcdef",
		Store:   store,
	}

	_, err := testableBreakGlassCheckCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for event not found")
	}

	if !errors.Is(err, breakglass.ErrEventNotFound) {
		t.Errorf("expected ErrEventNotFound, got: %v", err)
	}
}

func TestBreakGlassCheckCommand_InvalidID(t *testing.T) {
	store := &mockBreakGlassStore{}

	testCases := []struct {
		name    string
		eventID string
	}{
		{"too short", "abc123"},
		{"too long", "abc123def4567890extra"},
		{"uppercase", "ABC123DEF4567890"},
		{"invalid chars", "xyz123def456789!"},
		{"empty", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := BreakGlassCheckCommandInput{
				EventID: tc.eventID,
				Store:   store,
			}

			_, err := testableBreakGlassCheckCommand(context.Background(), input)
			if err == nil {
				t.Fatal("expected error for invalid event ID")
			}

			if err.Error() != "invalid event ID format" {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestBreakGlassCheckCommand_StoreError(t *testing.T) {
	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return nil, errors.New("network error: connection timeout")
		},
	}

	input := BreakGlassCheckCommandInput{
		EventID: "1234567890abcdef",
		Store:   store,
	}

	_, err := testableBreakGlassCheckCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when store fails")
	}

	if err.Error() != "network error: connection timeout" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCheckCommand_OutputFormat(t *testing.T) {
	now := time.Now()
	expectedEvent := &breakglass.BreakGlassEvent{
		ID:            "fedcba9876543210",
		Invoker:       "charlie",
		Profile:       "staging",
		ReasonCode:    breakglass.ReasonMaintenance,
		Justification: "Emergency maintenance for JIRA-999 - disk full issue",
		Duration:      90 * time.Minute, // 1h30m
		Status:        breakglass.StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(90 * time.Minute),
		RequestID:     "maintreq12345678",
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return expectedEvent, nil
		},
	}

	input := BreakGlassCheckCommandInput{
		EventID: "fedcba9876543210",
		Store:   store,
	}

	output, err := testableBreakGlassCheckCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all fields are present in output
	if output.ID != "fedcba9876543210" {
		t.Errorf("expected ID 'fedcba9876543210', got %q", output.ID)
	}
	if output.Invoker != "charlie" {
		t.Errorf("expected Invoker 'charlie', got %q", output.Invoker)
	}
	if output.Profile != "staging" {
		t.Errorf("expected Profile 'staging', got %q", output.Profile)
	}
	if output.ReasonCode != "maintenance" {
		t.Errorf("expected ReasonCode 'maintenance', got %q", output.ReasonCode)
	}
	if output.Justification != "Emergency maintenance for JIRA-999 - disk full issue" {
		t.Errorf("expected Justification 'Emergency maintenance for JIRA-999 - disk full issue', got %q", output.Justification)
	}
	if output.Status != "active" {
		t.Errorf("expected Status 'active', got %q", output.Status)
	}

	// Verify Duration is formatted as human-readable string
	if output.Duration != "1h30m" {
		t.Errorf("expected Duration '1h30m', got %q", output.Duration)
	}

	// Verify timestamps are set
	if output.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if output.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set")
	}
	if output.ExpiresAt.IsZero() {
		t.Error("expected ExpiresAt to be set")
	}

	// Verify RequestID is present
	if output.RequestID != "maintreq12345678" {
		t.Errorf("expected RequestID 'maintreq12345678', got %q", output.RequestID)
	}

	// Verify JSON marshaling works with omitempty for optional fields
	jsonBytes, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("failed to marshal output: %v", err)
	}

	var unmarshaled BreakGlassCheckCommandOutput
	if err := json.Unmarshal(jsonBytes, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	// Verify ClosedBy is empty (should be omitted in JSON)
	if unmarshaled.ClosedBy != "" {
		t.Errorf("expected empty ClosedBy in unmarshaled output, got %q", unmarshaled.ClosedBy)
	}
}

func TestBreakGlassCheckCommand_ClosedEvent(t *testing.T) {
	now := time.Now()
	expectedEvent := &breakglass.BreakGlassEvent{
		ID:            "1234567890abcdef",
		Invoker:       "developer",
		Profile:       "admin",
		ReasonCode:    breakglass.ReasonSecurity,
		Justification: "Security incident response - investigating unauthorized access",
		Duration:      4 * time.Hour,
		Status:        breakglass.StatusClosed,
		CreatedAt:     now.Add(-3 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(1 * time.Hour),
		ClosedBy:      "security-team",
		ClosedReason:  "Incident resolved, access no longer needed",
		RequestID:     "secreq1234567890",
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return expectedEvent, nil
		},
	}

	input := BreakGlassCheckCommandInput{
		EventID: "1234567890abcdef",
		Store:   store,
	}

	output, err := testableBreakGlassCheckCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify closed fields
	if output.ClosedBy != "security-team" {
		t.Errorf("expected ClosedBy 'security-team', got %q", output.ClosedBy)
	}
	if output.ClosedReason != "Incident resolved, access no longer needed" {
		t.Errorf("expected ClosedReason 'Incident resolved, access no longer needed', got %q", output.ClosedReason)
	}
	if output.Status != "closed" {
		t.Errorf("expected Status 'closed', got %q", output.Status)
	}
	if output.Duration != "4h" {
		t.Errorf("expected Duration '4h', got %q", output.Duration)
	}
}

func TestBreakGlassCheckCommand_ExpiredEvent(t *testing.T) {
	now := time.Now()
	expectedEvent := &breakglass.BreakGlassEvent{
		ID:            "abcdef1234567890",
		Invoker:       "ops-engineer",
		Profile:       "production-readonly",
		ReasonCode:    breakglass.ReasonRecovery,
		Justification: "Disaster recovery operations after data center outage",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusExpired,
		CreatedAt:     now.Add(-4 * time.Hour),
		UpdatedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:     now.Add(-2 * time.Hour),
		RequestID:     "drrec12345678901",
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return expectedEvent, nil
		},
	}

	input := BreakGlassCheckCommandInput{
		EventID: "abcdef1234567890",
		Store:   store,
	}

	output, err := testableBreakGlassCheckCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify expired status
	if output.Status != "expired" {
		t.Errorf("expected Status 'expired', got %q", output.Status)
	}
	if output.ReasonCode != "recovery" {
		t.Errorf("expected ReasonCode 'recovery', got %q", output.ReasonCode)
	}
	// ClosedBy should be empty for expired events
	if output.ClosedBy != "" {
		t.Errorf("expected ClosedBy to be empty for expired event, got %q", output.ClosedBy)
	}
}

func TestBreakGlassCheckCommand_AllReasonCodes(t *testing.T) {
	reasonCodes := []breakglass.ReasonCode{
		breakglass.ReasonIncident,
		breakglass.ReasonMaintenance,
		breakglass.ReasonSecurity,
		breakglass.ReasonRecovery,
		breakglass.ReasonOther,
	}

	for _, rc := range reasonCodes {
		t.Run(string(rc), func(t *testing.T) {
			now := time.Now()
			expectedEvent := &breakglass.BreakGlassEvent{
				ID:            "1234567890abcdef",
				Invoker:       "testuser",
				Profile:       "test-profile",
				ReasonCode:    rc,
				Justification: "Test justification for " + string(rc),
				Duration:      1 * time.Hour,
				Status:        breakglass.StatusActive,
				CreatedAt:     now,
				UpdatedAt:     now,
				ExpiresAt:     now.Add(1 * time.Hour),
			}

			store := &mockBreakGlassStore{
				getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
					return expectedEvent, nil
				},
			}

			input := BreakGlassCheckCommandInput{
				EventID: "1234567890abcdef",
				Store:   store,
			}

			output, err := testableBreakGlassCheckCommand(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error for reason code %s: %v", rc, err)
			}

			// Verify reason code is correctly output
			if output.ReasonCode != string(rc) {
				t.Errorf("expected ReasonCode %q, got %q", rc, output.ReasonCode)
			}
		})
	}
}

func TestBreakGlassCheckCommand_DurationFormatting(t *testing.T) {
	testCases := []struct {
		duration time.Duration
		expected string
	}{
		{1 * time.Hour, "1h"},
		{2 * time.Hour, "2h"},
		{30 * time.Minute, "30m"},
		{90 * time.Minute, "1h30m"},
		{150 * time.Minute, "2h30m"},
		{4 * time.Hour, "4h"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			now := time.Now()
			expectedEvent := &breakglass.BreakGlassEvent{
				ID:            "1234567890abcdef",
				Invoker:       "testuser",
				Profile:       "test-profile",
				ReasonCode:    breakglass.ReasonIncident,
				Justification: "Test duration formatting",
				Duration:      tc.duration,
				Status:        breakglass.StatusActive,
				CreatedAt:     now,
				UpdatedAt:     now,
				ExpiresAt:     now.Add(tc.duration),
			}

			store := &mockBreakGlassStore{
				getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
					return expectedEvent, nil
				},
			}

			input := BreakGlassCheckCommandInput{
				EventID: "1234567890abcdef",
				Store:   store,
			}

			output, err := testableBreakGlassCheckCommand(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if output.Duration != tc.expected {
				t.Errorf("expected Duration %q, got %q", tc.expected, output.Duration)
			}
		})
	}
}
