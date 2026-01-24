package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/notification"
)

// testableBreakGlassCloseCommandOutput contains test output for break-glass close command.
type testableBreakGlassCloseCommandOutput struct {
	Event *breakglass.BreakGlassEvent
}

// testableBreakGlassCloseCommand is a testable version that returns the event directly.
func testableBreakGlassCloseCommand(ctx context.Context, input BreakGlassCloseCommandInput) (*testableBreakGlassCloseCommandOutput, error) {
	// 1. Validate event ID format
	if !breakglass.ValidateBreakGlassID(input.EventID) {
		return nil, errors.New("invalid event ID format")
	}

	// 2. Validate reason is non-empty
	if input.Reason == "" {
		return nil, errors.New("reason is required")
	}

	// 3. Get AWS identity for closer (use STSClient from input)
	stsClient := input.STSClient
	if stsClient == nil {
		return nil, errors.New("STSClient is required for testing")
	}
	closer, err := identity.GetAWSUsername(ctx, stsClient)
	if err != nil {
		return nil, err
	}

	// 4. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 5. Fetch event using store.Get()
	event, err := store.Get(ctx, input.EventID)
	if err != nil {
		return nil, err
	}

	// 6. Check transition validity
	if !event.CanTransitionTo(breakglass.StatusClosed) {
		return nil, errors.New("invalid state transition")
	}

	// 7. Update event fields
	event.Status = breakglass.StatusClosed
	event.ClosedBy = closer
	event.ClosedReason = input.Reason
	// Note: UpdatedAt is set internally by store.Update() for optimistic locking

	// 8. Store updated event
	if err := store.Update(ctx, event); err != nil {
		return nil, err
	}

	// 9. Log break-glass close event if Logger is provided
	if input.Logger != nil {
		entry := logging.NewBreakGlassLogEntry(logging.BreakGlassEventClosed, event)
		input.Logger.LogBreakGlass(entry)
	}

	// 10. Fire notification if Notifier is provided (best-effort)
	if input.Notifier != nil {
		bgEvent := notification.NewBreakGlassEvent(notification.EventBreakGlassClosed, event, closer)
		// In tests, we capture the error but don't fail - mirrors production behavior
		_ = input.Notifier.NotifyBreakGlass(ctx, bgEvent)
	}

	return &testableBreakGlassCloseCommandOutput{
		Event: event,
	}, nil
}

// ============================================================================
// Success Cases
// ============================================================================

func TestBreakGlassCloseCommand_Success(t *testing.T) {
	eventID := "abcd123456789012"
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            eventID,
		Invoker:       defaultMockUsername,
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Production incident requiring emergency access",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		UpdatedAt:     time.Now().Add(-1 * time.Hour),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		RequestID:     "requestid1234567",
	}

	var updatedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			if id == eventID {
				return activeEvent, nil
			}
			return nil, breakglass.ErrEventNotFound
		},
		updateFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			updatedEvent = event
			return nil
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Incident resolved, no longer need access",
		Store:     store,
		STSClient: defaultMockSTSClient(),
	}

	output, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify event was updated
	if updatedEvent == nil {
		t.Fatal("expected event to be updated")
	}

	// Verify status changed to closed
	if updatedEvent.Status != breakglass.StatusClosed {
		t.Errorf("expected status 'closed', got '%s'", updatedEvent.Status)
	}

	// Verify closed_by is using AWS identity (mock username)
	if updatedEvent.ClosedBy != defaultMockUsername {
		t.Errorf("expected closed_by '%s', got '%s'", defaultMockUsername, updatedEvent.ClosedBy)
	}

	// Verify closed_reason
	if updatedEvent.ClosedReason != "Incident resolved, no longer need access" {
		t.Errorf("expected closed_reason to match, got '%s'", updatedEvent.ClosedReason)
	}

	// Verify output matches
	if output.Event.ID != eventID {
		t.Errorf("expected event ID '%s', got '%s'", eventID, output.Event.ID)
	}
	if output.Event.Status != breakglass.StatusClosed {
		t.Errorf("expected output status 'closed', got '%s'", output.Event.Status)
	}
}

// ============================================================================
// Validation Failures
// ============================================================================

func TestBreakGlassCloseCommand_InvalidEventIDFormat(t *testing.T) {
	store := &mockBreakGlassStore{}

	invalidIDs := []string{
		"",                   // empty
		"abc",                // too short
		"abcd12345678901234", // too long (18 chars)
		"ABCD123456789012",   // uppercase
		"abcd12345678901g",   // invalid char 'g'
		"abcd-1234-5678-90",  // dashes
	}

	for _, id := range invalidIDs {
		t.Run("id_"+id, func(t *testing.T) {
			input := BreakGlassCloseCommandInput{
				EventID:   id,
				Reason:    "Test reason",
				Store:     store,
				STSClient: defaultMockSTSClient(),
			}

			_, err := testableBreakGlassCloseCommand(context.Background(), input)
			if err == nil {
				t.Fatalf("expected error for invalid event ID %q", id)
			}
			if !strings.Contains(err.Error(), "invalid event ID format") {
				t.Errorf("unexpected error for ID %q: %v", id, err)
			}
		})
	}
}

func TestBreakGlassCloseCommand_EventNotFound(t *testing.T) {
	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return nil, breakglass.ErrEventNotFound
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   "abcd123456789012", // Valid format, but will return not found
		Reason:    "Test reason",
		Store:     store,
		STSClient: defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for nonexistent event")
	}
	if !errors.Is(err, breakglass.ErrEventNotFound) {
		t.Errorf("expected ErrEventNotFound, got: %v", err)
	}
}

func TestBreakGlassCloseCommand_MissingReason(t *testing.T) {
	store := &mockBreakGlassStore{}

	input := BreakGlassCloseCommandInput{
		EventID:   "abcd123456789012",
		Reason:    "", // empty reason
		Store:     store,
		STSClient: defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing reason")
	}
	if !strings.Contains(err.Error(), "reason is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================================
// State Transition Failures
// ============================================================================

func TestBreakGlassCloseCommand_AlreadyClosed(t *testing.T) {
	eventID := "abcd123456789012"
	closedEvent := &breakglass.BreakGlassEvent{
		ID:           eventID,
		Invoker:      "testuser",
		Profile:      "production",
		ReasonCode:   breakglass.ReasonIncident,
		Status:       breakglass.StatusClosed, // Already closed
		ClosedBy:     "otheruser",
		ClosedReason: "Previously closed",
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		UpdatedAt:    time.Now().Add(-1 * time.Hour),
		ExpiresAt:    time.Now().Add(2 * time.Hour),
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return closedEvent, nil
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Trying to close again",
		Store:     store,
		STSClient: defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for already closed event")
	}
	if !strings.Contains(err.Error(), "invalid state transition") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCloseCommand_AlreadyExpired(t *testing.T) {
	eventID := "abcd123456789012"
	expiredEvent := &breakglass.BreakGlassEvent{
		ID:         eventID,
		Invoker:    "testuser",
		Profile:    "production",
		ReasonCode: breakglass.ReasonIncident,
		Status:     breakglass.StatusExpired, // Already expired
		CreatedAt:  time.Now().Add(-5 * time.Hour),
		UpdatedAt:  time.Now().Add(-1 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return expiredEvent, nil
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Trying to close expired event",
		Store:     store,
		STSClient: defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for expired event")
	}
	if !strings.Contains(err.Error(), "invalid state transition") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================================
// Store Errors
// ============================================================================

func TestBreakGlassCloseCommand_ConcurrentModification(t *testing.T) {
	eventID := "abcd123456789012"
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            eventID,
		Invoker:       "testuser",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Testing concurrent modification",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		UpdatedAt:     time.Now().Add(-1 * time.Hour),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return activeEvent, nil
		},
		updateFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			return breakglass.ErrConcurrentModification
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Closing event",
		Store:     store,
		STSClient: defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for concurrent modification")
	}
	if !errors.Is(err, breakglass.ErrConcurrentModification) {
		t.Errorf("expected ErrConcurrentModification, got: %v", err)
	}
}

func TestBreakGlassCloseCommand_GetError(t *testing.T) {
	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return nil, errors.New("DynamoDB timeout")
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   "abcd123456789012",
		Reason:    "Test reason",
		Store:     store,
		STSClient: defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when Get fails")
	}
	if err.Error() != "DynamoDB timeout" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCloseCommand_UpdateError(t *testing.T) {
	eventID := "abcd123456789012"
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            eventID,
		Invoker:       "testuser",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Testing update error",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		UpdatedAt:     time.Now().Add(-1 * time.Hour),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return activeEvent, nil
		},
		updateFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			return errors.New("network error: connection refused")
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Test reason",
		Store:     store,
		STSClient: defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when Update fails")
	}
	if err.Error() != "network error: connection refused" {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================================
// Logging Integration
// ============================================================================

func TestBreakGlassCloseCommand_LogsCloseEvent(t *testing.T) {
	eventID := "abcd123456789012"
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            eventID,
		Invoker:       "originaluser",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Production incident requiring emergency access",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		UpdatedAt:     time.Now().Add(-1 * time.Hour),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		RequestID:     "requestid1234567",
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return activeEvent, nil
		},
		updateFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			return nil
		},
	}

	logger := &mockBreakGlassLogger{}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Incident resolved, access no longer needed",
		Store:     store,
		Logger:    logger,
		STSClient: defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify logger received exactly one break-glass entry
	if len(logger.breakGlassEntries) != 1 {
		t.Fatalf("expected 1 break-glass log entry, got %d", len(logger.breakGlassEntries))
	}

	entry := logger.breakGlassEntries[0]

	// Verify event type is closed
	if entry.Event != logging.BreakGlassEventClosed {
		t.Errorf("expected event %q, got %q", logging.BreakGlassEventClosed, entry.Event)
	}

	// Verify event ID matches
	if entry.EventID != eventID {
		t.Errorf("expected event_id %q, got %q", eventID, entry.EventID)
	}

	// Verify closed_by is using AWS identity (mock username)
	if entry.ClosedBy != defaultMockUsername {
		t.Errorf("expected closed_by %q, got %q", defaultMockUsername, entry.ClosedBy)
	}

	// Verify closed_reason
	if entry.ClosedReason != "Incident resolved, access no longer needed" {
		t.Errorf("expected closed_reason to match, got %q", entry.ClosedReason)
	}

	// Verify status is closed
	if entry.Status != "closed" {
		t.Errorf("expected status %q, got %q", "closed", entry.Status)
	}

	// Verify no other log types were called
	if len(logger.decisionEntries) != 0 {
		t.Errorf("expected no decision entries, got %d", len(logger.decisionEntries))
	}
	if len(logger.approvalEntries) != 0 {
		t.Errorf("expected no approval entries, got %d", len(logger.approvalEntries))
	}
}

func TestBreakGlassCloseCommand_NoLoggingWhenLoggerNil(t *testing.T) {
	eventID := "abcd123456789012"
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            eventID,
		Invoker:       "testuser",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Test without logger",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now().Add(-30 * time.Minute),
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}

	var updatedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return activeEvent, nil
		},
		updateFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			updatedEvent = event
			return nil
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Closing without logger",
		Store:     store,
		Logger:    nil, // Explicitly nil
		STSClient: defaultMockSTSClient(),
	}

	output, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error with nil Logger: %v", err)
	}

	// Verify command succeeded
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be closed")
	}
	if updatedEvent == nil {
		t.Fatal("expected event to be updated")
	}

	// Verify event was updated correctly
	if updatedEvent.Status != breakglass.StatusClosed {
		t.Errorf("expected status 'closed', got '%s'", updatedEvent.Status)
	}
}

// ============================================================================
// Notification Integration
// ============================================================================

func TestBreakGlassCloseCommand_NotifiesOnClose(t *testing.T) {
	eventID := "abcd123456789012"
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            eventID,
		Invoker:       "originaluser",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Production incident requiring emergency access",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		UpdatedAt:     time.Now().Add(-1 * time.Hour),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return activeEvent, nil
		},
		updateFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			return nil
		},
	}

	notifier := &mockBreakGlassNotifier{}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Incident resolved",
		STSClient: defaultMockSTSClient(),
		Store:    store,
		Notifier: notifier,
	}

	output, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify notification was sent
	if len(notifier.events) != 1 {
		t.Fatalf("expected 1 notification event, got %d", len(notifier.events))
	}

	event := notifier.events[0]

	// Verify event type is closed
	if event.Type != notification.EventBreakGlassClosed {
		t.Errorf("expected event type %q, got %q", notification.EventBreakGlassClosed, event.Type)
	}

	// Verify break-glass event matches
	if event.BreakGlass.ID != output.Event.ID {
		t.Errorf("expected break-glass ID %q, got %q", output.Event.ID, event.BreakGlass.ID)
	}
	if event.BreakGlass.Status != breakglass.StatusClosed {
		t.Errorf("expected status %q, got %q", breakglass.StatusClosed, event.BreakGlass.Status)
	}

	// Verify actor is using AWS identity (mock username - the closer)
	if event.Actor != defaultMockUsername {
		t.Errorf("expected actor %q, got %q", defaultMockUsername, event.Actor)
	}

	// Verify timestamp is set
	if event.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

func TestBreakGlassCloseCommand_NotificationErrorDoesNotFail(t *testing.T) {
	eventID := "abcd123456789012"
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            eventID,
		Invoker:       "testuser",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonSecurity,
		Justification: "Security incident response",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now().Add(-30 * time.Minute),
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}

	var updatedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return activeEvent, nil
		},
		updateFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			updatedEvent = event
			return nil
		},
	}

	notifier := &mockBreakGlassNotifier{
		notifyFn: func(ctx context.Context, event *notification.BreakGlassEvent) error {
			return errors.New("notification delivery failed")
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Incident resolved",
		Store:     store,
		Notifier:  notifier,
		STSClient: defaultMockSTSClient(),
	}

	// Command should succeed even when notification fails
	output, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("command should not fail when notification fails: %v", err)
	}

	// Verify event was still closed
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be closed")
	}
	if updatedEvent == nil {
		t.Fatal("expected event to be updated")
	}
	if updatedEvent.Status != breakglass.StatusClosed {
		t.Errorf("expected status 'closed', got '%s'", updatedEvent.Status)
	}

	// Verify notification was attempted
	if len(notifier.events) != 1 {
		t.Fatalf("expected 1 notification attempt, got %d", len(notifier.events))
	}
}

func TestBreakGlassCloseCommand_NilNotifierDoesNotPanic(t *testing.T) {
	eventID := "abcd123456789012"
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            eventID,
		Invoker:       "testuser",
		Profile:       "test-profile",
		ReasonCode:    breakglass.ReasonMaintenance,
		Justification: "Testing close without notifier",
		Duration:      1 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-30 * time.Minute),
		UpdatedAt:     time.Now().Add(-30 * time.Minute),
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}

	var updatedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return activeEvent, nil
		},
		updateFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			updatedEvent = event
			return nil
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Closing without notifier",
		Store:     store,
		Notifier:  nil, // Explicitly nil
		STSClient: defaultMockSTSClient(),
	}

	// Should not panic with nil notifier
	output, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error with nil notifier: %v", err)
	}

	// Verify command succeeded
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be closed")
	}
	if updatedEvent == nil {
		t.Fatal("expected event to be updated")
	}
}

// ============================================================================
// Output Field Verification
// ============================================================================

func TestBreakGlassCloseCommand_OutputFields(t *testing.T) {
	eventID := "abcd123456789012"
	activeEvent := &breakglass.BreakGlassEvent{
		ID:            eventID,
		Invoker:       "originaluser",
		Profile:       "production",
		ReasonCode:    breakglass.ReasonIncident,
		Justification: "Production incident",
		Duration:      2 * time.Hour,
		Status:        breakglass.StatusActive,
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		UpdatedAt:     time.Now().Add(-1 * time.Hour),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		RequestID:     "requestid1234567",
	}

	store := &mockBreakGlassStore{
		getFn: func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
			return activeEvent, nil
		},
		updateFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			return nil
		},
	}

	input := BreakGlassCloseCommandInput{
		EventID:   eventID,
		Reason:    "Incident resolved, production stable",
		Store:     store,
		STSClient: defaultMockSTSClient(),
	}

	output, err := testableBreakGlassCloseCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ID
	if output.Event.ID != eventID {
		t.Errorf("expected ID %q, got %q", eventID, output.Event.ID)
	}

	// Verify Profile
	if output.Event.Profile != "production" {
		t.Errorf("expected profile 'production', got '%s'", output.Event.Profile)
	}

	// Verify Status
	if output.Event.Status != breakglass.StatusClosed {
		t.Errorf("expected status 'closed', got '%s'", output.Event.Status)
	}

	// Verify ClosedBy uses AWS identity (mock username)
	if output.Event.ClosedBy != defaultMockUsername {
		t.Errorf("expected closed_by '%s', got '%s'", defaultMockUsername, output.Event.ClosedBy)
	}

	// Verify ClosedReason
	if output.Event.ClosedReason != "Incident resolved, production stable" {
		t.Errorf("expected closed_reason to match, got '%s'", output.Event.ClosedReason)
	}

	// Verify UpdatedAt is set (should be recent)
	if output.Event.UpdatedAt.IsZero() {
		t.Error("expected updated_at to be set")
	}
	if time.Since(output.Event.UpdatedAt) > 5*time.Second {
		t.Error("expected updated_at to be recent")
	}
}
