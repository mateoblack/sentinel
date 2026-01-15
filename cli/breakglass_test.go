package cli

import (
	"context"
	"errors"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/notification"
)

// mockBreakGlassStore implements breakglass.Store for testing.
type mockBreakGlassStore struct {
	createFn                      func(ctx context.Context, event *breakglass.BreakGlassEvent) error
	getFn                         func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error)
	updateFn                      func(ctx context.Context, event *breakglass.BreakGlassEvent) error
	deleteFn                      func(ctx context.Context, id string) error
	listByInvokerFn               func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error)
	listByStatusFn                func(ctx context.Context, status breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error)
	listByProfileFn               func(ctx context.Context, profile string, limit int) ([]*breakglass.BreakGlassEvent, error)
	findActiveByInvokerAndProfileFn func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error)
}

func (m *mockBreakGlassStore) Create(ctx context.Context, event *breakglass.BreakGlassEvent) error {
	if m.createFn != nil {
		return m.createFn(ctx, event)
	}
	return nil
}

func (m *mockBreakGlassStore) Get(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id)
	}
	return nil, breakglass.ErrEventNotFound
}

func (m *mockBreakGlassStore) Update(ctx context.Context, event *breakglass.BreakGlassEvent) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, event)
	}
	return nil
}

func (m *mockBreakGlassStore) Delete(ctx context.Context, id string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

func (m *mockBreakGlassStore) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
	if m.listByInvokerFn != nil {
		return m.listByInvokerFn(ctx, invoker, limit)
	}
	return nil, nil
}

func (m *mockBreakGlassStore) ListByStatus(ctx context.Context, status breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error) {
	if m.listByStatusFn != nil {
		return m.listByStatusFn(ctx, status, limit)
	}
	return nil, nil
}

func (m *mockBreakGlassStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*breakglass.BreakGlassEvent, error) {
	if m.listByProfileFn != nil {
		return m.listByProfileFn(ctx, profile, limit)
	}
	return nil, nil
}

func (m *mockBreakGlassStore) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
	if m.findActiveByInvokerAndProfileFn != nil {
		return m.findActiveByInvokerAndProfileFn(ctx, invoker, profile)
	}
	return nil, nil
}

// mockBreakGlassSentinel provides a Sentinel stub for testing that bypasses profile validation.
type mockBreakGlassSentinel struct {
	profileExists bool
	profileError  error
}

func (m *mockBreakGlassSentinel) ValidateProfile(profileName string) error {
	if m.profileError != nil {
		return m.profileError
	}
	if !m.profileExists {
		return errors.New("profile not found in AWS config; available profiles: []")
	}
	return nil
}

// mockBreakGlassLogger implements logging.Logger for testing break-glass logging.
type mockBreakGlassLogger struct {
	decisionEntries   []logging.DecisionLogEntry
	approvalEntries   []logging.ApprovalLogEntry
	breakGlassEntries []logging.BreakGlassLogEntry
}

func (m *mockBreakGlassLogger) LogDecision(entry logging.DecisionLogEntry) {
	m.decisionEntries = append(m.decisionEntries, entry)
}

func (m *mockBreakGlassLogger) LogApproval(entry logging.ApprovalLogEntry) {
	m.approvalEntries = append(m.approvalEntries, entry)
}

func (m *mockBreakGlassLogger) LogBreakGlass(entry logging.BreakGlassLogEntry) {
	m.breakGlassEntries = append(m.breakGlassEntries, entry)
}

// mockBreakGlassNotifier implements notification.BreakGlassNotifier for testing.
type mockBreakGlassNotifier struct {
	notifyFn func(ctx context.Context, event *notification.BreakGlassEvent) error
	events   []*notification.BreakGlassEvent
}

func (m *mockBreakGlassNotifier) NotifyBreakGlass(ctx context.Context, event *notification.BreakGlassEvent) error {
	m.events = append(m.events, event)
	if m.notifyFn != nil {
		return m.notifyFn(ctx, event)
	}
	return nil
}

// testableBreakGlassCommandOutput contains test output for break-glass command.
type testableBreakGlassCommandOutput struct {
	Event *breakglass.BreakGlassEvent
}

// testableBreakGlassCommand is a testable version that accepts a profile validator.
func testableBreakGlassCommand(ctx context.Context, input BreakGlassCommandInput, validateProfile func(string) error) (*testableBreakGlassCommandOutput, error) {
	// 1. Get current user (invoker)
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}
	username := currentUser.Username

	// 2. Validate profile exists in AWS config
	if err := validateProfile(input.ProfileName); err != nil {
		return nil, err
	}

	// 3. Parse and validate reason code
	reasonCode := breakglass.ReasonCode(input.ReasonCode)
	if !reasonCode.IsValid() {
		return nil, errors.New("invalid reason code: must be one of: incident, maintenance, security, recovery, other")
	}

	// 4. Cap duration at MaxDuration (4h)
	duration := input.Duration
	if duration > breakglass.MaxDuration {
		duration = breakglass.MaxDuration
	}

	// 5. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 6. Check for existing active break-glass for same user+profile
	existingEvent, err := store.FindActiveByInvokerAndProfile(ctx, username, input.ProfileName)
	if err != nil {
		return nil, err
	}
	if existingEvent != nil {
		return nil, errors.New("active break-glass already exists for this profile")
	}

	// 7. Build BreakGlassEvent struct
	now := time.Now()
	requestID := breakglass.NewBreakGlassID()
	event := &breakglass.BreakGlassEvent{
		ID:            breakglass.NewBreakGlassID(),
		Invoker:       username,
		Profile:       input.ProfileName,
		ReasonCode:    reasonCode,
		Justification: input.Justification,
		Duration:      duration,
		Status:        breakglass.StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(duration),
		RequestID:     requestID,
	}

	// 8. Validate event
	if err := event.Validate(); err != nil {
		return nil, err
	}

	// 9. Store event
	if err := store.Create(ctx, event); err != nil {
		return nil, err
	}

	// 10. Log break-glass invocation if Logger is provided
	if input.Logger != nil {
		entry := logging.NewBreakGlassLogEntry(logging.BreakGlassEventInvoked, event)
		input.Logger.LogBreakGlass(entry)
	}

	// 11. Fire notification if Notifier is provided
	// Notification errors are logged but don't fail the command (security alerts are best-effort)
	if input.Notifier != nil {
		bgEvent := notification.NewBreakGlassEvent(notification.EventBreakGlassInvoked, event, username)
		// In tests, we capture the error but don't fail - mirrors production behavior
		_ = input.Notifier.NotifyBreakGlass(ctx, bgEvent)
	}

	return &testableBreakGlassCommandOutput{
		Event: event,
	}, nil
}

// ============================================================================
// Success Cases
// ============================================================================

func TestBreakGlassCommand_Success(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil // No existing active break-glass
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "production",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: "Production database outage requiring immediate investigation and remediation",
		Store:         store,
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify event was stored
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}

	// Verify event fields
	if storedEvent.Profile != "production" {
		t.Errorf("expected profile 'production', got '%s'", storedEvent.Profile)
	}
	if storedEvent.Duration != 1*time.Hour {
		t.Errorf("expected duration 1h, got %v", storedEvent.Duration)
	}
	if storedEvent.Status != breakglass.StatusActive {
		t.Errorf("expected status 'active', got '%s'", storedEvent.Status)
	}
	if storedEvent.ReasonCode != breakglass.ReasonIncident {
		t.Errorf("expected reason code 'incident', got '%s'", storedEvent.ReasonCode)
	}

	// Verify output
	if output.Event.ID == "" {
		t.Error("expected event ID to be set")
	}
}

func TestBreakGlassCommand_AllReasonCodes(t *testing.T) {
	reasonCodes := []string{"incident", "maintenance", "security", "recovery", "other"}

	for _, rc := range reasonCodes {
		t.Run(rc, func(t *testing.T) {
			var storedEvent *breakglass.BreakGlassEvent
			store := &mockBreakGlassStore{
				createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
					storedEvent = event
					return nil
				},
				findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
					return nil, nil
				},
			}

			input := BreakGlassCommandInput{
				ProfileName:   "test-profile",
				Duration:      1 * time.Hour,
				ReasonCode:    rc,
				Justification: "Valid justification for testing break-glass with reason code " + rc,
				Store:         store,
			}

			output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
			if err != nil {
				t.Fatalf("unexpected error for reason code %s: %v", rc, err)
			}

			// Verify reason code was stored correctly
			if storedEvent.ReasonCode != breakglass.ReasonCode(rc) {
				t.Errorf("expected reason code '%s', got '%s'", rc, storedEvent.ReasonCode)
			}
			if output.Event.ReasonCode != breakglass.ReasonCode(rc) {
				t.Errorf("expected output reason code '%s', got '%s'", rc, output.Event.ReasonCode)
			}
		})
	}
}

func TestBreakGlassCommand_DurationCappedAtMax(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      8 * time.Hour, // Exceeds 4h max
		ReasonCode:    "incident",
		Justification: "Testing duration capping at maximum allowed time limit",
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify duration was capped at MaxDuration (4h)
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
	if storedEvent.Duration != breakglass.MaxDuration {
		t.Errorf("expected duration to be capped at %v, got %v", breakglass.MaxDuration, storedEvent.Duration)
	}
}

// ============================================================================
// Validation Failures
// ============================================================================

func TestBreakGlassCommand_InvalidProfile(t *testing.T) {
	store := &mockBreakGlassStore{}

	input := BreakGlassCommandInput{
		ProfileName:   "nonexistent-profile",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: "Testing break-glass with invalid profile name",
		Store:         store,
	}

	validateProfile := func(string) error {
		return errors.New("profile \"nonexistent-profile\" not found in AWS config; available profiles: [default, dev]")
	}

	_, err := testableBreakGlassCommand(context.Background(), input, validateProfile)
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}
	if !strings.Contains(err.Error(), "not found in AWS config") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCommand_InvalidReasonCode(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	invalidReasonCodes := []string{"invalid", "emergency", "urgent", ""}

	for _, rc := range invalidReasonCodes {
		t.Run("reason_"+rc, func(t *testing.T) {
			input := BreakGlassCommandInput{
				ProfileName:   "test-profile",
				Duration:      1 * time.Hour,
				ReasonCode:    rc,
				Justification: "Testing break-glass with invalid reason code",
				Store:         store,
			}

			_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
			if err == nil {
				t.Fatalf("expected error for invalid reason code %q", rc)
			}
			if !strings.Contains(err.Error(), "invalid reason code") {
				t.Errorf("unexpected error for reason code %q: %v", rc, err)
			}
		})
	}
}

func TestBreakGlassCommand_JustificationTooShort(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: "too short", // Only 9 chars, minimum is 20
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error for short justification")
	}
	if !strings.Contains(err.Error(), "justification too short") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCommand_JustificationTooLong(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	// Create a justification longer than 1000 characters
	longJustification := make([]byte, 1001)
	for i := range longJustification {
		longJustification[i] = 'a'
	}

	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: string(longJustification),
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error for long justification")
	}
	if !strings.Contains(err.Error(), "justification too long") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================================
// State Validation
// ============================================================================

func TestBreakGlassCommand_ActiveBreakGlassExists(t *testing.T) {
	currentUser, _ := user.Current()
	existingEvent := &breakglass.BreakGlassEvent{
		ID:        "existing1234567",
		Invoker:   currentUser.Username,
		Profile:   "production",
		Status:    breakglass.StatusActive,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			if invoker == currentUser.Username && profile == "production" {
				return existingEvent, nil
			}
			return nil, nil
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "production",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: "Attempting to create duplicate break-glass event",
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when active break-glass already exists")
	}
	if !strings.Contains(err.Error(), "active break-glass already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCommand_NoActiveBreakGlassExists(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil // No active break-glass
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "production",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: "Testing that break-glass succeeds when none exists",
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
}

func TestBreakGlassCommand_DifferentProfileAllowed(t *testing.T) {
	currentUser, _ := user.Current()
	existingEvent := &breakglass.BreakGlassEvent{
		ID:        "existing1234567",
		Invoker:   currentUser.Username,
		Profile:   "staging", // Different profile
		Status:    breakglass.StatusActive,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			// Only return existing event for staging, not production
			if invoker == currentUser.Username && profile == "staging" {
				return existingEvent, nil
			}
			return nil, nil
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "production", // Different from existing staging
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: "Break-glass for production while staging active is allowed",
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
}

// ============================================================================
// Store Errors
// ============================================================================

func TestBreakGlassCommand_StoreCreateError(t *testing.T) {
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			return errors.New("network error: connection refused")
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: "Testing break-glass command store error handling",
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when store.Create fails")
	}
	if err.Error() != "network error: connection refused" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCommand_FindActiveError(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, errors.New("DynamoDB timeout")
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: "Testing break-glass command find active error",
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when FindActiveByInvokerAndProfile fails")
	}
	if err.Error() != "DynamoDB timeout" {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================================
// JSON Output Structure Verification
// ============================================================================

func TestBreakGlassCommand_OutputFields(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "production",
		Duration:      2 * time.Hour,
		ReasonCode:    "security",
		Justification: "Security incident response requiring immediate access for forensics",
		Store:         store,
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify event ID is valid (16 hex chars)
	if !breakglass.ValidateBreakGlassID(output.Event.ID) {
		t.Errorf("invalid event ID format: %s", output.Event.ID)
	}

	// Verify profile
	if output.Event.Profile != "production" {
		t.Errorf("expected profile 'production', got '%s'", output.Event.Profile)
	}

	// Verify reason code
	if output.Event.ReasonCode != breakglass.ReasonSecurity {
		t.Errorf("expected reason code 'security', got '%s'", output.Event.ReasonCode)
	}

	// Verify status is active
	if output.Event.Status != breakglass.StatusActive {
		t.Errorf("expected status 'active', got '%s'", output.Event.Status)
	}

	// Verify expires_at is set
	if output.Event.ExpiresAt.IsZero() {
		t.Error("expected ExpiresAt to be set")
	}

	// Verify request_id is set (for CloudTrail correlation)
	if output.Event.RequestID == "" {
		t.Error("expected RequestID to be set for CloudTrail correlation")
	}
	if !breakglass.ValidateBreakGlassID(output.Event.RequestID) {
		t.Errorf("invalid RequestID format: %s", output.Event.RequestID)
	}

	// Verify invoker is current user
	currentUser, _ := user.Current()
	if output.Event.Invoker != currentUser.Username {
		t.Errorf("expected invoker '%s', got '%s'", currentUser.Username, output.Event.Invoker)
	}

	// Verify timestamps are set
	if storedEvent.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if storedEvent.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set")
	}

	// Verify ExpiresAt is approximately now + duration
	expectedExpiry := time.Now().Add(2 * time.Hour)
	if storedEvent.ExpiresAt.Sub(expectedExpiry) > time.Second {
		t.Errorf("ExpiresAt differs from expected by more than 1 second")
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestBreakGlassCommand_MinimumValidJustification(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	// Exactly 20 characters - minimum allowed
	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: "exactly20characters!", // 20 chars
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error with 20-char justification: %v", err)
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
}

func TestBreakGlassCommand_MaximumValidJustification(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	// Exactly 1000 characters - maximum allowed
	maxJustification := make([]byte, 1000)
	for i := range maxJustification {
		maxJustification[i] = 'a'
	}

	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		ReasonCode:    "incident",
		Justification: string(maxJustification),
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error with 1000-char justification: %v", err)
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
}

func TestBreakGlassCommand_MinimumValidDuration(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Minute, // Very short duration
		ReasonCode:    "incident",
		Justification: "Quick check requiring minimal access time",
		Store:         store,
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error with 1-minute duration: %v", err)
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
	if storedEvent.Duration != 1*time.Minute {
		t.Errorf("expected duration 1m, got %v", storedEvent.Duration)
	}
}

// ============================================================================
// Logging Integration
// ============================================================================

func TestBreakGlassCommand_LogsInvocation(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	logger := &mockBreakGlassLogger{}

	input := BreakGlassCommandInput{
		ProfileName:   "production",
		Duration:      2 * time.Hour,
		ReasonCode:    "incident",
		Justification: "Production database outage requiring immediate investigation",
		Store:         store,
		Logger:        logger,
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify logger received exactly one break-glass entry
	if len(logger.breakGlassEntries) != 1 {
		t.Fatalf("expected 1 break-glass log entry, got %d", len(logger.breakGlassEntries))
	}

	entry := logger.breakGlassEntries[0]

	// Verify event type
	if entry.Event != logging.BreakGlassEventInvoked {
		t.Errorf("expected event %q, got %q", logging.BreakGlassEventInvoked, entry.Event)
	}

	// Verify event ID matches output
	if entry.EventID != output.Event.ID {
		t.Errorf("expected event_id %q, got %q", output.Event.ID, entry.EventID)
	}

	// Verify request ID matches output
	if entry.RequestID != output.Event.RequestID {
		t.Errorf("expected request_id %q, got %q", output.Event.RequestID, entry.RequestID)
	}

	// Verify invoker is current user
	currentUser, _ := user.Current()
	if entry.Invoker != currentUser.Username {
		t.Errorf("expected invoker %q, got %q", currentUser.Username, entry.Invoker)
	}

	// Verify profile
	if entry.Profile != "production" {
		t.Errorf("expected profile %q, got %q", "production", entry.Profile)
	}

	// Verify reason code
	if entry.ReasonCode != "incident" {
		t.Errorf("expected reason_code %q, got %q", "incident", entry.ReasonCode)
	}

	// Verify justification
	if entry.Justification != "Production database outage requiring immediate investigation" {
		t.Errorf("expected justification %q, got %q", "Production database outage requiring immediate investigation", entry.Justification)
	}

	// Verify status is active
	if entry.Status != "active" {
		t.Errorf("expected status %q, got %q", "active", entry.Status)
	}

	// Verify duration is 2 hours in seconds
	expectedDuration := int((2 * time.Hour).Seconds())
	if entry.Duration != expectedDuration {
		t.Errorf("expected duration_seconds %d, got %d", expectedDuration, entry.Duration)
	}

	// Verify expires_at is non-empty
	if entry.ExpiresAt == "" {
		t.Error("expected expires_at to be set")
	}

	// Verify timestamp is non-empty (ISO8601 format)
	if entry.Timestamp == "" {
		t.Error("expected timestamp to be set")
	}

	// Verify no other log types were called
	if len(logger.decisionEntries) != 0 {
		t.Errorf("expected no decision entries, got %d", len(logger.decisionEntries))
	}
	if len(logger.approvalEntries) != 0 {
		t.Errorf("expected no approval entries, got %d", len(logger.approvalEntries))
	}

	_ = storedEvent // Verified in other tests
}

func TestBreakGlassCommand_NoLoggingWhenLoggerNil(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	// Explicitly set Logger to nil (default behavior)
	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		ReasonCode:    "maintenance",
		Justification: "Testing break-glass succeeds without logger",
		Store:         store,
		Logger:        nil, // Explicitly nil
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error with nil Logger: %v", err)
	}

	// Verify command succeeded
	if output == nil {
		t.Fatal("expected output to be non-nil")
	}
	if output.Event == nil {
		t.Fatal("expected event to be created")
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}

	// Verify event was stored correctly
	if storedEvent.Profile != "test-profile" {
		t.Errorf("expected profile 'test-profile', got '%s'", storedEvent.Profile)
	}
	if storedEvent.Status != breakglass.StatusActive {
		t.Errorf("expected status 'active', got '%s'", storedEvent.Status)
	}
}

// ============================================================================
// Notification Integration
// ============================================================================

func TestBreakGlassCommand_NotifiesOnInvocation(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	notifier := &mockBreakGlassNotifier{}

	input := BreakGlassCommandInput{
		ProfileName:   "production",
		Duration:      2 * time.Hour,
		ReasonCode:    "incident",
		Justification: "Production incident requiring emergency access",
		Store:         store,
		Notifier:      notifier,
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify notification was sent
	if len(notifier.events) != 1 {
		t.Fatalf("expected 1 notification event, got %d", len(notifier.events))
	}

	event := notifier.events[0]

	// Verify event type
	if event.Type != notification.EventBreakGlassInvoked {
		t.Errorf("expected event type %q, got %q", notification.EventBreakGlassInvoked, event.Type)
	}

	// Verify break-glass event matches
	if event.BreakGlass.ID != output.Event.ID {
		t.Errorf("expected break-glass ID %q, got %q", output.Event.ID, event.BreakGlass.ID)
	}
	if event.BreakGlass.Profile != "production" {
		t.Errorf("expected profile %q, got %q", "production", event.BreakGlass.Profile)
	}

	// Verify actor is current user
	currentUser, _ := user.Current()
	if event.Actor != currentUser.Username {
		t.Errorf("expected actor %q, got %q", currentUser.Username, event.Actor)
	}

	// Verify timestamp is set
	if event.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}

	_ = storedEvent
}

func TestBreakGlassCommand_NotificationErrorDoesNotFail(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	notifier := &mockBreakGlassNotifier{
		notifyFn: func(ctx context.Context, event *notification.BreakGlassEvent) error {
			return errors.New("notification delivery failed")
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "production",
		Duration:      1 * time.Hour,
		ReasonCode:    "security",
		Justification: "Security incident requiring immediate access",
		Store:         store,
		Notifier:      notifier,
	}

	// Command should succeed even when notification fails
	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("command should not fail when notification fails: %v", err)
	}

	// Verify event was still created
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be created")
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}

	// Verify notification was attempted
	if len(notifier.events) != 1 {
		t.Fatalf("expected 1 notification attempt, got %d", len(notifier.events))
	}
}

func TestBreakGlassCommand_NilNotifierDoesNotPanic(t *testing.T) {
	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		ReasonCode:    "maintenance",
		Justification: "Testing break-glass without notifier",
		Store:         store,
		Notifier:      nil, // Explicitly nil
	}

	// Should not panic with nil notifier
	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error with nil notifier: %v", err)
	}

	// Verify command succeeded
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be created")
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
}
