package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/policy"
)

// mockBreakGlassStore implements breakglass.Store for testing.
type mockBreakGlassStore struct {
	createFn                        func(ctx context.Context, event *breakglass.BreakGlassEvent) error
	getFn                           func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error)
	updateFn                        func(ctx context.Context, event *breakglass.BreakGlassEvent) error
	deleteFn                        func(ctx context.Context, id string) error
	listByInvokerFn                 func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error)
	listByStatusFn                  func(ctx context.Context, status breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error)
	listByProfileFn                 func(ctx context.Context, profile string, limit int) ([]*breakglass.BreakGlassEvent, error)
	findActiveByInvokerAndProfileFn func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error)
	countByInvokerSinceFn           func(ctx context.Context, invoker string, since time.Time) (int, error)
	countByProfileSinceFn           func(ctx context.Context, profile string, since time.Time) (int, error)
	getLastByInvokerAndProfileFn    func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error)
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
	// Set UpdatedAt to match real DynamoDB store behavior
	event.UpdatedAt = time.Now()
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

func (m *mockBreakGlassStore) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	if m.countByInvokerSinceFn != nil {
		return m.countByInvokerSinceFn(ctx, invoker, since)
	}
	return 0, nil
}

func (m *mockBreakGlassStore) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	if m.countByProfileSinceFn != nil {
		return m.countByProfileSinceFn(ctx, profile, since)
	}
	return 0, nil
}

func (m *mockBreakGlassStore) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
	if m.getLastByInvokerAndProfileFn != nil {
		return m.getLastByInvokerAndProfileFn(ctx, invoker, profile)
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

// mockBreakGlassSTSClient implements identity.STSAPI for testing break-glass commands.
type mockBreakGlassSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockBreakGlassSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetCallerIdentityFunc not set")
}

// defaultMockUsername returns the mock username used in tests.
const defaultMockUsername = "testuser"

// defaultMockARN returns the mock ARN used in tests.
const defaultMockARN = "arn:aws:iam::123456789012:user/testuser"

// defaultMockAccountID returns the mock account ID used in tests.
const defaultMockAccountID = "123456789012"

// newMockBreakGlassSTSClient creates a mock STS client that returns the given username in the ARN.
func newMockBreakGlassSTSClient(username string) identity.STSAPI {
	return &mockBreakGlassSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:user/" + username),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}
}

// defaultMockSTSClient returns a mock STS client for the default test user.
func defaultMockSTSClient() identity.STSAPI {
	return newMockBreakGlassSTSClient(defaultMockUsername)
}

// testableBreakGlassCommandOutput contains test output for break-glass command.
type testableBreakGlassCommandOutput struct {
	Event *breakglass.BreakGlassEvent
}

// testableBreakGlassCommand is a testable version that accepts a profile validator and mock STS client.
func testableBreakGlassCommand(ctx context.Context, input BreakGlassCommandInput, validateProfile func(string) error) (*testableBreakGlassCommandOutput, error) {
	// 1. Validate profile exists in AWS config
	if err := validateProfile(input.ProfileName); err != nil {
		return nil, err
	}

	// 2. Get AWS identity for invoker (use STSClient from input)
	stsClient := input.STSClient
	if stsClient == nil {
		return nil, errors.New("STSClient is required for testing")
	}
	username, err := identity.GetAWSUsername(ctx, stsClient)
	if err != nil {
		return nil, err
	}

	// 3. Parse and validate reason code
	reasonCode := breakglass.ReasonCode(input.ReasonCode)
	if !reasonCode.IsValid() {
		return nil, errors.New("invalid reason code: must be one of: incident, maintenance, security, recovery, other")
	}

	// 3.5 Check break-glass policy authorization if policy is provided
	if input.BreakGlassPolicy != nil {
		rule := breakglass.FindBreakGlassPolicyRule(input.BreakGlassPolicy, input.ProfileName)
		if rule == nil {
			// Policy exists but no rule matches - deny access
			return nil, errors.New("no break-glass policy rule matches profile")
		}

		// Check full authorization (user, reason code, time window, duration)
		if !breakglass.IsBreakGlassAllowed(rule, username, reasonCode, time.Now(), input.Duration) {
			// Determine specific reason for denial
			if !breakglass.CanInvokeBreakGlass(rule, username) {
				return nil, errors.New("not authorized to invoke break-glass for profile")
			}
			// Check reason code (empty = all allowed)
			if len(rule.AllowedReasonCodes) > 0 {
				found := false
				for _, rc := range rule.AllowedReasonCodes {
					if rc == reasonCode {
						found = true
						break
					}
				}
				if !found {
					return nil, errors.New("reason code not allowed for this profile")
				}
			}
			// Check time window
			if rule.Time != nil {
				return nil, errors.New("break-glass not allowed at this time")
			}
			// Check duration cap
			if rule.MaxDuration > 0 && input.Duration > rule.MaxDuration {
				return nil, errors.New("duration exceeds maximum allowed for this profile")
			}
		}
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

	// 6.5 Check rate limits if policy is provided
	if input.RateLimitPolicy != nil {
		result, err := breakglass.CheckRateLimit(ctx, store, input.RateLimitPolicy, username, input.ProfileName, time.Now())
		if err != nil {
			return nil, err
		}
		if !result.Allowed {
			return nil, errors.New("rate limit exceeded: " + result.Reason)
		}
		// Escalation warning handled silently in tests
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
		STSClient:     defaultMockSTSClient(),
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
				STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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
				STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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
	existingEvent := &breakglass.BreakGlassEvent{
		ID:        "existing1234567",
		Invoker:   defaultMockUsername,
		Profile:   "production",
		Status:    breakglass.StatusActive,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			if invoker == defaultMockUsername && profile == "production" {
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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
	existingEvent := &breakglass.BreakGlassEvent{
		ID:        "existing1234567",
		Invoker:   defaultMockUsername,
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
			if invoker == defaultMockUsername && profile == "staging" {
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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

	// Verify invoker is using AWS identity (mock username)
	if output.Event.Invoker != defaultMockUsername {
		t.Errorf("expected invoker '%s', got '%s'", defaultMockUsername, output.Event.Invoker)
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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

	// Verify invoker is using AWS identity (mock username)
	if entry.Invoker != defaultMockUsername {
		t.Errorf("expected invoker %q, got %q", defaultMockUsername, entry.Invoker)
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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

	// Verify actor is using AWS identity (mock username)
	if event.Actor != defaultMockUsername {
		t.Errorf("expected actor %q, got %q", defaultMockUsername, event.Actor)
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
		STSClient:     defaultMockSTSClient(),
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
		STSClient:     defaultMockSTSClient(),
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

// ============================================================================
// Rate Limiting Integration
// ============================================================================

func TestBreakGlassCommand_RateLimitBlocked_Cooldown(t *testing.T) {
	now := time.Now()
	lastEventTime := now.Add(-30 * time.Minute) // Recent event, cooldown not elapsed

	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil // No active event
		},
		getLastByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return &breakglass.BreakGlassEvent{
				ID:        "last001",
				Invoker:   invoker,
				Profile:   profile,
				CreatedAt: lastEventTime,
			}, nil
		},
	}

	policy := &breakglass.RateLimitPolicy{
		Version: "1",
		Rules: []breakglass.RateLimitRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Cooldown: time.Hour, // 1 hour cooldown
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:     "production",
		Duration:        1 * time.Hour,
		ReasonCode:      "incident",
		Justification:   "Testing rate limit cooldown blocking",
		Store:           store,
		RateLimitPolicy: policy,
		STSClient:       defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when rate limited by cooldown")
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "cooldown period not elapsed") {
		t.Errorf("expected cooldown reason, got: %v", err)
	}
}

func TestBreakGlassCommand_RateLimitBlocked_Quota(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil // No active event
		},
		countByInvokerSinceFn: func(ctx context.Context, invoker string, since time.Time) (int, error) {
			return 5, nil // At quota limit
		},
	}

	policy := &breakglass.RateLimitPolicy{
		Version: "1",
		Rules: []breakglass.RateLimitRule{
			{
				Name:        "production",
				Profiles:    []string{"production"},
				MaxPerUser:  5,
				QuotaWindow: 24 * time.Hour,
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:     "production",
		Duration:        1 * time.Hour,
		ReasonCode:      "incident",
		Justification:   "Testing rate limit quota blocking",
		Store:           store,
		RateLimitPolicy: policy,
		STSClient:       defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when rate limited by quota")
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "user quota exceeded") {
		t.Errorf("expected user quota reason, got: %v", err)
	}
}

func TestBreakGlassCommand_RateLimitAllowed(t *testing.T) {
	now := time.Now()
	lastEventTime := now.Add(-2 * time.Hour) // Well past cooldown

	var storedEvent *breakglass.BreakGlassEvent
	store := &mockBreakGlassStore{
		createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
			storedEvent = event
			return nil
		},
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil // No active event
		},
		getLastByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return &breakglass.BreakGlassEvent{
				ID:        "last001",
				Invoker:   invoker,
				Profile:   profile,
				CreatedAt: lastEventTime,
			}, nil
		},
		countByInvokerSinceFn: func(ctx context.Context, invoker string, since time.Time) (int, error) {
			return 2, nil // Under quota
		},
		countByProfileSinceFn: func(ctx context.Context, profile string, since time.Time) (int, error) {
			return 3, nil // Under quota
		},
	}

	policy := &breakglass.RateLimitPolicy{
		Version: "1",
		Rules: []breakglass.RateLimitRule{
			{
				Name:          "production",
				Profiles:      []string{"production"},
				Cooldown:      time.Hour,
				MaxPerUser:    5,
				MaxPerProfile: 10,
				QuotaWindow:   24 * time.Hour,
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:     "production",
		Duration:        1 * time.Hour,
		ReasonCode:      "incident",
		Justification:   "Testing rate limit allowed with all checks passing",
		Store:           store,
		RateLimitPolicy: policy,
		STSClient:       defaultMockSTSClient(),
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify event was created
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be created")
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
	if storedEvent.Profile != "production" {
		t.Errorf("expected profile 'production', got '%s'", storedEvent.Profile)
	}
}

func TestBreakGlassCommand_NilRateLimitPolicy(t *testing.T) {
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
		ProfileName:     "test-profile",
		Duration:        1 * time.Hour,
		ReasonCode:      "incident",
		Justification:   "Testing break-glass without rate limit policy",
		Store:           store,
		RateLimitPolicy: nil, // Explicitly nil
		STSClient:       defaultMockSTSClient(),
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error with nil rate limit policy: %v", err)
	}

	// Verify command succeeded without rate limit checks
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be created")
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
}

// ============================================================================
// Break-Glass Policy Integration
// ============================================================================

func TestBreakGlassCommand_PolicyAuthorized(t *testing.T) {
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

	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Users:    []string{defaultMockUsername},
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:      "production",
		Duration:         1 * time.Hour,
		ReasonCode:       "incident",
		Justification:    "Testing policy authorized break-glass invocation",
		Store:            store,
		BreakGlassPolicy: bgPolicy,
		STSClient:        defaultMockSTSClient(),
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify event was created
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be created")
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
	if storedEvent.Profile != "production" {
		t.Errorf("expected profile 'production', got '%s'", storedEvent.Profile)
	}
}

func TestBreakGlassCommand_PolicyUserNotAuthorized(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Users:    []string{"different-user"}, // Current user not in list
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:      "production",
		Duration:         1 * time.Hour,
		ReasonCode:       "incident",
		Justification:    "Testing policy user not authorized",
		Store:            store,
		BreakGlassPolicy: bgPolicy,
		STSClient:        defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when user not authorized")
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCommand_PolicyReasonCodeNotAllowed(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:               "production",
				Profiles:           []string{"production"},
				Users:              []string{defaultMockUsername},
				AllowedReasonCodes: []breakglass.ReasonCode{breakglass.ReasonIncident, breakglass.ReasonSecurity}, // maintenance not allowed
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:      "production",
		Duration:         1 * time.Hour,
		ReasonCode:       "maintenance", // Not in allowed list
		Justification:    "Testing policy reason code not allowed",
		Store:            store,
		BreakGlassPolicy: bgPolicy,
		STSClient:        defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when reason code not allowed")
	}
	if !strings.Contains(err.Error(), "reason code not allowed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCommand_PolicyTimeWindowBlocked(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	// Create a time window that definitely doesn't match current time
	// Use a day that is not today
	today := time.Now().Weekday()
	var blockedDay policy.Weekday
	switch today {
	case time.Monday:
		blockedDay = policy.Tuesday
	case time.Tuesday:
		blockedDay = policy.Wednesday
	case time.Wednesday:
		blockedDay = policy.Thursday
	case time.Thursday:
		blockedDay = policy.Friday
	case time.Friday:
		blockedDay = policy.Saturday
	case time.Saturday:
		blockedDay = policy.Sunday
	case time.Sunday:
		blockedDay = policy.Monday
	}

	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:     "production",
				Profiles: []string{"production"},
				Users:    []string{defaultMockUsername},
				Time: &policy.TimeWindow{
					Days: []policy.Weekday{blockedDay}, // A day that is not today
				},
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:      "production",
		Duration:         1 * time.Hour,
		ReasonCode:       "incident",
		Justification:    "Testing policy time window blocked",
		Store:            store,
		BreakGlassPolicy: bgPolicy,
		STSClient:        defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when time window blocked")
	}
	if !strings.Contains(err.Error(), "not allowed at this time") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCommand_PolicyDurationExceedsMaximum(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:        "production",
				Profiles:    []string{"production"},
				Users:       []string{defaultMockUsername},
				MaxDuration: 30 * time.Minute, // Cap at 30 minutes
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:      "production",
		Duration:         1 * time.Hour, // Exceeds 30 minute cap
		ReasonCode:       "incident",
		Justification:    "Testing policy duration exceeds maximum",
		Store:            store,
		BreakGlassPolicy: bgPolicy,
		STSClient:        defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when duration exceeds maximum")
	}
	if !strings.Contains(err.Error(), "duration exceeds maximum") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCommand_PolicyNoMatchingRule(t *testing.T) {
	store := &mockBreakGlassStore{
		findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
			return nil, nil
		},
	}

	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:     "staging",
				Profiles: []string{"staging"}, // Only staging, not production
				Users:    []string{"anyone"},
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:      "production", // No rule matches production
		Duration:         1 * time.Hour,
		ReasonCode:       "incident",
		Justification:    "Testing policy no matching rule",
		Store:            store,
		BreakGlassPolicy: bgPolicy,
		STSClient:        defaultMockSTSClient(),
	}

	_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when no policy rule matches")
	}
	if !strings.Contains(err.Error(), "no break-glass policy rule matches") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassCommand_NilPolicyAllows(t *testing.T) {
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
		ProfileName:      "any-profile",
		Duration:         1 * time.Hour,
		ReasonCode:       "incident",
		Justification:    "Testing nil policy allows any user (backward compatible)",
		Store:            store,
		BreakGlassPolicy: nil, // Explicitly nil - no policy enforcement
		STSClient:        defaultMockSTSClient(),
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error with nil policy: %v", err)
	}

	// Verify command succeeded without policy checks
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be created")
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
}

func TestBreakGlassCommand_PolicyWildcardProfile(t *testing.T) {
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

	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:     "all-profiles",
				Profiles: []string{}, // Empty = wildcard, matches all profiles
				Users:    []string{defaultMockUsername},
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:      "any-profile-name",
		Duration:         1 * time.Hour,
		ReasonCode:       "incident",
		Justification:    "Testing wildcard profile matches any profile",
		Store:            store,
		BreakGlassPolicy: bgPolicy,
		STSClient:        defaultMockSTSClient(),
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify event was created
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be created")
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
}

func TestBreakGlassCommand_PolicyEmptyReasonCodesAllowsAll(t *testing.T) {
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

	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:               "production",
				Profiles:           []string{"production"},
				Users:              []string{defaultMockUsername},
				AllowedReasonCodes: []breakglass.ReasonCode{}, // Empty = all allowed
			},
		},
	}

	// Test with various reason codes - all should be allowed
	reasonCodes := []string{"incident", "maintenance", "security", "recovery", "other"}

	for _, rc := range reasonCodes {
		t.Run(rc, func(t *testing.T) {
			input := BreakGlassCommandInput{
				ProfileName:      "production",
				Duration:         1 * time.Hour,
				ReasonCode:       rc,
				Justification:    "Testing empty reason codes allows all",
				Store:            store,
				BreakGlassPolicy: bgPolicy,
				STSClient:        defaultMockSTSClient(),
			}

			output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
			if err != nil {
				t.Fatalf("unexpected error for reason code %s: %v", rc, err)
			}
			if output == nil || output.Event == nil {
				t.Fatal("expected event to be created")
			}
			if storedEvent == nil {
				t.Fatal("expected event to be stored")
			}
		})
	}
}

func TestBreakGlassCommand_PolicyZeroMaxDurationNoLimit(t *testing.T) {
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

	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:        "production",
				Profiles:    []string{"production"},
				Users:       []string{defaultMockUsername},
				MaxDuration: 0, // Zero = no duration cap (system default applies)
			},
		},
	}

	input := BreakGlassCommandInput{
		ProfileName:      "production",
		Duration:         4 * time.Hour, // Max system duration
		ReasonCode:       "incident",
		Justification:    "Testing zero max duration allows any duration up to system max",
		Store:            store,
		BreakGlassPolicy: bgPolicy,
		STSClient:        defaultMockSTSClient(),
	}

	output, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify event was created with 4h duration (capped at system max)
	if output == nil || output.Event == nil {
		t.Fatal("expected event to be created")
	}
	if storedEvent == nil {
		t.Fatal("expected event to be stored")
	}
	if storedEvent.Duration != 4*time.Hour {
		t.Errorf("expected duration 4h, got %v", storedEvent.Duration)
	}
}
