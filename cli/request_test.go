package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// mockStore implements request.Store for testing.
type mockStore struct {
	createFn         func(ctx context.Context, req *request.Request) error
	getFn            func(ctx context.Context, id string) (*request.Request, error)
	updateFn         func(ctx context.Context, req *request.Request) error
	deleteFn         func(ctx context.Context, id string) error
	listByRequesterFn func(ctx context.Context, requester string, limit int) ([]*request.Request, error)
	listByStatusFn   func(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error)
	listByProfileFn  func(ctx context.Context, profile string, limit int) ([]*request.Request, error)
}

func (m *mockStore) Create(ctx context.Context, req *request.Request) error {
	if m.createFn != nil {
		return m.createFn(ctx, req)
	}
	return nil
}

func (m *mockStore) Get(ctx context.Context, id string) (*request.Request, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id)
	}
	return nil, request.ErrRequestNotFound
}

func (m *mockStore) Update(ctx context.Context, req *request.Request) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, req)
	}
	return nil
}

func (m *mockStore) Delete(ctx context.Context, id string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

func (m *mockStore) ListByRequester(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
	if m.listByRequesterFn != nil {
		return m.listByRequesterFn(ctx, requester, limit)
	}
	return nil, nil
}

func (m *mockStore) ListByStatus(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error) {
	if m.listByStatusFn != nil {
		return m.listByStatusFn(ctx, status, limit)
	}
	return nil, nil
}

func (m *mockStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
	if m.listByProfileFn != nil {
		return m.listByProfileFn(ctx, profile, limit)
	}
	return nil, nil
}

// mockLogger captures approval log entries for testing.
type mockLogger struct {
	approvalEntries   []logging.ApprovalLogEntry
	decisionEntries   []logging.DecisionLogEntry
	breakGlassEntries []logging.BreakGlassLogEntry
}

func (m *mockLogger) LogApproval(entry logging.ApprovalLogEntry) {
	m.approvalEntries = append(m.approvalEntries, entry)
}

func (m *mockLogger) LogDecision(entry logging.DecisionLogEntry) {
	m.decisionEntries = append(m.decisionEntries, entry)
}

func (m *mockLogger) LogBreakGlass(entry logging.BreakGlassLogEntry) {
	m.breakGlassEntries = append(m.breakGlassEntries, entry)
}

// mockSentinel provides a Sentinel stub for testing that bypasses profile validation.
type mockSentinel struct {
	profileExists bool
	profileError  error
}

func (m *mockSentinel) ValidateProfile(profileName string) error {
	if m.profileError != nil {
		return m.profileError
	}
	if !m.profileExists {
		return errors.New("profile not found in AWS config; available profiles: []")
	}
	return nil
}

// mockRequestSTSClient implements identity.STSAPI for testing request command.
type mockRequestSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockRequestSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetCallerIdentityFunc not set")
}

// newMockRequestSTSClient creates a mock STS client that returns the specified username.
func newMockRequestSTSClient(username string) *mockRequestSTSClient {
	return &mockRequestSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:user/" + username),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}
}

// extractRequestUsernameFromARN extracts the username from an IAM user ARN.
func extractRequestUsernameFromARN(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}

// testableRequestCommandOutput contains test output with auto-approval status.
type testableRequestCommandOutput struct {
	Request      *request.Request
	AutoApproved bool
	Logger       *mockLogger
}

// testableRequestCommand is a testable version that accepts a profile validator and STS client.
func testableRequestCommand(ctx context.Context, input RequestCommandInput, validateProfile func(string) error) (*testableRequestCommandOutput, error) {
	// 1. Validate profile exists in AWS config
	if err := validateProfile(input.ProfileName); err != nil {
		return nil, err
	}

	// 2. Get AWS identity for requester (must be provided via STSClient for testing)
	if input.STSClient == nil {
		return nil, errors.New("STSClient is required for testing")
	}
	identity, err := input.STSClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	arn := aws.ToString(identity.Arn)
	username := extractRequestUsernameFromARN(arn)

	// 3. Cap duration at MaxDuration
	duration := input.Duration
	if duration > request.MaxDuration {
		duration = request.MaxDuration
	}

	// 4. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 5. Build Request struct
	now := time.Now()
	req := &request.Request{
		ID:            request.NewRequestID(),
		Requester:     username,
		Profile:       input.ProfileName,
		Justification: input.Justification,
		Duration:      duration,
		Status:        request.StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(request.DefaultRequestTTL),
	}

	// 6. Check auto-approve if approval policy is provided
	autoApproved := false
	if input.ApprovalPolicy != nil {
		rule := policy.FindApprovalRule(input.ApprovalPolicy, input.ProfileName)
		if rule != nil && policy.ShouldAutoApprove(rule, username, now, duration) {
			req.Status = request.StatusApproved
			req.Approver = username
			req.ApproverComment = "auto-approved by policy"
			autoApproved = true
		}
	}

	// 7. Validate request
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// 8. Store request
	if err := store.Create(ctx, req); err != nil {
		return nil, err
	}

	// 9. Log approval events if Logger is provided
	var loggerUsed *mockLogger
	if input.Logger != nil {
		// Log request created event
		createdEntry := logging.NewApprovalLogEntry(notification.EventRequestCreated, req, username)
		input.Logger.LogApproval(createdEntry)

		// If auto-approved, also log the approval event
		if autoApproved {
			approvedEntry := logging.NewApprovalLogEntry(notification.EventRequestApproved, req, username)
			input.Logger.LogApproval(approvedEntry)
		}

		// If it's a mock logger, store reference for test verification
		if ml, ok := input.Logger.(*mockLogger); ok {
			loggerUsed = ml
		}
	}

	return &testableRequestCommandOutput{
		Request:      req,
		AutoApproved: autoApproved,
		Logger:       loggerUsed,
	}, nil
}

func TestRequestCommand_Success(t *testing.T) {
	var storedRequest *request.Request
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			storedRequest = req
			return nil
		},
	}

	input := RequestCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		Justification: "Testing the request command functionality",
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
	}

	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify request was stored
	if storedRequest == nil {
		t.Fatal("expected request to be stored")
	}

	// Verify request fields
	if storedRequest.Profile != "test-profile" {
		t.Errorf("expected profile 'test-profile', got '%s'", storedRequest.Profile)
	}
	if storedRequest.Duration != 1*time.Hour {
		t.Errorf("expected duration 1h, got %v", storedRequest.Duration)
	}
	if storedRequest.Status != request.StatusPending {
		t.Errorf("expected status 'pending', got '%s'", storedRequest.Status)
	}
	if storedRequest.Justification != "Testing the request command functionality" {
		t.Errorf("unexpected justification: %s", storedRequest.Justification)
	}

	// Verify requester was set to AWS username
	if storedRequest.Requester != "testuser" {
		t.Errorf("expected requester 'testuser', got '%s'", storedRequest.Requester)
	}

	// Verify auto-approve is false when no policy
	if output.AutoApproved {
		t.Error("expected AutoApproved to be false without policy")
	}
}

func TestRequestCommand_ProfileNotFound(t *testing.T) {
	store := &mockStore{}

	input := RequestCommandInput{
		ProfileName:   "nonexistent-profile",
		Duration:      1 * time.Hour,
		Justification: "Testing the request command functionality",
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
	}

	validateProfile := func(string) error {
		return errors.New("profile \"nonexistent-profile\" not found in AWS config; available profiles: [default, dev]")
	}

	_, err := testableRequestCommand(context.Background(), input, validateProfile)
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}
	if err.Error() != "profile \"nonexistent-profile\" not found in AWS config; available profiles: [default, dev]" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestCommand_JustificationTooShort(t *testing.T) {
	store := &mockStore{}

	input := RequestCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		Justification: "short", // Only 5 chars, minimum is 10
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
	}

	_, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error for short justification")
	}
	if err.Error() != "justification too short: minimum 10 characters" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestCommand_JustificationTooLong(t *testing.T) {
	store := &mockStore{}

	// Create a justification longer than 500 characters
	longJustification := make([]byte, 501)
	for i := range longJustification {
		longJustification[i] = 'a'
	}

	input := RequestCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		Justification: string(longJustification),
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
	}

	_, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error for long justification")
	}
	if err.Error() != "justification too long: maximum 500 characters" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestCommand_DurationExceedsMax(t *testing.T) {
	var storedRequest *request.Request
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			storedRequest = req
			return nil
		},
	}

	input := RequestCommandInput{
		ProfileName:   "test-profile",
		Duration:      12 * time.Hour, // Exceeds 8h max
		Justification: "Testing the request command functionality with long duration",
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
	}

	_, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify duration was capped at MaxDuration (8h)
	if storedRequest == nil {
		t.Fatal("expected request to be stored")
	}
	if storedRequest.Duration != request.MaxDuration {
		t.Errorf("expected duration to be capped at %v, got %v", request.MaxDuration, storedRequest.Duration)
	}
}

func TestRequestCommand_StoreCreateFails(t *testing.T) {
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			return errors.New("network error: connection refused")
		},
	}

	input := RequestCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		Justification: "Testing the request command functionality",
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
	}

	_, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err == nil {
		t.Fatal("expected error when store.Create fails")
	}
	if err.Error() != "network error: connection refused" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestCommand_RequestFieldsPopulated(t *testing.T) {
	var storedRequest *request.Request
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			storedRequest = req
			return nil
		},
	}

	input := RequestCommandInput{
		ProfileName:   "production",
		Duration:      2 * time.Hour,
		Justification: "Need access to investigate production issue TICKET-123",
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
	}

	_, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all required fields are populated correctly
	if storedRequest == nil {
		t.Fatal("expected request to be stored")
	}

	// ID should be valid
	if !request.ValidateRequestID(storedRequest.ID) {
		t.Errorf("invalid request ID: %s", storedRequest.ID)
	}

	// Requester should be AWS username from mock STS client
	if storedRequest.Requester != "testuser" {
		t.Errorf("expected requester 'testuser', got '%s'", storedRequest.Requester)
	}

	// Profile should match input
	if storedRequest.Profile != "production" {
		t.Errorf("expected profile 'production', got '%s'", storedRequest.Profile)
	}

	// Duration should match input
	if storedRequest.Duration != 2*time.Hour {
		t.Errorf("expected duration 2h, got %v", storedRequest.Duration)
	}

	// Status should be pending
	if storedRequest.Status != request.StatusPending {
		t.Errorf("expected status 'pending', got '%s'", storedRequest.Status)
	}

	// Timestamps should be set
	if storedRequest.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if storedRequest.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set")
	}
	if storedRequest.ExpiresAt.IsZero() {
		t.Error("expected ExpiresAt to be set")
	}

	// ExpiresAt should be ~24 hours from now
	expectedExpiry := time.Now().Add(request.DefaultRequestTTL)
	if storedRequest.ExpiresAt.Sub(expectedExpiry) > time.Second {
		t.Errorf("ExpiresAt differs from expected by more than 1 second")
	}
}

// Tests for approval policy integration

func TestRequestCommand_AutoApprove_NoPolicy(t *testing.T) {
	var storedRequest *request.Request
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			storedRequest = req
			return nil
		},
	}

	input := RequestCommandInput{
		ProfileName:   "production",
		Duration:      1 * time.Hour,
		Justification: "Testing request without approval policy",
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
		// No ApprovalPolicy set
	}

	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Request should stay pending without policy
	if storedRequest.Status != request.StatusPending {
		t.Errorf("expected status pending, got %s", storedRequest.Status)
	}
	if output.AutoApproved {
		t.Error("expected AutoApproved to be false without policy")
	}
}

func TestRequestCommand_AutoApprove_MatchingPolicy(t *testing.T) {
	var storedRequest *request.Request
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			storedRequest = req
			return nil
		},
	}

	// Create policy with auto-approve for test user
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-auto-approve",
				Profiles:  []string{"production"},
				Approvers: []string{"admin"},
				AutoApprove: &policy.AutoApproveCondition{
					Users:       []string{"testuser"},
					MaxDuration: 2 * time.Hour,
				},
			},
		},
	}

	input := RequestCommandInput{
		ProfileName:    "production",
		Duration:       1 * time.Hour,
		Justification:  "Testing auto-approve with matching policy",
		Store:          store,
		STSClient:      newMockRequestSTSClient("testuser"),
		ApprovalPolicy: approvalPolicy,
	}

	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Request should be auto-approved
	if storedRequest.Status != request.StatusApproved {
		t.Errorf("expected status approved, got %s", storedRequest.Status)
	}
	if storedRequest.Approver != "testuser" {
		t.Errorf("expected approver testuser, got %s", storedRequest.Approver)
	}
	if storedRequest.ApproverComment != "auto-approved by policy" {
		t.Errorf("unexpected approver comment: %s", storedRequest.ApproverComment)
	}
	if !output.AutoApproved {
		t.Error("expected AutoApproved to be true")
	}
}

func TestRequestCommand_AutoApprove_NonMatchingPolicy(t *testing.T) {
	var storedRequest *request.Request
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			storedRequest = req
			return nil
		},
	}

	// Create policy with auto-approve for different user
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-auto-approve",
				Profiles:  []string{"production"},
				Approvers: []string{"admin"},
				AutoApprove: &policy.AutoApproveCondition{
					Users:       []string{"different-user"},
					MaxDuration: 2 * time.Hour,
				},
			},
		},
	}

	input := RequestCommandInput{
		ProfileName:    "production",
		Duration:       1 * time.Hour,
		Justification:  "Testing auto-approve with non-matching user",
		Store:          store,
		STSClient:      newMockRequestSTSClient("testuser"),
		ApprovalPolicy: approvalPolicy,
	}

	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Request should stay pending
	if storedRequest.Status != request.StatusPending {
		t.Errorf("expected status pending, got %s", storedRequest.Status)
	}
	if output.AutoApproved {
		t.Error("expected AutoApproved to be false for non-matching user")
	}
}

func TestRequestCommand_AutoApprove_DurationExceedsMax(t *testing.T) {
	var storedRequest *request.Request
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			storedRequest = req
			return nil
		},
	}

	// Create policy with max duration of 1 hour
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-auto-approve",
				Profiles:  []string{"production"},
				Approvers: []string{"admin"},
				AutoApprove: &policy.AutoApproveCondition{
					Users:       []string{"testuser"},
					MaxDuration: 1 * time.Hour,
				},
			},
		},
	}

	input := RequestCommandInput{
		ProfileName:    "production",
		Duration:       2 * time.Hour, // Exceeds auto-approve max of 1h
		Justification:  "Testing auto-approve with duration exceeding max",
		Store:          store,
		STSClient:      newMockRequestSTSClient("testuser"),
		ApprovalPolicy: approvalPolicy,
	}

	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Request should stay pending because duration exceeds max
	if storedRequest.Status != request.StatusPending {
		t.Errorf("expected status pending, got %s", storedRequest.Status)
	}
	if output.AutoApproved {
		t.Error("expected AutoApproved to be false when duration exceeds max")
	}
}

func TestRequestCommand_AutoApprove_ProfileNoRule(t *testing.T) {
	var storedRequest *request.Request
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			storedRequest = req
			return nil
		},
	}

	// Create policy for different profile
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "staging-auto-approve",
				Profiles:  []string{"staging"},
				Approvers: []string{"admin"},
				AutoApprove: &policy.AutoApproveCondition{
					Users:       []string{"testuser"},
					MaxDuration: 2 * time.Hour,
				},
			},
		},
	}

	input := RequestCommandInput{
		ProfileName:    "production", // Different from rule profiles
		Duration:       1 * time.Hour,
		Justification:  "Testing request with no matching rule for profile",
		Store:          store,
		STSClient:      newMockRequestSTSClient("testuser"),
		ApprovalPolicy: approvalPolicy,
	}

	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Request should stay pending because no rule matches profile
	if storedRequest.Status != request.StatusPending {
		t.Errorf("expected status pending, got %s", storedRequest.Status)
	}
	if output.AutoApproved {
		t.Error("expected AutoApproved to be false when no rule matches profile")
	}
}

// Tests for approval logging

func TestRequestCommand_Logger_LogsCreatedEvent(t *testing.T) {
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			return nil
		},
	}

	logger := &mockLogger{}

	input := RequestCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		Justification: "Testing request logging functionality",
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
		Logger:        logger,
	}

	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify logger received the created event
	if len(logger.approvalEntries) != 1 {
		t.Fatalf("expected 1 approval log entry, got %d", len(logger.approvalEntries))
	}

	entry := logger.approvalEntries[0]
	if entry.Event != string(notification.EventRequestCreated) {
		t.Errorf("expected event %q, got %q", notification.EventRequestCreated, entry.Event)
	}
	if entry.RequestID != output.Request.ID {
		t.Errorf("expected request ID %q, got %q", output.Request.ID, entry.RequestID)
	}
	if entry.Profile != "test-profile" {
		t.Errorf("expected profile %q, got %q", "test-profile", entry.Profile)
	}
	if entry.Status != string(request.StatusPending) {
		t.Errorf("expected status %q, got %q", request.StatusPending, entry.Status)
	}
	if entry.AutoApproved {
		t.Error("expected AutoApproved to be false for non-auto-approved request")
	}
}

func TestRequestCommand_Logger_AutoApproved_LogsBothEvents(t *testing.T) {
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			return nil
		},
	}

	logger := &mockLogger{}

	// Create policy with auto-approve for test user
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-auto-approve",
				Profiles:  []string{"production"},
				Approvers: []string{"admin"},
				AutoApprove: &policy.AutoApproveCondition{
					Users:       []string{"testuser"},
					MaxDuration: 2 * time.Hour,
				},
			},
		},
	}

	input := RequestCommandInput{
		ProfileName:    "production",
		Duration:       1 * time.Hour,
		Justification:  "Testing auto-approve logging",
		Store:          store,
		STSClient:      newMockRequestSTSClient("testuser"),
		Logger:         logger,
		ApprovalPolicy: approvalPolicy,
	}

	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify request was auto-approved
	if !output.AutoApproved {
		t.Fatal("expected request to be auto-approved")
	}

	// Verify logger received both events
	if len(logger.approvalEntries) != 2 {
		t.Fatalf("expected 2 approval log entries, got %d", len(logger.approvalEntries))
	}

	// First entry should be created event
	createdEntry := logger.approvalEntries[0]
	if createdEntry.Event != string(notification.EventRequestCreated) {
		t.Errorf("expected first event to be %q, got %q", notification.EventRequestCreated, createdEntry.Event)
	}

	// Second entry should be approved event
	approvedEntry := logger.approvalEntries[1]
	if approvedEntry.Event != string(notification.EventRequestApproved) {
		t.Errorf("expected second event to be %q, got %q", notification.EventRequestApproved, approvedEntry.Event)
	}
	if !approvedEntry.AutoApproved {
		t.Error("expected AutoApproved to be true for auto-approved request")
	}
	if approvedEntry.Status != string(request.StatusApproved) {
		t.Errorf("expected status %q, got %q", request.StatusApproved, approvedEntry.Status)
	}
}

func TestRequestCommand_NoLogger_NoPanic(t *testing.T) {
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			return nil
		},
	}

	input := RequestCommandInput{
		ProfileName:   "test-profile",
		Duration:      1 * time.Hour,
		Justification: "Testing request without logger",
		Store:         store,
		STSClient:     newMockRequestSTSClient("testuser"),
		// Logger is nil
	}

	// Should not panic when Logger is nil
	_, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
