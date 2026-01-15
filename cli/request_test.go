package cli

import (
	"context"
	"errors"
	"os/user"
	"testing"
	"time"

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

// testableRequestCommandOutput contains test output with auto-approval status.
type testableRequestCommandOutput struct {
	Request      *request.Request
	AutoApproved bool
}

// testableRequestCommand is a testable version that accepts a profile validator.
func testableRequestCommand(ctx context.Context, input RequestCommandInput, validateProfile func(string) error) (*testableRequestCommandOutput, error) {
	// 1. Get current user
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}
	username := currentUser.Username

	// 2. Validate profile exists in AWS config
	if err := validateProfile(input.ProfileName); err != nil {
		return nil, err
	}

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

	return &testableRequestCommandOutput{
		Request:      req,
		AutoApproved: autoApproved,
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

	// Requester should be current user
	currentUser, _ := user.Current()
	if storedRequest.Requester != currentUser.Username {
		t.Errorf("expected requester '%s', got '%s'", currentUser.Username, storedRequest.Requester)
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
	currentUser, _ := user.Current()
	var storedRequest *request.Request
	store := &mockStore{
		createFn: func(ctx context.Context, req *request.Request) error {
			storedRequest = req
			return nil
		},
	}

	// Create policy with auto-approve for current user
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-auto-approve",
				Profiles:  []string{"production"},
				Approvers: []string{"admin"},
				AutoApprove: &policy.AutoApproveCondition{
					Users:       []string{currentUser.Username},
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
	if storedRequest.Approver != currentUser.Username {
		t.Errorf("expected approver %s, got %s", currentUser.Username, storedRequest.Approver)
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
	currentUser, _ := user.Current()
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
					Users:       []string{currentUser.Username},
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
	currentUser, _ := user.Current()
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
					Users:       []string{currentUser.Username},
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
