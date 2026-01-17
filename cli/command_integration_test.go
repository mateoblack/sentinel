package cli

import (
	"context"
	"errors"
	"os/user"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/testutil"
)

// ============================================================================
// Approval Workflow Command Integration Tests
// ============================================================================
//
// These tests verify the integration between CLI commands and their dependencies
// (stores, notifiers, policies) using mock infrastructure from testutil.

// ============================================================================
// RequestCommand Integration Tests
// ============================================================================

func TestCommandIntegration_Approval_RequestCreatesAndStores(t *testing.T) {
	// Test that RequestCommand creates a request with correct fields and stores it

	store := testutil.NewMockRequestStore()

	input := RequestCommandInput{
		ProfileName:   "production",
		Duration:      2 * time.Hour,
		Justification: "Integration test: need production access for deployment",
		Store:         store,
	}

	// Use testable version with profile validator
	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify request was stored
	if len(store.CreateCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(store.CreateCalls))
	}

	// Verify stored request fields
	storedReq := store.CreateCalls[0]
	if storedReq.Profile != "production" {
		t.Errorf("expected profile 'production', got '%s'", storedReq.Profile)
	}
	if storedReq.Duration != 2*time.Hour {
		t.Errorf("expected duration 2h, got %v", storedReq.Duration)
	}
	if storedReq.Status != request.StatusPending {
		t.Errorf("expected status pending, got %s", storedReq.Status)
	}

	// Verify output contains request info
	if output.Request.ID != storedReq.ID {
		t.Errorf("output request ID mismatch")
	}
}

func TestCommandIntegration_Approval_RequestAutoApprove(t *testing.T) {
	// Test that RequestCommand auto-approves when ApprovalPolicy matches

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user")
	}

	store := testutil.NewMockRequestStore()

	// Create policy with auto-approve for current user
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "staging-auto-approve",
				Profiles:  []string{"staging"},
				Approvers: []string{"admin"},
				AutoApprove: &policy.AutoApproveCondition{
					Users:       []string{currentUser.Username},
					MaxDuration: 4 * time.Hour,
				},
			},
		},
	}

	input := RequestCommandInput{
		ProfileName:    "staging",
		Duration:       1 * time.Hour,
		Justification:  "Integration test: auto-approve testing",
		Store:          store,
		ApprovalPolicy: approvalPolicy,
	}

	output, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify request was auto-approved
	if !output.AutoApproved {
		t.Error("expected request to be auto-approved")
	}

	storedReq := store.CreateCalls[0]
	if storedReq.Status != request.StatusApproved {
		t.Errorf("expected status approved, got %s", storedReq.Status)
	}
	if storedReq.Approver != currentUser.Username {
		t.Errorf("expected approver %s, got %s", currentUser.Username, storedReq.Approver)
	}
}

func TestCommandIntegration_Approval_RequestWithNotifier(t *testing.T) {
	// Test that RequestCommand wraps store with NotifyStore when Notifier is provided

	store := testutil.NewMockRequestStore()
	notifier := testutil.NewMockNotifier()

	input := RequestCommandInput{
		ProfileName:   "production",
		Duration:      1 * time.Hour,
		Justification: "Integration test: notification testing",
		Store:         store,
		Notifier:      notifier,
	}

	_, err := testableRequestCommand(context.Background(), input, func(string) error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify request was stored
	if len(store.CreateCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(store.CreateCalls))
	}

	// Note: NotifyStore is used internally, so notification would be sent through it
	// The mock store still tracks the Create call
}

// ============================================================================
// CheckCommand Integration Tests
// ============================================================================

func TestCommandIntegration_Approval_CheckRetrievesRequest(t *testing.T) {
	// Test that CheckCommand retrieves request by ID

	store := testutil.NewMockRequestStore()

	// Create a request in the mock store
	existingReq := &request.Request{
		ID:            "abcd1234abcd1234",
		Requester:     "testuser",
		Profile:       "production",
		Justification: "Test request for check command",
		Duration:      2 * time.Hour,
		Status:        request.StatusApproved,
		CreatedAt:     time.Now().Add(-1 * time.Hour),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(23 * time.Hour),
		Approver:      "admin",
	}
	store.Requests[existingReq.ID] = existingReq

	input := CheckCommandInput{
		RequestID: existingReq.ID,
		Store:     store,
	}

	err := CheckCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Get was called with correct ID
	if len(store.GetCalls) != 1 {
		t.Fatalf("expected 1 Get call, got %d", len(store.GetCalls))
	}
	if store.GetCalls[0] != existingReq.ID {
		t.Errorf("expected Get call with ID %s, got %s", existingReq.ID, store.GetCalls[0])
	}
}

func TestCommandIntegration_Approval_CheckNonExistent(t *testing.T) {
	// Test CheckCommand with non-existent request ID

	store := testutil.NewMockRequestStore()

	input := CheckCommandInput{
		RequestID: "aaaaaaaaaaaaaaaa", // Valid format but doesn't exist
		Store:     store,
	}

	err := CheckCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for non-existent request")
	}

	if !errors.Is(err, request.ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got %v", err)
	}
}

// ============================================================================
// ApproveCommand Integration Tests
// ============================================================================

func TestCommandIntegration_Approval_ApproveUpdatesStatus(t *testing.T) {
	// Test that ApproveCommand updates request status to approved

	store := testutil.NewMockRequestStore()

	// Create a pending request (ID must be 16 lowercase hex characters)
	pendingReq := &request.Request{
		ID:            "aaaa1234bbbb5678",
		Requester:     "requester",
		Profile:       "staging",
		Justification: "Need staging access",
		Duration:      1 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	store.Requests[pendingReq.ID] = pendingReq

	input := ApproveCommandInput{
		RequestID: pendingReq.ID,
		Comment:   "Approved for staging deployment",
		Store:     store,
	}

	err := ApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Get was called
	if len(store.GetCalls) != 1 {
		t.Fatalf("expected 1 Get call, got %d", len(store.GetCalls))
	}

	// Verify Update was called
	if len(store.UpdateCalls) != 1 {
		t.Fatalf("expected 1 Update call, got %d", len(store.UpdateCalls))
	}

	// Verify updated request has correct status
	updatedReq := store.UpdateCalls[0]
	if updatedReq.Status != request.StatusApproved {
		t.Errorf("expected status approved, got %s", updatedReq.Status)
	}
	if updatedReq.ApproverComment != "Approved for staging deployment" {
		t.Errorf("expected comment 'Approved for staging deployment', got '%s'", updatedReq.ApproverComment)
	}
}

func TestCommandIntegration_Approval_ApproveWithPolicy(t *testing.T) {
	// Test that ApproveCommand checks CanApprove from ApprovalPolicy

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user")
	}

	store := testutil.NewMockRequestStore()

	// Create a pending request (ID must be 16 lowercase hex characters)
	pendingReq := &request.Request{
		ID:            "bbbb5678cccc9012",
		Requester:     "requester",
		Profile:       "production",
		Justification: "Need production access",
		Duration:      1 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	store.Requests[pendingReq.ID] = pendingReq

	// Create policy where current user is an approver
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-approvers",
				Profiles:  []string{"production"},
				Approvers: []string{currentUser.Username}, // Current user can approve
			},
		},
	}

	input := ApproveCommandInput{
		RequestID:      pendingReq.ID,
		Store:          store,
		ApprovalPolicy: approvalPolicy,
	}

	err = ApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify approval succeeded
	if len(store.UpdateCalls) != 1 {
		t.Fatalf("expected 1 Update call, got %d", len(store.UpdateCalls))
	}
	if store.UpdateCalls[0].Status != request.StatusApproved {
		t.Errorf("expected status approved, got %s", store.UpdateCalls[0].Status)
	}
}

func TestCommandIntegration_Approval_ApproveUnauthorized(t *testing.T) {
	// Test that ApproveCommand rejects unauthorized approvers

	store := testutil.NewMockRequestStore()

	// Create a pending request (ID must be 16 lowercase hex characters)
	pendingReq := &request.Request{
		ID:            "cccc9012dddd3456",
		Requester:     "requester",
		Profile:       "production",
		Justification: "Need production access",
		Duration:      1 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	store.Requests[pendingReq.ID] = pendingReq

	// Create policy where only "special-admin" can approve
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-approvers",
				Profiles:  []string{"production"},
				Approvers: []string{"special-admin"}, // Only special-admin can approve
			},
		},
	}

	input := ApproveCommandInput{
		RequestID:      pendingReq.ID,
		Store:          store,
		ApprovalPolicy: approvalPolicy,
	}

	err := ApproveCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for unauthorized approver")
	}

	// Verify Update was NOT called
	if len(store.UpdateCalls) != 0 {
		t.Errorf("expected 0 Update calls for unauthorized, got %d", len(store.UpdateCalls))
	}
}

// ============================================================================
// DenyCommand Integration Tests
// ============================================================================

func TestCommandIntegration_Approval_DenyUpdatesStatus(t *testing.T) {
	// Test that DenyCommand updates request status to denied

	store := testutil.NewMockRequestStore()

	// Create a pending request (ID must be 16 lowercase hex characters)
	pendingReq := &request.Request{
		ID:            "dddd3456eeee7890",
		Requester:     "requester",
		Profile:       "production",
		Justification: "Need production access",
		Duration:      1 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	store.Requests[pendingReq.ID] = pendingReq

	input := DenyCommandInput{
		RequestID: pendingReq.ID,
		Comment:   "Access denied: insufficient justification",
		Store:     store,
	}

	err := DenyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Get was called
	if len(store.GetCalls) != 1 {
		t.Fatalf("expected 1 Get call, got %d", len(store.GetCalls))
	}

	// Verify Update was called
	if len(store.UpdateCalls) != 1 {
		t.Fatalf("expected 1 Update call, got %d", len(store.UpdateCalls))
	}

	// Verify updated request has correct status
	updatedReq := store.UpdateCalls[0]
	if updatedReq.Status != request.StatusDenied {
		t.Errorf("expected status denied, got %s", updatedReq.Status)
	}
	if updatedReq.ApproverComment != "Access denied: insufficient justification" {
		t.Errorf("unexpected comment: %s", updatedReq.ApproverComment)
	}
}

func TestCommandIntegration_Approval_DenyRecordsApprover(t *testing.T) {
	// Test that DenyCommand records the denier identity

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("cannot get current user")
	}

	store := testutil.NewMockRequestStore()

	// Create a pending request (ID must be 16 lowercase hex characters)
	pendingReq := &request.Request{
		ID:            "eeee7890ffff1234",
		Requester:     "requester",
		Profile:       "staging",
		Justification: "Need staging access",
		Duration:      1 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	store.Requests[pendingReq.ID] = pendingReq

	input := DenyCommandInput{
		RequestID: pendingReq.ID,
		Comment:   "Denied",
		Store:     store,
	}

	err = DenyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify approver is recorded
	updatedReq := store.UpdateCalls[0]
	if updatedReq.Approver != currentUser.Username {
		t.Errorf("expected approver %s, got %s", currentUser.Username, updatedReq.Approver)
	}
}

// ============================================================================
// ListByProfile Integration Tests (indirect through store)
// ============================================================================

func TestCommandIntegration_Approval_ListByProfileFilters(t *testing.T) {
	// Test that store ListByProfile is called with correct parameters

	store := testutil.NewMockRequestStore()

	// Configure store to return specific requests
	store.ListByProfileFunc = func(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
		if profile == "production" {
			return []*request.Request{
				{
					ID:        "req1-production",
					Profile:   "production",
					Status:    request.StatusPending,
					Requester: "user1",
				},
				{
					ID:        "req2-production",
					Profile:   "production",
					Status:    request.StatusApproved,
					Requester: "user2",
				},
			}, nil
		}
		return nil, nil
	}

	// Query the store directly (simulating what a list command would do)
	results, err := store.ListByProfile(context.Background(), "production", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Verify call tracking
	if len(store.ListByProfileCalls) != 1 {
		t.Fatalf("expected 1 ListByProfile call, got %d", len(store.ListByProfileCalls))
	}
	if store.ListByProfileCalls[0].Profile != "production" {
		t.Errorf("expected profile 'production', got '%s'", store.ListByProfileCalls[0].Profile)
	}
}

func TestCommandIntegration_Approval_ListEmptyResults(t *testing.T) {
	// Test that empty results are handled correctly

	store := testutil.NewMockRequestStore()

	// Configure store to return empty results
	store.ListByProfileFunc = func(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
		return []*request.Request{}, nil
	}

	results, err := store.ListByProfile(context.Background(), "nonexistent", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// ============================================================================
// Logger Integration Tests
// ============================================================================

func TestCommandIntegration_Approval_ApproveLogsEvent(t *testing.T) {
	// Test that ApproveCommand logs approval event

	store := testutil.NewMockRequestStore()
	logger := testutil.NewMockLogger()

	// Create a pending request (ID must be 16 lowercase hex characters)
	pendingReq := &request.Request{
		ID:            "ffff1111aaaa2222",
		Requester:     "requester",
		Profile:       "staging",
		Justification: "Need staging access",
		Duration:      1 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	store.Requests[pendingReq.ID] = pendingReq

	input := ApproveCommandInput{
		RequestID: pendingReq.ID,
		Comment:   "Approved",
		Store:     store,
		Logger:    logger,
	}

	err := ApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify approval was logged
	if logger.ApprovalCount() != 1 {
		t.Fatalf("expected 1 approval log entry, got %d", logger.ApprovalCount())
	}

	entry := logger.LastApproval()
	if entry.Event != string(notification.EventRequestApproved) {
		t.Errorf("expected event %s, got %s", notification.EventRequestApproved, entry.Event)
	}
	if entry.RequestID != pendingReq.ID {
		t.Errorf("expected request ID %s, got %s", pendingReq.ID, entry.RequestID)
	}
}

func TestCommandIntegration_Approval_DenyLogsEvent(t *testing.T) {
	// Test that DenyCommand logs denial event

	store := testutil.NewMockRequestStore()
	logger := testutil.NewMockLogger()

	// Create a pending request (ID must be 16 lowercase hex characters)
	pendingReq := &request.Request{
		ID:            "aaaa2222bbbb3333",
		Requester:     "requester",
		Profile:       "production",
		Justification: "Need production access",
		Duration:      1 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	store.Requests[pendingReq.ID] = pendingReq

	input := DenyCommandInput{
		RequestID: pendingReq.ID,
		Comment:   "Denied",
		Store:     store,
		Logger:    logger,
	}

	err := DenyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify denial was logged
	if logger.ApprovalCount() != 1 {
		t.Fatalf("expected 1 approval log entry, got %d", logger.ApprovalCount())
	}

	entry := logger.LastApproval()
	if entry.Event != string(notification.EventRequestDenied) {
		t.Errorf("expected event %s, got %s", notification.EventRequestDenied, entry.Event)
	}
}
