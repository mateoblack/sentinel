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

// mockApproveSTSClient implements identity.STSAPI for testing approve command.
type mockApproveSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockApproveSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetCallerIdentityFunc not set")
}

// newMockApproveSTSClient creates a mock STS client that returns the specified username.
func newMockApproveSTSClient(username string) *mockApproveSTSClient {
	return &mockApproveSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:user/" + username),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}
}

// testableApproveCommand is a testable version that allows mock store and STS client injection.
func testableApproveCommand(ctx context.Context, input ApproveCommandInput) (*ApproveCommandOutput, error) {
	// 1. Validate request ID format
	if !request.ValidateRequestID(input.RequestID) {
		return nil, errors.New("invalid request ID format")
	}

	// 2. Get AWS identity for approver (must be provided via STSClient for testing)
	if input.STSClient == nil {
		return nil, errors.New("STSClient is required for testing")
	}
	identity, err := input.STSClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	// Extract username from ARN - simple extraction for testing
	arn := aws.ToString(identity.Arn)
	approver := extractUsernameFromARN(arn)

	// 3. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 4. Fetch request from store
	req, err := store.Get(ctx, input.RequestID)
	if err != nil {
		return nil, err
	}

	// 5. Check approver authorization if policy is provided
	if input.ApprovalPolicy != nil {
		rule := policy.FindApprovalRule(input.ApprovalPolicy, req.Profile)
		if rule != nil {
			if !policy.CanApprove(rule, approver) {
				return nil, errors.New("user " + approver + " is not authorized to approve requests for profile " + req.Profile)
			}
		}
		// If no rule found, allow (passthrough - no approval routing for this profile)
	}

	// 6. Check if transition is valid
	if !req.CanTransitionTo(request.StatusApproved) {
		return nil, errors.New("invalid state transition")
	}

	// 7. Update request fields
	req.Status = request.StatusApproved
	req.Approver = approver
	req.ApproverComment = input.Comment
	// Note: UpdatedAt is set internally by store.Update() for optimistic locking

	// 8. Store updated request
	if err := store.Update(ctx, req); err != nil {
		return nil, err
	}

	// 9. Log approval event if Logger is provided
	if input.Logger != nil {
		entry := logging.NewApprovalLogEntry(notification.EventRequestApproved, req, approver)
		input.Logger.LogApproval(entry)
	}

	// 10. Return output
	return &ApproveCommandOutput{
		ID:              req.ID,
		Profile:         req.Profile,
		Status:          string(req.Status),
		Approver:        req.Approver,
		ApproverComment: req.ApproverComment,
		UpdatedAt:       req.UpdatedAt,
	}, nil
}

// extractUsernameFromARN extracts the username from an IAM user ARN.
// This is a simplified version for tests - the real implementation uses identity.ParseARN.
func extractUsernameFromARN(arn string) string {
	// Format: arn:aws:iam::123456789012:user/username or assumed-role/role/session
	parts := strings.Split(arn, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}

func TestApproveCommand_Success(t *testing.T) {
	now := time.Now()
	pendingReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour),
	}

	var updatedReq *request.Request
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
		updateFn: func(ctx context.Context, req *request.Request) error {
			updatedReq = req
			return nil
		},
	}

	input := ApproveCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockApproveSTSClient("bob"),
	}

	output, err := testableApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output fields
	if output.ID != "abc123def4567890" {
		t.Errorf("expected ID 'abc123def4567890', got %q", output.ID)
	}
	if output.Profile != "production" {
		t.Errorf("expected Profile 'production', got %q", output.Profile)
	}
	if output.Status != "approved" {
		t.Errorf("expected Status 'approved', got %q", output.Status)
	}

	// Verify approver was set to AWS username
	if output.Approver != "bob" {
		t.Errorf("expected Approver 'bob', got %q", output.Approver)
	}

	// Verify request was updated
	if updatedReq == nil {
		t.Fatal("expected request to be updated")
	}
	if updatedReq.Status != request.StatusApproved {
		t.Errorf("expected status to be approved, got %s", updatedReq.Status)
	}
}

func TestApproveCommand_WithComment(t *testing.T) {
	now := time.Now()
	pendingReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour),
	}

	var updatedReq *request.Request
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
		updateFn: func(ctx context.Context, req *request.Request) error {
			updatedReq = req
			return nil
		},
	}

	input := ApproveCommandInput{
		RequestID: "abc123def4567890",
		Comment:   "Approved for maintenance window only",
		Store:     store,
		STSClient: newMockApproveSTSClient("bob"),
	}

	output, err := testableApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify comment in output
	if output.ApproverComment != "Approved for maintenance window only" {
		t.Errorf("expected ApproverComment 'Approved for maintenance window only', got %q", output.ApproverComment)
	}

	// Verify comment was stored
	if updatedReq == nil {
		t.Fatal("expected request to be updated")
	}
	if updatedReq.ApproverComment != "Approved for maintenance window only" {
		t.Errorf("expected ApproverComment 'Approved for maintenance window only', got %q", updatedReq.ApproverComment)
	}
}

func TestApproveCommand_NotFound(t *testing.T) {
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return nil, request.ErrRequestNotFound
		},
	}

	input := ApproveCommandInput{
		RequestID: "1234567890abcdef",
		Store:     store,
		STSClient: newMockApproveSTSClient("bob"),
	}

	_, err := testableApproveCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for request not found")
	}

	if !errors.Is(err, request.ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got: %v", err)
	}
}

func TestApproveCommand_InvalidID(t *testing.T) {
	store := &mockStore{}

	testCases := []struct {
		name      string
		requestID string
	}{
		{"too short", "abc123"},
		{"too long", "abc123def4567890extra"},
		{"uppercase", "ABC123DEF4567890"},
		{"invalid chars", "xyz123def456789!"},
		{"empty", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := ApproveCommandInput{
				RequestID: tc.requestID,
				Store:     store,
				STSClient: newMockApproveSTSClient("bob"),
			}

			_, err := testableApproveCommand(context.Background(), input)
			if err == nil {
				t.Fatal("expected error for invalid request ID")
			}

			if err.Error() != "invalid request ID format" {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestApproveCommand_AlreadyApproved(t *testing.T) {
	now := time.Now()
	approvedReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusApproved, // Already approved
		CreatedAt:     now.Add(-2 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(22 * time.Hour),
		Approver:      "bob",
	}

	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return approvedReq, nil
		},
	}

	input := ApproveCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockApproveSTSClient("charlie"),
	}

	_, err := testableApproveCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for already approved request")
	}

	if err.Error() != "invalid state transition" {
		t.Errorf("expected 'invalid state transition' error, got: %v", err)
	}
}

func TestApproveCommand_AlreadyDenied(t *testing.T) {
	now := time.Now()
	deniedReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusDenied, // Already denied
		CreatedAt:     now.Add(-2 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(22 * time.Hour),
		Approver:      "bob",
	}

	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return deniedReq, nil
		},
	}

	input := ApproveCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockApproveSTSClient("charlie"),
	}

	_, err := testableApproveCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for already denied request")
	}

	if err.Error() != "invalid state transition" {
		t.Errorf("expected 'invalid state transition' error, got: %v", err)
	}
}

func TestApproveCommand_StoreError(t *testing.T) {
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return nil, errors.New("network error: connection timeout")
		},
	}

	input := ApproveCommandInput{
		RequestID: "1234567890abcdef",
		Store:     store,
		STSClient: newMockApproveSTSClient("bob"),
	}

	_, err := testableApproveCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when store fails")
	}

	if err.Error() != "network error: connection timeout" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestApproveCommand_ConcurrentModification(t *testing.T) {
	now := time.Now()
	pendingReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour),
	}

	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
		updateFn: func(ctx context.Context, req *request.Request) error {
			return request.ErrConcurrentModification
		},
	}

	input := ApproveCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockApproveSTSClient("bob"),
	}

	_, err := testableApproveCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for concurrent modification")
	}

	if !errors.Is(err, request.ErrConcurrentModification) {
		t.Errorf("expected ErrConcurrentModification, got: %v", err)
	}
}

// Tests for approval policy authorization

func TestApproveCommand_NoPolicy_AllowsAnyApprover(t *testing.T) {
	now := time.Now()
	pendingReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour),
	}

	var updatedReq *request.Request
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
		updateFn: func(ctx context.Context, req *request.Request) error {
			updatedReq = req
			return nil
		},
	}

	input := ApproveCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockApproveSTSClient("bob"),
		// No ApprovalPolicy set
	}

	output, err := testableApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should succeed without policy
	if output.Status != "approved" {
		t.Errorf("expected status approved, got %s", output.Status)
	}
	if updatedReq == nil {
		t.Fatal("expected request to be updated")
	}
}

func TestApproveCommand_Policy_AuthorizedApprover(t *testing.T) {
	now := time.Now()
	pendingReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour),
	}

	var updatedReq *request.Request
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
		updateFn: func(ctx context.Context, req *request.Request) error {
			updatedReq = req
			return nil
		},
	}

	// Create policy where "admin-user" is an authorized approver
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-approvers",
				Profiles:  []string{"production"},
				Approvers: []string{"admin-user", "other-admin"},
			},
		},
	}

	input := ApproveCommandInput{
		RequestID:      "abc123def4567890",
		Store:          store,
		ApprovalPolicy: approvalPolicy,
		STSClient:      newMockApproveSTSClient("admin-user"),
	}

	output, err := testableApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should succeed for authorized approver
	if output.Status != "approved" {
		t.Errorf("expected status approved, got %s", output.Status)
	}
	if updatedReq == nil {
		t.Fatal("expected request to be updated")
	}
}

func TestApproveCommand_Policy_UnauthorizedApprover(t *testing.T) {
	now := time.Now()
	pendingReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour),
	}

	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
	}

	// Create policy where "unauthorized-user" is NOT an authorized approver
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-approvers",
				Profiles:  []string{"production"},
				Approvers: []string{"admin1", "admin2"}, // unauthorized-user not included
			},
		},
	}

	input := ApproveCommandInput{
		RequestID:      "abc123def4567890",
		Store:          store,
		ApprovalPolicy: approvalPolicy,
		STSClient:      newMockApproveSTSClient("unauthorized-user"),
	}

	_, err := testableApproveCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for unauthorized approver")
	}

	// Check error message contains both user and profile
	if !strings.Contains(err.Error(), "is not authorized to approve") {
		t.Errorf("expected authorization error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "production") {
		t.Errorf("expected error to mention profile, got: %v", err)
	}
}

func TestApproveCommand_Policy_NoRuleMatchesProfile(t *testing.T) {
	now := time.Now()
	pendingReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "development", // Different from rule profiles
		Justification: "Investigating issue",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour),
	}

	var updatedReq *request.Request
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
		updateFn: func(ctx context.Context, req *request.Request) error {
			updatedReq = req
			return nil
		},
	}

	// Create policy with rules only for production
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-approvers",
				Profiles:  []string{"production"},
				Approvers: []string{"admin1"},
			},
		},
	}

	input := ApproveCommandInput{
		RequestID:      "abc123def4567890",
		Store:          store,
		ApprovalPolicy: approvalPolicy,
		STSClient:      newMockApproveSTSClient("bob"),
	}

	output, err := testableApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should succeed when no rule matches (passthrough)
	if output.Status != "approved" {
		t.Errorf("expected status approved, got %s", output.Status)
	}
	if updatedReq == nil {
		t.Fatal("expected request to be updated")
	}
}

// Tests for approval logging

func TestApproveCommand_Logger_LogsApprovedEvent(t *testing.T) {
	now := time.Now()
	pendingReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour),
	}

	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
		updateFn: func(ctx context.Context, req *request.Request) error {
			return nil
		},
	}

	logger := &mockLogger{}

	input := ApproveCommandInput{
		RequestID: "abc123def4567890",
		Comment:   "Approved for maintenance window",
		Store:     store,
		Logger:    logger,
		STSClient: newMockApproveSTSClient("approver-user"),
	}

	output, err := testableApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output
	if output.Status != "approved" {
		t.Errorf("expected status approved, got %s", output.Status)
	}

	// Verify logger received the approved event
	if len(logger.approvalEntries) != 1 {
		t.Fatalf("expected 1 approval log entry, got %d", len(logger.approvalEntries))
	}

	entry := logger.approvalEntries[0]
	if entry.Event != string(notification.EventRequestApproved) {
		t.Errorf("expected event %q, got %q", notification.EventRequestApproved, entry.Event)
	}
	if entry.RequestID != "abc123def4567890" {
		t.Errorf("expected request ID %q, got %q", "abc123def4567890", entry.RequestID)
	}
	if entry.Profile != "production" {
		t.Errorf("expected profile %q, got %q", "production", entry.Profile)
	}
	if entry.Status != string(request.StatusApproved) {
		t.Errorf("expected status %q, got %q", request.StatusApproved, entry.Status)
	}
	if entry.Actor != "approver-user" {
		t.Errorf("expected actor %q, got %q", "approver-user", entry.Actor)
	}
	if entry.Approver != "approver-user" {
		t.Errorf("expected approver %q, got %q", "approver-user", entry.Approver)
	}
	if entry.ApproverComment != "Approved for maintenance window" {
		t.Errorf("expected comment %q, got %q", "Approved for maintenance window", entry.ApproverComment)
	}
}

func TestApproveCommand_NoLogger_NoPanic(t *testing.T) {
	now := time.Now()
	pendingReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour),
	}

	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
		updateFn: func(ctx context.Context, req *request.Request) error {
			return nil
		},
	}

	input := ApproveCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockApproveSTSClient("bob"),
		// Logger is nil
	}

	// Should not panic when Logger is nil
	_, err := testableApproveCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
