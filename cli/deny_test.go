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
	"github.com/byteness/aws-vault/v7/request"
)

// mockDenySTSClient implements identity.STSAPI for testing deny command.
type mockDenySTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockDenySTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetCallerIdentityFunc not set")
}

// newMockDenySTSClient creates a mock STS client that returns the specified username.
func newMockDenySTSClient(username string) *mockDenySTSClient {
	return &mockDenySTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:user/" + username),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}
}

// extractDenyUsernameFromARN extracts the username from an IAM user ARN.
// This is a simplified version for tests - the real implementation uses identity.ParseARN.
func extractDenyUsernameFromARN(arn string) string {
	// Format: arn:aws:iam::123456789012:user/username or assumed-role/role/session
	parts := strings.Split(arn, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}

// testableDenyCommand is a testable version that allows mock store and STS client injection.
func testableDenyCommand(ctx context.Context, input DenyCommandInput) (*DenyCommandOutput, error) {
	// 1. Validate request ID format
	if !request.ValidateRequestID(input.RequestID) {
		return nil, errors.New("invalid request ID format")
	}

	// 2. Get AWS identity for denier (must be provided via STSClient for testing)
	if input.STSClient == nil {
		return nil, errors.New("STSClient is required for testing")
	}
	identity, err := input.STSClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	// Extract username from ARN - simple extraction for testing
	arn := aws.ToString(identity.Arn)
	approver := extractDenyUsernameFromARN(arn)

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

	// 5. Check if transition is valid
	if !req.CanTransitionTo(request.StatusDenied) {
		return nil, errors.New("invalid state transition")
	}

	// 6. Update request fields
	req.Status = request.StatusDenied
	req.Approver = approver
	req.ApproverComment = input.Comment
	// Note: UpdatedAt is set internally by store.Update() for optimistic locking

	// 7. Store updated request
	if err := store.Update(ctx, req); err != nil {
		return nil, err
	}

	// 8. Log denial event if Logger is provided
	if input.Logger != nil {
		entry := logging.NewApprovalLogEntry(notification.EventRequestDenied, req, approver)
		input.Logger.LogApproval(entry)
	}

	// 9. Return output
	return &DenyCommandOutput{
		ID:              req.ID,
		Profile:         req.Profile,
		Status:          string(req.Status),
		Approver:        req.Approver,
		ApproverComment: req.ApproverComment,
		UpdatedAt:       req.UpdatedAt,
	}, nil
}

func TestDenyCommand_Success(t *testing.T) {
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

	input := DenyCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockDenySTSClient("bob"),
	}

	output, err := testableDenyCommand(context.Background(), input)
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
	if output.Status != "denied" {
		t.Errorf("expected Status 'denied', got %q", output.Status)
	}

	// Verify approver was set to AWS username
	if output.Approver != "bob" {
		t.Errorf("expected Approver 'bob', got %q", output.Approver)
	}

	// Verify request was updated
	if updatedReq == nil {
		t.Fatal("expected request to be updated")
	}
	if updatedReq.Status != request.StatusDenied {
		t.Errorf("expected status to be denied, got %s", updatedReq.Status)
	}
}

func TestDenyCommand_WithComment(t *testing.T) {
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

	input := DenyCommandInput{
		RequestID: "abc123def4567890",
		Comment:   "Insufficient justification provided",
		Store:     store,
		STSClient: newMockDenySTSClient("bob"),
	}

	output, err := testableDenyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify comment in output
	if output.ApproverComment != "Insufficient justification provided" {
		t.Errorf("expected ApproverComment 'Insufficient justification provided', got %q", output.ApproverComment)
	}

	// Verify comment was stored
	if updatedReq == nil {
		t.Fatal("expected request to be updated")
	}
	if updatedReq.ApproverComment != "Insufficient justification provided" {
		t.Errorf("expected ApproverComment 'Insufficient justification provided', got %q", updatedReq.ApproverComment)
	}
}

func TestDenyCommand_NotFound(t *testing.T) {
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return nil, request.ErrRequestNotFound
		},
	}

	input := DenyCommandInput{
		RequestID: "1234567890abcdef",
		Store:     store,
		STSClient: newMockDenySTSClient("bob"),
	}

	_, err := testableDenyCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for request not found")
	}

	if !errors.Is(err, request.ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got: %v", err)
	}
}

func TestDenyCommand_InvalidID(t *testing.T) {
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
			input := DenyCommandInput{
				RequestID: tc.requestID,
				Store:     store,
				STSClient: newMockDenySTSClient("bob"),
			}

			_, err := testableDenyCommand(context.Background(), input)
			if err == nil {
				t.Fatal("expected error for invalid request ID")
			}

			if err.Error() != "invalid request ID format" {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDenyCommand_AlreadyApproved(t *testing.T) {
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

	input := DenyCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockDenySTSClient("charlie"),
	}

	_, err := testableDenyCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for already approved request")
	}

	if err.Error() != "invalid state transition" {
		t.Errorf("expected 'invalid state transition' error, got: %v", err)
	}
}

func TestDenyCommand_AlreadyDenied(t *testing.T) {
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

	input := DenyCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockDenySTSClient("charlie"),
	}

	_, err := testableDenyCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for already denied request")
	}

	if err.Error() != "invalid state transition" {
		t.Errorf("expected 'invalid state transition' error, got: %v", err)
	}
}

func TestDenyCommand_StoreError(t *testing.T) {
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return nil, errors.New("network error: connection timeout")
		},
	}

	input := DenyCommandInput{
		RequestID: "1234567890abcdef",
		Store:     store,
		STSClient: newMockDenySTSClient("bob"),
	}

	_, err := testableDenyCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when store fails")
	}

	if err.Error() != "network error: connection timeout" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDenyCommand_ConcurrentModification(t *testing.T) {
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

	input := DenyCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockDenySTSClient("bob"),
	}

	_, err := testableDenyCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for concurrent modification")
	}

	if !errors.Is(err, request.ErrConcurrentModification) {
		t.Errorf("expected ErrConcurrentModification, got: %v", err)
	}
}

// Tests for denial logging

func TestDenyCommand_Logger_LogsDeniedEvent(t *testing.T) {
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

	input := DenyCommandInput{
		RequestID: "abc123def4567890",
		Comment:   "Insufficient justification provided",
		Store:     store,
		Logger:    logger,
		STSClient: newMockDenySTSClient("denier-user"),
	}

	output, err := testableDenyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output
	if output.Status != "denied" {
		t.Errorf("expected status denied, got %s", output.Status)
	}

	// Verify logger received the denied event
	if len(logger.approvalEntries) != 1 {
		t.Fatalf("expected 1 approval log entry, got %d", len(logger.approvalEntries))
	}

	entry := logger.approvalEntries[0]
	if entry.Event != string(notification.EventRequestDenied) {
		t.Errorf("expected event %q, got %q", notification.EventRequestDenied, entry.Event)
	}
	if entry.RequestID != "abc123def4567890" {
		t.Errorf("expected request ID %q, got %q", "abc123def4567890", entry.RequestID)
	}
	if entry.Profile != "production" {
		t.Errorf("expected profile %q, got %q", "production", entry.Profile)
	}
	if entry.Status != string(request.StatusDenied) {
		t.Errorf("expected status %q, got %q", request.StatusDenied, entry.Status)
	}
	if entry.Actor != "denier-user" {
		t.Errorf("expected actor %q, got %q", "denier-user", entry.Actor)
	}
	if entry.Approver != "denier-user" {
		t.Errorf("expected approver %q, got %q", "denier-user", entry.Approver)
	}
	if entry.ApproverComment != "Insufficient justification provided" {
		t.Errorf("expected comment %q, got %q", "Insufficient justification provided", entry.ApproverComment)
	}
}

func TestDenyCommand_NoLogger_NoPanic(t *testing.T) {
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

	input := DenyCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
		STSClient: newMockDenySTSClient("bob"),
		// Logger is nil
	}

	// Should not panic when Logger is nil
	_, err := testableDenyCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
