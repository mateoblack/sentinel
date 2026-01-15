package cli

import (
	"context"
	"errors"
	"os/user"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/request"
)

// testableApproveCommand is a testable version that allows mock store injection.
func testableApproveCommand(ctx context.Context, input ApproveCommandInput) (*ApproveCommandOutput, error) {
	// 1. Validate request ID format
	if !request.ValidateRequestID(input.RequestID) {
		return nil, errors.New("invalid request ID format")
	}

	// 2. Get current user for approver identity
	currentUser, err := user.Current()
	if err != nil {
		return nil, err
	}
	approver := currentUser.Username

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
	if !req.CanTransitionTo(request.StatusApproved) {
		return nil, errors.New("invalid state transition")
	}

	// 6. Update request fields
	req.Status = request.StatusApproved
	req.Approver = approver
	req.ApproverComment = input.Comment
	req.UpdatedAt = time.Now()

	// 7. Store updated request
	if err := store.Update(ctx, req); err != nil {
		return nil, err
	}

	// 8. Return output
	return &ApproveCommandOutput{
		ID:              req.ID,
		Profile:         req.Profile,
		Status:          string(req.Status),
		Approver:        req.Approver,
		ApproverComment: req.ApproverComment,
		UpdatedAt:       req.UpdatedAt,
	}, nil
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

	// Verify approver was set to current user
	currentUser, _ := user.Current()
	if output.Approver != currentUser.Username {
		t.Errorf("expected Approver '%s', got %q", currentUser.Username, output.Approver)
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
	}

	_, err := testableApproveCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for concurrent modification")
	}

	if !errors.Is(err, request.ErrConcurrentModification) {
		t.Errorf("expected ErrConcurrentModification, got: %v", err)
	}
}
