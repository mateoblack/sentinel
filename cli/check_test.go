package cli

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/request"
)

// testableCheckCommand is a testable version that allows mock store injection.
func testableCheckCommand(ctx context.Context, input CheckCommandInput) (*CheckCommandOutput, error) {
	// 1. Validate request ID format
	if !request.ValidateRequestID(input.RequestID) {
		return nil, errors.New("invalid request ID format")
	}

	// 2. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 3. Fetch request from store
	req, err := store.Get(ctx, input.RequestID)
	if err != nil {
		return nil, err
	}

	// 4. Format duration as human-readable string
	duration := formatDuration(req.Duration)

	// 5. Return output
	return &CheckCommandOutput{
		ID:              req.ID,
		Requester:       req.Requester,
		Profile:         req.Profile,
		Justification:   req.Justification,
		Duration:        duration,
		Status:          string(req.Status),
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.UpdatedAt,
		ExpiresAt:       req.ExpiresAt,
		Approver:        req.Approver,
		ApproverComment: req.ApproverComment,
	}, nil
}

func TestCheckCommand_Success(t *testing.T) {
	now := time.Now()
	expectedReq := &request.Request{
		ID:            "abc123def4567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Investigating incident INC-12345",
		Duration:      2 * time.Hour,
		Status:        request.StatusApproved,
		CreatedAt:     now.Add(-1 * time.Hour),
		UpdatedAt:     now.Add(-30 * time.Minute),
		ExpiresAt:     now.Add(23 * time.Hour),
		Approver:      "bob",
	}

	var calledID string
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			calledID = id
			return expectedReq, nil
		},
	}

	input := CheckCommandInput{
		RequestID: "abc123def4567890",
		Store:     store,
	}

	output, err := testableCheckCommand(context.Background(), input)
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
	if output.Requester != "alice" {
		t.Errorf("expected Requester 'alice', got %q", output.Requester)
	}
	if output.Profile != "production" {
		t.Errorf("expected Profile 'production', got %q", output.Profile)
	}
	if output.Status != "approved" {
		t.Errorf("expected Status 'approved', got %q", output.Status)
	}
	if output.Approver != "bob" {
		t.Errorf("expected Approver 'bob', got %q", output.Approver)
	}
}

func TestCheckCommand_NotFound(t *testing.T) {
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return nil, request.ErrRequestNotFound
		},
	}

	input := CheckCommandInput{
		RequestID: "1234567890abcdef",
		Store:     store,
	}

	_, err := testableCheckCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for request not found")
	}

	if !errors.Is(err, request.ErrRequestNotFound) {
		t.Errorf("expected ErrRequestNotFound, got: %v", err)
	}
}

func TestCheckCommand_InvalidID(t *testing.T) {
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
			input := CheckCommandInput{
				RequestID: tc.requestID,
				Store:     store,
			}

			_, err := testableCheckCommand(context.Background(), input)
			if err == nil {
				t.Fatal("expected error for invalid request ID")
			}

			if err.Error() != "invalid request ID format" {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCheckCommand_StoreError(t *testing.T) {
	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return nil, errors.New("network error: connection timeout")
		},
	}

	input := CheckCommandInput{
		RequestID: "1234567890abcdef",
		Store:     store,
	}

	_, err := testableCheckCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when store fails")
	}

	if err.Error() != "network error: connection timeout" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckCommand_OutputFormat(t *testing.T) {
	now := time.Now()
	expectedReq := &request.Request{
		ID:              "fedcba9876543210",
		Requester:       "charlie",
		Profile:         "staging",
		Justification:   "Deploy hotfix for JIRA-999",
		Duration:        90 * time.Minute, // 1h30m
		Status:          request.StatusPending,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Approver:        "",
		ApproverComment: "",
	}

	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return expectedReq, nil
		},
	}

	input := CheckCommandInput{
		RequestID: "fedcba9876543210",
		Store:     store,
	}

	output, err := testableCheckCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all fields are present in output
	if output.ID != "fedcba9876543210" {
		t.Errorf("expected ID 'fedcba9876543210', got %q", output.ID)
	}
	if output.Requester != "charlie" {
		t.Errorf("expected Requester 'charlie', got %q", output.Requester)
	}
	if output.Profile != "staging" {
		t.Errorf("expected Profile 'staging', got %q", output.Profile)
	}
	if output.Justification != "Deploy hotfix for JIRA-999" {
		t.Errorf("expected Justification 'Deploy hotfix for JIRA-999', got %q", output.Justification)
	}
	if output.Status != "pending" {
		t.Errorf("expected Status 'pending', got %q", output.Status)
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

	// Verify JSON marshaling works with omitempty for Approver fields
	jsonBytes, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("failed to marshal output: %v", err)
	}

	var unmarshaled CheckCommandOutput
	if err := json.Unmarshal(jsonBytes, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	// Verify Approver is empty (should be omitted in JSON)
	if unmarshaled.Approver != "" {
		t.Errorf("expected empty Approver in unmarshaled output, got %q", unmarshaled.Approver)
	}
}

func TestCheckCommand_DurationFormatting(t *testing.T) {
	testCases := []struct {
		duration time.Duration
		expected string
	}{
		{1 * time.Hour, "1h"},
		{2 * time.Hour, "2h"},
		{30 * time.Minute, "30m"},
		{90 * time.Minute, "1h30m"},
		{150 * time.Minute, "2h30m"},
		{8 * time.Hour, "8h"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := formatDuration(tc.duration)
			if result != tc.expected {
				t.Errorf("formatDuration(%v) = %q, expected %q", tc.duration, result, tc.expected)
			}
		})
	}
}

func TestCheckCommand_ApprovedRequestWithComment(t *testing.T) {
	now := time.Now()
	expectedReq := &request.Request{
		ID:              "1234567890abcdef",
		Requester:       "developer",
		Profile:         "admin",
		Justification:   "Database migration required",
		Duration:        4 * time.Hour,
		Status:          request.StatusApproved,
		CreatedAt:       now.Add(-2 * time.Hour),
		UpdatedAt:       now.Add(-1 * time.Hour),
		ExpiresAt:       now.Add(2 * time.Hour),
		Approver:        "security-team",
		ApproverComment: "Approved for maintenance window only",
	}

	store := &mockStore{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return expectedReq, nil
		},
	}

	input := CheckCommandInput{
		RequestID: "1234567890abcdef",
		Store:     store,
	}

	output, err := testableCheckCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify approver fields
	if output.Approver != "security-team" {
		t.Errorf("expected Approver 'security-team', got %q", output.Approver)
	}
	if output.ApproverComment != "Approved for maintenance window only" {
		t.Errorf("expected ApproverComment 'Approved for maintenance window only', got %q", output.ApproverComment)
	}
	if output.Duration != "4h" {
		t.Errorf("expected Duration '4h', got %q", output.Duration)
	}
}
