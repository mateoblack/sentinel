package cli

import (
	"context"
	"errors"
	"os/user"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/request"
)

// testableSentinelListCommand is a testable version that doesn't require current user lookup
// when a requester filter or other filter is explicitly provided.
func testableSentinelListCommand(ctx context.Context, input SentinelListCommandInput, mockUsername string) ([]RequestSummary, error) {
	// 1. Get requester (use mockUsername as default if no filter)
	requester := input.Requester
	if requester == "" && input.Status == "" && input.Profile == "" {
		requester = mockUsername
	}

	// 2. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 3. Query based on flags (priority: status > profile > requester)
	var requests []*request.Request
	var err error
	limit := input.Limit
	if limit == 0 {
		limit = 100
	}

	if input.Status != "" {
		// Query by status
		status := request.RequestStatus(input.Status)
		if !status.IsValid() {
			return nil, errors.New("invalid status: " + input.Status)
		}
		requests, err = store.ListByStatus(ctx, status, limit)
	} else if input.Profile != "" {
		// Query by profile
		requests, err = store.ListByProfile(ctx, input.Profile, limit)
	} else {
		// Query by requester (default to mock username)
		requests, err = store.ListByRequester(ctx, requester, limit)
	}

	if err != nil {
		return nil, err
	}

	// 4. Filter by requester if specified AND query was not by requester
	if input.Requester != "" && (input.Status != "" || input.Profile != "") {
		filtered := make([]*request.Request, 0, len(requests))
		for _, req := range requests {
			if req.Requester == input.Requester {
				filtered = append(filtered, req)
			}
		}
		requests = filtered
	}

	// 5. Format results
	summaries := make([]RequestSummary, 0, len(requests))
	for _, req := range requests {
		summaries = append(summaries, RequestSummary{
			ID:        req.ID,
			Profile:   req.Profile,
			Status:    string(req.Status),
			Requester: req.Requester,
			CreatedAt: req.CreatedAt,
			ExpiresAt: req.ExpiresAt,
		})
	}

	return summaries, nil
}

func TestSentinelListCommand_DefaultListsCurrentUserRequests(t *testing.T) {
	currentUser, _ := user.Current()
	mockUsername := currentUser.Username

	now := time.Now()
	expectedReqs := []*request.Request{
		{
			ID:        "abc123def4567890",
			Requester: mockUsername,
			Profile:   "dev",
			Status:    request.StatusPending,
			CreatedAt: now,
			ExpiresAt: now.Add(24 * time.Hour),
		},
		{
			ID:        "def456ghi7890123",
			Requester: mockUsername,
			Profile:   "prod",
			Status:    request.StatusApproved,
			CreatedAt: now.Add(-1 * time.Hour),
			ExpiresAt: now.Add(23 * time.Hour),
		},
	}

	var calledRequester string
	store := &mockStore{
		listByRequesterFn: func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			calledRequester = requester
			return expectedReqs, nil
		},
	}

	input := SentinelListCommandInput{
		Store: store,
		Limit: 100,
	}

	summaries, err := testableSentinelListCommand(context.Background(), input, mockUsername)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByRequester was called with current user
	if calledRequester != mockUsername {
		t.Errorf("expected requester %q, got %q", mockUsername, calledRequester)
	}

	// Verify results
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}

	if summaries[0].ID != "abc123def4567890" {
		t.Errorf("unexpected first request ID: %s", summaries[0].ID)
	}
	if summaries[0].Profile != "dev" {
		t.Errorf("unexpected first request profile: %s", summaries[0].Profile)
	}
}

func TestSentinelListCommand_FilterByStatus(t *testing.T) {
	now := time.Now()
	expectedReqs := []*request.Request{
		{
			ID:        "abc123def4567890",
			Requester: "alice",
			Profile:   "dev",
			Status:    request.StatusPending,
			CreatedAt: now,
			ExpiresAt: now.Add(24 * time.Hour),
		},
		{
			ID:        "def456ghi7890123",
			Requester: "bob",
			Profile:   "staging",
			Status:    request.StatusPending,
			CreatedAt: now.Add(-30 * time.Minute),
			ExpiresAt: now.Add(23 * time.Hour),
		},
	}

	var calledStatus request.RequestStatus
	store := &mockStore{
		listByStatusFn: func(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error) {
			calledStatus = status
			return expectedReqs, nil
		},
	}

	input := SentinelListCommandInput{
		Status: "pending",
		Store:  store,
		Limit:  100,
	}

	summaries, err := testableSentinelListCommand(context.Background(), input, "currentuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByStatus was called with correct status
	if calledStatus != request.StatusPending {
		t.Errorf("expected status %q, got %q", request.StatusPending, calledStatus)
	}

	// Verify results include both requesters (no filtering by current user)
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}

	if summaries[0].Requester != "alice" {
		t.Errorf("unexpected first requester: %s", summaries[0].Requester)
	}
	if summaries[1].Requester != "bob" {
		t.Errorf("unexpected second requester: %s", summaries[1].Requester)
	}
}

func TestSentinelListCommand_FilterByProfile(t *testing.T) {
	now := time.Now()
	expectedReqs := []*request.Request{
		{
			ID:        "abc123def4567890",
			Requester: "alice",
			Profile:   "prod",
			Status:    request.StatusPending,
			CreatedAt: now,
			ExpiresAt: now.Add(24 * time.Hour),
		},
	}

	var calledProfile string
	store := &mockStore{
		listByProfileFn: func(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
			calledProfile = profile
			return expectedReqs, nil
		},
	}

	input := SentinelListCommandInput{
		Profile: "prod",
		Store:   store,
		Limit:   100,
	}

	summaries, err := testableSentinelListCommand(context.Background(), input, "currentuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByProfile was called with correct profile
	if calledProfile != "prod" {
		t.Errorf("expected profile %q, got %q", "prod", calledProfile)
	}

	// Verify results
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	if summaries[0].Profile != "prod" {
		t.Errorf("unexpected profile: %s", summaries[0].Profile)
	}
}

func TestSentinelListCommand_FilterByRequester(t *testing.T) {
	now := time.Now()
	expectedReqs := []*request.Request{
		{
			ID:        "abc123def4567890",
			Requester: "other-user",
			Profile:   "dev",
			Status:    request.StatusPending,
			CreatedAt: now,
			ExpiresAt: now.Add(24 * time.Hour),
		},
	}

	var calledRequester string
	store := &mockStore{
		listByRequesterFn: func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			calledRequester = requester
			return expectedReqs, nil
		},
	}

	input := SentinelListCommandInput{
		Requester: "other-user",
		Store:     store,
		Limit:     100,
	}

	summaries, err := testableSentinelListCommand(context.Background(), input, "currentuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByRequester was called with specified user (not current user)
	if calledRequester != "other-user" {
		t.Errorf("expected requester %q, got %q", "other-user", calledRequester)
	}

	// Verify results
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	if summaries[0].Requester != "other-user" {
		t.Errorf("unexpected requester: %s", summaries[0].Requester)
	}
}

func TestSentinelListCommand_EmptyResults(t *testing.T) {
	store := &mockStore{
		listByRequesterFn: func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			return []*request.Request{}, nil
		},
	}

	input := SentinelListCommandInput{
		Store: store,
		Limit: 100,
	}

	summaries, err := testableSentinelListCommand(context.Background(), input, "currentuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify empty results
	if len(summaries) != 0 {
		t.Fatalf("expected 0 summaries, got %d", len(summaries))
	}
}

func TestSentinelListCommand_StoreError(t *testing.T) {
	store := &mockStore{
		listByRequesterFn: func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			return nil, errors.New("network error: connection refused")
		},
	}

	input := SentinelListCommandInput{
		Store: store,
		Limit: 100,
	}

	_, err := testableSentinelListCommand(context.Background(), input, "currentuser")
	if err == nil {
		t.Fatal("expected error when store fails")
	}

	if err.Error() != "network error: connection refused" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSentinelListCommand_InvalidStatus(t *testing.T) {
	store := &mockStore{}

	input := SentinelListCommandInput{
		Status: "invalid-status",
		Store:  store,
		Limit:  100,
	}

	_, err := testableSentinelListCommand(context.Background(), input, "currentuser")
	if err == nil {
		t.Fatal("expected error for invalid status")
	}

	if err.Error() != "invalid status: invalid-status" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSentinelListCommand_FilterByStatusAndRequester(t *testing.T) {
	now := time.Now()
	// Store returns requests from multiple users
	allReqs := []*request.Request{
		{
			ID:        "abc123def4567890",
			Requester: "alice",
			Profile:   "dev",
			Status:    request.StatusPending,
			CreatedAt: now,
			ExpiresAt: now.Add(24 * time.Hour),
		},
		{
			ID:        "def456ghi7890123",
			Requester: "bob",
			Profile:   "staging",
			Status:    request.StatusPending,
			CreatedAt: now.Add(-30 * time.Minute),
			ExpiresAt: now.Add(23 * time.Hour),
		},
	}

	store := &mockStore{
		listByStatusFn: func(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error) {
			return allReqs, nil
		},
	}

	// Filter by status=pending AND requester=alice
	input := SentinelListCommandInput{
		Status:    "pending",
		Requester: "alice",
		Store:     store,
		Limit:     100,
	}

	summaries, err := testableSentinelListCommand(context.Background(), input, "currentuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should filter to only alice's requests
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary (filtered), got %d", len(summaries))
	}

	if summaries[0].Requester != "alice" {
		t.Errorf("expected requester 'alice', got %s", summaries[0].Requester)
	}
}
