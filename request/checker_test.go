package request

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockStore implements Store interface for testing FindApprovedRequest.
type mockStore struct {
	listByRequesterFunc func(ctx context.Context, requester string, limit int) ([]*Request, error)
}

func (m *mockStore) Create(ctx context.Context, req *Request) error {
	return nil
}

func (m *mockStore) Get(ctx context.Context, id string) (*Request, error) {
	return nil, nil
}

func (m *mockStore) Update(ctx context.Context, req *Request) error {
	return nil
}

func (m *mockStore) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockStore) ListByRequester(ctx context.Context, requester string, limit int) ([]*Request, error) {
	if m.listByRequesterFunc != nil {
		return m.listByRequesterFunc(ctx, requester, limit)
	}
	return []*Request{}, nil
}

func (m *mockStore) ListByStatus(ctx context.Context, status RequestStatus, limit int) ([]*Request, error) {
	return []*Request{}, nil
}

func (m *mockStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*Request, error) {
	return []*Request{}, nil
}

func TestFindApprovedRequest_Found(t *testing.T) {
	now := time.Now()
	validRequest := &Request{
		ID:        "valid001",
		Requester: "alice",
		Profile:   "production",
		Status:    StatusApproved,
		Duration:  2 * time.Hour,
		CreatedAt: now.Add(-time.Hour), // Created 1 hour ago
		ExpiresAt: now.Add(23 * time.Hour), // Expires in 23 hours
	}

	store := &mockStore{
		listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*Request, error) {
			return []*Request{validRequest}, nil
		},
	}

	result, err := FindApprovedRequest(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindApprovedRequest() error = %v, want nil", err)
	}
	if result == nil {
		t.Fatal("FindApprovedRequest() = nil, want valid request")
	}
	if result.ID != "valid001" {
		t.Errorf("FindApprovedRequest().ID = %q, want %q", result.ID, "valid001")
	}
}

func TestFindApprovedRequest_WrongProfile(t *testing.T) {
	now := time.Now()
	approvedForDifferentProfile := &Request{
		ID:        "profile001",
		Requester: "alice",
		Profile:   "staging", // Different profile
		Status:    StatusApproved,
		Duration:  2 * time.Hour,
		CreatedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(23 * time.Hour),
	}

	store := &mockStore{
		listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*Request, error) {
			return []*Request{approvedForDifferentProfile}, nil
		},
	}

	result, err := FindApprovedRequest(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindApprovedRequest() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("FindApprovedRequest() = %v, want nil for wrong profile", result)
	}
}

func TestFindApprovedRequest_WrongStatus(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		name   string
		status RequestStatus
	}{
		{"pending", StatusPending},
		{"denied", StatusDenied},
		{"expired", StatusExpired},
		{"cancelled", StatusCancelled},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wrongStatusRequest := &Request{
				ID:        "status001",
				Requester: "alice",
				Profile:   "production",
				Status:    tc.status,
				Duration:  2 * time.Hour,
				CreatedAt: now.Add(-time.Hour),
				ExpiresAt: now.Add(23 * time.Hour),
			}

			store := &mockStore{
				listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*Request, error) {
					return []*Request{wrongStatusRequest}, nil
				},
			}

			result, err := FindApprovedRequest(context.Background(), store, "alice", "production")
			if err != nil {
				t.Fatalf("FindApprovedRequest() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("FindApprovedRequest() = %v, want nil for status %q", result, tc.status)
			}
		})
	}
}

func TestFindApprovedRequest_Expired(t *testing.T) {
	now := time.Now()
	expiredRequest := &Request{
		ID:        "expired001",
		Requester: "alice",
		Profile:   "production",
		Status:    StatusApproved,
		Duration:  2 * time.Hour,
		CreatedAt: now.Add(-25 * time.Hour), // Created 25 hours ago
		ExpiresAt: now.Add(-time.Hour),      // Expired 1 hour ago
	}

	store := &mockStore{
		listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*Request, error) {
			return []*Request{expiredRequest}, nil
		},
	}

	result, err := FindApprovedRequest(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindApprovedRequest() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("FindApprovedRequest() = %v, want nil for expired request", result)
	}
}

func TestFindApprovedRequest_DurationElapsed(t *testing.T) {
	now := time.Now()
	durationElapsedRequest := &Request{
		ID:        "duration001",
		Requester: "alice",
		Profile:   "production",
		Status:    StatusApproved,
		Duration:  time.Hour,               // 1 hour duration
		CreatedAt: now.Add(-2 * time.Hour), // Created 2 hours ago (window closed)
		ExpiresAt: now.Add(22 * time.Hour), // Still not expired per TTL
	}

	store := &mockStore{
		listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*Request, error) {
			return []*Request{durationElapsedRequest}, nil
		},
	}

	result, err := FindApprovedRequest(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindApprovedRequest() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("FindApprovedRequest() = %v, want nil for duration elapsed", result)
	}
}

func TestFindApprovedRequest_NoRequests(t *testing.T) {
	store := &mockStore{
		listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*Request, error) {
			return []*Request{}, nil
		},
	}

	result, err := FindApprovedRequest(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindApprovedRequest() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("FindApprovedRequest() = %v, want nil for no requests", result)
	}
}

func TestFindApprovedRequest_StoreError(t *testing.T) {
	expectedErr := errors.New("database connection failed")
	store := &mockStore{
		listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*Request, error) {
			return nil, expectedErr
		},
	}

	result, err := FindApprovedRequest(context.Background(), store, "alice", "production")
	if err == nil {
		t.Fatal("FindApprovedRequest() error = nil, want error")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("FindApprovedRequest() error = %v, want %v", err, expectedErr)
	}
	if result != nil {
		t.Errorf("FindApprovedRequest() = %v, want nil on error", result)
	}
}

func TestFindApprovedRequest_MultipleCandidates(t *testing.T) {
	now := time.Now()

	// Mix of valid and invalid requests - should return the first valid one
	requests := []*Request{
		{
			ID:        "pending001",
			Requester: "alice",
			Profile:   "production",
			Status:    StatusPending, // Wrong status
			Duration:  2 * time.Hour,
			CreatedAt: now.Add(-time.Hour),
			ExpiresAt: now.Add(23 * time.Hour),
		},
		{
			ID:        "expired001",
			Requester: "alice",
			Profile:   "production",
			Status:    StatusApproved,
			Duration:  2 * time.Hour,
			CreatedAt: now.Add(-25 * time.Hour),
			ExpiresAt: now.Add(-time.Hour), // Expired
		},
		{
			ID:        "valid001",
			Requester: "alice",
			Profile:   "production",
			Status:    StatusApproved, // Correct status
			Duration:  2 * time.Hour,
			CreatedAt: now.Add(-time.Hour), // Valid window
			ExpiresAt: now.Add(23 * time.Hour), // Not expired
		},
		{
			ID:        "valid002",
			Requester: "alice",
			Profile:   "production",
			Status:    StatusApproved,
			Duration:  4 * time.Hour,
			CreatedAt: now.Add(-30 * time.Minute),
			ExpiresAt: now.Add(23 * time.Hour),
		},
	}

	store := &mockStore{
		listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*Request, error) {
			return requests, nil
		},
	}

	result, err := FindApprovedRequest(context.Background(), store, "alice", "production")
	if err != nil {
		t.Fatalf("FindApprovedRequest() error = %v, want nil", err)
	}
	if result == nil {
		t.Fatal("FindApprovedRequest() = nil, want valid request")
	}
	// Should find valid001 as the first valid one (skipping pending and expired)
	if result.ID != "valid001" {
		t.Errorf("FindApprovedRequest().ID = %q, want %q (first valid match)", result.ID, "valid001")
	}
}
