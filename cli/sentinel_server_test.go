package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/session"
)

// mockSessionStore implements session.Store for testing.
type mockSessionStore struct {
	createFn                     func(ctx context.Context, sess *session.ServerSession) error
	getFn                        func(ctx context.Context, id string) (*session.ServerSession, error)
	updateFn                     func(ctx context.Context, sess *session.ServerSession) error
	deleteFn                     func(ctx context.Context, id string) error
	listByUserFn                 func(ctx context.Context, user string, limit int) ([]*session.ServerSession, error)
	listByStatusFn               func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error)
	listByProfileFn              func(ctx context.Context, profile string, limit int) ([]*session.ServerSession, error)
	findActiveByServerInstanceFn func(ctx context.Context, serverInstanceID string) (*session.ServerSession, error)
	touchFn                      func(ctx context.Context, id string) error
	listByTimeRangeFn            func(ctx context.Context, startTime, endTime time.Time, limit int) ([]*session.ServerSession, error)
}

func (m *mockSessionStore) Create(ctx context.Context, sess *session.ServerSession) error {
	if m.createFn != nil {
		return m.createFn(ctx, sess)
	}
	return nil
}

func (m *mockSessionStore) Get(ctx context.Context, id string) (*session.ServerSession, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id)
	}
	return nil, session.ErrSessionNotFound
}

func (m *mockSessionStore) Update(ctx context.Context, sess *session.ServerSession) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, sess)
	}
	return nil
}

func (m *mockSessionStore) Delete(ctx context.Context, id string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

func (m *mockSessionStore) ListByUser(ctx context.Context, user string, limit int) ([]*session.ServerSession, error) {
	if m.listByUserFn != nil {
		return m.listByUserFn(ctx, user, limit)
	}
	return nil, nil
}

func (m *mockSessionStore) ListByStatus(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
	if m.listByStatusFn != nil {
		return m.listByStatusFn(ctx, status, limit)
	}
	return nil, nil
}

func (m *mockSessionStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*session.ServerSession, error) {
	if m.listByProfileFn != nil {
		return m.listByProfileFn(ctx, profile, limit)
	}
	return nil, nil
}

func (m *mockSessionStore) FindActiveByServerInstance(ctx context.Context, serverInstanceID string) (*session.ServerSession, error) {
	if m.findActiveByServerInstanceFn != nil {
		return m.findActiveByServerInstanceFn(ctx, serverInstanceID)
	}
	return nil, nil
}

func (m *mockSessionStore) Touch(ctx context.Context, id string) error {
	if m.touchFn != nil {
		return m.touchFn(ctx, id)
	}
	return nil
}

func (m *mockSessionStore) ListByTimeRange(ctx context.Context, startTime, endTime time.Time, limit int) ([]*session.ServerSession, error) {
	if m.listByTimeRangeFn != nil {
		return m.listByTimeRangeFn(ctx, startTime, endTime, limit)
	}
	return nil, nil
}

func (m *mockSessionStore) GetBySourceIdentity(ctx context.Context, sourceIdentity string) (*session.ServerSession, error) {
	return nil, nil
}

// mockSessionSTSClient implements identity.STSAPI for testing.
type mockSessionSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockSessionSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return nil, errors.New("not implemented")
}

// Test constants
const sessionTestUsername = "sessiontestuser"

// newMockSessionSTSClient creates a mock STS client that returns the given username in the ARN.
func newMockSessionSTSClient(username string) identity.STSAPI {
	return &mockSessionSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:user/" + username),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}
}

// defaultSessionMockSTSClient returns a mock STS client for the default test user.
func defaultSessionMockSTSClient() identity.STSAPI {
	return newMockSessionSTSClient(sessionTestUsername)
}

// testableServerSessionsCommand is a testable version that uses mock STS client.
func testableServerSessionsCommand(ctx context.Context, input ServerSessionsCommandInput) ([]ServerSessionSummary, error) {
	// 1. Get user (use STSClient if no user filter and no other filter)
	user := input.User
	if user == "" && input.Status == "" && input.Profile == "" {
		stsClient := input.STSClient
		if stsClient == nil {
			return nil, errors.New("STSClient is required for testing when no filter is provided")
		}
		var err error
		user, err = identity.GetAWSUsername(ctx, stsClient)
		if err != nil {
			return nil, err
		}
	}

	// 2. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 3. Query based on flags (priority: status > profile > user)
	var sessions []*session.ServerSession
	var err error
	limit := input.Limit
	if limit == 0 {
		limit = 100
	}

	if input.Status != "" {
		// Query by status
		status := session.SessionStatus(input.Status)
		if !status.IsValid() {
			return nil, errors.New("invalid status: " + input.Status)
		}
		sessions, err = store.ListByStatus(ctx, status, limit)
	} else if input.Profile != "" {
		// Query by profile
		sessions, err = store.ListByProfile(ctx, input.Profile, limit)
	} else if user != "" {
		// Query by user
		sessions, err = store.ListByUser(ctx, user, limit)
	} else {
		// Default to active sessions
		sessions, err = store.ListByStatus(ctx, session.StatusActive, limit)
	}

	if err != nil {
		return nil, err
	}

	// 4. Filter by user if specified AND query was not by user
	if input.User != "" && (input.Status != "" || input.Profile != "") {
		filtered := make([]*session.ServerSession, 0, len(sessions))
		for _, sess := range sessions {
			if sess.User == input.User {
				filtered = append(filtered, sess)
			}
		}
		sessions = filtered
	}

	// 5. Format results
	summaries := make([]ServerSessionSummary, 0, len(sessions))
	for _, sess := range sessions {
		summaries = append(summaries, ServerSessionSummary{
			ID:               sess.ID,
			User:             sess.User,
			Profile:          sess.Profile,
			Status:           string(sess.Status),
			StartedAt:        sess.StartedAt,
			LastAccessAt:     sess.LastAccessAt,
			ExpiresAt:        sess.ExpiresAt,
			RequestCount:     sess.RequestCount,
			ServerInstanceID: sess.ServerInstanceID,
		})
	}

	return summaries, nil
}

// testableServerSessionCommand is a testable version for the detail command.
func testableServerSessionCommand(ctx context.Context, input ServerSessionCommandInput) (*session.ServerSession, error) {
	// 1. Validate session ID format
	if !session.ValidateSessionID(input.SessionID) {
		return nil, errors.New("invalid session ID format: " + input.SessionID)
	}

	// 2. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 3. Get session by ID
	sess, err := store.Get(ctx, input.SessionID)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

// TestServerSessionsCommand_ListActive tests listing active sessions.
func TestServerSessionsCommand_ListActive(t *testing.T) {
	now := time.Now()
	expectedSessions := []*session.ServerSession{
		{
			ID:               "abc123def4567890",
			User:             "alice",
			Profile:          "dev",
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now.Add(10 * time.Minute),
			ExpiresAt:        now.Add(30 * time.Minute),
			RequestCount:     42,
			ServerInstanceID: "server-1",
		},
		{
			ID:               "def456ghi7890123",
			User:             "bob",
			Profile:          "staging",
			Status:           session.StatusActive,
			StartedAt:        now.Add(-1 * time.Hour),
			LastAccessAt:     now.Add(-30 * time.Minute),
			ExpiresAt:        now.Add(1 * time.Hour),
			RequestCount:     100,
			ServerInstanceID: "server-2",
		},
	}

	var calledStatus session.SessionStatus
	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			calledStatus = status
			return expectedSessions, nil
		},
	}

	input := ServerSessionsCommandInput{
		Status: "active",
		Store:  store,
		Limit:  100,
	}

	summaries, err := testableServerSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByStatus was called with active status
	if calledStatus != session.StatusActive {
		t.Errorf("expected status %q, got %q", session.StatusActive, calledStatus)
	}

	// Verify results
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}

	if summaries[0].ID != "abc123def4567890" {
		t.Errorf("unexpected first session ID: %s", summaries[0].ID)
	}
	if summaries[0].User != "alice" {
		t.Errorf("unexpected first session user: %s", summaries[0].User)
	}
	if summaries[0].RequestCount != 42 {
		t.Errorf("unexpected first session request count: %d", summaries[0].RequestCount)
	}
}

// TestServerSessionsCommand_FilterByStatus tests filtering by different status values.
func TestServerSessionsCommand_FilterByStatus(t *testing.T) {
	statuses := []string{"active", "revoked", "expired"}

	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			now := time.Now()
			expectedSessions := []*session.ServerSession{
				{
					ID:               "abc123def4567890",
					User:             "testuser",
					Profile:          "test-profile",
					Status:           session.SessionStatus(status),
					StartedAt:        now,
					LastAccessAt:     now,
					ExpiresAt:        now.Add(30 * time.Minute),
					RequestCount:     10,
					ServerInstanceID: "server-1",
				},
			}

			var calledStatus session.SessionStatus
			store := &mockSessionStore{
				listByStatusFn: func(ctx context.Context, s session.SessionStatus, limit int) ([]*session.ServerSession, error) {
					calledStatus = s
					return expectedSessions, nil
				},
			}

			input := ServerSessionsCommandInput{
				Status: status,
				Store:  store,
				Limit:  100,
			}

			summaries, err := testableServerSessionsCommand(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error for status %s: %v", status, err)
			}

			// Verify correct status was queried
			if calledStatus != session.SessionStatus(status) {
				t.Errorf("expected status %q, got %q", status, calledStatus)
			}

			// Verify results
			if len(summaries) != 1 {
				t.Fatalf("expected 1 summary, got %d", len(summaries))
			}

			if summaries[0].Status != status {
				t.Errorf("expected status %q in output, got %q", status, summaries[0].Status)
			}
		})
	}
}

// TestServerSessionsCommand_FilterByUser tests filtering by user.
func TestServerSessionsCommand_FilterByUser(t *testing.T) {
	now := time.Now()
	expectedSessions := []*session.ServerSession{
		{
			ID:               "abc123def4567890",
			User:             "alice",
			Profile:          "dev",
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now,
			ExpiresAt:        now.Add(30 * time.Minute),
			RequestCount:     10,
			ServerInstanceID: "server-1",
		},
	}

	var calledUser string
	store := &mockSessionStore{
		listByUserFn: func(ctx context.Context, user string, limit int) ([]*session.ServerSession, error) {
			calledUser = user
			return expectedSessions, nil
		},
	}

	input := ServerSessionsCommandInput{
		User:  "alice",
		Store: store,
		Limit: 100,
	}

	summaries, err := testableServerSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByUser was called with correct user
	if calledUser != "alice" {
		t.Errorf("expected user %q, got %q", "alice", calledUser)
	}

	// Verify results
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	if summaries[0].User != "alice" {
		t.Errorf("unexpected user: %s", summaries[0].User)
	}
}

// TestServerSessionsCommand_FilterByProfile tests filtering by profile.
func TestServerSessionsCommand_FilterByProfile(t *testing.T) {
	now := time.Now()
	expectedSessions := []*session.ServerSession{
		{
			ID:               "abc123def4567890",
			User:             "alice",
			Profile:          "production",
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now,
			ExpiresAt:        now.Add(30 * time.Minute),
			RequestCount:     100,
			ServerInstanceID: "server-1",
		},
	}

	var calledProfile string
	store := &mockSessionStore{
		listByProfileFn: func(ctx context.Context, profile string, limit int) ([]*session.ServerSession, error) {
			calledProfile = profile
			return expectedSessions, nil
		},
	}

	input := ServerSessionsCommandInput{
		Profile: "production",
		Store:   store,
		Limit:   100,
	}

	summaries, err := testableServerSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByProfile was called with correct profile
	if calledProfile != "production" {
		t.Errorf("expected profile %q, got %q", "production", calledProfile)
	}

	// Verify results
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	if summaries[0].Profile != "production" {
		t.Errorf("unexpected profile: %s", summaries[0].Profile)
	}
}

// TestServerSessionsCommand_DefaultListsCurrentUserSessions tests default behavior.
func TestServerSessionsCommand_DefaultListsCurrentUserSessions(t *testing.T) {
	now := time.Now()
	expectedSessions := []*session.ServerSession{
		{
			ID:               "abc123def4567890",
			User:             sessionTestUsername,
			Profile:          "dev",
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now,
			ExpiresAt:        now.Add(30 * time.Minute),
			RequestCount:     10,
			ServerInstanceID: "server-1",
		},
	}

	var calledUser string
	store := &mockSessionStore{
		listByUserFn: func(ctx context.Context, user string, limit int) ([]*session.ServerSession, error) {
			calledUser = user
			return expectedSessions, nil
		},
	}

	input := ServerSessionsCommandInput{
		Store:     store,
		Limit:     100,
		STSClient: defaultSessionMockSTSClient(),
	}

	summaries, err := testableServerSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByUser was called with current user from STS
	if calledUser != sessionTestUsername {
		t.Errorf("expected user %q, got %q", sessionTestUsername, calledUser)
	}

	// Verify results
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
}

// TestServerSessionsCommand_InvalidStatus tests error for invalid status.
func TestServerSessionsCommand_InvalidStatus(t *testing.T) {
	store := &mockSessionStore{}

	input := ServerSessionsCommandInput{
		Status: "invalid-status",
		Store:  store,
		Limit:  100,
	}

	_, err := testableServerSessionsCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid status")
	}

	if err.Error() != "invalid status: invalid-status" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestServerSessionsCommand_EmptyResults tests empty result handling.
func TestServerSessionsCommand_EmptyResults(t *testing.T) {
	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return []*session.ServerSession{}, nil
		},
	}

	input := ServerSessionsCommandInput{
		Status: "active",
		Store:  store,
		Limit:  100,
	}

	summaries, err := testableServerSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(summaries) != 0 {
		t.Fatalf("expected 0 summaries, got %d", len(summaries))
	}
}

// TestServerSessionsCommand_StoreError tests error handling from store.
func TestServerSessionsCommand_StoreError(t *testing.T) {
	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return nil, errors.New("network error: connection refused")
		},
	}

	input := ServerSessionsCommandInput{
		Status: "active",
		Store:  store,
		Limit:  100,
	}

	_, err := testableServerSessionsCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when store fails")
	}

	if err.Error() != "network error: connection refused" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestServerSessionsCommand_FilterByStatusAndUser tests combined filtering.
func TestServerSessionsCommand_FilterByStatusAndUser(t *testing.T) {
	now := time.Now()
	// Store returns sessions from multiple users
	allSessions := []*session.ServerSession{
		{
			ID:               "abc123def4567890",
			User:             "alice",
			Profile:          "dev",
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now,
			ExpiresAt:        now.Add(30 * time.Minute),
			RequestCount:     10,
			ServerInstanceID: "server-1",
		},
		{
			ID:               "def456ghi7890123",
			User:             "bob",
			Profile:          "staging",
			Status:           session.StatusActive,
			StartedAt:        now.Add(-30 * time.Minute),
			LastAccessAt:     now,
			ExpiresAt:        now.Add(1 * time.Hour),
			RequestCount:     20,
			ServerInstanceID: "server-2",
		},
	}

	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return allSessions, nil
		},
	}

	// Filter by status=active AND user=alice
	input := ServerSessionsCommandInput{
		Status: "active",
		User:   "alice",
		Store:  store,
		Limit:  100,
	}

	summaries, err := testableServerSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should filter to only alice's sessions
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary (filtered), got %d", len(summaries))
	}

	if summaries[0].User != "alice" {
		t.Errorf("expected user 'alice', got %s", summaries[0].User)
	}
}

// TestServerSessionCommand_GetByID tests getting session details by ID.
func TestServerSessionCommand_GetByID(t *testing.T) {
	now := time.Now()
	expectedSession := &session.ServerSession{
		ID:               "abc123def4567890",
		User:             "alice",
		Profile:          "production-admin",
		Status:           session.StatusActive,
		StartedAt:        now,
		LastAccessAt:     now.Add(15 * time.Minute),
		ExpiresAt:        now.Add(30 * time.Minute),
		RequestCount:     42,
		ServerInstanceID: "server-xyz789",
		SourceIdentity:   "sentinel:alice:req123",
	}

	var calledID string
	store := &mockSessionStore{
		getFn: func(ctx context.Context, id string) (*session.ServerSession, error) {
			calledID = id
			return expectedSession, nil
		},
	}

	input := ServerSessionCommandInput{
		SessionID: "abc123def4567890",
		Store:     store,
	}

	sess, err := testableServerSessionCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Get was called with correct ID
	if calledID != "abc123def4567890" {
		t.Errorf("expected ID %q, got %q", "abc123def4567890", calledID)
	}

	// Verify all fields are present
	if sess.ID != "abc123def4567890" {
		t.Errorf("unexpected ID: %s", sess.ID)
	}
	if sess.User != "alice" {
		t.Errorf("unexpected user: %s", sess.User)
	}
	if sess.Profile != "production-admin" {
		t.Errorf("unexpected profile: %s", sess.Profile)
	}
	if sess.Status != session.StatusActive {
		t.Errorf("unexpected status: %s", sess.Status)
	}
	if sess.RequestCount != 42 {
		t.Errorf("unexpected request count: %d", sess.RequestCount)
	}
	if sess.SourceIdentity != "sentinel:alice:req123" {
		t.Errorf("unexpected source identity: %s", sess.SourceIdentity)
	}
}

// TestServerSessionCommand_NotFound tests error when session not found.
func TestServerSessionCommand_NotFound(t *testing.T) {
	store := &mockSessionStore{
		getFn: func(ctx context.Context, id string) (*session.ServerSession, error) {
			return nil, session.ErrSessionNotFound
		},
	}

	input := ServerSessionCommandInput{
		SessionID: "abc123def4567890",
		Store:     store,
	}

	_, err := testableServerSessionCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for not found session")
	}

	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

// TestServerSessionCommand_InvalidID tests error for invalid session ID format.
func TestServerSessionCommand_InvalidID(t *testing.T) {
	invalidIDs := []string{
		"",                  // empty
		"abc",               // too short
		"abc123def456789",   // too short (15 chars)
		"abc123def45678901", // too long (17 chars)
		"ABC123DEF4567890",  // uppercase
		"abc123def456789g",  // invalid hex char
		"abc-123-def-4567",  // contains dashes
	}

	store := &mockSessionStore{}

	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			input := ServerSessionCommandInput{
				SessionID: id,
				Store:     store,
			}

			_, err := testableServerSessionCommand(context.Background(), input)
			if err == nil {
				t.Fatalf("expected error for invalid session ID %q", id)
			}
			if err.Error() != "invalid session ID format: "+id {
				t.Errorf("unexpected error for ID %q: %v", id, err)
			}
		})
	}
}

// TestServerSessionCommand_RevokedSession tests display of revoked session details.
func TestServerSessionCommand_RevokedSession(t *testing.T) {
	now := time.Now()
	expectedSession := &session.ServerSession{
		ID:               "abc123def4567890",
		User:             "alice",
		Profile:          "production",
		Status:           session.StatusRevoked,
		StartedAt:        now.Add(-1 * time.Hour),
		LastAccessAt:     now.Add(-30 * time.Minute),
		ExpiresAt:        now.Add(30 * time.Minute),
		RequestCount:     100,
		ServerInstanceID: "server-1",
		RevokedBy:        "security-admin",
		RevokedReason:    "Suspicious activity detected",
	}

	store := &mockSessionStore{
		getFn: func(ctx context.Context, id string) (*session.ServerSession, error) {
			return expectedSession, nil
		},
	}

	input := ServerSessionCommandInput{
		SessionID: "abc123def4567890",
		Store:     store,
	}

	sess, err := testableServerSessionCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify revocation info is present
	if sess.Status != session.StatusRevoked {
		t.Errorf("expected status 'revoked', got %s", sess.Status)
	}
	if sess.RevokedBy != "security-admin" {
		t.Errorf("expected revoked_by 'security-admin', got %s", sess.RevokedBy)
	}
	if sess.RevokedReason != "Suspicious activity detected" {
		t.Errorf("expected revoked_reason 'Suspicious activity detected', got %s", sess.RevokedReason)
	}
}

// testableServerRevokeCommand is a testable version for the revoke command.
// It returns the revoked session for verification instead of outputting to stdout.
func testableServerRevokeCommand(ctx context.Context, input ServerRevokeCommandInput) (*session.ServerSession, error) {
	// 1. Validate session ID format
	if !session.ValidateSessionID(input.SessionID) {
		return nil, errors.New("invalid session ID format: " + input.SessionID)
	}

	// 2. Validate reason is non-empty
	if input.Reason == "" {
		return nil, errors.New("reason is required for revocation")
	}

	// 3. Get AWS identity for RevokedBy
	stsClient := input.STSClient
	if stsClient == nil {
		return nil, errors.New("STSClient is required for testing")
	}
	revokedBy, err := identity.GetAWSUsername(ctx, stsClient)
	if err != nil {
		return nil, err
	}

	// 4. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 5. Revoke session
	revokeInput := session.RevokeInput{
		SessionID: input.SessionID,
		RevokedBy: revokedBy,
		Reason:    input.Reason,
	}

	revokedSession, err := session.Revoke(ctx, store, revokeInput)
	if err != nil {
		return nil, err
	}

	return revokedSession, nil
}

// TestServerRevokeCommand_Success tests successful session revocation.
func TestServerRevokeCommand_Success(t *testing.T) {
	now := time.Now()
	activeSession := &session.ServerSession{
		ID:               "abc1234567890def",
		User:             "alice",
		Profile:          "production",
		Status:           session.StatusActive,
		StartedAt:        now.Add(-30 * time.Minute),
		LastAccessAt:     now.Add(-5 * time.Minute),
		ExpiresAt:        now.Add(30 * time.Minute),
		RequestCount:     42,
		ServerInstanceID: "server-1",
		SourceIdentity:   "sentinel:alice:req123",
	}

	// Create a mock store that tracks session updates
	var updatedSession *session.ServerSession
	store := &mockSessionStore{
		getFn: func(ctx context.Context, id string) (*session.ServerSession, error) {
			if id == activeSession.ID {
				// Return a copy so we can track updates separately
				sessCopy := *activeSession
				return &sessCopy, nil
			}
			return nil, session.ErrSessionNotFound
		},
		updateFn: func(ctx context.Context, sess *session.ServerSession) error {
			updatedSession = sess
			return nil
		},
	}

	input := ServerRevokeCommandInput{
		SessionID: activeSession.ID,
		Reason:    "Security incident",
		Store:     store,
		STSClient: newMockSessionSTSClient("admin"),
	}

	revokedSession, err := testableServerRevokeCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify session was revoked
	if revokedSession.Status != session.StatusRevoked {
		t.Errorf("Expected status revoked, got %s", revokedSession.Status)
	}
	if revokedSession.RevokedBy != "admin" {
		t.Errorf("Expected revoked_by 'admin', got %s", revokedSession.RevokedBy)
	}
	if revokedSession.RevokedReason != "Security incident" {
		t.Errorf("Expected revoked_reason 'Security incident', got %s", revokedSession.RevokedReason)
	}

	// Verify update was called
	if updatedSession == nil {
		t.Fatal("Expected store.Update to be called")
	}
	if updatedSession.Status != session.StatusRevoked {
		t.Errorf("Expected updated session status revoked, got %s", updatedSession.Status)
	}
}

// TestServerRevokeCommand_NotFound tests error when session not found.
func TestServerRevokeCommand_NotFound(t *testing.T) {
	store := &mockSessionStore{
		getFn: func(ctx context.Context, id string) (*session.ServerSession, error) {
			return nil, session.ErrSessionNotFound
		},
	}

	input := ServerRevokeCommandInput{
		SessionID: "abc1234567890def",
		Reason:    "Test reason",
		Store:     store,
		STSClient: newMockSessionSTSClient("admin"),
	}

	_, err := testableServerRevokeCommand(context.Background(), input)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

// TestServerRevokeCommand_AlreadyRevoked tests error when session already revoked.
func TestServerRevokeCommand_AlreadyRevoked(t *testing.T) {
	now := time.Now()
	revokedSession := &session.ServerSession{
		ID:            "abc1234567890def",
		User:          "alice",
		Profile:       "production",
		Status:        session.StatusRevoked,
		StartedAt:     now.Add(-1 * time.Hour),
		LastAccessAt:  now.Add(-30 * time.Minute),
		ExpiresAt:     now.Add(30 * time.Minute),
		RevokedBy:     "previous-admin",
		RevokedReason: "Earlier revocation",
	}

	store := &mockSessionStore{
		getFn: func(ctx context.Context, id string) (*session.ServerSession, error) {
			if id == revokedSession.ID {
				sessCopy := *revokedSession
				return &sessCopy, nil
			}
			return nil, session.ErrSessionNotFound
		},
	}

	input := ServerRevokeCommandInput{
		SessionID: revokedSession.ID,
		Reason:    "Attempt to revoke again",
		Store:     store,
		STSClient: newMockSessionSTSClient("admin"),
	}

	_, err := testableServerRevokeCommand(context.Background(), input)
	if !errors.Is(err, session.ErrSessionAlreadyRevoked) {
		t.Errorf("Expected ErrSessionAlreadyRevoked, got: %v", err)
	}
}

// TestServerRevokeCommand_Expired tests error when session already expired.
func TestServerRevokeCommand_Expired(t *testing.T) {
	now := time.Now()
	expiredSession := &session.ServerSession{
		ID:           "abc1234567890def",
		User:         "alice",
		Profile:      "production",
		Status:       session.StatusExpired,
		StartedAt:    now.Add(-2 * time.Hour),
		LastAccessAt: now.Add(-1 * time.Hour),
		ExpiresAt:    now.Add(-30 * time.Minute),
	}

	store := &mockSessionStore{
		getFn: func(ctx context.Context, id string) (*session.ServerSession, error) {
			if id == expiredSession.ID {
				sessCopy := *expiredSession
				return &sessCopy, nil
			}
			return nil, session.ErrSessionNotFound
		},
	}

	input := ServerRevokeCommandInput{
		SessionID: expiredSession.ID,
		Reason:    "Attempt to revoke expired session",
		Store:     store,
		STSClient: newMockSessionSTSClient("admin"),
	}

	_, err := testableServerRevokeCommand(context.Background(), input)
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("Expected ErrSessionExpired, got: %v", err)
	}
}

// TestServerRevokeCommand_InvalidSessionID tests error for invalid session ID format.
func TestServerRevokeCommand_InvalidSessionID(t *testing.T) {
	invalidIDs := []string{
		"invalid",           // Not 16 hex chars
		"ABC1234567890DEF",  // Uppercase
		"abc123def456789",   // Too short (15 chars)
		"abc1234567890defg", // Too long (17 chars)
		"abc-123-456-890d",  // Contains dashes
		"",                  // Empty
	}

	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			input := ServerRevokeCommandInput{
				SessionID: id,
				Reason:    "Test reason",
				STSClient: newMockSessionSTSClient("admin"),
			}

			_, err := testableServerRevokeCommand(context.Background(), input)
			if err == nil {
				t.Errorf("Expected error for invalid session ID %q", id)
			}
		})
	}
}

// TestServerRevokeCommand_EmptyReason tests error when reason is empty.
func TestServerRevokeCommand_EmptyReason(t *testing.T) {
	input := ServerRevokeCommandInput{
		SessionID: "abc1234567890def",
		Reason:    "", // Empty reason
		STSClient: newMockSessionSTSClient("admin"),
	}

	_, err := testableServerRevokeCommand(context.Background(), input)
	if err == nil {
		t.Error("Expected error for empty reason")
	}
	expectedErr := "reason is required for revocation"
	if err != nil && err.Error() != expectedErr {
		t.Errorf("Expected error %q, got: %v", expectedErr, err)
	}
}

// TestServerRevokeCommand_JSONOutput tests that revocation returns correct data for JSON output.
func TestServerRevokeCommand_JSONOutput(t *testing.T) {
	now := time.Now()
	activeSession := &session.ServerSession{
		ID:               "abc1234567890def",
		User:             "alice",
		Profile:          "production",
		Status:           session.StatusActive,
		StartedAt:        now.Add(-30 * time.Minute),
		LastAccessAt:     now.Add(-5 * time.Minute),
		ExpiresAt:        now.Add(30 * time.Minute),
		RequestCount:     42,
		ServerInstanceID: "server-1",
	}

	store := &mockSessionStore{
		getFn: func(ctx context.Context, id string) (*session.ServerSession, error) {
			if id == activeSession.ID {
				sessCopy := *activeSession
				return &sessCopy, nil
			}
			return nil, session.ErrSessionNotFound
		},
		updateFn: func(ctx context.Context, sess *session.ServerSession) error {
			return nil
		},
	}

	input := ServerRevokeCommandInput{
		SessionID:    activeSession.ID,
		Reason:       "Security audit",
		OutputFormat: "json",
		Store:        store,
		STSClient:    newMockSessionSTSClient("security-team"),
	}

	revokedSession, err := testableServerRevokeCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify the session data that would be in JSON output
	if revokedSession.ID != activeSession.ID {
		t.Errorf("Expected ID %q, got %q", activeSession.ID, revokedSession.ID)
	}
	if revokedSession.Status != session.StatusRevoked {
		t.Errorf("Expected status revoked, got %s", revokedSession.Status)
	}
	if revokedSession.RevokedBy != "securityteam" {
		t.Errorf("Expected revoked_by 'securityteam', got %s", revokedSession.RevokedBy)
	}
	if revokedSession.RevokedReason != "Security audit" {
		t.Errorf("Expected revoked_reason 'Security audit', got %s", revokedSession.RevokedReason)
	}
}

// TestServerRevokeCommand_StoreError tests error handling when store fails.
func TestServerRevokeCommand_StoreError(t *testing.T) {
	now := time.Now()
	activeSession := &session.ServerSession{
		ID:           "abc1234567890def",
		User:         "alice",
		Profile:      "production",
		Status:       session.StatusActive,
		StartedAt:    now.Add(-30 * time.Minute),
		LastAccessAt: now.Add(-5 * time.Minute),
		ExpiresAt:    now.Add(30 * time.Minute),
	}

	expectedErr := errors.New("DynamoDB write capacity exceeded")
	store := &mockSessionStore{
		getFn: func(ctx context.Context, id string) (*session.ServerSession, error) {
			if id == activeSession.ID {
				sessCopy := *activeSession
				return &sessCopy, nil
			}
			return nil, session.ErrSessionNotFound
		},
		updateFn: func(ctx context.Context, sess *session.ServerSession) error {
			return expectedErr
		},
	}

	input := ServerRevokeCommandInput{
		SessionID: activeSession.ID,
		Reason:    "Test revocation",
		Store:     store,
		STSClient: newMockSessionSTSClient("admin"),
	}

	_, err := testableServerRevokeCommand(context.Background(), input)
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error %v, got: %v", expectedErr, err)
	}
}
