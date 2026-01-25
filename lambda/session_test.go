package lambda

import (
	"context"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/session"
)

// mockSessionStore implements session.Store for testing.
type mockSessionStore struct {
	sessions  map[string]*session.ServerSession
	createErr error
	getErr    error
	touchErr  error
	updateErr error
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*session.ServerSession),
	}
}

func (m *mockSessionStore) Create(ctx context.Context, sess *session.ServerSession) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.sessions[sess.ID] = sess
	return nil
}

func (m *mockSessionStore) Get(ctx context.Context, id string) (*session.ServerSession, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	sess, ok := m.sessions[id]
	if !ok {
		return nil, session.ErrSessionNotFound
	}
	return sess, nil
}

func (m *mockSessionStore) Touch(ctx context.Context, id string) error {
	if m.touchErr != nil {
		return m.touchErr
	}
	sess, ok := m.sessions[id]
	if !ok {
		return session.ErrSessionNotFound
	}
	sess.LastAccessAt = time.Now().UTC()
	sess.RequestCount++
	return nil
}

func (m *mockSessionStore) Update(ctx context.Context, sess *session.ServerSession) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sessions[sess.ID] = sess
	return nil
}

// Implement remaining Store interface methods as no-ops for testing
func (m *mockSessionStore) Delete(ctx context.Context, id string) error { return nil }
func (m *mockSessionStore) ListByUser(ctx context.Context, user string, limit int) ([]*session.ServerSession, error) {
	return nil, nil
}
func (m *mockSessionStore) ListByStatus(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
	return nil, nil
}
func (m *mockSessionStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*session.ServerSession, error) {
	return nil, nil
}
func (m *mockSessionStore) FindActiveByServerInstance(ctx context.Context, serverInstanceID string) (*session.ServerSession, error) {
	return nil, nil
}
func (m *mockSessionStore) ListByTimeRange(ctx context.Context, start, end time.Time, limit int) ([]*session.ServerSession, error) {
	return nil, nil
}
func (m *mockSessionStore) GetBySourceIdentity(ctx context.Context, sourceIdentity string) (*session.ServerSession, error) {
	return nil, nil
}

func TestCreateSessionContext_NoStore(t *testing.T) {
	cfg := &TVMConfig{SessionStore: nil}
	sc := CreateSessionContext(context.Background(), cfg, "alice", "dev")

	if sc.ID != "" {
		t.Errorf("expected empty ID when store is nil, got %s", sc.ID)
	}
	if sc.Session != nil {
		t.Errorf("expected nil session when store is nil")
	}
}

func TestCreateSessionContext_WithStore(t *testing.T) {
	store := newMockSessionStore()
	cfg := &TVMConfig{
		SessionStore:    store,
		DefaultDuration: 15 * time.Minute,
	}

	sc := CreateSessionContext(context.Background(), cfg, "alice", "dev")

	if sc.ID == "" {
		t.Error("expected session ID to be set")
	}
	if sc.Session == nil {
		t.Error("expected session to be created")
	}
	if sc.Session.User != "alice" {
		t.Errorf("expected user alice, got %s", sc.Session.User)
	}
	if sc.Session.Profile != "dev" {
		t.Errorf("expected profile dev, got %s", sc.Session.Profile)
	}
	if sc.Session.Status != session.StatusActive {
		t.Errorf("expected status active, got %s", sc.Session.Status)
	}
}

func TestSessionContext_CheckRevocation_NotRevoked(t *testing.T) {
	store := newMockSessionStore()
	sess := &session.ServerSession{
		ID:     "test-session-1234",
		Status: session.StatusActive,
	}
	store.sessions[sess.ID] = sess

	sc := &SessionContext{
		ID:    sess.ID,
		Store: store,
	}

	if sc.CheckRevocation(context.Background()) {
		t.Error("expected not revoked for active session")
	}
}

func TestSessionContext_CheckRevocation_Revoked(t *testing.T) {
	store := newMockSessionStore()
	sess := &session.ServerSession{
		ID:     "test-session-1234",
		Status: session.StatusRevoked,
	}
	store.sessions[sess.ID] = sess

	sc := &SessionContext{
		ID:    sess.ID,
		Store: store,
	}

	if !sc.CheckRevocation(context.Background()) {
		t.Error("expected revoked for revoked session")
	}
}

func TestSessionContext_CheckRevocation_NoStore(t *testing.T) {
	sc := &SessionContext{
		ID:    "test-session",
		Store: nil,
	}

	if sc.CheckRevocation(context.Background()) {
		t.Error("expected not revoked when store is nil")
	}
}

func TestSessionContext_CheckRevocation_NoID(t *testing.T) {
	store := newMockSessionStore()
	sc := &SessionContext{
		ID:    "",
		Store: store,
	}

	if sc.CheckRevocation(context.Background()) {
		t.Error("expected not revoked when ID is empty")
	}
}

func TestSessionContext_Touch(t *testing.T) {
	store := newMockSessionStore()
	sess := &session.ServerSession{
		ID:           "test-session-1234",
		Status:       session.StatusActive,
		RequestCount: 0,
	}
	store.sessions[sess.ID] = sess

	sc := &SessionContext{
		ID:    sess.ID,
		Store: store,
	}

	sc.Touch(context.Background())

	// Verify request count incremented
	if sess.RequestCount != 1 {
		t.Errorf("expected request count 1, got %d", sess.RequestCount)
	}
}

func TestSessionContext_Touch_NoStore(t *testing.T) {
	sc := &SessionContext{
		ID:    "test-session",
		Store: nil,
	}

	// Should not panic
	sc.Touch(context.Background())
}

func TestSessionContext_Expire(t *testing.T) {
	store := newMockSessionStore()
	sess := &session.ServerSession{
		ID:     "test-session-1234",
		Status: session.StatusActive,
	}
	store.sessions[sess.ID] = sess

	sc := &SessionContext{
		ID:    sess.ID,
		Store: store,
	}

	sc.Expire(context.Background())

	// Verify status changed to expired
	if sess.Status != session.StatusExpired {
		t.Errorf("expected status expired, got %s", sess.Status)
	}
}

func TestSessionContext_Expire_AlreadyRevoked(t *testing.T) {
	store := newMockSessionStore()
	sess := &session.ServerSession{
		ID:     "test-session-1234",
		Status: session.StatusRevoked,
	}
	store.sessions[sess.ID] = sess

	sc := &SessionContext{
		ID:    sess.ID,
		Store: store,
	}

	sc.Expire(context.Background())

	// Status should remain revoked (terminal state)
	if sess.Status != session.StatusRevoked {
		t.Errorf("expected status to remain revoked, got %s", sess.Status)
	}
}

func TestVendInput_SessionID(t *testing.T) {
	input := &VendInput{
		SessionID: "test-session-id",
	}

	if input.SessionID != "test-session-id" {
		t.Errorf("expected session ID test-session-id, got %s", input.SessionID)
	}
}
