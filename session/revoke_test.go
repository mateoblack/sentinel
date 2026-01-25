package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockStore implements Store interface for testing.
type mockStore struct {
	sessions       map[string]*ServerSession
	getErr         error
	updateErr      error
	getCalledWith  string
	updateCalledWith *ServerSession
}

func newMockStore() *mockStore {
	return &mockStore{
		sessions: make(map[string]*ServerSession),
	}
}

func (m *mockStore) Create(ctx context.Context, session *ServerSession) error {
	if _, exists := m.sessions[session.ID]; exists {
		return ErrSessionExists
	}
	m.sessions[session.ID] = session
	return nil
}

func (m *mockStore) Get(ctx context.Context, id string) (*ServerSession, error) {
	m.getCalledWith = id
	if m.getErr != nil {
		return nil, m.getErr
	}
	sess, exists := m.sessions[id]
	if !exists {
		return nil, ErrSessionNotFound
	}
	// Return a copy to avoid mutation
	copy := *sess
	return &copy, nil
}

func (m *mockStore) Update(ctx context.Context, session *ServerSession) error {
	m.updateCalledWith = session
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, exists := m.sessions[session.ID]; !exists {
		return ErrSessionNotFound
	}
	m.sessions[session.ID] = session
	return nil
}

func (m *mockStore) Delete(ctx context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

func (m *mockStore) ListByUser(ctx context.Context, user string, limit int) ([]*ServerSession, error) {
	return nil, nil
}

func (m *mockStore) ListByStatus(ctx context.Context, status SessionStatus, limit int) ([]*ServerSession, error) {
	return nil, nil
}

func (m *mockStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*ServerSession, error) {
	return nil, nil
}

func (m *mockStore) FindActiveByServerInstance(ctx context.Context, serverInstanceID string) (*ServerSession, error) {
	return nil, nil
}

func (m *mockStore) Touch(ctx context.Context, id string) error {
	return nil
}

func (m *mockStore) ListByTimeRange(ctx context.Context, start, end time.Time, limit int) ([]*ServerSession, error) {
	return nil, nil
}

func (m *mockStore) GetBySourceIdentity(ctx context.Context, sourceIdentity string) (*ServerSession, error) {
	return nil, nil
}

// createActiveSession creates an active session for testing.
func createActiveSession(id string) *ServerSession {
	now := time.Now().UTC()
	return &ServerSession{
		ID:               id,
		User:             "testuser",
		Profile:          "testprofile",
		ServerInstanceID: "server123",
		Status:           StatusActive,
		StartedAt:        now,
		LastAccessAt:     now,
		ExpiresAt:        now.Add(15 * time.Minute),
		RequestCount:     0,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// createRevokedSession creates a revoked session for testing.
func createRevokedSession(id string) *ServerSession {
	sess := createActiveSession(id)
	sess.Status = StatusRevoked
	sess.RevokedBy = "admin"
	sess.RevokedReason = "Security review"
	return sess
}

// createExpiredSession creates an expired session for testing.
func createExpiredSession(id string) *ServerSession {
	sess := createActiveSession(id)
	sess.Status = StatusExpired
	return sess
}

func TestRevoke_Success(t *testing.T) {
	t.Run("active session gets revoked", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()

		sessionID := "a1b2c3d4e5f67890"
		sess := createActiveSession(sessionID)
		store.sessions[sessionID] = sess

		input := RevokeInput{
			SessionID: sessionID,
			RevokedBy: "securityadmin",
			Reason:    "Incident response - compromised credentials",
		}

		result, err := Revoke(ctx, store, input)
		if err != nil {
			t.Fatalf("Revoke() error = %v, want nil", err)
		}

		// Verify status changed
		if result.Status != StatusRevoked {
			t.Errorf("result.Status = %v, want %v", result.Status, StatusRevoked)
		}

		// Verify RevokedBy populated
		if result.RevokedBy != input.RevokedBy {
			t.Errorf("result.RevokedBy = %q, want %q", result.RevokedBy, input.RevokedBy)
		}

		// Verify Reason populated
		if result.RevokedReason != input.Reason {
			t.Errorf("result.RevokedReason = %q, want %q", result.RevokedReason, input.Reason)
		}

		// Verify UpdatedAt was set
		if result.UpdatedAt.IsZero() {
			t.Error("result.UpdatedAt should not be zero")
		}

		// Verify store was updated
		storedSess, _ := store.Get(ctx, sessionID)
		if storedSess.Status != StatusRevoked {
			t.Errorf("stored session status = %v, want %v", storedSess.Status, StatusRevoked)
		}
	})
}

func TestRevoke_AlreadyRevoked(t *testing.T) {
	t.Run("revoked session returns ErrSessionAlreadyRevoked", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()

		sessionID := "a1b2c3d4e5f67890"
		sess := createRevokedSession(sessionID)
		store.sessions[sessionID] = sess

		input := RevokeInput{
			SessionID: sessionID,
			RevokedBy: "admin2",
			Reason:    "Duplicate revocation attempt",
		}

		_, err := Revoke(ctx, store, input)
		if !errors.Is(err, ErrSessionAlreadyRevoked) {
			t.Errorf("Revoke() error = %v, want %v", err, ErrSessionAlreadyRevoked)
		}
	})
}

func TestRevoke_Expired(t *testing.T) {
	t.Run("expired session returns ErrSessionExpired", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()

		sessionID := "a1b2c3d4e5f67890"
		sess := createExpiredSession(sessionID)
		store.sessions[sessionID] = sess

		input := RevokeInput{
			SessionID: sessionID,
			RevokedBy: "admin",
			Reason:    "Cannot revoke expired session",
		}

		_, err := Revoke(ctx, store, input)
		if !errors.Is(err, ErrSessionExpired) {
			t.Errorf("Revoke() error = %v, want %v", err, ErrSessionExpired)
		}
	})
}

func TestRevoke_NotFound(t *testing.T) {
	t.Run("non-existent session returns ErrSessionNotFound", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()

		input := RevokeInput{
			SessionID: "a1b2c3d4e5f67890",
			RevokedBy: "admin",
			Reason:    "Session does not exist",
		}

		_, err := Revoke(ctx, store, input)
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("Revoke() error = %v, want %v", err, ErrSessionNotFound)
		}
	})
}

func TestRevoke_InvalidInput(t *testing.T) {
	testCases := []struct {
		name  string
		input RevokeInput
	}{
		{
			name: "empty SessionID",
			input: RevokeInput{
				SessionID: "",
				RevokedBy: "admin",
				Reason:    "Valid reason",
			},
		},
		{
			name: "empty RevokedBy",
			input: RevokeInput{
				SessionID: "a1b2c3d4e5f67890",
				RevokedBy: "",
				Reason:    "Valid reason",
			},
		},
		{
			name: "empty Reason",
			input: RevokeInput{
				SessionID: "a1b2c3d4e5f67890",
				RevokedBy: "admin",
				Reason:    "",
			},
		},
		{
			name: "invalid SessionID format",
			input: RevokeInput{
				SessionID: "invalid-format",
				RevokedBy: "admin",
				Reason:    "Valid reason",
			},
		},
		{
			name: "all empty",
			input: RevokeInput{
				SessionID: "",
				RevokedBy: "",
				Reason:    "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := newMockStore()

			_, err := Revoke(ctx, store, tc.input)
			if !errors.Is(err, ErrInvalidRevokeInput) {
				t.Errorf("Revoke() error = %v, want %v", err, ErrInvalidRevokeInput)
			}
		})
	}
}

func TestRevoke_StoreGetError(t *testing.T) {
	t.Run("store Get error is propagated", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()
		expectedErr := errors.New("DynamoDB connection failed")
		store.getErr = expectedErr

		input := RevokeInput{
			SessionID: "a1b2c3d4e5f67890",
			RevokedBy: "admin",
			Reason:    "Valid reason",
		}

		_, err := Revoke(ctx, store, input)
		if !errors.Is(err, expectedErr) {
			t.Errorf("Revoke() error = %v, want %v", err, expectedErr)
		}
	})
}

func TestRevoke_StoreUpdateError(t *testing.T) {
	t.Run("store Update error is propagated", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()

		sessionID := "a1b2c3d4e5f67890"
		sess := createActiveSession(sessionID)
		store.sessions[sessionID] = sess

		expectedErr := errors.New("DynamoDB write capacity exceeded")
		store.updateErr = expectedErr

		input := RevokeInput{
			SessionID: sessionID,
			RevokedBy: "admin",
			Reason:    "Valid reason",
		}

		_, err := Revoke(ctx, store, input)
		if !errors.Is(err, expectedErr) {
			t.Errorf("Revoke() error = %v, want %v", err, expectedErr)
		}
	})
}

func TestIsSessionRevoked(t *testing.T) {
	t.Run("returns true for revoked session", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()

		sessionID := "a1b2c3d4e5f67890"
		sess := createRevokedSession(sessionID)
		store.sessions[sessionID] = sess

		revoked, err := IsSessionRevoked(ctx, store, sessionID)
		if err != nil {
			t.Fatalf("IsSessionRevoked() error = %v, want nil", err)
		}
		if !revoked {
			t.Error("IsSessionRevoked() = false, want true")
		}
	})

	t.Run("returns false for active session", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()

		sessionID := "a1b2c3d4e5f67890"
		sess := createActiveSession(sessionID)
		store.sessions[sessionID] = sess

		revoked, err := IsSessionRevoked(ctx, store, sessionID)
		if err != nil {
			t.Fatalf("IsSessionRevoked() error = %v, want nil", err)
		}
		if revoked {
			t.Error("IsSessionRevoked() = true, want false")
		}
	})

	t.Run("returns false for expired session", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()

		sessionID := "a1b2c3d4e5f67890"
		sess := createExpiredSession(sessionID)
		store.sessions[sessionID] = sess

		revoked, err := IsSessionRevoked(ctx, store, sessionID)
		if err != nil {
			t.Fatalf("IsSessionRevoked() error = %v, want nil", err)
		}
		if revoked {
			t.Error("IsSessionRevoked() = true, want false for expired (not revoked)")
		}
	})

	t.Run("returns false for not found (fail-open)", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()

		revoked, err := IsSessionRevoked(ctx, store, "nonexistent12345")
		if err != nil {
			t.Fatalf("IsSessionRevoked() error = %v, want nil (fail-open)", err)
		}
		if revoked {
			t.Error("IsSessionRevoked() = true, want false (fail-open on not found)")
		}
	})

	t.Run("returns error for store errors (not ErrSessionNotFound)", func(t *testing.T) {
		ctx := context.Background()
		store := newMockStore()
		expectedErr := errors.New("DynamoDB connection failed")
		store.getErr = expectedErr

		_, err := IsSessionRevoked(ctx, store, "a1b2c3d4e5f67890")
		if !errors.Is(err, expectedErr) {
			t.Errorf("IsSessionRevoked() error = %v, want %v", err, expectedErr)
		}
	})
}

func TestRevokeInput_Validate(t *testing.T) {
	t.Run("valid input passes validation", func(t *testing.T) {
		input := RevokeInput{
			SessionID: "a1b2c3d4e5f67890",
			RevokedBy: "admin",
			Reason:    "Security incident",
		}

		err := input.Validate()
		if err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("uppercase session ID fails validation", func(t *testing.T) {
		input := RevokeInput{
			SessionID: "A1B2C3D4E5F67890",
			RevokedBy: "admin",
			Reason:    "Valid reason",
		}

		err := input.Validate()
		if !errors.Is(err, ErrInvalidRevokeInput) {
			t.Errorf("Validate() error = %v, want %v", err, ErrInvalidRevokeInput)
		}
	})

	t.Run("short session ID fails validation", func(t *testing.T) {
		input := RevokeInput{
			SessionID: "a1b2c3d4e5f6789",
			RevokedBy: "admin",
			Reason:    "Valid reason",
		}

		err := input.Validate()
		if !errors.Is(err, ErrInvalidRevokeInput) {
			t.Errorf("Validate() error = %v, want %v", err, ErrInvalidRevokeInput)
		}
	})
}
