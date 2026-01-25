package lambda

import (
	"context"
	"log"
	"time"

	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/session"
)

// SessionContext holds session state for a TVM request.
// Created at the start of HandleRequest, used throughout the request lifecycle.
type SessionContext struct {
	// ID is the session ID (empty if session tracking disabled).
	ID string

	// Session is the ServerSession record (nil if session tracking disabled).
	Session *session.ServerSession

	// Store is the session store (nil if disabled).
	Store session.Store
}

// CreateSessionContext creates a new session if session tracking is enabled.
// Returns empty SessionContext if SessionStore is nil.
// The deviceID parameter is optional (empty string means no device binding).
func CreateSessionContext(ctx context.Context, cfg *TVMConfig, username, profile, deviceID string) *SessionContext {
	sc := &SessionContext{
		Store: cfg.SessionStore,
	}

	if cfg.SessionStore == nil {
		return sc
	}

	// Generate session ID
	sessionID := session.NewSessionID()
	now := time.Now().UTC()

	// Calculate expiry based on config
	duration := cfg.DefaultDuration
	if duration == 0 {
		duration = 15 * time.Minute
	}

	// Create session record
	serverSession := &session.ServerSession{
		ID:               sessionID,
		User:             username,
		Profile:          profile,
		ServerInstanceID: identity.NewRequestID(), // Each Lambda invocation is unique
		Status:           session.StatusActive,
		StartedAt:        now,
		LastAccessAt:     now,
		ExpiresAt:        now.Add(duration),
		RequestCount:     0,
		DeviceID:         deviceID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	// Store session (best-effort - don't fail request on session error)
	if err := cfg.SessionStore.Create(ctx, serverSession); err != nil {
		log.Printf("Warning: failed to create session: %v", err)
		return sc
	}

	sc.ID = sessionID
	sc.Session = serverSession
	if deviceID != "" {
		log.Printf("Session created: %s user=%s profile=%s device_bound=true", sessionID, username, profile)
	} else {
		log.Printf("Session created: %s user=%s profile=%s", sessionID, username, profile)
	}

	return sc
}

// Touch updates LastAccessAt and increments RequestCount.
// No-op if session tracking is disabled.
func (sc *SessionContext) Touch(ctx context.Context) {
	if sc.Store == nil || sc.ID == "" {
		return
	}

	if err := sc.Store.Touch(ctx, sc.ID); err != nil {
		log.Printf("Warning: failed to touch session: %v", err)
	}
}

// CheckRevocation checks if the session has been revoked.
// Returns true if revoked, false otherwise.
// Fails-closed: revoked = deny. Fails-open on store errors for availability.
func (sc *SessionContext) CheckRevocation(ctx context.Context) bool {
	if sc.Store == nil || sc.ID == "" {
		return false // Not tracking, not revoked
	}

	revoked, err := session.IsSessionRevoked(ctx, sc.Store, sc.ID)
	if err != nil {
		// Store error - fail open for availability
		log.Printf("Warning: failed to check session revocation: %v", err)
		return false
	}

	if revoked {
		log.Printf("Session revoked: %s - denying credentials", sc.ID)
	}
	return revoked
}

// Expire marks the session as expired.
// Called on handler completion or error.
func (sc *SessionContext) Expire(ctx context.Context) {
	if sc.Store == nil || sc.ID == "" {
		return
	}

	sess, err := sc.Store.Get(ctx, sc.ID)
	if err != nil {
		log.Printf("Warning: failed to get session for expiry: %v", err)
		return
	}

	if !sess.Status.IsTerminal() {
		sess.Status = session.StatusExpired
		sess.UpdatedAt = time.Now().UTC()
		if err := sc.Store.Update(ctx, sess); err != nil {
			log.Printf("Warning: failed to expire session: %v", err)
		}
	}
}
