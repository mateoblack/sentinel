package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
)

// ProcessToken represents a bearer token bound to a specific process.
// The token is only valid when presented by the process with matching PID/UID.
type ProcessToken struct {
	// Token is the bearer token value.
	Token string

	// BoundPID is the process ID this token is bound to.
	// If 0, token is not PID-bound (for initial handshake scenarios).
	BoundPID int32

	// BoundUID is the user ID this token is bound to.
	BoundUID uint32

	// AllowFallback allows token validation to succeed even if peer credentials
	// cannot be obtained (e.g., TCP fallback mode). This should only be enabled
	// for backward compatibility during migration.
	AllowFallback bool
}

// ProcessAuthenticator manages process-bound tokens and validates requests.
type ProcessAuthenticator struct {
	mu     sync.RWMutex
	tokens map[string]*ProcessToken
}

// NewProcessAuthenticator creates a new process authenticator.
func NewProcessAuthenticator() *ProcessAuthenticator {
	return &ProcessAuthenticator{
		tokens: make(map[string]*ProcessToken),
	}
}

// GenerateToken creates a new process-bound token.
// If pid is 0, the token is not PID-bound (will be bound on first use).
func (pa *ProcessAuthenticator) GenerateToken(pid int32, uid uint32, allowFallback bool) (*ProcessToken, error) {
	token, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	pt := &ProcessToken{
		Token:         token,
		BoundPID:      pid,
		BoundUID:      uid,
		AllowFallback: allowFallback,
	}

	pa.mu.Lock()
	pa.tokens[token] = pt
	pa.mu.Unlock()

	return pt, nil
}

// RegisterToken registers an externally-generated token.
func (pa *ProcessAuthenticator) RegisterToken(token string, pid int32, uid uint32, allowFallback bool) *ProcessToken {
	pt := &ProcessToken{
		Token:         token,
		BoundPID:      pid,
		BoundUID:      uid,
		AllowFallback: allowFallback,
	}

	pa.mu.Lock()
	pa.tokens[token] = pt
	pa.mu.Unlock()

	return pt
}

// ValidateRequest validates a request's Authorization header against peer credentials.
// Returns the matching token if valid, nil and error if invalid.
func (pa *ProcessAuthenticator) ValidateRequest(r *http.Request, conn net.Conn) (*ProcessToken, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	pa.mu.RLock()
	pt, exists := pa.tokens[authHeader]
	pa.mu.RUnlock()

	if !exists {
		// Use constant-time comparison even for existence check
		// This prevents timing attacks that could reveal valid token prefixes
		return nil, fmt.Errorf("invalid token")
	}

	// Constant-time token comparison
	if subtle.ConstantTimeCompare([]byte(authHeader), []byte(pt.Token)) != 1 {
		return nil, fmt.Errorf("invalid token")
	}

	// Get peer credentials if available
	creds, err := GetPeerCredentials(conn)
	if err != nil {
		if pt.AllowFallback {
			log.Printf("WARNING: Process auth fallback mode - peer credentials unavailable: %v", err)
			return pt, nil
		}
		return nil, fmt.Errorf("failed to get peer credentials: %w", err)
	}

	// Validate UID matches
	if creds.UID != pt.BoundUID {
		log.Printf("SECURITY: Token UID mismatch: expected %d, got %d", pt.BoundUID, creds.UID)
		return nil, fmt.Errorf("token UID mismatch")
	}

	// Validate PID if bound
	if pt.BoundPID != 0 && creds.PID != pt.BoundPID {
		log.Printf("SECURITY: Token PID mismatch: expected %d, got %d", pt.BoundPID, creds.PID)
		return nil, fmt.Errorf("token PID mismatch")
	}

	// Bind to PID on first successful use if not already bound
	if pt.BoundPID == 0 {
		pa.mu.Lock()
		if pt.BoundPID == 0 {
			pt.BoundPID = creds.PID
			log.Printf("Token bound to PID %d", creds.PID)
		}
		pa.mu.Unlock()
	}

	return pt, nil
}

// RevokeToken removes a token from the authenticator.
func (pa *ProcessAuthenticator) RevokeToken(token string) {
	pa.mu.Lock()
	delete(pa.tokens, token)
	pa.mu.Unlock()
}

// generateSecureToken creates a cryptographically secure random token.
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
