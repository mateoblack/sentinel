package lambda

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/byteness/aws-vault/v7/session"
)

func TestAuthorizer_HandleRequest_ValidSession(t *testing.T) {
	store := newMockSessionStore()
	store.sessions["test-session-id"] = &session.ServerSession{
		ID:     "test-session-id",
		Status: session.StatusActive,
	}

	auth := NewAuthorizer(store, "test-table")

	req := events.APIGatewayV2CustomAuthorizerV2Request{
		Headers: map[string]string{
			"X-Sentinel-Session-ID": "test-session-id",
		},
	}

	resp, err := auth.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.IsAuthorized {
		t.Error("expected authorized response for valid session")
	}
}

func TestAuthorizer_HandleRequest_RevokedSession(t *testing.T) {
	store := newMockSessionStore()
	store.sessions["revoked-session"] = &session.ServerSession{
		ID:     "revoked-session",
		Status: session.StatusRevoked,
	}

	auth := NewAuthorizer(store, "test-table")

	req := events.APIGatewayV2CustomAuthorizerV2Request{
		Headers: map[string]string{
			"X-Sentinel-Session-ID": "revoked-session",
		},
	}

	resp, err := auth.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.IsAuthorized {
		t.Error("expected denied response for revoked session")
	}
}

func TestAuthorizer_HandleRequest_MissingSessionID(t *testing.T) {
	store := newMockSessionStore()
	auth := NewAuthorizer(store, "test-table")

	req := events.APIGatewayV2CustomAuthorizerV2Request{
		Headers: map[string]string{},
	}

	resp, err := auth.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.IsAuthorized {
		t.Error("expected denied response when session ID is missing")
	}
}

func TestAuthorizer_HandleRequest_QueryParam(t *testing.T) {
	store := newMockSessionStore()
	store.sessions["query-session"] = &session.ServerSession{
		ID:     "query-session",
		Status: session.StatusActive,
	}

	auth := NewAuthorizer(store, "test-table")

	req := events.APIGatewayV2CustomAuthorizerV2Request{
		QueryStringParameters: map[string]string{
			"sentinel_session_id": "query-session",
		},
	}

	resp, err := auth.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.IsAuthorized {
		t.Error("expected authorized response for session ID in query param")
	}
}

func TestAuthorizer_HandleRequest_StoreError(t *testing.T) {
	store := newMockSessionStore()
	store.getErr = errors.New("DynamoDB error")

	auth := NewAuthorizer(store, "test-table")

	req := events.APIGatewayV2CustomAuthorizerV2Request{
		Headers: map[string]string{
			"X-Sentinel-Session-ID": "any-session",
		},
	}

	resp, err := auth.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Fail-closed: errors result in deny
	if resp.IsAuthorized {
		t.Error("expected denied response on store error (fail-closed)")
	}
}

func TestAuthorizer_ValidateSession(t *testing.T) {
	store := newMockSessionStore()
	store.sessions["valid-session"] = &session.ServerSession{
		ID:     "valid-session",
		Status: session.StatusActive,
	}
	store.sessions["revoked-session"] = &session.ServerSession{
		ID:     "revoked-session",
		Status: session.StatusRevoked,
	}

	auth := NewAuthorizer(store, "test-table")

	tests := []struct {
		name      string
		sessionID string
		wantErr   error
	}{
		{"empty session ID", "", ErrMissingSessionID},
		{"valid session", "valid-session", nil},
		{"revoked session", "revoked-session", ErrSessionRevoked},
		{"not found", "unknown", ErrSessionNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.ValidateSession(context.Background(), tt.sessionID)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateSession(%q) = %v, want %v", tt.sessionID, err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("ValidateSession(%q) = %v, want nil", tt.sessionID, err)
			}
		})
	}
}

func TestExtractSessionID_HeaderCaseInsensitive(t *testing.T) {
	store := newMockSessionStore()
	auth := NewAuthorizer(store, "test-table")

	tests := []struct {
		headerKey string
		expected  string
	}{
		{"X-Sentinel-Session-ID", "test-id"},
		{"x-sentinel-session-id", "test-id"},
		{"X-SENTINEL-SESSION-ID", "test-id"},
	}

	for _, tt := range tests {
		req := events.APIGatewayV2CustomAuthorizerV2Request{
			Headers: map[string]string{
				tt.headerKey: "test-id",
			},
		}
		result := auth.extractSessionID(req)
		if result != tt.expected {
			t.Errorf("extractSessionID with header %q = %q, want %q",
				tt.headerKey, result, tt.expected)
		}
	}
}
