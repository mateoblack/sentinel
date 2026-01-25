// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/session"
)

// Authorizer environment variables.
const (
	// EnvAuthorizerSessionTable is the DynamoDB table name for session lookup.
	EnvAuthorizerSessionTable = "SENTINEL_SESSION_TABLE"
)

// AuthorizerErrors returned by the Lambda authorizer.
var (
	ErrMissingSessionID   = errors.New("missing SentinelSessionID in request")
	ErrSessionRevoked     = errors.New("session has been revoked")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionTableNotSet = errors.New("SENTINEL_SESSION_TABLE not configured")
)

// Authorizer handles Lambda authorizer requests for session validation.
// This enables sensitive downstream APIs to validate Sentinel session status
// before processing requests, supporting instant revocation.
//
// Usage pattern:
//  1. TVM vends credentials with SentinelSessionID session tag
//  2. Downstream API uses Lambda authorizer to validate session
//  3. If session is revoked, authorizer returns deny
//  4. Revocation propagates instantly (no credential expiry wait)
type Authorizer struct {
	store     session.Store
	tableName string
}

// NewAuthorizer creates a new Authorizer with the given session store.
func NewAuthorizer(store session.Store, tableName string) *Authorizer {
	return &Authorizer{
		store:     store,
		tableName: tableName,
	}
}

// NewAuthorizerFromEnv creates an Authorizer using environment variables.
// Returns error if SENTINEL_SESSION_TABLE is not set.
func NewAuthorizerFromEnv(ctx context.Context) (*Authorizer, error) {
	tableName := os.Getenv(EnvAuthorizerSessionTable)
	if tableName == "" {
		return nil, ErrSessionTableNotSet
	}

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create DynamoDB session store
	store := session.NewDynamoDBStore(awsCfg, tableName)

	return &Authorizer{
		store:     store,
		tableName: tableName,
	}, nil
}

// HandleRequest processes a Lambda authorizer request.
// Extracts SentinelSessionID from the request and validates against DynamoDB.
//
// The authorizer looks for session ID in this order:
//  1. Request headers: X-Sentinel-Session-ID
//  2. Query string parameter: sentinel_session_id
//
// Returns IAM policy allowing or denying the request.
func (a *Authorizer) HandleRequest(ctx context.Context, req events.APIGatewayV2CustomAuthorizerV2Request) (events.APIGatewayV2CustomAuthorizerSimpleResponse, error) {
	// Extract session ID from request
	sessionID := a.extractSessionID(req)
	if sessionID == "" {
		log.Printf("DENY: No SentinelSessionID found in request")
		return denyResponse(), nil
	}

	// Check session revocation
	revoked, err := session.IsSessionRevoked(ctx, a.store, sessionID)
	if err != nil {
		// Fail-closed: errors result in deny for security
		log.Printf("DENY: Failed to check session %s: %v", sessionID, err)
		return denyResponse(), nil
	}

	if revoked {
		log.Printf("DENY: Session %s is revoked", sessionID)
		return denyResponse(), nil
	}

	log.Printf("ALLOW: Session %s is valid", sessionID)
	return allowResponse(), nil
}

// extractSessionID extracts the Sentinel session ID from the request.
// Checks headers first, then query parameters.
func (a *Authorizer) extractSessionID(req events.APIGatewayV2CustomAuthorizerV2Request) string {
	// Check headers (case-insensitive)
	for key, value := range req.Headers {
		if strings.EqualFold(key, "X-Sentinel-Session-ID") {
			return value
		}
	}

	// Check query parameters
	if sessionID, ok := req.QueryStringParameters["sentinel_session_id"]; ok {
		return sessionID
	}

	// Session ID not found in request
	return ""
}

// allowResponse creates an allow response.
func allowResponse() events.APIGatewayV2CustomAuthorizerSimpleResponse {
	return events.APIGatewayV2CustomAuthorizerSimpleResponse{
		IsAuthorized: true,
	}
}

// denyResponse creates a deny response.
func denyResponse() events.APIGatewayV2CustomAuthorizerSimpleResponse {
	return events.APIGatewayV2CustomAuthorizerSimpleResponse{
		IsAuthorized: false,
	}
}

// ValidateSession is a convenience function for validating a session ID.
// Returns nil if session is valid, error otherwise.
func (a *Authorizer) ValidateSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return ErrMissingSessionID
	}

	revoked, err := session.IsSessionRevoked(ctx, a.store, sessionID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("failed to check session: %w", err)
	}

	if revoked {
		return ErrSessionRevoked
	}

	return nil
}
