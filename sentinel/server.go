// Package sentinel provides Sentinel's server mode for real-time credential revocation.
// This file implements the SentinelServer which evaluates policy on every credential request.
package sentinel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// CredentialProvider defines the interface for retrieving credentials with SourceIdentity.
// This abstraction enables testing without real AWS credentials.
type CredentialProvider interface {
	// GetCredentialsWithSourceIdentity retrieves credentials with SourceIdentity stamping.
	GetCredentialsWithSourceIdentity(ctx context.Context, req CredentialRequest) (*CredentialResult, error)
}

// CredentialRequest contains the input for credential retrieval.
type CredentialRequest struct {
	ProfileName     string
	NoSession       bool
	SessionDuration time.Duration
	Region          string
	User            string
	RequestID       string
}

// CredentialResult contains retrieved credentials.
type CredentialResult struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	CanExpire       bool
	SourceIdentity  string
	RoleARN         string
}

// SentinelServerConfig contains configuration for the Sentinel credential server.
type SentinelServerConfig struct {
	// ProfileName is the AWS profile to serve credentials for.
	ProfileName string

	// PolicyParameter is the SSM parameter path for policy.
	PolicyParameter string

	// Region is the AWS region.
	Region string

	// NoSession skips STS session token creation.
	NoSession bool

	// SessionDuration is the credential duration.
	SessionDuration time.Duration

	// User is the username for SourceIdentity (from STS GetCallerIdentity at server startup).
	User string

	// Logger is used for decision logging. Can be nil to disable logging.
	Logger logging.Logger

	// Store is the optional approval request store for checking approved requests.
	Store request.Store

	// BreakGlassStore is the optional break-glass store for checking active break-glass.
	BreakGlassStore breakglass.Store

	// PolicyLoader is the cached policy loader.
	PolicyLoader policy.PolicyLoader

	// CredentialProvider retrieves credentials with SourceIdentity stamping.
	CredentialProvider CredentialProvider

	// LazyLoad defers credential prefetch when true.
	LazyLoad bool
}

// SentinelServer is an HTTP server that serves policy-gated AWS credentials.
// It evaluates policy on each credential request, enabling real-time revocation.
type SentinelServer struct {
	listener  net.Listener
	authToken string
	server    http.Server
	config    SentinelServerConfig
}

// NewSentinelServer creates a new SentinelServer that listens on the specified port.
// If port is 0, an available port is automatically assigned.
// If authToken is empty, a random token is generated.
func NewSentinelServer(ctx context.Context, config SentinelServerConfig, authToken string, port int) (*SentinelServer, error) {
	// Listen on localhost only for security
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	// Generate random auth token if not provided
	if authToken == "" {
		authToken = generateRandomString()
	}

	// Prefetch credentials to ensure validity unless LazyLoad is enabled
	if !config.LazyLoad && config.CredentialProvider != nil {
		log.Printf("Prefetching credentials for profile %s", config.ProfileName)
		credReq := CredentialRequest{
			ProfileName:     config.ProfileName,
			Region:          config.Region,
			NoSession:       config.NoSession,
			SessionDuration: config.SessionDuration,
			User:            config.User,
			RequestID:       identity.NewRequestID(),
		}
		_, err := config.CredentialProvider.GetCredentialsWithSourceIdentity(ctx, credReq)
		if err != nil {
			listener.Close()
			return nil, fmt.Errorf("failed to prefetch credentials: %w", err)
		}
	}

	s := &SentinelServer{
		listener:  listener,
		authToken: authToken,
		config:    config,
	}

	// Set up HTTP router
	router := http.NewServeMux()
	router.HandleFunc("/", s.DefaultRoute)
	s.server.Handler = withLogging(withAuthorizationCheck(s.authToken, router.ServeHTTP))

	return s, nil
}

// DefaultRoute handles credential requests with policy evaluation.
// It evaluates policy before serving credentials, enabling real-time revocation.
func (s *SentinelServer) DefaultRoute(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Build policy request
	policyRequest := &policy.Request{
		User:    s.config.User,
		Profile: s.config.ProfileName,
		Time:    time.Now(),
		Mode:    policy.ModeServer, // Server mode - per-request evaluation
	}

	// Load policy
	loadedPolicy, err := s.config.PolicyLoader.Load(ctx, s.config.PolicyParameter)
	if err != nil {
		log.Printf("Failed to load policy: %v", err)
		writeErrorMessage(w, fmt.Sprintf("Failed to load policy: %v", err), http.StatusInternalServerError)
		return
	}

	// Evaluate policy
	decision := policy.Evaluate(loadedPolicy, policyRequest)

	// Handle deny decision - check for approved request or break-glass first
	var approvedReq *request.Request
	var activeBreakGlass *breakglass.BreakGlassEvent
	if decision.Effect == policy.EffectDeny {
		// Check for approved request before denying
		if s.config.Store != nil {
			var storeErr error
			approvedReq, storeErr = request.FindApprovedRequest(ctx, s.config.Store, s.config.User, s.config.ProfileName)
			if storeErr != nil {
				log.Printf("Warning: failed to check approved requests: %v", storeErr)
			}
		}

		// If no approved request, check for active break-glass
		if approvedReq == nil && s.config.BreakGlassStore != nil {
			var bgErr error
			activeBreakGlass, bgErr = breakglass.FindActiveBreakGlass(ctx, s.config.BreakGlassStore, s.config.User, s.config.ProfileName)
			if bgErr != nil {
				log.Printf("Warning: failed to check break-glass: %v", bgErr)
			}
		}

		if approvedReq == nil && activeBreakGlass == nil {
			// No approved request and no active break-glass - deny access
			if s.config.Logger != nil {
				entry := logging.NewDecisionLogEntry(policyRequest, decision, s.config.PolicyParameter)
				s.config.Logger.LogDecision(entry)
			}
			writeErrorMessage(w, "Policy denied access", http.StatusForbidden)
			return
		}
		// Approved request or active break-glass found - continue to credential issuance
	}

	// Cap session duration to remaining break-glass time if applicable
	sessionDuration := s.config.SessionDuration
	if activeBreakGlass != nil {
		remainingTime := breakglass.RemainingDuration(activeBreakGlass)
		if sessionDuration == 0 || sessionDuration > remainingTime {
			sessionDuration = remainingTime
			log.Printf("Capping session duration to break-glass remaining time: %v", remainingTime)
		}
	}

	// Generate request ID for correlation
	requestID := identity.NewRequestID()

	// Build credential request
	credReq := CredentialRequest{
		ProfileName:     s.config.ProfileName,
		Region:          s.config.Region,
		NoSession:       s.config.NoSession,
		SessionDuration: sessionDuration,
		User:            s.config.User,
		RequestID:       requestID,
	}

	// Retrieve credentials with SourceIdentity stamping
	creds, err := s.config.CredentialProvider.GetCredentialsWithSourceIdentity(ctx, credReq)
	if err != nil {
		log.Printf("Failed to retrieve credentials: %v", err)
		writeErrorMessage(w, fmt.Sprintf("Failed to retrieve credentials: %v", err), http.StatusInternalServerError)
		return
	}

	// Log allow decision with credential context
	if s.config.Logger != nil {
		credFields := &logging.CredentialIssuanceFields{
			RequestID:       requestID,
			SourceIdentity:  creds.SourceIdentity,
			RoleARN:         creds.RoleARN,
			SessionDuration: sessionDuration,
		}
		// Include approved request ID if credentials were issued via approval override
		if approvedReq != nil {
			credFields.ApprovedRequestID = approvedReq.ID
		}
		// Include break-glass event ID if credentials were issued via break-glass override
		if activeBreakGlass != nil {
			credFields.BreakGlassEventID = activeBreakGlass.ID
		}
		entry := logging.NewEnhancedDecisionLogEntry(policyRequest, decision, s.config.PolicyParameter, credFields)
		s.config.Logger.LogDecision(entry)
	}

	// Write credentials response (SDK-compatible format)
	writeCredsToResponse(creds, w)
}

// BaseURL returns the base URL of the server.
func (s *SentinelServer) BaseURL() string {
	return fmt.Sprintf("http://%s", s.listener.Addr().String())
}

// AuthToken returns the authorization token required for requests.
func (s *SentinelServer) AuthToken() string {
	return s.authToken
}

// Serve starts the HTTP server. This call blocks until the server is shut down.
func (s *SentinelServer) Serve() error {
	return s.server.Serve(s.listener)
}

// Shutdown gracefully shuts down the server.
func (s *SentinelServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// writeErrorMessage writes a JSON error response.
func writeErrorMessage(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{"Message": msg}); err != nil {
		log.Printf("Failed to write error response: %v", err)
	}
}

// withAuthorizationCheck is middleware that validates the Authorization header.
func withAuthorizationCheck(authToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authToken {
			writeErrorMessage(w, "invalid Authorization token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// withLogging is middleware that logs HTTP requests.
func withLogging(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestStart := time.Now()
		w2 := &loggingMiddlewareResponseWriter{w, http.StatusOK}
		handler.ServeHTTP(w2, r)
		log.Printf("http: %s: %d %s %s (%s)", r.RemoteAddr, w2.Code, r.Method, r.URL, time.Since(requestStart))
	})
}

// loggingMiddlewareResponseWriter captures the status code for logging.
type loggingMiddlewareResponseWriter struct {
	http.ResponseWriter
	Code int
}

func (w *loggingMiddlewareResponseWriter) WriteHeader(statusCode int) {
	w.Code = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// writeCredsToResponse writes credentials in SDK-compatible JSON format.
func writeCredsToResponse(creds *CredentialResult, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	err := json.NewEncoder(w).Encode(map[string]string{
		"AccessKeyId":     creds.AccessKeyID,
		"SecretAccessKey": creds.SecretAccessKey,
		"Token":           creds.SessionToken,
		"Expiration":      iso8601.Format(creds.Expiration),
	})
	if err != nil {
		log.Printf("Failed to write credentials response: %v", err)
	}
}

// generateRandomString generates a cryptographically random base64 string.
func generateRandomString() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
