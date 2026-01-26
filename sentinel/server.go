// Package sentinel provides Sentinel's server mode for real-time credential revocation.
// This file implements the SentinelServer which evaluates policy on every credential request.
package sentinel

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/device"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/ratelimit"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/session"
)

const (
	// DefaultServerSessionDuration is the default session duration in server mode.
	// Short sessions enable rapid credential revocation - policy changes take effect
	// within this window as credentials are refreshed per-request.
	// 15 minutes balances security (rapid revocation) with performance (SDK caches credentials).
	// AWS SDKs typically refresh 5 minutes before expiry, so 15-minute credentials
	// refresh roughly every 10 minutes.
	DefaultServerSessionDuration = 15 * time.Minute
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
	ApprovalID      string // Optional: approved request ID for SourceIdentity (empty = direct access)
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

	// SessionStore is the optional session store for tracking active sessions.
	// If nil, session tracking is disabled (best-effort feature).
	SessionStore session.Store

	// ServerInstanceID is a unique identifier for this server instance.
	// If empty, a new ID is generated using identity.NewRequestID().
	// Used for session correlation and multi-server scenarios.
	ServerInstanceID string

	// RateLimiter is the optional rate limiter for credential requests.
	// If nil, rate limiting is disabled.
	RateLimiter ratelimit.RateLimiter

	// RateLimitConfig is used to create a default rate limiter if RateLimiter is nil.
	// If both are nil, rate limiting is disabled.
	RateLimitConfig *ratelimit.Config
}

// SentinelServer is an HTTP server that serves policy-gated AWS credentials.
// It evaluates policy on each credential request, enabling real-time revocation.
type SentinelServer struct {
	listener    net.Listener
	authToken   string
	server      http.Server
	config      SentinelServerConfig
	rateLimiter ratelimit.RateLimiter

	// sessionID is the current session ID (created on startup if SessionStore is configured).
	// Empty string if session tracking is disabled.
	sessionID string

	// deviceID is the device identifier collected at server startup for decision logging.
	// Empty string if device ID collection failed (fail-open).
	deviceID string
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
		var err error
		authToken, err = generateRandomString()
		if err != nil {
			return nil, fmt.Errorf("failed to generate auth token: %w", err)
		}
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
		// Use timeout context to prevent blocking forever on slow credential providers
		prefetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := config.CredentialProvider.GetCredentialsWithSourceIdentity(prefetchCtx, credReq)
		if err != nil {
			listener.Close()
			return nil, fmt.Errorf("failed to prefetch credentials: %w", err)
		}
	}

	// Generate ServerInstanceID if not provided
	if config.ServerInstanceID == "" {
		config.ServerInstanceID = identity.NewRequestID()
	}

	// Initialize rate limiter if configured
	var rateLimiter ratelimit.RateLimiter
	if config.RateLimiter != nil {
		rateLimiter = config.RateLimiter
	} else if config.RateLimitConfig != nil {
		limiter, limiterErr := ratelimit.NewMemoryRateLimiter(*config.RateLimitConfig)
		if limiterErr != nil {
			listener.Close()
			return nil, fmt.Errorf("failed to create rate limiter: %w", limiterErr)
		}
		rateLimiter = limiter
	}

	// Collect device ID once at server startup for decision logging (fail-open)
	deviceID, deviceErr := device.GetDeviceID()
	if deviceErr != nil {
		log.Printf("Warning: failed to collect device ID for logging: %v", deviceErr)
		deviceID = "" // Continue without device ID
	}

	s := &SentinelServer{
		listener:    listener,
		authToken:   authToken,
		config:      config,
		rateLimiter: rateLimiter,
		deviceID:    deviceID,
	}

	// Create session if SessionStore is configured (best-effort tracking)
	if config.SessionStore != nil {
		sessionID := session.NewSessionID()
		now := time.Now().UTC()

		// Calculate session expiry: use SessionDuration or default
		sessionDuration := config.SessionDuration
		if sessionDuration == 0 {
			sessionDuration = DefaultServerSessionDuration
		}

		serverSession := &session.ServerSession{
			ID:               sessionID,
			User:             config.User,
			Profile:          config.ProfileName,
			ServerInstanceID: config.ServerInstanceID,
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now,
			ExpiresAt:        now.Add(sessionDuration),
			RequestCount:     0,
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		if err := config.SessionStore.Create(ctx, serverSession); err != nil {
			// Log error but don't fail server startup - session tracking is best-effort
			log.Printf("Warning: failed to create session record: %v", err)
		} else {
			s.sessionID = sessionID
			log.Printf("Session created: %s for user %s profile %s", sessionID, config.User, config.ProfileName)
		}
	}

	// Set up HTTP router
	router := http.NewServeMux()
	router.HandleFunc("/", s.DefaultRoute)
	// Middleware chain: logging -> auth -> rate limit -> handler
	s.server.Handler = withLogging(
		withAuthorizationCheck(s.authToken,
			withRateLimiting(s.rateLimiter,
				router.ServeHTTP)))

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
		log.Printf("ERROR: Failed to load policy from %s: %v", s.config.PolicyParameter, err)
		writeErrorMessage(w, "Failed to load policy", http.StatusInternalServerError)
		return
	}

	// Evaluate policy
	decision := policy.Evaluate(loadedPolicy, policyRequest)

	// Handle deny decision - check for approved request or break-glass first
	// Note: require_server rules return EffectAllow in server mode (handled by Evaluate),
	// so they never reach this deny block when accessed via SentinelServer.
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

	// Check for session revocation before serving credentials
	// Revocation check fails-closed for security (revoked = deny) but fails-open for store errors (availability)
	if s.sessionID != "" && s.config.SessionStore != nil {
		revoked, revokeErr := session.IsSessionRevoked(ctx, s.config.SessionStore, s.sessionID)
		if revokeErr != nil {
			// Store error - log but don't deny (fail-open for availability)
			log.Printf("Warning: failed to check session revocation: %v", revokeErr)
		} else if revoked {
			// Session is revoked - deny access immediately (fail-closed for security)
			log.Printf("Session revoked: %s - denying credentials", s.sessionID)
			writeErrorMessage(w, "Session revoked", http.StatusForbidden)
			return
		}
	}

	// Apply session duration capping (order: policy cap -> break-glass cap -> final)
	sessionDuration := s.config.SessionDuration

	// Apply policy-based session duration cap (if set by matched rule)
	if decision.MaxServerDuration > 0 {
		if sessionDuration == 0 || sessionDuration > decision.MaxServerDuration {
			sessionDuration = decision.MaxServerDuration
			log.Printf("Capping session duration to policy max_server_duration: %v", decision.MaxServerDuration)
		}
	}

	// Cap session duration to remaining break-glass time if applicable
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

	// If credentials are being issued via an approved request, include the approval ID
	// in the SourceIdentity. This enables AWS SCPs to distinguish between approved
	// and non-approved (direct) access.
	if approvedReq != nil {
		credReq.ApprovalID = approvedReq.ID
	}

	// Retrieve credentials with SourceIdentity stamping
	creds, err := s.config.CredentialProvider.GetCredentialsWithSourceIdentity(ctx, credReq)
	if err != nil {
		log.Printf("ERROR: Failed to retrieve credentials for profile=%s: %v", s.config.ProfileName, err)
		writeErrorMessage(w, "Failed to retrieve credentials", http.StatusInternalServerError)
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
		// Include device ID in logs for forensic correlation
		if s.deviceID != "" {
			credFields.DevicePosture = &device.DevicePosture{
				DeviceID: s.deviceID,
			}
		}
		entry := logging.NewEnhancedDecisionLogEntry(policyRequest, decision, s.config.PolicyParameter, credFields)
		s.config.Logger.LogDecision(entry)
	}

	// Touch session to update LastAccessAt and increment RequestCount
	// This is fire-and-forget - session tracking should not impact credential serving
	if s.sessionID != "" && s.config.SessionStore != nil {
		if touchErr := s.config.SessionStore.Touch(ctx, s.sessionID); touchErr != nil {
			log.Printf("Warning: failed to touch session: %v", touchErr)
		}
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
	// Mark session as expired if session tracking is enabled
	if s.sessionID != "" && s.config.SessionStore != nil {
		sess, err := s.config.SessionStore.Get(ctx, s.sessionID)
		if err != nil {
			log.Printf("Warning: failed to get session for shutdown: %v", err)
		} else if !sess.Status.IsTerminal() {
			sess.Status = session.StatusExpired
			sess.UpdatedAt = time.Now().UTC()
			if updateErr := s.config.SessionStore.Update(ctx, sess); updateErr != nil {
				log.Printf("Warning: failed to mark session expired on shutdown: %v", updateErr)
			} else {
				log.Printf("Session %s marked expired on shutdown", s.sessionID)
			}
		}
	}

	// Close rate limiter if it implements io.Closer
	if s.rateLimiter != nil {
		if closer, ok := s.rateLimiter.(io.Closer); ok {
			if closeErr := closer.Close(); closeErr != nil {
				log.Printf("Warning: failed to close rate limiter: %v", closeErr)
			}
		}
	}

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
// SECURITY: Uses constant-time comparison to prevent timing attacks on bearer tokens.
func withAuthorizationCheck(authToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// SECURITY: Use constant-time comparison to prevent timing attacks.
		// Direct string comparison (!=) returns early on first mismatched byte,
		// leaking timing information that allows attackers to extract the token
		// byte-by-byte by measuring response times.
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(authToken)) != 1 {
			writeErrorMessage(w, "invalid Authorization token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// withRateLimiting is middleware that enforces rate limits per remote address.
func withRateLimiting(limiter ratelimit.RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if limiter != nil {
			// Use remote address as rate limit key
			// For localhost server, this is always 127.0.0.1 but still provides burst protection
			key := r.RemoteAddr
			allowed, retryAfter, err := limiter.Allow(r.Context(), key)
			if err != nil {
				log.Printf("WARNING: Rate limit check failed: %v", err)
				// Fail open - allow the request
			} else if !allowed {
				log.Printf("RATE_LIMITED: addr=%s retry_after=%v", key, retryAfter)
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
				writeErrorMessage(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
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
func generateRandomString() (string, error) {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
