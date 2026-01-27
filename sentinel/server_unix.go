//go:build linux || darwin

// DEPRECATED: Unix socket server mode is deprecated in Sentinel v2.1.
// Use Lambda TVM (--remote-server) instead for verified server-side credential vending.
// See package comment in server.go for migration details.

package sentinel

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/byteness/aws-vault/v7/device"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/ratelimit"
	"github.com/byteness/aws-vault/v7/server"
	"github.com/byteness/aws-vault/v7/session"
)

// NewSentinelServerUnix creates a SentinelServer using Unix domain sockets
// with process-based authentication.
//
// DEPRECATED: NewSentinelServerUnix is deprecated in v2.1. Use Lambda TVM instead.
// This function now returns ErrServerDeprecated.
func NewSentinelServerUnix(ctx context.Context, config SentinelServerConfig) (*SentinelServer, error) {
	return nil, ErrServerDeprecated

	// The following code is retained for reference but is no longer executed.
	// Determine socket path
	socketPath := config.UnixSocketPath
	if socketPath == "" {
		socketPath = filepath.Join(os.TempDir(), fmt.Sprintf("sentinel-%d.sock", os.Getpid()))
	}

	// Determine socket mode
	socketMode := config.UnixSocketMode
	if socketMode == 0 {
		socketMode = 0600
	}

	// Create process authenticator
	processAuth := server.NewProcessAuthenticator()

	// Generate token bound to current process (it will serve itself)
	currentUID := uint32(os.Getuid())
	token, err := processAuth.GenerateToken(0, currentUID, config.AllowProcessAuthFallback)
	if err != nil {
		return nil, fmt.Errorf("failed to generate process token: %w", err)
	}

	// Generate ServerInstanceID if not provided
	serverInstanceID := config.ServerInstanceID
	if serverInstanceID == "" {
		serverInstanceID = identity.NewRequestID()
	}

	// Initialize rate limiter if configured
	var rateLimiter ratelimit.RateLimiter
	if config.RateLimiter != nil {
		rateLimiter = config.RateLimiter
	} else if config.RateLimitConfig != nil {
		limiter, limiterErr := ratelimit.NewMemoryRateLimiter(*config.RateLimitConfig)
		if limiterErr != nil {
			return nil, fmt.Errorf("failed to create rate limiter: %w", limiterErr)
		}
		rateLimiter = limiter
	}

	// Collect device ID for logging (fail-open)
	deviceID, deviceErr := device.GetDeviceID()
	if deviceErr != nil {
		log.Printf("Warning: failed to collect device ID for logging: %v", deviceErr)
		deviceID = ""
	}

	s := &SentinelServer{
		authToken:   token.Token,
		config:      config,
		rateLimiter: rateLimiter,
		deviceID:    deviceID,
		processAuth: processAuth,
	}

	// Create the credential handler (same as TCP mode)
	credHandler := http.HandlerFunc(s.DefaultRoute)

	// Wrap with process authentication
	authedHandler := server.WithProcessAuth(processAuth, credHandler)

	// Wrap with rate limiting
	rateLimitedHandler := withRateLimiting(rateLimiter, authedHandler.ServeHTTP)

	// Wrap with logging
	loggedHandler := withLogging(rateLimitedHandler)

	// Create Unix server
	unixConfig := server.UnixServerConfig{
		SocketPath:    socketPath,
		SocketMode:    socketMode,
		Handler:       loggedHandler,
		AllowFallback: config.AllowProcessAuthFallback,
		BoundUID:      currentUID,
	}

	unixServer, err := server.NewUnixServer(ctx, unixConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Unix server: %w", err)
	}

	s.unixServer = unixServer
	s.listener = nil // Not used in Unix mode

	// Prefetch credentials if not lazy loading
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
		prefetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := config.CredentialProvider.GetCredentialsWithSourceIdentity(prefetchCtx, credReq)
		if err != nil {
			unixServer.Shutdown(ctx)
			return nil, fmt.Errorf("failed to prefetch credentials: %w", err)
		}
	}

	// Create session if SessionStore is configured
	if config.SessionStore != nil {
		sessionID := session.NewSessionID()
		now := time.Now().UTC()

		sessionDuration := config.SessionDuration
		if sessionDuration == 0 {
			sessionDuration = DefaultServerSessionDuration
		}

		serverSession := &session.ServerSession{
			ID:               sessionID,
			User:             config.User,
			Profile:          config.ProfileName,
			ServerInstanceID: serverInstanceID,
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now,
			ExpiresAt:        now.Add(sessionDuration),
			RequestCount:     0,
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		if err := config.SessionStore.Create(ctx, serverSession); err != nil {
			log.Printf("Warning: failed to create session record: %v", err)
		} else {
			s.sessionID = sessionID
			log.Printf("Session created: %s for user %s profile %s (Unix socket)", sessionID, config.User, config.ProfileName)
		}
	}

	return s, nil
}

// ServeUnix starts serving on the Unix domain socket. This call blocks.
func (s *SentinelServer) ServeUnix() error {
	if s.unixServer == nil {
		return fmt.Errorf("Unix server not initialized - use NewSentinelServerUnix")
	}
	return s.unixServer.Serve()
}

// ShutdownUnix gracefully shuts down the Unix socket server.
func (s *SentinelServer) ShutdownUnix(ctx context.Context) error {
	if s.unixServer == nil {
		return nil
	}

	// Mark session as expired if tracking
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

	// Close rate limiter
	if s.rateLimiter != nil {
		if closer, ok := s.rateLimiter.(io.Closer); ok {
			if closeErr := closer.Close(); closeErr != nil {
				log.Printf("Warning: failed to close rate limiter: %v", closeErr)
			}
		}
	}

	return s.unixServer.Shutdown(ctx)
}

// UnixSocketPath returns the path to the Unix socket.
// Returns empty string if not in Unix socket mode.
func (s *SentinelServer) UnixSocketPath() string {
	if s.unixServer == nil {
		return ""
	}
	return s.unixServer.SocketPath()
}

// IsUnixMode returns true if the server is using Unix domain sockets.
func (s *SentinelServer) IsUnixMode() bool {
	return s.unixServer != nil
}
