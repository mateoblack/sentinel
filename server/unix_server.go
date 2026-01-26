package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// UnixServer is an HTTP server that listens on a Unix domain socket
// and supports process-based authentication via peer credentials.
type UnixServer struct {
	listener      net.Listener
	socketPath    string
	server        http.Server
	authenticator *ProcessAuthenticator

	// mu protects cleanup state
	mu      sync.Mutex
	cleaned bool
}

// UnixServerConfig contains configuration for UnixServer.
type UnixServerConfig struct {
	// SocketPath is the path for the Unix domain socket.
	// If empty, a temporary socket in os.TempDir() is created.
	SocketPath string

	// SocketMode is the file mode for the socket (default: 0600).
	SocketMode os.FileMode

	// Handler is the HTTP handler to serve.
	Handler http.Handler

	// AllowFallback enables TCP fallback mode for testing/compatibility.
	// When true, tokens work even without peer credentials (less secure).
	AllowFallback bool

	// BoundUID is the UID to bind tokens to (usually current user).
	BoundUID uint32
}

// NewUnixServer creates a new Unix domain socket server.
func NewUnixServer(ctx context.Context, config UnixServerConfig) (*UnixServer, error) {
	socketPath := config.SocketPath
	if socketPath == "" {
		// Create temporary socket
		socketPath = filepath.Join(os.TempDir(), fmt.Sprintf("sentinel-%d.sock", os.Getpid()))
	}

	// Remove existing socket if it exists
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create Unix listener: %w", err)
	}

	// Set socket permissions (default: owner only)
	mode := config.SocketMode
	if mode == 0 {
		mode = 0600
	}
	if err := os.Chmod(socketPath, mode); err != nil {
		listener.Close()
		os.Remove(socketPath)
		return nil, fmt.Errorf("failed to set socket permissions: %w", err)
	}

	authenticator := NewProcessAuthenticator()

	us := &UnixServer{
		listener:      listener,
		socketPath:    socketPath,
		authenticator: authenticator,
	}

	us.server = http.Server{
		Handler: config.Handler,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// Store connection in context for later retrieval
			return context.WithValue(ctx, connContextKey{}, c)
		},
	}

	return us, nil
}

// connContextKey is the context key for storing the connection.
type connContextKey struct{}

// GetConnFromRequest retrieves the net.Conn from an HTTP request's context.
// This is used by handlers to get peer credentials.
func GetConnFromRequest(r *http.Request) net.Conn {
	if conn, ok := r.Context().Value(connContextKey{}).(net.Conn); ok {
		return conn
	}
	return nil
}

// SocketPath returns the path to the Unix socket.
func (us *UnixServer) SocketPath() string {
	return us.socketPath
}

// SocketURL returns the URL for connecting to this server.
// Format: unix:///path/to/socket
func (us *UnixServer) SocketURL() string {
	return fmt.Sprintf("unix://%s", us.socketPath)
}

// Authenticator returns the process authenticator for token management.
func (us *UnixServer) Authenticator() *ProcessAuthenticator {
	return us.authenticator
}

// Serve starts serving HTTP requests. This call blocks.
func (us *UnixServer) Serve() error {
	return us.server.Serve(us.listener)
}

// Shutdown gracefully shuts down the server.
func (us *UnixServer) Shutdown(ctx context.Context) error {
	us.mu.Lock()
	defer us.mu.Unlock()

	if us.cleaned {
		return nil
	}

	err := us.server.Shutdown(ctx)

	// Clean up socket file
	if rmErr := os.Remove(us.socketPath); rmErr != nil && !os.IsNotExist(rmErr) {
		log.Printf("Warning: failed to remove socket file: %v", rmErr)
	}

	us.cleaned = true
	return err
}

// WithProcessAuth creates HTTP middleware that validates process authentication.
// It extracts peer credentials from the connection and validates against the token.
func WithProcessAuth(authenticator *ProcessAuthenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := GetConnFromRequest(r)
		if conn == nil {
			log.Printf("ERROR: No connection context available for process auth")
			writeErrorMessage(w, "Authentication failed", http.StatusInternalServerError)
			return
		}

		token, err := authenticator.ValidateRequest(r, conn)
		if err != nil {
			log.Printf("SECURITY: Process auth failed: %v", err)
			writeErrorMessage(w, "invalid Authorization token", http.StatusForbidden)
			return
		}

		// Add token info to request context for handlers
		ctx := context.WithValue(r.Context(), processTokenContextKey{}, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// processTokenContextKey is the context key for storing the validated token.
type processTokenContextKey struct{}

// GetProcessTokenFromContext retrieves the validated ProcessToken from request context.
func GetProcessTokenFromContext(ctx context.Context) *ProcessToken {
	if token, ok := ctx.Value(processTokenContextKey{}).(*ProcessToken); ok {
		return token
	}
	return nil
}
