//go:build linux || darwin

package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/vault"
)

// NewEcsServerUnix creates an EcsServer using Unix domain sockets
// with process-based authentication.
func NewEcsServerUnix(ctx context.Context, baseCredsProvider aws.CredentialsProvider, config *vault.ProfileConfig, socketPath string, socketMode os.FileMode, lazyLoadBaseCreds bool) (*EcsServer, error) {
	// Determine socket path
	if socketPath == "" {
		socketPath = filepath.Join(os.TempDir(), fmt.Sprintf("ecs-creds-%d.sock", os.Getpid()))
	}

	// Determine socket mode
	if socketMode == 0 {
		socketMode = 0600
	}

	// Create process authenticator
	processAuth := NewProcessAuthenticator()

	// Generate token bound to current user (PID binding happens on first use)
	currentUID := uint32(os.Getuid())
	token, err := processAuth.GenerateToken(0, currentUID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to generate process token: %w", err)
	}

	// Pre-fetch credentials if not lazy loading
	credsCache := aws.NewCredentialsCache(baseCredsProvider)
	if !lazyLoadBaseCreds {
		_, err := credsCache.Retrieve(ctx)
		if err != nil {
			return nil, fmt.Errorf("Retrieving creds: %w", err)
		}
	}

	e := &EcsServer{
		authToken:         token.Token,
		baseCredsProvider: credsCache,
		config:            config,
		processAuth:       processAuth,
	}

	// Create router with credential routes
	router := http.NewServeMux()
	router.HandleFunc("/", e.DefaultRoute)
	router.HandleFunc("/role-arn/", e.AssumeRoleArnRoute)

	// Wrap with process authentication
	authedHandler := WithProcessAuth(processAuth, router)

	// Wrap with logging
	loggedHandler := withLogging(authedHandler)

	// Create Unix server
	unixConfig := UnixServerConfig{
		SocketPath:    socketPath,
		SocketMode:    socketMode,
		Handler:       loggedHandler,
		AllowFallback: false,
		BoundUID:      currentUID,
	}

	unixServer, err := NewUnixServer(ctx, unixConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Unix server: %w", err)
	}

	e.unixServer = unixServer
	e.listener = nil // Not used in Unix mode

	return e, nil
}
