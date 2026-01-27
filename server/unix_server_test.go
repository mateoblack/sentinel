//go:build linux || darwin

package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixServer_BasicOperation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-server-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "server.sock")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	config := UnixServerConfig{
		SocketPath: socketPath,
		Handler:    handler,
		BoundUID:   uint32(os.Getuid()),
	}

	ctx := context.Background()
	server, err := NewUnixServer(ctx, config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Start server in background
	go server.Serve()
	defer server.Shutdown(ctx)

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect and make request
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	resp, err := client.Get("http://unix/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "success" {
		t.Errorf("expected 'success', got %q", string(body))
	}
}

func TestUnixServer_SocketPermissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-server-perm-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "server.sock")

	config := UnixServerConfig{
		SocketPath: socketPath,
		SocketMode: 0600, // Owner only
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		BoundUID:   uint32(os.Getuid()),
	}

	ctx := context.Background()
	server, err := NewUnixServer(ctx, config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(ctx)

	// Check socket permissions
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("expected socket mode 0600, got %o", mode)
	}
}

func TestUnixServer_CleanupOnShutdown(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-server-cleanup-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "server.sock")

	config := UnixServerConfig{
		SocketPath: socketPath,
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		BoundUID:   uint32(os.Getuid()),
	}

	ctx := context.Background()
	server, err := NewUnixServer(ctx, config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Verify socket exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("socket should exist after server creation")
	}

	// Shutdown
	server.Shutdown(ctx)

	// Verify socket is cleaned up
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket should be removed after shutdown")
	}
}

func TestUnixServer_WithProcessAuth(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-server-auth-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "auth-server.sock")
	currentUID := uint32(os.Getuid())
	currentPID := int32(os.Getpid())

	authenticator := NewProcessAuthenticator()
	token := authenticator.RegisterToken("server-test-token", currentPID, currentUID, false)

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify we can get the token from context
		pt := GetProcessTokenFromContext(r.Context())
		if pt == nil {
			t.Error("expected token in context")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authenticated"))
	})

	config := UnixServerConfig{
		SocketPath: socketPath,
		Handler:    WithProcessAuth(authenticator, innerHandler),
		BoundUID:   currentUID,
	}

	ctx := context.Background()
	server, err := NewUnixServer(ctx, config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	go server.Serve()
	defer server.Shutdown(ctx)

	time.Sleep(50 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	// Request with valid token
	req, _ := http.NewRequest("GET", "http://unix/", nil)
	req.Header.Set("Authorization", token.Token)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Request with invalid token
	req2, _ := http.NewRequest("GET", "http://unix/", nil)
	req2.Header.Set("Authorization", "wrong-token")

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 for invalid token, got %d", resp2.StatusCode)
	}
}

func TestUnixServer_SocketURL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-server-url-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "url-test.sock")

	config := UnixServerConfig{
		SocketPath: socketPath,
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		BoundUID:   uint32(os.Getuid()),
	}

	ctx := context.Background()
	server, err := NewUnixServer(ctx, config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(ctx)

	expectedURL := "unix://" + socketPath
	if server.SocketURL() != expectedURL {
		t.Errorf("expected URL %q, got %q", expectedURL, server.SocketURL())
	}

	if server.SocketPath() != socketPath {
		t.Errorf("expected path %q, got %q", socketPath, server.SocketPath())
	}
}

func TestUnixServer_Authenticator(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-server-authenticator-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "auth-test.sock")

	config := UnixServerConfig{
		SocketPath: socketPath,
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		BoundUID:   uint32(os.Getuid()),
	}

	ctx := context.Background()
	server, err := NewUnixServer(ctx, config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer server.Shutdown(ctx)

	// Get authenticator and generate a token
	auth := server.Authenticator()
	if auth == nil {
		t.Fatal("expected non-nil authenticator")
	}

	token, err := auth.GenerateToken(int32(os.Getpid()), uint32(os.Getuid()), false)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if token.Token == "" {
		t.Error("expected non-empty token")
	}
}

func TestUnixServer_RemoveExistingSocket(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "unix-server-existing-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "existing.sock")

	// Create an existing regular file at socket path (simulating stale socket)
	// Note: In Go 1.25+, closing a Unix listener removes the socket file,
	// so we create a regular file to simulate a stale/orphaned socket path
	if err := os.WriteFile(socketPath, []byte{}, 0600); err != nil {
		t.Fatalf("failed to create stale socket file: %v", err)
	}

	// Verify file exists at socket path
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Fatal("expected existing socket file")
	}

	// Create new server - should remove and replace existing socket
	config := UnixServerConfig{
		SocketPath: socketPath,
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		BoundUID:   uint32(os.Getuid()),
	}

	ctx := context.Background()
	server, err := NewUnixServer(ctx, config)
	if err != nil {
		t.Fatalf("failed to create server with existing socket: %v", err)
	}
	defer server.Shutdown(ctx)

	// New server should work
	go server.Serve()
	time.Sleep(50 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	resp, err := client.Get("http://unix/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestGetConnFromRequest_NoContext(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	conn := GetConnFromRequest(req)
	if conn != nil {
		t.Error("expected nil connection for request without connection context")
	}
}

func TestGetProcessTokenFromContext_NoContext(t *testing.T) {
	ctx := context.Background()
	token := GetProcessTokenFromContext(ctx)
	if token != nil {
		t.Error("expected nil token for context without token")
	}
}
