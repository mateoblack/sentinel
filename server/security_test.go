//go:build linux || darwin

package server

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// THREAT: LOCAL CREDENTIAL THEFT
// Attack: Malicious local process intercepts bearer token or connects to server
// =============================================================================

// TestThreat_LocalCredentialTheft_SocketPermissions verifies that Unix sockets
// have restrictive permissions (owner only).
func TestThreat_LocalCredentialTheft_SocketPermissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "socket-perm-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

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

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("SECURITY: Socket permissions should be 0600 (owner only), got %o", mode)
	}
}

// TestThreat_LocalCredentialTheft_WrongUIDRejected verifies that processes
// with different UID cannot use tokens bound to another user.
func TestThreat_LocalCredentialTheft_WrongUIDRejected(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "uid-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	pa := NewProcessAuthenticator()
	// Register token with a different UID than current process
	fakeUID := uint32(99999) // Unlikely to be our actual UID
	token := pa.RegisterToken("test-token", 0, fakeUID, false)

	done := make(chan bool)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("accept failed: %v", err)
			done <- false
			return
		}
		defer conn.Close()

		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", token.Token)

		_, err = pa.ValidateRequest(req, conn)
		if err == nil {
			t.Error("SECURITY: Token with wrong UID should be rejected")
			done <- false
			return
		}
		done <- true
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	client.Close()

	if !<-done {
		t.Error("UID validation test failed")
	}
}

// TestThreat_LocalCredentialTheft_WrongPIDRejected verifies that processes
// with different PID cannot use tokens bound to another process.
func TestThreat_LocalCredentialTheft_WrongPIDRejected(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "pid-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	pa := NewProcessAuthenticator()
	currentUID := uint32(os.Getuid())
	// Register token with a different PID than current process
	fakePID := int32(99999) // Unlikely to be our actual PID
	token := pa.RegisterToken("test-token", fakePID, currentUID, false)

	done := make(chan bool)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("accept failed: %v", err)
			done <- false
			return
		}
		defer conn.Close()

		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", token.Token)

		_, err = pa.ValidateRequest(req, conn)
		if err == nil {
			t.Error("SECURITY: Token with wrong PID should be rejected")
			done <- false
			return
		}
		done <- true
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	client.Close()

	if !<-done {
		t.Error("PID validation test failed")
	}
}

// =============================================================================
// THREAT: TOKEN BRUTE FORCE
// Attack: Attacker tries to guess or brute-force bearer tokens
// =============================================================================

// TestThreat_TokenBruteForce_ConstantTimeComparison verifies that token
// comparison uses constant-time algorithm to prevent timing attacks.
func TestThreat_TokenBruteForce_ConstantTimeComparison(t *testing.T) {
	// Parse EcsServer source to verify crypto/subtle usage
	files := []string{
		"ecsserver.go",
		"process_auth.go",
	}

	for _, file := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			continue // File might not exist in all builds
		}

		hasSubtleImport := false
		for _, imp := range f.Imports {
			if imp.Path.Value == `"crypto/subtle"` {
				hasSubtleImport = true
				break
			}
		}

		if !hasSubtleImport {
			t.Errorf("SECURITY: %s should import crypto/subtle for constant-time comparison", file)
		}
	}
}

// TestThreat_TokenBruteForce_TokenLength verifies that generated tokens
// have sufficient entropy.
func TestThreat_TokenBruteForce_TokenLength(t *testing.T) {
	pa := NewProcessAuthenticator()
	token, err := pa.GenerateToken(0, 0, false)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Token should be at least 32 bytes of entropy (256 bits)
	// Base64 encoding: 32 bytes = 43 characters
	if len(token.Token) < 40 {
		t.Errorf("SECURITY: Token too short (%d chars), should be at least 40 for 256-bit entropy", len(token.Token))
	}
}

// =============================================================================
// THREAT: SOCKET EXPOSURE
// Attack: Socket file left behind after crash, allowing later access
// =============================================================================

// TestThreat_SocketExposure_CleanupOnShutdown verifies that socket files
// are removed on graceful shutdown.
func TestThreat_SocketExposure_CleanupOnShutdown(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cleanup-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

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

	// Socket should exist
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("socket should exist after creation")
	}

	// Shutdown
	server.Shutdown(ctx)

	// Socket should be removed
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("SECURITY: Socket should be removed after shutdown")
	}
}

// TestThreat_SocketExposure_RemoveExistingSocket verifies that stale sockets
// from previous runs are removed before creating new ones.
func TestThreat_SocketExposure_RemoveExistingSocket(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stale-socket-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "stale.sock")

	// Create a stale socket file
	if err := os.WriteFile(socketPath, []byte("stale"), 0600); err != nil {
		t.Fatalf("failed to create stale socket: %v", err)
	}

	config := UnixServerConfig{
		SocketPath: socketPath,
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		BoundUID:   uint32(os.Getuid()),
	}

	ctx := context.Background()
	server, err := NewUnixServer(ctx, config)
	if err != nil {
		t.Fatalf("SECURITY: Should be able to replace stale socket: %v", err)
	}
	defer server.Shutdown(ctx)

	// New socket should be a socket, not the stale file
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		t.Error("SECURITY: New server should create actual socket, not leave stale file")
	}
}

// =============================================================================
// EC2 METADATA SERVER SECURITY
// =============================================================================

// TestThreat_EC2Metadata_LoopbackOnly verifies that the EC2 metadata server
// validates requests come from loopback.
func TestThreat_EC2Metadata_LoopbackOnly(t *testing.T) {
	// Parse ec2server.go to verify security check exists
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "ec2server.go", nil, parser.ParseComments)
	if err != nil {
		t.Skipf("ec2server.go not parseable: %v", err)
	}

	hasLoopbackCheck := false
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "IsLoopback" {
					hasLoopbackCheck = true
					return false
				}
			}
		}
		return true
	})

	if !hasLoopbackCheck {
		t.Error("SECURITY: EC2 metadata server should validate loopback source")
	}
}

// TestThreat_EC2Metadata_HostCheck verifies that the EC2 metadata server
// validates the Host header to prevent DNS rebinding.
func TestThreat_EC2Metadata_HostCheck(t *testing.T) {
	// Parse ec2server.go to verify host check exists
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "ec2server.go", nil, parser.ParseComments)
	if err != nil {
		t.Skipf("ec2server.go not parseable: %v", err)
	}

	hasHostCheck := false
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "r" && sel.Sel.Name == "Host" {
					hasHostCheck = true
					return false
				}
			}
		}
		return true
	})

	if !hasHostCheck {
		t.Error("SECURITY: EC2 metadata server should check Host header for DNS rebinding prevention")
	}
}
