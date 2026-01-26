//go:build linux || darwin

package server

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessAuthenticator_GenerateToken(t *testing.T) {
	pa := NewProcessAuthenticator()

	token, err := pa.GenerateToken(12345, 1000, false)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if token.Token == "" {
		t.Error("token should not be empty")
	}
	if token.BoundPID != 12345 {
		t.Errorf("expected PID 12345, got %d", token.BoundPID)
	}
	if token.BoundUID != 1000 {
		t.Errorf("expected UID 1000, got %d", token.BoundUID)
	}
}

func TestProcessAuthenticator_ValidateRequest_Success(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "process-auth-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create Unix socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	pa := NewProcessAuthenticator()
	currentUID := uint32(os.Getuid())
	currentPID := int32(os.Getpid())

	// Register token bound to current process
	token := pa.RegisterToken("test-token-123", currentPID, currentUID, false)

	done := make(chan error)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", token.Token)

		validatedToken, err := pa.ValidateRequest(req, conn)
		if err != nil {
			done <- err
			return
		}

		if validatedToken.Token != token.Token {
			done <- errors.New("token mismatch")
			return
		}

		done <- nil
	}()

	// Connect as client
	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err != nil {
		t.Fatalf("validation failed: %v", err)
	}
}

func TestProcessAuthenticator_ValidateRequest_WrongUID(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "process-auth-test")
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
	// Register token with wrong UID
	token := pa.RegisterToken("test-token-456", 0, 99999, false)

	done := make(chan error)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", token.Token)

		_, err = pa.ValidateRequest(req, conn)
		if err == nil {
			done <- errors.New("expected UID mismatch error")
			return
		}
		done <- nil // Expected to fail
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessAuthenticator_ValidateRequest_WrongPID(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "process-auth-test")
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
	// Register token with correct UID but wrong PID
	token := pa.RegisterToken("test-token-789", 99999, currentUID, false)

	done := make(chan error)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", token.Token)

		_, err = pa.ValidateRequest(req, conn)
		if err == nil {
			done <- errors.New("expected PID mismatch error")
			return
		}
		done <- nil // Expected to fail
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessAuthenticator_ValidateRequest_InvalidToken(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "process-auth-test")
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

	done := make(chan error)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "invalid-token")

		_, err = pa.ValidateRequest(req, conn)
		if err == nil {
			done <- errors.New("expected invalid token error")
			return
		}
		done <- nil // Expected to fail
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessAuthenticator_TokenBinding(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "process-auth-test")
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
	currentPID := int32(os.Getpid())

	// Register token with PID=0 (unbound)
	token := pa.RegisterToken("bind-test-token", 0, currentUID, false)

	if token.BoundPID != 0 {
		t.Error("token should start unbound")
	}

	done := make(chan error)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", token.Token)

		_, err = pa.ValidateRequest(req, conn)
		if err != nil {
			done <- err
			return
		}

		done <- nil
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Token should now be bound to current PID
	if token.BoundPID != currentPID {
		t.Errorf("expected token bound to PID %d, got %d", currentPID, token.BoundPID)
	}
}

func TestProcessAuthenticator_FallbackMode(t *testing.T) {
	pa := NewProcessAuthenticator()

	// Register token with fallback enabled
	token := pa.RegisterToken("fallback-token", 12345, 1000, true)

	// Create a TCP connection (no peer credentials available)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	done := make(chan error)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", token.Token)

		// Should succeed in fallback mode despite TCP connection
		validated, err := pa.ValidateRequest(req, conn)
		if err != nil {
			done <- err
			return
		}
		if validated.Token != token.Token {
			done <- errors.New("token mismatch")
			return
		}
		done <- nil
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err != nil {
		t.Fatalf("fallback mode failed: %v", err)
	}
}

func TestProcessAuthenticator_RevokeToken(t *testing.T) {
	pa := NewProcessAuthenticator()
	token, _ := pa.GenerateToken(12345, 1000, true)

	// Token should exist
	pa.mu.RLock()
	_, exists := pa.tokens[token.Token]
	pa.mu.RUnlock()
	if !exists {
		t.Error("token should exist before revocation")
	}

	// Revoke
	pa.RevokeToken(token.Token)

	// Token should not exist
	pa.mu.RLock()
	_, exists = pa.tokens[token.Token]
	pa.mu.RUnlock()
	if exists {
		t.Error("token should not exist after revocation")
	}
}

func TestProcessAuthenticator_ValidateRequest_MissingAuthHeader(t *testing.T) {
	pa := NewProcessAuthenticator()

	// Create a mock connection (we won't actually use peer creds here)
	tmpDir, err := os.MkdirTemp("", "process-auth-test")
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

	done := make(chan error)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		req, _ := http.NewRequest("GET", "/", nil)
		// No Authorization header

		_, err = pa.ValidateRequest(req, conn)
		if err == nil {
			done <- errors.New("expected error for missing auth header")
			return
		}
		if err.Error() != "missing Authorization header" {
			done <- errors.New("expected 'missing Authorization header' error")
			return
		}
		done <- nil
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
