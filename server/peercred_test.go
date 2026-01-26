//go:build linux || darwin

package server

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestGetPeerCredentials_UnixSocket(t *testing.T) {
	// Create a temporary directory for the socket
	tmpDir, err := os.MkdirTemp("", "peercred-test")
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

	// Connect to the socket in a goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("failed to accept: %v", err)
			return
		}
		defer conn.Close()

		creds, err := GetPeerCredentials(conn)
		if err != nil {
			t.Errorf("failed to get peer credentials: %v", err)
			return
		}

		// Verify we got valid credentials
		if creds.PID <= 0 {
			t.Errorf("expected positive PID, got %d", creds.PID)
		}

		// UID should match current process
		expectedUID := uint32(os.Getuid())
		if creds.UID != expectedUID {
			t.Errorf("expected UID %d, got %d", expectedUID, creds.UID)
		}

		// GID should match current process primary group
		expectedGID := uint32(os.Getgid())
		if creds.GID != expectedGID {
			t.Errorf("expected GID %d, got %d", expectedGID, creds.GID)
		}
	}()

	// Connect as client
	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	client.Close()

	<-done
}

func TestGetPeerCredentials_TCPSocket_ReturnsError(t *testing.T) {
	// Create TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_, err = GetPeerCredentials(conn)
		if err == nil {
			t.Error("expected error for TCP socket, got nil")
			return
		}

		var notUnix *ErrNotUnixSocket
		if !errors.As(err, &notUnix) {
			t.Errorf("expected ErrNotUnixSocket, got %T", err)
		}
	}()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	client.Close()

	<-done
}

func TestPeerCredentials_String(t *testing.T) {
	creds := &PeerCredentials{
		PID: 12345,
		UID: 1000,
		GID: 1000,
	}

	expected := "pid=12345 uid=1000 gid=1000"
	if creds.String() != expected {
		t.Errorf("expected %q, got %q", expected, creds.String())
	}
}

func TestGetPeerCredentials_VerifiesCurrentProcess(t *testing.T) {
	// This test verifies that we get our own process credentials when connecting
	// to ourselves via Unix socket
	tmpDir, err := os.MkdirTemp("", "peercred-self-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "self.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	var serverCreds *PeerCredentials
	done := make(chan error)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		serverCreds, err = GetPeerCredentials(conn)
		done <- err
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	client.Close()

	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}

	// The client is our own process
	currentPID := int32(os.Getpid())
	if serverCreds.PID != currentPID {
		t.Errorf("expected PID %d (current process), got %d", currentPID, serverCreds.PID)
	}
}

func TestErrNotUnixSocket_Error(t *testing.T) {
	err := &ErrNotUnixSocket{ConnType: "TCP"}
	expected := "peer credentials only available for Unix sockets, got TCP"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrPeerCredentialsUnavailable_Error(t *testing.T) {
	err := &ErrPeerCredentialsUnavailable{
		Platform: "windows",
		Reason:   "not supported",
	}
	expected := "peer credentials unavailable on windows: not supported"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}
