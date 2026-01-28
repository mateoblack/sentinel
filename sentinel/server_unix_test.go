//go:build linux

package sentinel

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/policy"
)

// TestSecurityRegression_UnixSocket_ProcessAuthentication verifies that
// only the process that received the token can use it.
func TestSecurityRegression_UnixSocket_ProcessAuthentication(t *testing.T) {
	t.Skip("DEPRECATED: Local server mode tests skipped - use Lambda TVM instead (v1.22)")
	tmpDir, err := os.MkdirTemp("", "sentinel-unix-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "test.sock")

	config := SentinelServerConfig{
		ProfileName:    "test-profile",
		User:           "test-user",
		LazyLoad:       true,
		UseUnixSocket:  true,
		UnixSocketPath: socketPath,
		UnixSocketMode: 0600,
		PolicyLoader:   &unixTestPolicyLoader{policy: &policy.Policy{Version: "1"}},
	}

	ctx := context.Background()
	server, err := NewSentinelServerUnix(ctx, config)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	go server.ServeUnix()
	defer server.ShutdownUnix(ctx)

	time.Sleep(50 * time.Millisecond)

	// Verify socket permissions
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("SECURITY: socket should be owner-only (0600), got %o", mode)
	}

	// Test that valid token works
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	req, _ := http.NewRequest("GET", "http://unix/", nil)
	req.Header.Set("Authorization", server.AuthToken())

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// Status might be error due to no credential provider, but should not be 403
	// (auth should pass, then fail at credential retrieval)
	if resp.StatusCode == http.StatusForbidden {
		t.Error("SECURITY: valid token should not be rejected")
	}

	// Test that invalid token is rejected
	req2, _ := http.NewRequest("GET", "http://unix/", nil)
	req2.Header.Set("Authorization", "invalid-token")

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("SECURITY: invalid token should be rejected with 403, got %d", resp2.StatusCode)
	}
}

// TestSecurityRegression_UnixSocket_SocketCleanup verifies that the socket
// is cleaned up on shutdown.
func TestSecurityRegression_UnixSocket_SocketCleanup(t *testing.T) {
	t.Skip("DEPRECATED: Local server mode tests skipped - use Lambda TVM instead (v1.22)")
	tmpDir, err := os.MkdirTemp("", "sentinel-unix-cleanup-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "cleanup.sock")

	config := SentinelServerConfig{
		ProfileName:    "test-profile",
		User:           "test-user",
		LazyLoad:       true,
		UseUnixSocket:  true,
		UnixSocketPath: socketPath,
		PolicyLoader:   &unixTestPolicyLoader{policy: &policy.Policy{Version: "1"}},
	}

	ctx := context.Background()
	server, err := NewSentinelServerUnix(ctx, config)
	if err != nil {
		t.Fatalf("failed to create Unix server: %v", err)
	}

	// Verify socket exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("socket should exist after server creation")
	}

	// Shutdown
	server.ShutdownUnix(ctx)

	// Verify socket is cleaned up
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("SECURITY: socket should be removed after shutdown")
	}
}

// TestSecurityRegression_UnixSocket_TCPFallbackDisabledByDefault verifies
// that TCP fallback is disabled by default.
func TestSecurityRegression_UnixSocket_TCPFallbackDisabledByDefault(t *testing.T) {
	t.Skip("DEPRECATED: Local server mode tests skipped - use Lambda TVM instead (v1.22)")
	config := SentinelServerConfig{
		ProfileName:   "test-profile",
		User:          "test-user",
		UseUnixSocket: true,
	}

	if config.AllowProcessAuthFallback {
		t.Error("SECURITY: TCP fallback should be disabled by default")
	}
}

// unixTestPolicyLoader is a test mock for PolicyLoader used in Unix-specific tests.
type unixTestPolicyLoader struct {
	policy *policy.Policy
	err    error
}

func (m *unixTestPolicyLoader) Load(ctx context.Context, path string) (*policy.Policy, error) {
	return m.policy, m.err
}
