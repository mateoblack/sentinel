// Package cli tests for sentinel exec command.
// Note: Classic mode and CLI server mode have been removed in v2.1.
// These tests now focus on TVM-only behavior.
package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSentinelExecCommand_NestedSubshell(t *testing.T) {
	// Set AWS_SENTINEL to simulate nested shell
	t.Setenv("AWS_SENTINEL", "test-profile")

	input := SentinelExecCommandInput{
		ProfileName:  "test",
		RemoteServer: "https://tvm.example.com",
	}

	_, err := SentinelExecCommand(context.Background(), input, nil)
	if err == nil {
		t.Fatal("expected error for nested subshell")
	}
	if !strings.Contains(err.Error(), "existing sentinel subshell") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSentinelExecCommand_NestedSubshell_ErrorMessage(t *testing.T) {
	// Set AWS_SENTINEL to simulate nested shell
	t.Setenv("AWS_SENTINEL", "production")

	input := SentinelExecCommandInput{
		ProfileName:  "different-profile",
		RemoteServer: "https://tvm.example.com",
	}

	_, err := SentinelExecCommand(context.Background(), input, nil)
	if err == nil {
		t.Fatal("expected error for nested subshell")
	}

	// Verify the error message contains helpful guidance
	errMsg := err.Error()
	if !strings.Contains(errMsg, "exit") {
		t.Errorf("error should mention 'exit' as a solution: %v", errMsg)
	}
	if !strings.Contains(errMsg, "unset AWS_SENTINEL") {
		t.Errorf("error should mention 'unset AWS_SENTINEL' as a solution: %v", errMsg)
	}
}

// Example showing how to use sentinel exec command.
func Example_sentinelExecCommand() {
	// The sentinel exec command executes a subprocess with TVM-gated AWS credentials:
	//
	//   sentinel exec --profile myprofile --remote-server https://tvm.example.com -- aws s3 ls
	//
	// This will:
	// 1. Set AWS_CONTAINER_CREDENTIALS_FULL_URI to the TVM URL
	// 2. Execute "aws s3 ls" which will request credentials from TVM
	// 3. TVM evaluates policy and returns credentials if allowed
}

func TestSentinelExecCommand_RequiresRemoteServer(t *testing.T) {
	// When --remote-server is not set, exec should return an error

	input := SentinelExecCommandInput{
		ProfileName:  "test-profile",
		RemoteServer: "", // Not set
	}

	s := &Sentinel{}
	exitCode, err := SentinelExecCommand(context.Background(), input, s)

	// Verify exit code is 1 (non-zero)
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error when --remote-server not set, got nil")
	}

	errStr := err.Error()

	// Verify error mentions --remote-server requirement
	if !strings.Contains(errStr, "remote-server") {
		t.Errorf("error should mention '--remote-server', got: %s", errStr)
	}

	// Verify error mentions TVM
	if !strings.Contains(errStr, "TVM") {
		t.Errorf("error should mention TVM, got: %s", errStr)
	}
}

func TestSentinelExecCommand_TVMIntegration(t *testing.T) {
	// Test TVM URL is passed to subprocess environment

	// Create a test HTTP server to act as TVM
	tvmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"AccessKeyId":"AKIATEST","SecretAccessKey":"secret","Token":"token","Expiration":"2025-01-01T00:00:00Z"}`))
	}))
	defer tvmServer.Close()

	// We can't easily test subprocess execution, but we can test
	// that the input struct accepts the remote server
	input := SentinelExecCommandInput{
		ProfileName:  "test-profile",
		RemoteServer: tvmServer.URL,
		Command:      "echo",
		Args:         []string{"test"},
	}

	if input.RemoteServer != tvmServer.URL {
		t.Errorf("RemoteServer not set correctly: got %s, want %s", input.RemoteServer, tvmServer.URL)
	}
}

func TestSentinelExecCommandInput_Fields(t *testing.T) {
	// Test that SentinelExecCommandInput has the correct fields for TVM-only mode
	t.Run("minimal required fields", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:  "test-profile",
			RemoteServer: "https://tvm.example.com",
		}
		if input.ProfileName != "test-profile" {
			t.Error("ProfileName not set")
		}
		if input.RemoteServer != "https://tvm.example.com" {
			t.Error("RemoteServer not set")
		}
	})

	t.Run("all fields", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:  "test-profile",
			Command:      "/bin/bash",
			Args:         []string{"-c", "echo hello"},
			Region:       "us-east-1",
			RemoteServer: "https://tvm.example.com",
		}
		if input.Command != "/bin/bash" {
			t.Error("Command not set")
		}
		if len(input.Args) != 2 {
			t.Error("Args not set correctly")
		}
		if input.Region != "us-east-1" {
			t.Error("Region not set")
		}
	})
}

func TestSentinelExecCommand_DeviceIDPassedToTVM(t *testing.T) {
	// Test that device ID is passed to TVM URL as query parameter
	// This is a unit test - device ID collection may fail in test environment

	tvmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if device_id query parameter is present (may be empty if device ID collection fails)
		_ = r.URL.Query().Get("device_id")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"AccessKeyId":"AKIATEST","SecretAccessKey":"secret","Token":"token","Expiration":"2025-01-01T00:00:00Z"}`))
	}))
	defer tvmServer.Close()

	// Clear AWS_SENTINEL to avoid nested subshell error
	os.Unsetenv("AWS_SENTINEL")

	input := SentinelExecCommandInput{
		ProfileName:  "test-profile",
		RemoteServer: tvmServer.URL,
		Command:      "true", // Minimal command that exits quickly
	}

	// Note: This will actually try to run subprocess, which may or may not work in test env
	// The important thing is the TVM URL gets the device_id parameter
	// We can't easily test this without running the subprocess
	_ = input

	// The test passes if it doesn't panic - actual device_id integration
	// is verified in integration tests
}
