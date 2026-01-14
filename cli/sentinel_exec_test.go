package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSentinelExecCommand_NestedSubshell(t *testing.T) {
	// Set AWS_SENTINEL to simulate nested shell
	t.Setenv("AWS_SENTINEL", "test-profile")

	input := SentinelExecCommandInput{
		ProfileName:     "test",
		PolicyParameter: "/sentinel/test",
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
		ProfileName:     "different-profile",
		PolicyParameter: "/sentinel/policies/default",
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
	// The sentinel exec command executes a subprocess with policy-gated AWS credentials:
	//
	//   sentinel exec --profile myprofile --policy-parameter /sentinel/policies/default -- aws s3 ls
	//
	// This will:
	// 1. Load the policy from SSM parameter /sentinel/policies/default
	// 2. Evaluate if the current user can access the "myprofile" profile at the current time
	// 3. If allowed, retrieve credentials and inject them into the subprocess environment
	// 4. Execute "aws s3 ls" with the injected credentials
}

func TestSentinelExecCommand_InvalidProfile(t *testing.T) {
	// Create a temp config file with known profiles
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config")

	configContent := `[profile production]
region = us-east-1

[profile staging]
region = us-west-2
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Set AWS_CONFIG_FILE to use our test config
	t.Setenv("AWS_CONFIG_FILE", configFile)

	input := SentinelExecCommandInput{
		ProfileName:     "nonexistent",
		PolicyParameter: "/sentinel/policies/default",
	}

	s := &Sentinel{}
	exitCode, err := SentinelExecCommand(context.Background(), input, s)

	// Verify exit code is 1 (non-zero)
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}

	// Verify error is returned
	if err == nil {
		t.Fatal("expected error for invalid profile, got nil")
	}

	errStr := err.Error()

	// Verify error message contains "not found"
	if !strings.Contains(errStr, "not found") {
		t.Errorf("error should mention 'not found', got: %s", errStr)
	}

	// Verify error mentions the profile name
	if !strings.Contains(errStr, "nonexistent") {
		t.Errorf("error should mention the profile name, got: %s", errStr)
	}

	// Verify error lists available profiles
	if !strings.Contains(errStr, "production") || !strings.Contains(errStr, "staging") {
		t.Errorf("error should list available profiles, got: %s", errStr)
	}
}

func TestSentinelExecCommand_ValidProfile_ReachesPolicy(t *testing.T) {
	// This test verifies that when profile is valid, exec proceeds past profile validation
	// It will fail at policy loading (no SSM access), but that's expected
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config")

	configContent := `[profile valid-profile]
region = us-east-1
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configFile)

	input := SentinelExecCommandInput{
		ProfileName:     "valid-profile",
		PolicyParameter: "/sentinel/policies/default",
	}

	s := &Sentinel{}
	_, err := SentinelExecCommand(context.Background(), input, s)

	// We expect an error (will fail at AWS config or policy loading),
	// but it should NOT be a profile validation error
	if err != nil && strings.Contains(err.Error(), "not found in AWS config") {
		t.Errorf("should not fail on profile validation for valid profile, got: %v", err)
	}
}
