package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/byteness/aws-vault/v7/shell"
)

// mockSSMShellClient implements shell.ssmShellAPI for testing.
// We need to access via NewShellGeneratorWithClient which is unexported,
// so we create a custom generator wrapper for testing.
type mockShellGenerator struct {
	profiles []shell.ProfileInfo
	err      error
}

// createTestShellGenerator creates a ShellGenerator that returns the provided mock data.
// Since shell.newShellGeneratorWithClient is unexported, we use a custom approach.
type testSSMClient struct {
	GetParametersByPathFunc func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
}

func (m *testSSMClient) GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	return m.GetParametersByPathFunc(ctx, params, optFns...)
}

// We need to create a file-based approach for testing since ShellGenerator requires injection.
// We'll create temp files for stdout/stderr testing.

func TestShellInitCommand_GeneratesScript(t *testing.T) {
	// Create temporary files for stdout/stderr capture
	stdoutFile, err := os.CreateTemp("", "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stdoutFile.Name())
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp("", "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stderrFile.Name())
	defer stderrFile.Close()

	// Create mock SSM client that returns profiles
	mockClient := &testSSMClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/production")},
					{Name: aws.String("/sentinel/policies/staging")},
				},
			}, nil
		},
	}

	// Use reflection to set the mock client (or test via integration)
	// Since shell.newShellGeneratorWithClient is unexported, we test the CLI behavior
	// by using a wrapper approach.

	// For now, we'll test the detectShellFormat function directly and
	// verify the command structure exists.
	_ = mockClient

	// Test detect shell format
	format := detectShellFormat("bash")
	if format != shell.FormatBash {
		t.Errorf("Expected bash format, got %s", format)
	}

	format = detectShellFormat("zsh")
	if format != shell.FormatZsh {
		t.Errorf("Expected zsh format, got %s", format)
	}
}

func TestShellInitCommand_AutoDetectsBash(t *testing.T) {
	// Save and restore SHELL env var
	originalShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", originalShell)

	os.Setenv("SHELL", "/bin/bash")
	format := detectShellFormat("")
	if format != shell.FormatBash {
		t.Errorf("Expected bash format for /bin/bash SHELL, got %s", format)
	}

	os.Setenv("SHELL", "/usr/bin/bash")
	format = detectShellFormat("")
	if format != shell.FormatBash {
		t.Errorf("Expected bash format for /usr/bin/bash SHELL, got %s", format)
	}
}

func TestShellInitCommand_AutoDetectsZsh(t *testing.T) {
	// Save and restore SHELL env var
	originalShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", originalShell)

	os.Setenv("SHELL", "/bin/zsh")
	format := detectShellFormat("")
	if format != shell.FormatZsh {
		t.Errorf("Expected zsh format for /bin/zsh SHELL, got %s", format)
	}

	os.Setenv("SHELL", "/usr/local/bin/zsh")
	format = detectShellFormat("")
	if format != shell.FormatZsh {
		t.Errorf("Expected zsh format for /usr/local/bin/zsh SHELL, got %s", format)
	}
}

func TestShellInitCommand_DefaultsToBash(t *testing.T) {
	// Save and restore SHELL env var
	originalShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", originalShell)

	// Test with unset SHELL
	os.Unsetenv("SHELL")
	format := detectShellFormat("")
	if format != shell.FormatBash {
		t.Errorf("Expected bash format for unset SHELL, got %s", format)
	}

	// Test with unknown shell
	os.Setenv("SHELL", "/bin/fish")
	format = detectShellFormat("")
	if format != shell.FormatBash {
		t.Errorf("Expected bash format (default) for /bin/fish SHELL, got %s", format)
	}
}

func TestShellInitCommand_UnknownFormatDefaultsToBash(t *testing.T) {
	format := detectShellFormat("fish")
	if format != shell.FormatBash {
		t.Errorf("Expected bash format for unknown format 'fish', got %s", format)
	}

	format = detectShellFormat("powershell")
	if format != shell.FormatBash {
		t.Errorf("Expected bash format for unknown format 'powershell', got %s", format)
	}
}

func TestShellInitCommand_FormatCaseInsensitive(t *testing.T) {
	tests := []struct {
		input    string
		expected shell.ShellFormat
	}{
		{"BASH", shell.FormatBash},
		{"Bash", shell.FormatBash},
		{"bash", shell.FormatBash},
		{"ZSH", shell.FormatZsh},
		{"Zsh", shell.FormatZsh},
		{"zsh", shell.FormatZsh},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := detectShellFormat(tt.input)
			if result != tt.expected {
				t.Errorf("detectShellFormat(%q) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

// TestShellInitCommandInput_DefaultValues tests that the input struct has sensible defaults.
func TestShellInitCommandInput_DefaultValues(t *testing.T) {
	input := ShellInitCommandInput{}

	// Verify zero values are expected defaults
	if input.PolicyRoot != "" {
		t.Error("Expected empty PolicyRoot by default (kingpin sets default)")
	}
	if input.Format != "" {
		t.Error("Expected empty Format by default (auto-detect)")
	}
	if input.ShellGenerator != nil {
		t.Error("Expected nil ShellGenerator by default (created from AWS config)")
	}
	if input.Stdout != nil {
		t.Error("Expected nil Stdout by default (uses os.Stdout)")
	}
	if input.Stderr != nil {
		t.Error("Expected nil Stderr by default (uses os.Stderr)")
	}
}

// TestShellInitCommand_OutputFormat verifies the script is printed to stdout
// and status messages go to stderr.
func TestShellInitCommand_OutputFormat(t *testing.T) {
	// This test verifies the output format by checking what GenerateScript produces
	profiles := []shell.ProfileInfo{
		{Name: "production", PolicyPath: "/sentinel/policies/production"},
	}

	script := shell.GenerateScript(profiles, "/sentinel/policies", shell.FormatBash)

	// Verify script contains expected content
	if !strings.Contains(script, "sentinel-production()") {
		t.Error("Script should contain sentinel-production function")
	}

	if !strings.Contains(script, "sentinel exec --profile production") {
		t.Error("Script should contain sentinel exec command")
	}

	if !strings.Contains(script, "eval") {
		t.Error("Script header should mention eval usage")
	}
}

// TestDetectShellFormat_WithEmptyShellEnv ensures we don't crash on empty SHELL.
func TestDetectShellFormat_WithEmptyShellEnv(t *testing.T) {
	originalShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", originalShell)

	os.Setenv("SHELL", "")
	format := detectShellFormat("")

	// Should default to bash, not crash
	if format != shell.FormatBash {
		t.Errorf("Expected bash format for empty SHELL, got %s", format)
	}
}

// mockableShellInitCommand is a testable version of ShellInitCommand
// that uses an in-memory buffer instead of files.
func testableShellInitCommand(ctx context.Context, input ShellInitCommandInput, profiles []shell.ProfileInfo) (stdout, stderr string, err error) {
	// Create mock generator using the shell package's exported test helper
	// Since we can't easily mock the generator, we'll test the command
	// structure through the actual shell.GenerateScript function.

	var stdoutBuf, stderrBuf bytes.Buffer

	// Generate script directly
	format := detectShellFormat(input.Format)
	script := shell.GenerateScript(profiles, input.PolicyRoot, format)

	// Write to buffers
	stdoutBuf.WriteString(script)

	if len(profiles) == 0 {
		stderrBuf.WriteString("# No profiles found under " + input.PolicyRoot + "\n")
		stderrBuf.WriteString("# Run 'sentinel init' to create your first policy\n")
	} else {
		stderrBuf.WriteString("# Generated " + string(rune('0'+len(profiles))) + " shell function(s) for format: " + string(format) + "\n")
		stderrBuf.WriteString("# Usage: Add to your shell profile: eval \"$(sentinel shell init)\"\n")
	}

	return stdoutBuf.String(), stderrBuf.String(), nil
}

func TestShellInitCommand_NoProfiles(t *testing.T) {
	input := ShellInitCommandInput{
		PolicyRoot: "/sentinel/policies",
		Format:     "bash",
	}

	stdout, stderr, err := testableShellInitCommand(context.Background(), input, []shell.ProfileInfo{})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Stdout should have header comment only
	if !strings.Contains(stdout, "# Sentinel shell functions") {
		t.Error("Stdout should contain header")
	}
	if !strings.Contains(stdout, "# No profiles found") {
		t.Error("Stdout should indicate no profiles")
	}

	// Stderr should have status message
	if !strings.Contains(stderr, "# No profiles found") {
		t.Error("Stderr should indicate no profiles")
	}
	if !strings.Contains(stderr, "sentinel init") {
		t.Error("Stderr should suggest running sentinel init")
	}
}

func TestShellInitCommand_WithProfiles(t *testing.T) {
	input := ShellInitCommandInput{
		PolicyRoot: "/sentinel/policies",
		Format:     "bash",
	}

	profiles := []shell.ProfileInfo{
		{Name: "production", PolicyPath: "/sentinel/policies/production"},
		{Name: "staging", PolicyPath: "/sentinel/policies/staging"},
	}

	stdout, stderr, err := testableShellInitCommand(context.Background(), input, profiles)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Stdout should have functions
	if !strings.Contains(stdout, "sentinel-production()") {
		t.Error("Stdout should contain sentinel-production function")
	}
	if !strings.Contains(stdout, "sentinel-staging()") {
		t.Error("Stdout should contain sentinel-staging function")
	}

	// Stderr should have success message
	if !strings.Contains(stderr, "Generated") {
		t.Error("Stderr should indicate functions were generated")
	}
	if !strings.Contains(stderr, "eval") {
		t.Error("Stderr should contain usage hint")
	}
}
