package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// CLI Integration Tests
// ============================================================================
//
// These tests verify that CLI commands work correctly via `go run`:
// - All commands accept --help flag and show appropriate help text
// - Commands with required arguments return helpful error messages
// - Offline commands (validate, lint, shell init) are tested end-to-end
//
// Note: Commands requiring AWS credentials test help/error paths only
// to avoid external dependencies in CI.

// getProjectRoot returns the project root directory for running go commands.
func getProjectRoot(t *testing.T) string {
	t.Helper()
	// cli package is at project_root/cli, so go up one level
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	return filepath.Dir(cwd)
}

// runSentinelCommand runs a sentinel CLI command via go run and returns output.
func runSentinelCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	projectRoot := getProjectRoot(t)

	cmdArgs := append([]string{"run", "./cmd/sentinel"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	return string(output), err
}

// ============================================================================
// Command Inventory Tests - Verify all commands are registered
// ============================================================================

func TestIntegration_AllCommands_Registered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Run sentinel --help to see all registered commands
	output, err := runSentinelCommand(t, "--help")
	// --help returns exit code 0, err may be nil or indicate exit status
	_ = err

	// Only include commands that are registered in cmd/sentinel/main.go
	expectedCommands := []string{
		// Credential operations
		"credentials",
		"exec",

		// Access request commands
		"request",
		"approve",
		"deny",
		"check",
		"list",

		// Break-glass commands
		"breakglass",
		"breakglass-list",
		"breakglass-check",
		"breakglass-close",

		// Infrastructure/init commands
		"init",

		// Policy commands
		"policy",

		// Enforce commands
		"enforce",

		// Audit commands
		"audit",

		// Permissions commands
		"permissions",

		// Config commands
		"config",

		// Shell commands
		"shell",

		// Server session commands
		"server-sessions",
		"server-session",
		"server-revoke",

		// Device session commands
		"device-sessions",
		"devices",

		// Identity commands
		"whoami",
	}

	for _, cmd := range expectedCommands {
		if !strings.Contains(output, cmd) {
			t.Errorf("expected command %q to be registered, not found in help output", cmd)
		}
	}
}

// ============================================================================
// Credential Operations Tests
// ============================================================================

func TestIntegration_Credentials_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "credentials", "--help")
	_ = err // --help may return non-zero exit code

	expectedContent := []string{
		"credentials",
		"--profile",
		"--policy-parameter",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_Credentials_MissingArgs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "credentials")
	if err == nil {
		t.Error("expected error for missing required args")
	}

	// Should mention missing required flags
	if !strings.Contains(output, "profile") || !strings.Contains(output, "policy-parameter") {
		t.Errorf("error message should mention missing required args, got: %s", output)
	}
}

func TestIntegration_Exec_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "exec", "--help")
	_ = err

	expectedContent := []string{
		"exec",
		"--profile",
		"--policy-parameter",
		"--server",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Access Request Commands Tests
// ============================================================================

func TestIntegration_Request_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "request", "--help")
	_ = err

	expectedContent := []string{
		"request",
		"--profile",
		"--justification",
		"--request-table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_Approve_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "approve", "--help")
	_ = err

	expectedContent := []string{
		"approve",
		"--request-table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_Deny_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "deny", "--help")
	_ = err

	expectedContent := []string{
		"deny",
		"--request-table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_Check_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "check", "--help")
	_ = err

	expectedContent := []string{
		"check",
		"--request-table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_List_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "list", "--help")
	_ = err

	expectedContent := []string{
		"list",
		"--request-table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Break-Glass Commands Tests
// ============================================================================

func TestIntegration_BreakGlass_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "breakglass", "--help")
	_ = err

	expectedContent := []string{
		"breakglass",
		"--profile",
		"--reason-code",
		"--justification",
		"--breakglass-table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_BreakGlassList_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "breakglass-list", "--help")
	_ = err

	expectedContent := []string{
		"breakglass-list",
		"--breakglass-table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_BreakGlassCheck_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "breakglass-check", "--help")
	_ = err

	expectedContent := []string{
		"breakglass-check",
		"--breakglass-table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_BreakGlassClose_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "breakglass-close", "--help")
	_ = err

	expectedContent := []string{
		"breakglass-close",
		"--breakglass-table",
		"--reason",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Init Commands Tests
// ============================================================================

func TestIntegration_Init_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "init", "--help")
	_ = err

	// Check that init subcommands are listed
	expectedSubcommands := []string{
		"bootstrap",
		"status",
		"approvals",
		"breakglass",
		"sessions",
		"wizard",
	}
	for _, subcmd := range expectedSubcommands {
		if !strings.Contains(output, subcmd) {
			t.Errorf("init help missing subcommand: %q", subcmd)
		}
	}
}

func TestIntegration_InitBootstrap_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "init", "bootstrap", "--help")
	_ = err

	expectedContent := []string{
		"bootstrap",
		"--profile",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_InitStatus_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "init", "status", "--help")
	_ = err

	expectedContent := []string{
		"status",
		"--policy-root",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_InitApprovals_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "init", "approvals", "--help")
	_ = err

	expectedContent := []string{
		"approvals",
		"--region",
		"--table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_InitBreakglass_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "init", "breakglass", "--help")
	_ = err

	expectedContent := []string{
		"breakglass",
		"--region",
		"--table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_InitSessions_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "init", "sessions", "--help")
	_ = err

	expectedContent := []string{
		"sessions",
		"--region",
		"--table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_InitWizard_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "init", "wizard", "--help")
	_ = err

	expectedContent := []string{
		"wizard",
		"--profile",
		"--feature",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Policy Commands Tests
// ============================================================================

func TestIntegration_Policy_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "policy", "--help")
	_ = err

	// Check that policy subcommands are listed
	expectedSubcommands := []string{
		"pull",
		"push",
		"diff",
		"validate",
		"sign",
		"verify",
	}
	for _, subcmd := range expectedSubcommands {
		if !strings.Contains(output, subcmd) {
			t.Errorf("policy help missing subcommand: %q", subcmd)
		}
	}
}

func TestIntegration_PolicyPull_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "policy", "pull", "--help")
	_ = err

	expectedContent := []string{
		"pull",
		"--policy-root",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_PolicyPush_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "policy", "push", "--help")
	_ = err

	expectedContent := []string{
		"push",
		"--policy-root",
		"--sign",
		"--key-id",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_PolicyDiff_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "policy", "diff", "--help")
	_ = err

	expectedContent := []string{
		"diff",
		"--policy-root",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_PolicyValidate_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "policy", "validate", "--help")
	_ = err

	expectedContent := []string{
		"validate",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_PolicySign_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "policy", "sign", "--help")
	_ = err

	expectedContent := []string{
		"sign",
		"--key-id",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_PolicyVerify_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "policy", "verify", "--help")
	_ = err

	expectedContent := []string{
		"verify",
		"--key-id",
		"--signature",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Policy Validate - Offline Functional Test
// ============================================================================

func TestIntegration_PolicyValidate_ValidPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a temporary valid policy file with proper conditions
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	validPolicy := `version: "1"
rules:
  - name: allow-dev
    effect: allow
    conditions:
      profiles:
        - dev
    reason: Allow dev access
`
	if err := os.WriteFile(policyPath, []byte(validPolicy), 0600); err != nil {
		t.Fatalf("failed to write test policy: %v", err)
	}

	output, err := runSentinelCommand(t, "policy", "validate", policyPath)
	if err != nil {
		t.Errorf("expected valid policy to pass validation, got error: %v\nOutput: %s", err, output)
	}

	if !strings.Contains(output, "valid") {
		t.Errorf("expected output to indicate policy is valid, got: %s", output)
	}
}

func TestIntegration_PolicyValidate_InvalidPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a temporary invalid policy file (missing version)
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	invalidPolicy := `rules:
  - name: missing-version
    effect: allow
`
	if err := os.WriteFile(policyPath, []byte(invalidPolicy), 0600); err != nil {
		t.Fatalf("failed to write test policy: %v", err)
	}

	output, err := runSentinelCommand(t, "policy", "validate", policyPath)
	if err == nil {
		t.Error("expected invalid policy to fail validation")
	}

	// Should indicate validation failure
	if !strings.Contains(strings.ToLower(output), "error") && !strings.Contains(strings.ToLower(output), "invalid") {
		t.Errorf("expected output to indicate validation error, got: %s", output)
	}
}

// ============================================================================
// Enforce Commands Tests
// ============================================================================

func TestIntegration_Enforce_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "enforce", "--help")
	_ = err

	// Check that enforce subcommands are listed
	expectedSubcommands := []string{
		"plan",
		"generate",
	}
	for _, subcmd := range expectedSubcommands {
		if !strings.Contains(output, subcmd) {
			t.Errorf("enforce help missing subcommand: %q", subcmd)
		}
	}
}

func TestIntegration_EnforcePlan_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "enforce", "plan", "--help")
	_ = err

	expectedContent := []string{
		"plan",
		"--role",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_EnforceGenerate_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "enforce", "generate", "--help")
	_ = err

	expectedContent := []string{
		"generate",
		"trust-policy",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_EnforceGenerateTrustPolicy_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "enforce", "generate", "trust-policy", "--help")
	_ = err

	expectedContent := []string{
		"trust-policy",
		"--pattern",
		"--principal",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Audit Commands Tests
// ============================================================================

func TestIntegration_Audit_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "audit", "--help")
	_ = err

	// Check that audit subcommands are listed
	expectedSubcommands := []string{
		"verify",
		"untracked-sessions",
		"session-compliance",
		"verify-logs",
	}
	for _, subcmd := range expectedSubcommands {
		if !strings.Contains(output, subcmd) {
			t.Errorf("audit help missing subcommand: %q", subcmd)
		}
	}
}

func TestIntegration_AuditVerify_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "audit", "verify", "--help")
	_ = err

	expectedContent := []string{
		"verify",
		"--start",
		"--end",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_AuditUntrackedSessions_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "audit", "untracked-sessions", "--help")
	_ = err

	expectedContent := []string{
		"untracked-sessions",
		"--since",
		"--region",
		"--table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_AuditSessionCompliance_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "audit", "session-compliance", "--help")
	_ = err

	expectedContent := []string{
		"session-compliance",
		"--since",
		"--region",
		"--table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_AuditVerifyLogs_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "audit", "verify-logs", "--help")
	_ = err

	expectedContent := []string{
		"verify-logs",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Permissions Commands Tests
// ============================================================================

func TestIntegration_Permissions_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "permissions", "--help")
	_ = err

	expectedSubcommands := []string{
		"list",
		"check",
	}
	for _, subcmd := range expectedSubcommands {
		if !strings.Contains(output, subcmd) {
			t.Errorf("permissions help missing subcommand: %q", subcmd)
		}
	}
}

func TestIntegration_PermissionsList_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "permissions", "list", "--help")
	_ = err

	expectedContent := []string{
		"list",
		"--format",
		"--subsystem",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_PermissionsCheck_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "permissions", "check", "--help")
	_ = err

	expectedContent := []string{
		"check",
		"--feature",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// Permissions list is an offline command - test actual functionality
func TestIntegration_PermissionsList_OutputsPermissions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "permissions", "list")
	if err != nil {
		t.Errorf("permissions list should succeed without AWS credentials: %v\nOutput: %s", err, output)
	}

	// Should contain permission information
	expectedContent := []string{
		"ssm",
		"sts",
	}
	for _, content := range expectedContent {
		if !strings.Contains(strings.ToLower(output), content) {
			t.Errorf("expected output to contain %q, got: %s", content, output)
		}
	}
}

// ============================================================================
// Config Commands Tests
// ============================================================================

func TestIntegration_Config_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "config", "--help")
	_ = err

	expectedSubcommands := []string{
		"validate",
		"generate",
	}
	for _, subcmd := range expectedSubcommands {
		if !strings.Contains(output, subcmd) {
			t.Errorf("config help missing subcommand: %q", subcmd)
		}
	}
}

func TestIntegration_ConfigValidate_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "config", "validate", "--help")
	_ = err

	expectedContent := []string{
		"validate",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_ConfigGenerate_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "config", "generate", "--help")
	_ = err

	expectedContent := []string{
		"generate",
		"--template",
		"--profile",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// Config generate is an offline command - test actual functionality
func TestIntegration_ConfigGenerate_BasicTemplate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "config", "generate", "--template", "basic", "--profile", "test-profile")
	if err != nil {
		t.Errorf("config generate should succeed without AWS credentials: %v\nOutput: %s", err, output)
	}

	// Should contain generated config
	if !strings.Contains(output, "version") || !strings.Contains(output, "rules") {
		t.Errorf("expected output to contain policy config, got: %s", output)
	}
}

// ============================================================================
// Shell Commands Tests
// ============================================================================

func TestIntegration_Shell_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "shell", "--help")
	_ = err

	expectedSubcommands := []string{
		"init",
	}
	for _, subcmd := range expectedSubcommands {
		if !strings.Contains(output, subcmd) {
			t.Errorf("shell help missing subcommand: %q", subcmd)
		}
	}
}

func TestIntegration_ShellInit_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "shell", "init", "--help")
	_ = err

	expectedContent := []string{
		"init",
		"--policy-root",
		"--format",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Server Session Commands Tests
// ============================================================================

func TestIntegration_ServerSessions_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "server-sessions", "--help")
	_ = err

	expectedContent := []string{
		"server-sessions",
		"--region",
		"--table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_ServerSession_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "server-session", "--help")
	_ = err

	expectedContent := []string{
		"server-session",
		"--region",
		"--table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_ServerRevoke_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "server-revoke", "--help")
	_ = err

	expectedContent := []string{
		"server-revoke",
		"--region",
		"--table",
		"--reason",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Device Session Commands Tests
// ============================================================================

func TestIntegration_DeviceSessions_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "device-sessions", "--help")
	_ = err

	expectedContent := []string{
		"device-sessions",
		"--region",
		"--table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

func TestIntegration_Devices_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "devices", "--help")
	_ = err

	expectedContent := []string{
		"devices",
		"--region",
		"--table",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Identity Commands Tests
// ============================================================================

func TestIntegration_Whoami_Help(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	output, err := runSentinelCommand(t, "whoami", "--help")
	_ = err

	expectedContent := []string{
		"whoami",
	}
	for _, content := range expectedContent {
		if !strings.Contains(output, content) {
			t.Errorf("help output missing expected content: %q", content)
		}
	}
}

// ============================================================================
// Note: Trust, Deploy, SSM, DynamoDB, SCP, and Monitoring commands are
// defined in cli/ but not yet registered in cmd/sentinel/main.go.
// They are available for aws-vault but not for the sentinel CLI.
// ============================================================================
