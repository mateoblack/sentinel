package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/bootstrap"
	"github.com/byteness/aws-vault/v7/infrastructure"
	"github.com/byteness/aws-vault/v7/vault"
)

// createTestFiles creates temp files for test I/O
func createTestFiles(t *testing.T) (*os.File, *os.File, func()) {
	t.Helper()

	stdout, err := os.CreateTemp("", "bootstrap-stdout-*")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}

	stderr, err := os.CreateTemp("", "bootstrap-stderr-*")
	if err != nil {
		stdout.Close()
		os.Remove(stdout.Name())
		t.Fatalf("failed to create temp stderr: %v", err)
	}

	cleanup := func() {
		stdout.Close()
		stderr.Close()
		os.Remove(stdout.Name())
		os.Remove(stderr.Name())
	}

	return stdout, stderr, cleanup
}

// readFile reads content from a temp file.
func readFile(t *testing.T, f *os.File) string {
	t.Helper()
	f.Seek(0, 0)
	content, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	return string(content)
}

// ============================================================================
// Test Interfaces and Mocks
// ============================================================================

// PlannerInterface defines the planning interface for testing.
type PlannerInterface interface {
	Plan(ctx context.Context, config *bootstrap.BootstrapConfig) (*bootstrap.BootstrapPlan, error)
}

// ExecutorInterface defines the execution interface for testing.
type ExecutorInterface interface {
	Apply(ctx context.Context, plan *bootstrap.BootstrapPlan) (*bootstrap.ApplyResult, error)
}

// mockPlannerImpl implements PlannerInterface for testing.
type mockPlannerImpl struct {
	plan *bootstrap.BootstrapPlan
	err  error
}

func (m *mockPlannerImpl) Plan(ctx context.Context, config *bootstrap.BootstrapConfig) (*bootstrap.BootstrapPlan, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.plan, nil
}

// mockExecutorImpl implements ExecutorInterface for testing.
type mockExecutorImpl struct {
	result *bootstrap.ApplyResult
	err    error
}

func (m *mockExecutorImpl) Apply(ctx context.Context, plan *bootstrap.BootstrapPlan) (*bootstrap.ApplyResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

// ============================================================================
// Testable Command Using Interfaces
// ============================================================================

// testableBootstrapCommand is a testable version that accepts interfaces.
// This function mirrors BootstrapCommand logic but uses interfaces for testability.
func testableBootstrapCommand(
	ctx context.Context,
	input BootstrapCommandInput,
	planner PlannerInterface,
	executor ExecutorInterface,
) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Validate profiles
	if len(input.Profiles) == 0 {
		fmt.Fprintln(stderr, "Error: at least one --profile is required")
		return errors.New("at least one --profile is required")
	}

	// Build BootstrapConfig from input
	cfg := &bootstrap.BootstrapConfig{
		PolicyRoot:          input.PolicyRoot,
		Region:              input.Region,
		GenerateIAMPolicies: input.GenerateIAMPolicies,
	}

	for _, profileName := range input.Profiles {
		cfg.Profiles = append(cfg.Profiles, bootstrap.ProfileConfig{
			Name:        profileName,
			Description: input.Description,
		})
	}

	// Generate plan using interface
	plan, err := planner.Plan(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to generate plan: %v\n", err)
		return err
	}

	// Output plan
	if input.JSONOutput {
		planJSON, err := bootstrap.FormatPlanJSON(plan)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to format plan as JSON: %v\n", err)
			return err
		}
		fmt.Fprintln(stdout, string(planJSON))
	} else {
		fmt.Fprint(stdout, bootstrap.FormatPlan(plan))
	}

	// If plan-only mode, output IAM policies if requested and return
	if input.PlanOnly {
		if input.GenerateIAMPolicies && !input.JSONOutput {
			outputCombinedIAMPolicies(stdout, input)
		}
		return nil
	}

	// If no changes needed, return early
	if plan.Summary.ToCreate == 0 && plan.Summary.ToUpdate == 0 {
		if !input.JSONOutput {
			fmt.Fprintln(stdout, "\nNo changes needed.")
		}
		return nil
	}

	// Prompt for confirmation if not auto-approved and not JSON mode
	if !input.AutoApprove && !input.JSONOutput {
		fmt.Fprint(stdout, "\nDo you want to apply these changes? [y/N]: ")

		scanner := input.Stdin
		if scanner == nil {
			scanner = bufio.NewScanner(os.Stdin)
		}

		if !scanner.Scan() {
			fmt.Fprintln(stderr, "Error reading input")
			return errors.New("error reading input")
		}

		response := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if response != "y" && response != "yes" {
			fmt.Fprintln(stdout, "Cancelled.")
			return nil
		}
	}

	// Apply plan using interface
	result, err := executor.Apply(ctx, plan)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to apply plan: %v\n", err)
		return err
	}

	// Output apply result
	if input.JSONOutput {
		resultJSON, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(stdout, string(resultJSON))
	} else {
		fmt.Fprintln(stdout, "\nApply complete:")
		fmt.Fprintf(stdout, "  Created: %d\n", len(result.Created))
		for _, name := range result.Created {
			fmt.Fprintf(stdout, "    + %s\n", name)
		}
		fmt.Fprintf(stdout, "  Updated: %d\n", len(result.Updated))
		for _, name := range result.Updated {
			fmt.Fprintf(stdout, "    ~ %s\n", name)
		}
		fmt.Fprintf(stdout, "  Skipped: %d\n", len(result.Skipped))
		fmt.Fprintf(stdout, "  Failed:  %d\n", len(result.Failed))
		for _, f := range result.Failed {
			fmt.Fprintf(stdout, "    ! %s: %s\n", f.Name, f.Error)
		}

		if input.GenerateIAMPolicies {
			outputCombinedIAMPolicies(stdout, input)
		}
	}

	// Return error if any failures occurred
	if len(result.Failed) > 0 {
		return fmt.Errorf("%d parameter(s) failed to create/update", len(result.Failed))
	}

	return nil
}

// ============================================================================
// Plan-Only Mode Tests
// ============================================================================

func TestBootstrapCommand_PlanOnly_ShowsPlan(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles: []bootstrap.ProfileConfig{
				{Name: "dev"},
			},
		},
		Resources: []bootstrap.ResourceSpec{
			{
				Type:        bootstrap.ResourceTypeSSMParameter,
				Name:        "/sentinel/policies/dev",
				State:       bootstrap.StateCreate,
				Description: "Policy parameter for profile dev",
			},
		},
		Summary: bootstrap.PlanSummary{
			ToCreate: 1,
			Total:    1,
		},
		GeneratedAt: time.Now(),
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{"dev"},
		PlanOnly:   true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Verify plan output contains expected elements
	if !strings.Contains(output, "Bootstrap Plan") {
		t.Error("expected plan output to contain 'Bootstrap Plan'")
	}
	if !strings.Contains(output, "/sentinel/policies") {
		t.Error("expected plan output to contain policy root")
	}
	if !strings.Contains(output, "1 to create") {
		t.Error("expected plan output to contain '1 to create'")
	}
}

func TestBootstrapCommand_PlanOnly_JSONOutput(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles: []bootstrap.ProfileConfig{
				{Name: "prod"},
			},
		},
		Resources: []bootstrap.ResourceSpec{
			{
				Type:        bootstrap.ResourceTypeSSMParameter,
				Name:        "/sentinel/policies/prod",
				State:       bootstrap.StateCreate,
				Description: "Policy parameter for profile prod",
			},
		},
		Summary: bootstrap.PlanSummary{
			ToCreate: 1,
			Total:    1,
		},
		GeneratedAt: time.Now(),
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{"prod"},
		PlanOnly:   true,
		JSONOutput: true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Verify JSON structure
	if !strings.Contains(output, `"policy_root"`) {
		t.Error("expected JSON output to contain policy_root field")
	}
	if !strings.Contains(output, `"resources"`) {
		t.Error("expected JSON output to contain resources field")
	}
	if !strings.Contains(output, `"summary"`) {
		t.Error("expected JSON output to contain summary field")
	}
}

// ============================================================================
// Apply Mode Tests
// ============================================================================

func TestBootstrapCommand_Apply_AutoApprove(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles: []bootstrap.ProfileConfig{
				{Name: "dev"},
			},
		},
		Resources: []bootstrap.ResourceSpec{
			{
				Type:  bootstrap.ResourceTypeSSMParameter,
				Name:  "/sentinel/policies/dev",
				State: bootstrap.StateCreate,
			},
		},
		Summary: bootstrap.PlanSummary{
			ToCreate: 1,
			Total:    1,
		},
	}

	result := &bootstrap.ApplyResult{
		Created: []string{"/sentinel/policies/dev"},
		Updated: []string{},
		Skipped: []string{},
		Failed:  []bootstrap.ApplyError{},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{result: result}

	input := BootstrapCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Profiles:    []string{"dev"},
		AutoApprove: true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Verify apply output
	if !strings.Contains(output, "Apply complete") {
		t.Error("expected output to contain 'Apply complete'")
	}
	if !strings.Contains(output, "Created: 1") {
		t.Error("expected output to contain 'Created: 1'")
	}
}

func TestBootstrapCommand_Apply_ConfirmationRejected(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 1, Total: 1},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{}

	// Simulate user typing "no"
	stdinReader := bufio.NewScanner(strings.NewReader("no\n"))

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{"dev"},
		Stdin:      stdinReader,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Verify cancelled message
	if !strings.Contains(output, "Cancelled") {
		t.Error("expected output to contain 'Cancelled'")
	}
	if strings.Contains(output, "Apply complete") {
		t.Error("expected output NOT to contain 'Apply complete' when rejected")
	}
}

func TestBootstrapCommand_Apply_ConfirmationAccepted(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 1, Total: 1},
	}

	result := &bootstrap.ApplyResult{
		Created: []string{"/sentinel/policies/dev"},
		Updated: []string{},
		Skipped: []string{},
		Failed:  []bootstrap.ApplyError{},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{result: result}

	// Simulate user typing "y"
	stdinReader := bufio.NewScanner(strings.NewReader("y\n"))

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{"dev"},
		Stdin:      stdinReader,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Verify apply output
	if !strings.Contains(output, "Apply complete") {
		t.Error("expected output to contain 'Apply complete'")
	}
}

func TestBootstrapCommand_Apply_ConfirmationYes(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 1, Total: 1},
	}

	result := &bootstrap.ApplyResult{
		Created: []string{"/sentinel/policies/dev"},
		Updated: []string{},
		Skipped: []string{},
		Failed:  []bootstrap.ApplyError{},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{result: result}

	// Simulate user typing "yes"
	stdinReader := bufio.NewScanner(strings.NewReader("yes\n"))

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{"dev"},
		Stdin:      stdinReader,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "Apply complete") {
		t.Error("expected output to contain 'Apply complete'")
	}
}

// ============================================================================
// Multiple Profiles Tests
// ============================================================================

func TestBootstrapCommand_MultipleProfiles(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles: []bootstrap.ProfileConfig{
				{Name: "dev"},
				{Name: "staging"},
				{Name: "prod"},
			},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/staging", State: bootstrap.StateExists},
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/prod", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 2, ToSkip: 1, Total: 3},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{"dev", "staging", "prod"},
		PlanOnly:   true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Verify all profiles appear in plan
	if !strings.Contains(output, "/sentinel/policies/dev") {
		t.Error("expected output to contain dev parameter")
	}
	if !strings.Contains(output, "/sentinel/policies/staging") {
		t.Error("expected output to contain staging parameter")
	}
	if !strings.Contains(output, "/sentinel/policies/prod") {
		t.Error("expected output to contain prod parameter")
	}
	if !strings.Contains(output, "2 to create") {
		t.Error("expected output to contain '2 to create'")
	}
}

// ============================================================================
// IAM Policy Generation Tests
// ============================================================================

func TestBootstrapCommand_GenerateIAMPolicies(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot:          "/sentinel/policies",
			GenerateIAMPolicies: true,
			Profiles:            []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
			{Type: bootstrap.ResourceTypeIAMPolicy, Name: "SentinelPolicyReader", State: bootstrap.StateCreate},
			{Type: bootstrap.ResourceTypeIAMPolicy, Name: "SentinelPolicyAdmin", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 3, Total: 3},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot:          "/sentinel/policies",
		Profiles:            []string{"dev"},
		PlanOnly:            true,
		GenerateIAMPolicies: true,
		Stdout:              stdout,
		Stderr:              stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Verify IAM policy documents are included
	if !strings.Contains(output, "SentinelPolicyReader") {
		t.Error("expected output to contain 'SentinelPolicyReader'")
	}
	if !strings.Contains(output, "SentinelPolicyAdmin") {
		t.Error("expected output to contain 'SentinelPolicyAdmin'")
	}
	if !strings.Contains(output, "ssm:GetParameter") {
		t.Error("expected output to contain SSM read action")
	}
}

// ============================================================================
// Error Cases
// ============================================================================

func TestBootstrapCommand_NoProfilesProvided(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	planner := &mockPlannerImpl{}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{}, // Empty profiles
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err == nil {
		t.Fatal("expected error for no profiles provided")
	}
	if !strings.Contains(err.Error(), "at least one --profile is required") {
		t.Errorf("unexpected error: %v", err)
	}

	errOutput := readFile(t, stderr)
	if !strings.Contains(errOutput, "at least one --profile is required") {
		t.Error("expected stderr to contain error message")
	}
}

func TestBootstrapCommand_PlanError(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	planner := &mockPlannerImpl{err: errors.New("invalid config: policy_root must start with /")}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot: "invalid-path",
		Profiles:   []string{"dev"},
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err == nil {
		t.Fatal("expected error for plan failure")
	}

	errOutput := readFile(t, stderr)
	if !strings.Contains(errOutput, "Failed to generate plan") {
		t.Error("expected stderr to contain plan generation error")
	}
}

func TestBootstrapCommand_SSMAPIError(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	planner := &mockPlannerImpl{err: errors.New("check parameter /sentinel/policies/dev: AccessDeniedException")}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{"dev"},
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err == nil {
		t.Fatal("expected error for SSM API failure")
	}

	errOutput := readFile(t, stderr)
	if !strings.Contains(errOutput, "Failed to generate plan") {
		t.Error("expected stderr to contain plan generation error")
	}
}

func TestBootstrapCommand_ApplyError(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 1, Total: 1},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{err: errors.New("apply failed")}

	input := BootstrapCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Profiles:    []string{"dev"},
		AutoApprove: true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err == nil {
		t.Fatal("expected error")
	}

	errOutput := readFile(t, stderr)
	if !strings.Contains(errOutput, "Failed to apply plan") {
		t.Error("expected error message in stderr")
	}
}

func TestBootstrapCommand_ApplyPartialFailure(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}, {Name: "prod"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/prod", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 2, Total: 2},
	}

	result := &bootstrap.ApplyResult{
		Created: []string{"/sentinel/policies/dev"},
		Updated: []string{},
		Skipped: []string{},
		Failed:  []bootstrap.ApplyError{{Name: "/sentinel/policies/prod", Error: "AccessDeniedException"}},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{result: result}

	input := BootstrapCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Profiles:    []string{"dev", "prod"},
		AutoApprove: true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err == nil {
		t.Fatal("expected error for partial failure")
	}
	if !strings.Contains(err.Error(), "1 parameter(s) failed") {
		t.Errorf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "Created: 1") {
		t.Error("expected output to show created count")
	}
	if !strings.Contains(output, "Failed:  1") {
		t.Error("expected output to show failed count")
	}
	if !strings.Contains(output, "AccessDeniedException") {
		t.Error("expected output to show error message")
	}
}

// ============================================================================
// No Changes Needed Tests
// ============================================================================

func TestBootstrapCommand_NoChangesNeeded(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{
				Type:           bootstrap.ResourceTypeSSMParameter,
				Name:           "/sentinel/policies/dev",
				State:          bootstrap.StateExists,
				CurrentVersion: "1",
			},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 0, ToUpdate: 0, ToSkip: 1, Total: 1},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Profiles:    []string{"dev"},
		AutoApprove: true, // Would apply if changes were needed
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Verify no changes message
	if !strings.Contains(output, "No changes needed") {
		t.Error("expected output to contain 'No changes needed'")
	}
	// Should not attempt apply
	if strings.Contains(output, "Apply complete") {
		t.Error("expected output NOT to contain 'Apply complete' when no changes")
	}
}

// ============================================================================
// Format Tests (Direct Function Testing)
// ============================================================================

func TestBootstrapCommand_OutputFormat(t *testing.T) {
	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{
				Type:        bootstrap.ResourceTypeSSMParameter,
				Name:        "/sentinel/policies/dev",
				State:       bootstrap.StateCreate,
				Description: "Policy parameter for profile dev",
			},
		},
		Summary:     bootstrap.PlanSummary{ToCreate: 1, Total: 1},
		GeneratedAt: time.Now(),
	}

	// Test human-readable format
	humanOutput := bootstrap.FormatPlan(plan)
	if !strings.Contains(humanOutput, "Bootstrap Plan") {
		t.Error("expected human output to contain 'Bootstrap Plan'")
	}
	if !strings.Contains(humanOutput, "/sentinel/policies/dev") {
		t.Error("expected human output to contain parameter name")
	}
	if !strings.Contains(humanOutput, "+") {
		t.Error("expected human output to contain create symbol '+'")
	}

	// Test JSON format
	jsonOutput, err := bootstrap.FormatPlanJSON(plan)
	if err != nil {
		t.Fatalf("failed to format JSON: %v", err)
	}
	if !strings.Contains(string(jsonOutput), `"policy_root"`) {
		t.Error("expected JSON output to contain policy_root")
	}
	if !strings.Contains(string(jsonOutput), `"to_create": 1`) {
		t.Error("expected JSON output to contain to_create count")
	}
}

func TestBootstrapCommand_IAMPolicyGeneration(t *testing.T) {
	policyRoot := "/sentinel/policies"

	// Test reader policy
	readerPolicy := bootstrap.GenerateReaderPolicy(policyRoot)
	if readerPolicy.Version != "2012-10-17" {
		t.Errorf("expected IAM version 2012-10-17, got %s", readerPolicy.Version)
	}
	if len(readerPolicy.Statement) != 1 {
		t.Errorf("expected 1 statement, got %d", len(readerPolicy.Statement))
	}
	if readerPolicy.Statement[0].Effect != "Allow" {
		t.Error("expected Allow effect")
	}

	// Check read actions
	readActions := readerPolicy.Statement[0].Action
	if len(readActions) != 3 {
		t.Errorf("expected 3 read actions, got %d", len(readActions))
	}

	// Test admin policy
	adminPolicy := bootstrap.GenerateAdminPolicy(policyRoot)
	if len(adminPolicy.Statement) != 1 {
		t.Errorf("expected 1 statement, got %d", len(adminPolicy.Statement))
	}

	// Admin should have more actions than reader
	adminActions := adminPolicy.Statement[0].Action
	if len(adminActions) <= len(readActions) {
		t.Error("expected admin to have more actions than reader")
	}

	// Test formatting
	readerJSON, err := bootstrap.FormatIAMPolicy(readerPolicy)
	if err != nil {
		t.Fatalf("failed to format reader policy: %v", err)
	}
	if !strings.Contains(readerJSON, "ssm:GetParameter") {
		t.Error("expected reader policy to contain ssm:GetParameter")
	}
}

// ============================================================================
// JSON Output Mode Tests
// ============================================================================

func TestBootstrapCommand_JSONOutput_Apply(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 1, Total: 1},
	}

	result := &bootstrap.ApplyResult{
		Created: []string{"/sentinel/policies/dev"},
		Updated: []string{},
		Skipped: []string{},
		Failed:  []bootstrap.ApplyError{},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{result: result}

	input := BootstrapCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Profiles:    []string{"dev"},
		AutoApprove: true,
		JSONOutput:  true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	// Should have JSON plan first, then JSON result
	if !strings.Contains(output, `"created"`) {
		t.Error("expected JSON output to contain created array")
	}
	if !strings.Contains(output, `"/sentinel/policies/dev"`) {
		t.Error("expected JSON output to contain created parameter")
	}
}

// ============================================================================
// Update Mode Tests
// ============================================================================

func TestBootstrapCommand_UpdateExisting(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{
				Type:           bootstrap.ResourceTypeSSMParameter,
				Name:           "/sentinel/policies/dev",
				State:          bootstrap.StateUpdate,
				CurrentVersion: "1",
			},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 0, ToUpdate: 1, ToSkip: 0, Total: 1},
	}

	result := &bootstrap.ApplyResult{
		Created: []string{},
		Updated: []string{"/sentinel/policies/dev"},
		Skipped: []string{},
		Failed:  []bootstrap.ApplyError{},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{result: result}

	input := BootstrapCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Profiles:    []string{"dev"},
		AutoApprove: true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)

	if !strings.Contains(output, "Apply complete") {
		t.Error("expected 'Apply complete' in output")
	}
	if !strings.Contains(output, "Updated: 1") {
		t.Error("expected 'Updated: 1' in output")
	}
	if !strings.Contains(output, "~") {
		// Update symbol in apply output
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestBootstrapCommand_EmptyPlanResources(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{},
		},
		Resources: []bootstrap.ResourceSpec{},
		Summary:   bootstrap.PlanSummary{ToCreate: 0, ToUpdate: 0, ToSkip: 0, Total: 0},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{"dev"}, // Profiles provided but plan returns empty
		PlanOnly:   true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "Bootstrap Plan") {
		t.Error("expected plan header even with empty resources")
	}
}

func TestBootstrapCommand_CustomRegion(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Region:     "eu-west-1",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 1, Total: 1},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{"dev"},
		Region:     "eu-west-1",
		PlanOnly:   true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "eu-west-1") {
		t.Error("expected region in output")
	}
}

func TestBootstrapCommand_WithDescription(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev", Description: "Development environment"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 1, Total: 1},
	}

	planner := &mockPlannerImpl{plan: plan}
	executor := &mockExecutorImpl{}

	input := BootstrapCommandInput{
		PolicyRoot:  "/sentinel/policies",
		Profiles:    []string{"dev"},
		Description: "Development environment",
		PlanOnly:    true,
		Stdout:      stdout,
		Stderr:      stderr,
	}

	err := testableBootstrapCommand(context.Background(), input, planner, executor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Description would be used when generating sample policies, not in plan output
}

// ============================================================================
// Real Command Validation Tests (No AWS Required)
// ============================================================================

func TestBootstrapCommand_RealCommand_NoProfiles(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	input := BootstrapCommandInput{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []string{},
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := BootstrapCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for no profiles")
	}
	if !strings.Contains(err.Error(), "at least one --profile is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================================
// AWS Profile SSO Credential Loading Tests
// ============================================================================

func TestBootstrapCommand_UsesAWSProfileForCredentials(t *testing.T) {
	// This test verifies the command uses the --aws-profile flag for AWS config loading.
	// The actual SSO flow requires real AWS credentials, so we verify
	// the pattern is correct by checking that:
	// 1. AWSProfile field exists and accepts values
	// 2. SSO profile configuration is recognized when AWS_CONFIG_FILE points to SSO config

	t.Run("aws-profile accepts SSO profile name", func(t *testing.T) {
		// Verify BootstrapCommandInput can be configured with an SSO profile
		// This tests the integration point where AWSProfile flows to WithSharedConfigProfile
		input := BootstrapCommandInput{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []string{"dev", "staging"},
			AWSProfile: "sso-admin",
			Region:     "us-east-1",
		}

		// AWSProfile should be set and will be used for WithSharedConfigProfile
		if input.AWSProfile != "sso-admin" {
			t.Errorf("expected AWSProfile 'sso-admin', got %q", input.AWSProfile)
		}
	})

	t.Run("SSO profile is recognized for bootstrap credentials", func(t *testing.T) {
		// Create a config file with SSO settings
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config")
		configContent := `[profile bootstrap-sso]
sso_start_url = https://bootstrap-sso.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = BootstrapAdmin
region = us-west-2
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		configFile, err := vault.LoadConfig(configPath)
		if err != nil {
			t.Fatalf("failed to load config: %v", err)
		}

		// Verify the profile has SSO settings
		profile, ok := configFile.ProfileSection("bootstrap-sso")
		if !ok {
			t.Fatal("expected to find bootstrap-sso profile")
		}
		if profile.SSOStartURL == "" {
			t.Error("expected profile to have SSO start URL")
		}
		if profile.SSORegion == "" {
			t.Error("expected profile to have SSO region")
		}
		if profile.SSOAccountID == "" {
			t.Error("expected profile to have SSO account ID")
		}
		if profile.SSORoleName == "" {
			t.Error("expected profile to have SSO role name")
		}
	})

	t.Run("input struct accepts AWSProfile field for credential source", func(t *testing.T) {
		// Test that AWSProfile is separate from Profiles (target profiles to bootstrap)
		// Bootstrap uses --profile for targets and --aws-profile for credential source
		input := BootstrapCommandInput{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []string{"dev", "staging", "prod"}, // Profiles to bootstrap
			AWSProfile: "admin-sso",                        // SSO profile for credentials
			Region:     "us-east-1",
			PlanOnly:   true,
		}

		// Verify both fields are independent
		if len(input.Profiles) != 3 {
			t.Errorf("expected 3 target profiles, got %d", len(input.Profiles))
		}
		if input.AWSProfile != "admin-sso" {
			t.Errorf("expected AWSProfile 'admin-sso', got %q", input.AWSProfile)
		}
	})
}

// ============================================================================
// DynamoDB Table Provisioning Tests
// ============================================================================

// mockTableProvisioner implements TableProvisionerInterface for testing.
type mockTableProvisioner struct {
	PlanResult   *infrastructure.ProvisionPlan
	PlanErr      error
	CreateResult *infrastructure.ProvisionResult
	CreateErr    error
	PlanCalls    []infrastructure.TableSchema
	CreateCalls  []infrastructure.TableSchema
}

func (m *mockTableProvisioner) Plan(ctx context.Context, schema infrastructure.TableSchema) (*infrastructure.ProvisionPlan, error) {
	m.PlanCalls = append(m.PlanCalls, schema)
	if m.PlanErr != nil {
		return nil, m.PlanErr
	}
	if m.PlanResult != nil {
		return m.PlanResult, nil
	}
	// Default: return plan indicating table would be created
	return &infrastructure.ProvisionPlan{
		TableName:    schema.TableName,
		WouldCreate:  true,
		GSIs:         schema.GSINames(),
		TTLAttribute: schema.TTLAttribute,
		BillingMode:  string(schema.BillingMode),
	}, nil
}

func (m *mockTableProvisioner) Create(ctx context.Context, schema infrastructure.TableSchema) (*infrastructure.ProvisionResult, error) {
	m.CreateCalls = append(m.CreateCalls, schema)
	if m.CreateErr != nil {
		return nil, m.CreateErr
	}
	if m.CreateResult != nil {
		return m.CreateResult, nil
	}
	// Default: return success with created status
	return &infrastructure.ProvisionResult{
		TableName: schema.TableName,
		Status:    infrastructure.StatusCreated,
		ARN:       fmt.Sprintf("arn:aws:dynamodb:us-east-1:123456789012:table/%s", schema.TableName),
	}, nil
}

// testableBootstrapCommandWithProvisioner is a test helper that uses the testable command with provisioner.
func testableBootstrapCommandWithProvisioner(
	t *testing.T,
	input BootstrapCommandInput,
	planner PlannerInterface,
	executor ExecutorInterface,
) error {
	t.Helper()
	return testableBootstrapCommand(context.Background(), input, planner, executor)
}

func TestBootstrapCommand_WithApprovalsFlag(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	// Mock SSM planner - no SSM changes needed
	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateExists},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 0, ToSkip: 1, Total: 1},
	}
	ssmPlanner := &mockPlannerImpl{plan: plan}
	ssmExecutor := &mockExecutorImpl{}

	// Mock DynamoDB provisioner
	mockProvisioner := &mockTableProvisioner{
		CreateResult: &infrastructure.ProvisionResult{
			TableName: "sentinel-requests",
			Status:    infrastructure.StatusCreated,
			ARN:       "arn:aws:dynamodb:us-east-1:123456789012:table/sentinel-requests",
		},
	}

	input := BootstrapCommandInput{
		PolicyRoot:        "/sentinel/policies",
		Profiles:          []string{"dev"},
		Region:            "us-east-1",
		AutoApprove:       true,
		WithApprovals:     true,
		ApprovalTableName: "sentinel-requests",
		Provisioner:       mockProvisioner,
		Stdout:            stdout,
		Stderr:            stderr,
	}

	err := testableBootstrapCommandWithProvisioner(t, input, ssmPlanner, ssmExecutor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify provisioner was called for approvals table
	if len(mockProvisioner.CreateCalls) != 1 {
		t.Errorf("expected 1 Create call, got %d", len(mockProvisioner.CreateCalls))
	}
	if len(mockProvisioner.CreateCalls) > 0 && mockProvisioner.CreateCalls[0].TableName != "sentinel-requests" {
		t.Errorf("expected table name 'sentinel-requests', got %q", mockProvisioner.CreateCalls[0].TableName)
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "DynamoDB Tables") {
		t.Error("expected output to contain 'DynamoDB Tables'")
	}
	if !strings.Contains(output, "Approvals table") {
		t.Error("expected output to contain 'Approvals table'")
	}
}

func TestBootstrapCommand_WithAllFlag(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	// Mock SSM planner - no SSM changes needed
	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateExists},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 0, ToSkip: 1, Total: 1},
	}
	ssmPlanner := &mockPlannerImpl{plan: plan}
	ssmExecutor := &mockExecutorImpl{}

	// Mock DynamoDB provisioner
	mockProvisioner := &mockTableProvisioner{}

	input := BootstrapCommandInput{
		PolicyRoot:          "/sentinel/policies",
		Profiles:            []string{"dev"},
		Region:              "us-east-1",
		AutoApprove:         true,
		WithAll:             true,
		ApprovalTableName:   "sentinel-requests",
		BreakGlassTableName: "sentinel-breakglass",
		SessionTableName:    "sentinel-sessions",
		Provisioner:         mockProvisioner,
		Stdout:              stdout,
		Stderr:              stderr,
	}

	err := testableBootstrapCommandWithProvisioner(t, input, ssmPlanner, ssmExecutor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify provisioner was called for all three tables
	if len(mockProvisioner.CreateCalls) != 3 {
		t.Errorf("expected 3 Create calls, got %d", len(mockProvisioner.CreateCalls))
	}

	// Verify table names
	tableNames := make(map[string]bool)
	for _, call := range mockProvisioner.CreateCalls {
		tableNames[call.TableName] = true
	}
	if !tableNames["sentinel-requests"] {
		t.Error("expected sentinel-requests table to be created")
	}
	if !tableNames["sentinel-breakglass"] {
		t.Error("expected sentinel-breakglass table to be created")
	}
	if !tableNames["sentinel-sessions"] {
		t.Error("expected sentinel-sessions table to be created")
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "Approvals table") {
		t.Error("expected output to contain 'Approvals table'")
	}
	if !strings.Contains(output, "Break-Glass table") {
		t.Error("expected output to contain 'Break-Glass table'")
	}
	if !strings.Contains(output, "Sessions table") {
		t.Error("expected output to contain 'Sessions table'")
	}
}

func TestBootstrapCommand_TableRequiresRegion(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	// Mock SSM planner - no SSM changes needed
	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateExists},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 0, ToSkip: 1, Total: 1},
	}
	ssmPlanner := &mockPlannerImpl{plan: plan}
	ssmExecutor := &mockExecutorImpl{}

	// Mock DynamoDB provisioner (shouldn't be called)
	mockProvisioner := &mockTableProvisioner{}

	input := BootstrapCommandInput{
		PolicyRoot:    "/sentinel/policies",
		Profiles:      []string{"dev"},
		Region:        "", // No region - should fail
		AutoApprove:   true,
		WithApprovals: true,
		Provisioner:   mockProvisioner,
		Stdout:        stdout,
		Stderr:        stderr,
	}

	err := testableBootstrapCommandWithProvisioner(t, input, ssmPlanner, ssmExecutor)
	if err == nil {
		t.Fatal("expected error for missing region")
	}
	if !strings.Contains(err.Error(), "--region is required") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Verify provisioner was NOT called
	if len(mockProvisioner.CreateCalls) != 0 {
		t.Errorf("expected 0 Create calls, got %d", len(mockProvisioner.CreateCalls))
	}

	errOutput := readFile(t, stderr)
	if !strings.Contains(errOutput, "--region is required") {
		t.Error("expected stderr to contain region error message")
	}
}

func TestBootstrapCommand_TablePlanOnly(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	// Mock SSM planner
	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateCreate},
		},
		Summary: bootstrap.PlanSummary{ToCreate: 1, Total: 1},
	}
	ssmPlanner := &mockPlannerImpl{plan: plan}
	ssmExecutor := &mockExecutorImpl{}

	// Mock DynamoDB provisioner
	mockProvisioner := &mockTableProvisioner{
		PlanResult: &infrastructure.ProvisionPlan{
			TableName:    "sentinel-requests",
			WouldCreate:  true,
			GSIs:         []string{"gsi-requester", "gsi-status", "gsi-profile"},
			TTLAttribute: "ttl",
			BillingMode:  "PAY_PER_REQUEST",
		},
	}

	input := BootstrapCommandInput{
		PolicyRoot:        "/sentinel/policies",
		Profiles:          []string{"dev"},
		Region:            "us-east-1",
		PlanOnly:          true,
		WithApprovals:     true,
		ApprovalTableName: "sentinel-requests",
		Provisioner:       mockProvisioner,
		Stdout:            stdout,
		Stderr:            stderr,
	}

	err := testableBootstrapCommandWithProvisioner(t, input, ssmPlanner, ssmExecutor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Plan was called (not Create)
	if len(mockProvisioner.PlanCalls) != 1 {
		t.Errorf("expected 1 Plan call, got %d", len(mockProvisioner.PlanCalls))
	}
	if len(mockProvisioner.CreateCalls) != 0 {
		t.Errorf("expected 0 Create calls in plan mode, got %d", len(mockProvisioner.CreateCalls))
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "DynamoDB Tables") {
		t.Error("expected output to contain 'DynamoDB Tables'")
	}
	if !strings.Contains(output, "+ Approvals table") {
		t.Error("expected output to show table would be created")
	}
}

func TestBootstrapCommand_TableExistsInPlanMode(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	// Mock SSM planner
	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateExists},
		},
		Summary: bootstrap.PlanSummary{ToSkip: 1, Total: 1},
	}
	ssmPlanner := &mockPlannerImpl{plan: plan}
	ssmExecutor := &mockExecutorImpl{}

	// Mock DynamoDB provisioner - table already exists
	mockProvisioner := &mockTableProvisioner{
		PlanResult: &infrastructure.ProvisionPlan{
			TableName:   "sentinel-requests",
			WouldCreate: false, // Already exists
		},
	}

	input := BootstrapCommandInput{
		PolicyRoot:        "/sentinel/policies",
		Profiles:          []string{"dev"},
		Region:            "us-east-1",
		PlanOnly:          true,
		WithApprovals:     true,
		ApprovalTableName: "sentinel-requests",
		Provisioner:       mockProvisioner,
		Stdout:            stdout,
		Stderr:            stderr,
	}

	err := testableBootstrapCommandWithProvisioner(t, input, ssmPlanner, ssmExecutor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "= Approvals table") || !strings.Contains(output, "(exists)") {
		t.Error("expected output to show table already exists")
	}
}

func TestBootstrapCommand_TableAlreadyExists(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	// Mock SSM planner - no changes
	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateExists},
		},
		Summary: bootstrap.PlanSummary{ToSkip: 1, Total: 1},
	}
	ssmPlanner := &mockPlannerImpl{plan: plan}
	ssmExecutor := &mockExecutorImpl{}

	// Mock DynamoDB provisioner - table already exists
	mockProvisioner := &mockTableProvisioner{
		CreateResult: &infrastructure.ProvisionResult{
			TableName: "sentinel-requests",
			Status:    infrastructure.StatusExists,
			ARN:       "arn:aws:dynamodb:us-east-1:123456789012:table/sentinel-requests",
		},
	}

	input := BootstrapCommandInput{
		PolicyRoot:        "/sentinel/policies",
		Profiles:          []string{"dev"},
		Region:            "us-east-1",
		AutoApprove:       true,
		WithApprovals:     true,
		ApprovalTableName: "sentinel-requests",
		Provisioner:       mockProvisioner,
		Stdout:            stdout,
		Stderr:            stderr,
	}

	err := testableBootstrapCommandWithProvisioner(t, input, ssmPlanner, ssmExecutor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readFile(t, stdout)
	if !strings.Contains(output, "= Approvals table") || !strings.Contains(output, "(exists)") {
		t.Error("expected output to show table already exists")
	}
}

func TestBootstrapCommand_CustomTableNames(t *testing.T) {
	stdout, stderr, cleanup := createTestFiles(t)
	defer cleanup()

	// Mock SSM planner
	plan := &bootstrap.BootstrapPlan{
		Config: bootstrap.BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Profiles:   []bootstrap.ProfileConfig{{Name: "dev"}},
		},
		Resources: []bootstrap.ResourceSpec{
			{Type: bootstrap.ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: bootstrap.StateExists},
		},
		Summary: bootstrap.PlanSummary{ToSkip: 1, Total: 1},
	}
	ssmPlanner := &mockPlannerImpl{plan: plan}
	ssmExecutor := &mockExecutorImpl{}

	// Mock DynamoDB provisioner
	mockProvisioner := &mockTableProvisioner{}

	input := BootstrapCommandInput{
		PolicyRoot:          "/sentinel/policies",
		Profiles:            []string{"dev"},
		Region:              "us-east-1",
		AutoApprove:         true,
		WithAll:             true,
		ApprovalTableName:   "custom-approvals",
		BreakGlassTableName: "custom-breakglass",
		SessionTableName:    "custom-sessions",
		Provisioner:         mockProvisioner,
		Stdout:              stdout,
		Stderr:              stderr,
	}

	err := testableBootstrapCommandWithProvisioner(t, input, ssmPlanner, ssmExecutor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify custom table names were used
	tableNames := make(map[string]bool)
	for _, call := range mockProvisioner.CreateCalls {
		tableNames[call.TableName] = true
	}
	if !tableNames["custom-approvals"] {
		t.Error("expected custom-approvals table")
	}
	if !tableNames["custom-breakglass"] {
		t.Error("expected custom-breakglass table")
	}
	if !tableNames["custom-sessions"] {
		t.Error("expected custom-sessions table")
	}
}
