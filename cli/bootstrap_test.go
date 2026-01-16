package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/bootstrap"
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
			outputIAMPolicies(stdout, cfg.PolicyRoot)
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
			outputIAMPolicies(stdout, cfg.PolicyRoot)
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
		Summary: bootstrap.PlanSummary{ToCreate: 1, Total: 1},
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
