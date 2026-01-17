package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// mockSSMAPI implements ssmAPI for testing.
type mockSSMAPI struct {
	getParameterFunc func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	calls            []string
}

func (m *mockSSMAPI) GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	m.calls = append(m.calls, aws.ToString(params.Name))
	if m.getParameterFunc != nil {
		return m.getParameterFunc(ctx, params, optFns...)
	}
	return nil, &types.ParameterNotFound{}
}

func TestPlanner_Plan_ParameterExists(t *testing.T) {
	mock := &mockSSMAPI{
		getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:    params.Name,
					Value:   aws.String("test-value"),
					Version: 3,
				},
			}, nil
		},
	}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{Name: "dev"},
		},
	}

	plan, err := planner.Plan(context.Background(), config)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if len(plan.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(plan.Resources))
	}

	r := plan.Resources[0]
	if r.State != StateExists {
		t.Errorf("expected state %s, got %s", StateExists, r.State)
	}
	if r.CurrentVersion != "3" {
		t.Errorf("expected version '3', got %q", r.CurrentVersion)
	}
	if r.Name != "/sentinel/policies/dev" {
		t.Errorf("expected name '/sentinel/policies/dev', got %q", r.Name)
	}
}

func TestPlanner_Plan_ParameterNotFound(t *testing.T) {
	mock := &mockSSMAPI{
		getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return nil, &types.ParameterNotFound{}
		},
	}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{Name: "staging"},
		},
	}

	plan, err := planner.Plan(context.Background(), config)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if len(plan.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(plan.Resources))
	}

	r := plan.Resources[0]
	if r.State != StateCreate {
		t.Errorf("expected state %s, got %s", StateCreate, r.State)
	}
	if r.CurrentVersion != "" {
		t.Errorf("expected empty version, got %q", r.CurrentVersion)
	}
}

func TestPlanner_Plan_SSMError(t *testing.T) {
	mock := &mockSSMAPI{
		getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{Name: "prod"},
		},
	}

	_, err := planner.Plan(context.Background(), config)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errors.New("")) && err.Error() == "" {
		t.Errorf("expected non-empty error message")
	}
}

func TestPlanner_Plan_InvalidConfig(t *testing.T) {
	mock := &mockSSMAPI{}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot: "", // Invalid: empty
		Profiles:   []ProfileConfig{},
	}

	_, err := planner.Plan(context.Background(), config)
	if err == nil {
		t.Fatal("expected error for invalid config, got nil")
	}

	// Verify no SSM calls were made
	if len(mock.calls) > 0 {
		t.Errorf("expected no SSM calls for invalid config, got %d calls", len(mock.calls))
	}
}

func TestPlanner_Plan_MultipleProfiles(t *testing.T) {
	callCount := 0
	mock := &mockSSMAPI{
		getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			callCount++
			name := aws.ToString(params.Name)
			// First profile exists, second doesn't
			if name == "/sentinel/policies/dev" {
				return &ssm.GetParameterOutput{
					Parameter: &types.Parameter{
						Name:    params.Name,
						Value:   aws.String("policy"),
						Version: 5,
					},
				}, nil
			}
			return nil, &types.ParameterNotFound{}
		},
	}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{Name: "dev"},
			{Name: "staging"},
			{Name: "prod"},
		},
	}

	plan, err := planner.Plan(context.Background(), config)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if callCount != 3 {
		t.Errorf("expected 3 SSM calls, got %d", callCount)
	}

	if len(plan.Resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(plan.Resources))
	}

	// Check states
	if plan.Resources[0].State != StateExists {
		t.Errorf("dev: expected %s, got %s", StateExists, plan.Resources[0].State)
	}
	if plan.Resources[1].State != StateCreate {
		t.Errorf("staging: expected %s, got %s", StateCreate, plan.Resources[1].State)
	}
	if plan.Resources[2].State != StateCreate {
		t.Errorf("prod: expected %s, got %s", StateCreate, plan.Resources[2].State)
	}
}

func TestPlanner_Plan_WithIAMPolicies(t *testing.T) {
	mock := &mockSSMAPI{
		getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return nil, &types.ParameterNotFound{}
		},
	}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot:          "/sentinel/policies",
		GenerateIAMPolicies: true,
		Profiles: []ProfileConfig{
			{Name: "dev"},
		},
	}

	plan, err := planner.Plan(context.Background(), config)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	// Should have 1 SSM parameter + 2 IAM policies = 3 resources
	if len(plan.Resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(plan.Resources))
	}

	// Check IAM policy names
	iamCount := 0
	for _, r := range plan.Resources {
		if r.Type == ResourceTypeIAMPolicy {
			iamCount++
			if r.Name != "SentinelPolicyReader" && r.Name != "SentinelPolicyAdmin" {
				t.Errorf("unexpected IAM policy name: %s", r.Name)
			}
			if r.State != StateCreate {
				t.Errorf("IAM policy %s: expected state %s, got %s", r.Name, StateCreate, r.State)
			}
		}
	}
	if iamCount != 2 {
		t.Errorf("expected 2 IAM policies, got %d", iamCount)
	}
}

func TestPlanner_Plan_CustomPolicyParameterName(t *testing.T) {
	mock := &mockSSMAPI{
		getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return nil, &types.ParameterNotFound{}
		},
	}

	planner := newPlannerWithClient(mock)
	customName := "/custom/path/my-policy"
	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{
				Name:                "dev",
				PolicyParameterName: customName,
			},
		},
	}

	plan, err := planner.Plan(context.Background(), config)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	// Verify custom name was used
	if len(mock.calls) != 1 || mock.calls[0] != customName {
		t.Errorf("expected SSM call with %q, got %v", customName, mock.calls)
	}

	if plan.Resources[0].Name != customName {
		t.Errorf("expected resource name %q, got %q", customName, plan.Resources[0].Name)
	}
}

func TestPlanner_Plan_Summary(t *testing.T) {
	callIdx := 0
	mock := &mockSSMAPI{
		getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			callIdx++
			// First exists, second and third don't
			if callIdx == 1 {
				return &ssm.GetParameterOutput{
					Parameter: &types.Parameter{
						Name:    params.Name,
						Value:   aws.String("policy"),
						Version: 1,
					},
				}, nil
			}
			return nil, &types.ParameterNotFound{}
		},
	}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{Name: "dev"},
			{Name: "staging"},
			{Name: "prod"},
		},
	}

	plan, err := planner.Plan(context.Background(), config)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	// Summary should be computed: 1 exists, 2 to create
	if plan.Summary.ToCreate != 2 {
		t.Errorf("expected ToCreate=2, got %d", plan.Summary.ToCreate)
	}
	if plan.Summary.ToSkip != 1 {
		t.Errorf("expected ToSkip=1 (exists counts as skip), got %d", plan.Summary.ToSkip)
	}
	if plan.Summary.ToUpdate != 0 {
		t.Errorf("expected ToUpdate=0, got %d", plan.Summary.ToUpdate)
	}
	if plan.Summary.Total != 3 {
		t.Errorf("expected Total=3, got %d", plan.Summary.Total)
	}
}

func TestPlanner_Plan_GeneratedAt(t *testing.T) {
	mock := &mockSSMAPI{}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{Name: "dev"},
		},
	}

	plan, err := planner.Plan(context.Background(), config)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if plan.GeneratedAt.IsZero() {
		t.Error("expected GeneratedAt to be set")
	}
}

// TestPlanner_Plan_ContextCancellation tests that cancelled context propagates correctly.
func TestPlanner_Plan_ContextCancellation(t *testing.T) {
	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	mock := &mockSSMAPI{
		getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			// Simulate context-aware SSM call that returns context error
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, &types.ParameterNotFound{}
		},
	}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{Name: "production"},
		},
	}

	_, err := planner.Plan(ctx, config)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}

	// Error should indicate context cancellation
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context cancellation error, got: %v", err)
	}
}

// TestPlanner_Plan_NilConfig tests that nil config is handled gracefully.
func TestPlanner_Plan_NilConfig(t *testing.T) {
	mock := &mockSSMAPI{}
	planner := newPlannerWithClient(mock)

	// This should panic or return an error
	// Testing that the code handles nil gracefully
	defer func() {
		if r := recover(); r != nil {
			// Panic is acceptable for nil config - it's a programming error
			t.Logf("Plan() panicked on nil config (acceptable behavior): %v", r)
		}
	}()

	_, err := planner.Plan(context.Background(), nil)
	if err == nil {
		t.Error("expected error for nil config, got nil")
	}
}

// TestPlanner_Plan_ConfigNilProfiles tests config with nil Profiles slice.
func TestPlanner_Plan_ConfigNilProfiles(t *testing.T) {
	mock := &mockSSMAPI{}
	planner := newPlannerWithClient(mock)

	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles:   nil, // nil profiles
	}

	_, err := planner.Plan(context.Background(), config)
	if err == nil {
		t.Fatal("expected error for nil profiles, got nil")
	}

	// Error should indicate profiles are required
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("expected error about profiles, got: %v", err)
	}

	// Verify no SSM calls were made
	if len(mock.calls) > 0 {
		t.Errorf("expected no SSM calls for nil profiles, got %d calls", len(mock.calls))
	}
}

// TestPlanner_Plan_ConfigEmptyProfiles tests config with empty Profiles slice.
func TestPlanner_Plan_ConfigEmptyProfiles(t *testing.T) {
	mock := &mockSSMAPI{}
	planner := newPlannerWithClient(mock)

	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles:   []ProfileConfig{}, // empty profiles
	}

	_, err := planner.Plan(context.Background(), config)
	if err == nil {
		t.Fatal("expected error for empty profiles, got nil")
	}

	// Error should indicate profiles are required
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("expected error about profiles, got: %v", err)
	}

	// Verify no SSM calls were made
	if len(mock.calls) > 0 {
		t.Errorf("expected no SSM calls for empty profiles, got %d calls", len(mock.calls))
	}
}

// TestPlanner_Plan_ParameterVersionEdgeCases tests edge cases for parameter version handling.
func TestPlanner_Plan_ParameterVersionEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		version        int64
		expectedVer    string
		shouldHaveVer  bool
	}{
		{
			name:           "version 0 (no version)",
			version:        0,
			expectedVer:    "",
			shouldHaveVer:  false,
		},
		{
			name:           "version 1",
			version:        1,
			expectedVer:    "1",
			shouldHaveVer:  true,
		},
		{
			name:           "very high version number",
			version:        9999999999,
			expectedVer:    "9999999999",
			shouldHaveVer:  true,
		},
		{
			name:           "max int64 version",
			version:        9223372036854775807,
			expectedVer:    "9223372036854775807",
			shouldHaveVer:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockSSMAPI{
				getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
					return &ssm.GetParameterOutput{
						Parameter: &types.Parameter{
							Name:    params.Name,
							Value:   aws.String("policy-content"),
							Version: tt.version,
						},
					}, nil
				},
			}

			planner := newPlannerWithClient(mock)
			config := &BootstrapConfig{
				PolicyRoot: "/sentinel/policies",
				Profiles: []ProfileConfig{
					{Name: "test"},
				},
			}

			plan, err := planner.Plan(context.Background(), config)
			if err != nil {
				t.Fatalf("Plan() error = %v", err)
			}

			if len(plan.Resources) != 1 {
				t.Fatalf("expected 1 resource, got %d", len(plan.Resources))
			}

			r := plan.Resources[0]
			if r.State != StateExists {
				t.Errorf("expected state %s, got %s", StateExists, r.State)
			}

			if tt.shouldHaveVer {
				if r.CurrentVersion != tt.expectedVer {
					t.Errorf("expected version %q, got %q", tt.expectedVer, r.CurrentVersion)
				}
			} else {
				if r.CurrentVersion != "" {
					t.Errorf("expected empty version, got %q", r.CurrentVersion)
				}
			}
		})
	}
}

// TestPlanner_Plan_NilParameter tests handling when GetParameter returns nil Parameter field.
func TestPlanner_Plan_NilParameter(t *testing.T) {
	mock := &mockSSMAPI{
		getParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			// Return successful response but with nil Parameter
			return &ssm.GetParameterOutput{
				Parameter: nil,
			}, nil
		},
	}

	planner := newPlannerWithClient(mock)
	config := &BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{Name: "test"},
		},
	}

	plan, err := planner.Plan(context.Background(), config)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	// Should still mark as exists (successful GetParameter)
	// Version should be empty due to nil Parameter
	if len(plan.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(plan.Resources))
	}

	r := plan.Resources[0]
	if r.State != StateExists {
		t.Errorf("expected state %s, got %s", StateExists, r.State)
	}
	if r.CurrentVersion != "" {
		t.Errorf("expected empty version for nil Parameter, got %q", r.CurrentVersion)
	}
}
