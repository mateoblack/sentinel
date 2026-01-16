package bootstrap

import (
	"context"
	"errors"
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
