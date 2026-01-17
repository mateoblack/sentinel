package bootstrap

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/byteness/aws-vault/v7/policy"
)

// PutParameterCall records a PutParameter invocation.
type PutParameterCall struct {
	Name      string
	Value     string
	Overwrite bool
	Type      types.ParameterType
}

// mockSSMWriterAPI implements ssmWriterAPI for testing.
type mockSSMWriterAPI struct {
	putParameterFunc func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
	calls            []PutParameterCall
}

func (m *mockSSMWriterAPI) PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	m.calls = append(m.calls, PutParameterCall{
		Name:      aws.ToString(params.Name),
		Value:     aws.ToString(params.Value),
		Overwrite: aws.ToBool(params.Overwrite),
		Type:      params.Type,
	})
	if m.putParameterFunc != nil {
		return m.putParameterFunc(ctx, params, optFns...)
	}
	return &ssm.PutParameterOutput{}, nil
}

func TestExecutor_Apply_CreateSuccess(t *testing.T) {
	mock := &mockSSMWriterAPI{}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{
				Type:  ResourceTypeSSMParameter,
				Name:  "/sentinel/policies/dev",
				State: StateCreate,
			},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify PutParameter was called with Overwrite=false
	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(mock.calls))
	}
	if mock.calls[0].Overwrite {
		t.Error("expected Overwrite=false for create")
	}
	if mock.calls[0].Name != "/sentinel/policies/dev" {
		t.Errorf("expected name '/sentinel/policies/dev', got %q", mock.calls[0].Name)
	}
	if mock.calls[0].Type != types.ParameterTypeString {
		t.Errorf("expected type String, got %v", mock.calls[0].Type)
	}

	// Verify result
	if len(result.Created) != 1 || result.Created[0] != "/sentinel/policies/dev" {
		t.Errorf("expected created=['/sentinel/policies/dev'], got %v", result.Created)
	}
	if len(result.Failed) != 0 {
		t.Errorf("expected no failures, got %v", result.Failed)
	}
}

func TestExecutor_Apply_UpdateSuccess(t *testing.T) {
	mock := &mockSSMWriterAPI{}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{
				Type:  ResourceTypeSSMParameter,
				Name:  "/sentinel/policies/staging",
				State: StateUpdate,
			},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify PutParameter was called with Overwrite=true
	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(mock.calls))
	}
	if !mock.calls[0].Overwrite {
		t.Error("expected Overwrite=true for update")
	}

	// Verify result
	if len(result.Updated) != 1 || result.Updated[0] != "/sentinel/policies/staging" {
		t.Errorf("expected updated=['/sentinel/policies/staging'], got %v", result.Updated)
	}
	if len(result.Failed) != 0 {
		t.Errorf("expected no failures, got %v", result.Failed)
	}
}

func TestExecutor_Apply_SkipExisting(t *testing.T) {
	mock := &mockSSMWriterAPI{}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{
				Type:           ResourceTypeSSMParameter,
				Name:           "/sentinel/policies/prod",
				State:          StateExists,
				CurrentVersion: "5",
			},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify no PutParameter call
	if len(mock.calls) != 0 {
		t.Errorf("expected no calls for existing, got %d", len(mock.calls))
	}

	// Verify result
	if len(result.Skipped) != 1 || result.Skipped[0] != "/sentinel/policies/prod" {
		t.Errorf("expected skipped=['/sentinel/policies/prod'], got %v", result.Skipped)
	}
}

func TestExecutor_Apply_SkipMarked(t *testing.T) {
	mock := &mockSSMWriterAPI{}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{
				Type:  ResourceTypeSSMParameter,
				Name:  "/sentinel/policies/legacy",
				State: StateSkip,
			},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify no PutParameter call
	if len(mock.calls) != 0 {
		t.Errorf("expected no calls for skip, got %d", len(mock.calls))
	}

	// Verify result
	if len(result.Skipped) != 1 || result.Skipped[0] != "/sentinel/policies/legacy" {
		t.Errorf("expected skipped=['/sentinel/policies/legacy'], got %v", result.Skipped)
	}
}

func TestExecutor_Apply_MultipleResources(t *testing.T) {
	mock := &mockSSMWriterAPI{}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/staging", State: StateUpdate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/prod", State: StateExists},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/legacy", State: StateSkip},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify calls: create and update only
	if len(mock.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(mock.calls))
	}

	// First call should be create (Overwrite=false)
	if mock.calls[0].Name != "/sentinel/policies/dev" || mock.calls[0].Overwrite {
		t.Errorf("call[0]: expected dev create, got %+v", mock.calls[0])
	}
	// Second call should be update (Overwrite=true)
	if mock.calls[1].Name != "/sentinel/policies/staging" || !mock.calls[1].Overwrite {
		t.Errorf("call[1]: expected staging update, got %+v", mock.calls[1])
	}

	// Verify result counts
	if len(result.Created) != 1 {
		t.Errorf("expected 1 created, got %d", len(result.Created))
	}
	if len(result.Updated) != 1 {
		t.Errorf("expected 1 updated, got %d", len(result.Updated))
	}
	if len(result.Skipped) != 2 {
		t.Errorf("expected 2 skipped, got %d", len(result.Skipped))
	}
}

func TestExecutor_Apply_CreateAlreadyExists(t *testing.T) {
	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			return nil, &types.ParameterAlreadyExists{}
		},
	}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify failure recorded
	if len(result.Failed) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(result.Failed))
	}
	if result.Failed[0].Name != "/sentinel/policies/dev" {
		t.Errorf("expected failed name '/sentinel/policies/dev', got %q", result.Failed[0].Name)
	}
	if result.Failed[0].Error == "" {
		t.Error("expected non-empty error message")
	}

	// Verify not in created list
	if len(result.Created) != 0 {
		t.Errorf("expected 0 created, got %v", result.Created)
	}
}

func TestExecutor_Apply_GenericError(t *testing.T) {
	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			return nil, errors.New("access denied")
		},
	}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify failure recorded
	if len(result.Failed) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(result.Failed))
	}
	if result.Failed[0].Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestExecutor_Apply_ContinuesOnError(t *testing.T) {
	callCount := 0
	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			callCount++
			name := aws.ToString(params.Name)
			// First create fails
			if name == "/sentinel/policies/dev" {
				return nil, errors.New("access denied")
			}
			return &ssm.PutParameterOutput{}, nil
		},
	}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/staging", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/prod", State: StateCreate},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify all 3 calls were made despite first failure
	if callCount != 3 {
		t.Errorf("expected 3 calls (continues on error), got %d", callCount)
	}

	// Verify 1 failure, 2 successes
	if len(result.Failed) != 1 {
		t.Errorf("expected 1 failure, got %d", len(result.Failed))
	}
	if len(result.Created) != 2 {
		t.Errorf("expected 2 created, got %d", len(result.Created))
	}
}

func TestExecutor_Apply_IAMPolicySkipped(t *testing.T) {
	mock := &mockSSMWriterAPI{}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeIAMPolicy, Name: "SentinelPolicyReader", State: StateCreate},
			{Type: ResourceTypeIAMPolicy, Name: "SentinelPolicyAdmin", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify only SSM parameter was processed
	if len(mock.calls) != 1 {
		t.Errorf("expected 1 call (SSM only), got %d", len(mock.calls))
	}

	// Verify IAM policies in skipped
	if len(result.Skipped) != 2 {
		t.Errorf("expected 2 skipped (IAM policies), got %d", len(result.Skipped))
	}
	// Verify SSM parameter in created
	if len(result.Created) != 1 {
		t.Errorf("expected 1 created (SSM parameter), got %d", len(result.Created))
	}
}

func TestExecutor_Apply_EmptyPlan(t *testing.T) {
	mock := &mockSSMWriterAPI{}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify no calls
	if len(mock.calls) != 0 {
		t.Errorf("expected 0 calls, got %d", len(mock.calls))
	}

	// Verify empty result
	if len(result.Created) != 0 || len(result.Updated) != 0 || len(result.Skipped) != 0 || len(result.Failed) != 0 {
		t.Errorf("expected empty result, got created=%d updated=%d skipped=%d failed=%d",
			len(result.Created), len(result.Updated), len(result.Skipped), len(result.Failed))
	}
}
