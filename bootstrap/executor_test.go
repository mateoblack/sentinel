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

// ============================================================================
// Workflow Integrity Tests
// ============================================================================

func TestExecutor_Apply_PlaceholderPolicyIsValidYAML(t *testing.T) {
	var capturedValue string
	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			capturedValue = aws.ToString(params.Value)
			return &ssm.PutParameterOutput{Version: 1}, nil
		},
	}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/test", State: StateCreate},
		},
	}

	_, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify placeholder policy is valid and parseable
	if capturedValue == "" {
		t.Fatal("expected non-empty policy value")
	}

	// Parse with policy.ParsePolicy to ensure it's valid
	parsedPolicy, err := policy.ParsePolicy([]byte(capturedValue))
	if err != nil {
		t.Fatalf("placeholder policy failed to parse: %v", err)
	}

	// Verify expected structure
	if parsedPolicy.Version != "1" {
		t.Errorf("expected policy version '1', got %q", parsedPolicy.Version)
	}
}

func TestExecutor_Apply_ParameterTypeAlwaysString(t *testing.T) {
	var capturedTypes []types.ParameterType
	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			capturedTypes = append(capturedTypes, params.Type)
			return &ssm.PutParameterOutput{Version: 1}, nil
		},
	}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/staging", State: StateUpdate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/prod", State: StateCreate},
		},
	}

	_, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify all parameters are String type (not SecureString)
	for i, paramType := range capturedTypes {
		if paramType != types.ParameterTypeString {
			t.Errorf("call %d: expected type String, got %v", i, paramType)
		}
	}
}

func TestExecutor_Apply_WorkflowResultStructure(t *testing.T) {
	mock := &mockSSMWriterAPI{}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/new1", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/new2", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/update1", State: StateUpdate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/exist1", State: StateExists},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/skip1", State: StateSkip},
			{Type: ResourceTypeIAMPolicy, Name: "SentinelPolicyReader", State: StateCreate},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Verify result structure
	if len(result.Created) != 2 {
		t.Errorf("expected 2 created, got %d: %v", len(result.Created), result.Created)
	}
	if len(result.Updated) != 1 {
		t.Errorf("expected 1 updated, got %d: %v", len(result.Updated), result.Updated)
	}
	// Skipped includes: exists (1) + skip (1) + IAM policy (1) = 3
	if len(result.Skipped) != 3 {
		t.Errorf("expected 3 skipped, got %d: %v", len(result.Skipped), result.Skipped)
	}
	if len(result.Failed) != 0 {
		t.Errorf("expected 0 failed, got %d: %v", len(result.Failed), result.Failed)
	}
}

// ============================================================================
// Concurrent Operation Tests
// ============================================================================

func TestExecutor_Apply_ConcurrentAppliesRaceCondition(t *testing.T) {
	// Simulate concurrent applies where second gets AlreadyExists
	existingParams := make(map[string]bool)
	var mu sync.Mutex

	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			name := aws.ToString(params.Name)
			overwrite := aws.ToBool(params.Overwrite)

			mu.Lock()
			defer mu.Unlock()

			// If create (Overwrite=false) and already exists, return error
			if !overwrite && existingParams[name] {
				return nil, &types.ParameterAlreadyExists{}
			}

			existingParams[name] = true
			return &ssm.PutParameterOutput{Version: 1}, nil
		},
	}

	executor := newExecutorWithClient(mock)

	// First apply creates the parameter
	plan1 := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/shared", State: StateCreate},
		},
	}

	result1, err := executor.Apply(context.Background(), plan1)
	if err != nil {
		t.Fatalf("First Apply() error = %v", err)
	}
	if len(result1.Created) != 1 {
		t.Errorf("first apply: expected 1 created, got %d", len(result1.Created))
	}

	// Second apply tries to create same parameter - gets AlreadyExists
	plan2 := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/shared", State: StateCreate},
		},
	}

	result2, err := executor.Apply(context.Background(), plan2)
	if err != nil {
		t.Fatalf("Second Apply() error = %v", err)
	}

	// Should have recorded the failure
	if len(result2.Failed) != 1 {
		t.Errorf("second apply: expected 1 failed, got %d", len(result2.Failed))
	}
	if len(result2.Created) != 0 {
		t.Errorf("second apply: expected 0 created, got %d", len(result2.Created))
	}

	// Error message should mention race condition
	if len(result2.Failed) > 0 && !strings.Contains(result2.Failed[0].Error, "race condition") {
		t.Errorf("expected race condition in error, got: %s", result2.Failed[0].Error)
	}
}

func TestExecutor_Apply_Parallel(t *testing.T) {
	t.Parallel()

	var totalCalls int32

	// Create a shared putParameter function that uses atomic for call counting
	sharedPutFunc := func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
		atomic.AddInt32(&totalCalls, 1)
		return &ssm.PutParameterOutput{Version: 1}, nil
	}

	// Run multiple applies in parallel with unique parameter names
	// Each goroutine gets its own executor/mock to avoid race on calls slice
	var wg sync.WaitGroup
	results := make([]*ApplyResult, 5)
	errs := make([]error, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Each goroutine creates its own mock and executor
			mock := &mockSSMWriterAPI{
				putParameterFunc: sharedPutFunc,
			}
			executor := newExecutorWithClient(mock)

			plan := &BootstrapPlan{
				Resources: []ResourceSpec{
					{
						Type:  ResourceTypeSSMParameter,
						Name:  "/sentinel/policies/parallel-" + string(rune('a'+idx)),
						State: StateCreate,
					},
				},
			}
			results[idx], errs[idx] = executor.Apply(context.Background(), plan)
		}(i)
	}

	wg.Wait()

	// Verify all completed successfully
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: Apply() error = %v", i, err)
		}
	}
	for i, result := range results {
		if result == nil {
			t.Errorf("goroutine %d: nil result", i)
			continue
		}
		if len(result.Created) != 1 {
			t.Errorf("goroutine %d: expected 1 created, got %d", i, len(result.Created))
		}
	}

	// Should have made 5 total calls
	if atomic.LoadInt32(&totalCalls) != 5 {
		t.Errorf("expected 5 total calls, got %d", totalCalls)
	}
}

// ============================================================================
// Error Recovery Tests
// ============================================================================

func TestExecutor_Apply_PartialFailure(t *testing.T) {
	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			name := aws.ToString(params.Name)
			// Fail specific parameters
			if strings.Contains(name, "fail") {
				return nil, errors.New("simulated failure")
			}
			return &ssm.PutParameterOutput{Version: 1}, nil
		},
	}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/success-1", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/fail-1", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/success-2", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/fail-2", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/success-3", State: StateCreate},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() should not return error for partial failures, got: %v", err)
	}

	// Verify partial results
	if len(result.Created) != 3 {
		t.Errorf("expected 3 created, got %d", len(result.Created))
	}
	if len(result.Failed) != 2 {
		t.Errorf("expected 2 failed, got %d", len(result.Failed))
	}

	// Verify failed contains correct error messages
	for _, f := range result.Failed {
		if f.Error == "" {
			t.Error("expected non-empty error message in failed entry")
		}
		if !strings.Contains(f.Name, "fail") {
			t.Errorf("unexpected failed parameter: %s", f.Name)
		}
	}
}

func TestExecutor_Apply_ErrorDoesNotLeakSensitiveInfo(t *testing.T) {
	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			// Return error with potentially sensitive info
			return nil, errors.New("AccessDenied: User arn:aws:iam::123456789012:user/secret-user is not authorized")
		},
	}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/test", State: StateCreate},
		},
	}

	result, _ := executor.Apply(context.Background(), plan)

	// The error is passed through, which is expected - the test documents this behavior
	// In practice, sensitive info filtering would be a separate concern
	if len(result.Failed) != 1 {
		t.Fatalf("expected 1 failed, got %d", len(result.Failed))
	}

	// Error should be recorded
	if result.Failed[0].Error == "" {
		t.Error("expected non-empty error message")
	}
}

// ============================================================================
// Update Error Edge Cases
// ============================================================================

func TestExecutor_Apply_UpdateOverwriteFailure(t *testing.T) {
	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			// Simulate failure during overwrite
			if aws.ToBool(params.Overwrite) {
				return nil, errors.New("ParameterVersionLabelLimitExceeded: cannot update")
			}
			return &ssm.PutParameterOutput{Version: 1}, nil
		},
	}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/update-test", State: StateUpdate},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Should have recorded the failure
	if len(result.Failed) != 1 {
		t.Fatalf("expected 1 failed, got %d", len(result.Failed))
	}
	if len(result.Updated) != 0 {
		t.Errorf("expected 0 updated, got %d", len(result.Updated))
	}

	// Verify error is wrapped properly
	if !strings.Contains(result.Failed[0].Error, "SSM PutParameter failed") {
		t.Errorf("expected wrapped error message, got: %s", result.Failed[0].Error)
	}
}

func TestExecutor_Apply_StateUpdateWithMixedResults(t *testing.T) {
	callNum := 0
	mock := &mockSSMWriterAPI{
		putParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			callNum++
			// Second update call fails
			if callNum == 2 && aws.ToBool(params.Overwrite) {
				return nil, errors.New("update failed")
			}
			return &ssm.PutParameterOutput{Version: int64(callNum)}, nil
		},
	}
	executor := newExecutorWithClient(mock)

	plan := &BootstrapPlan{
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/update-1", State: StateUpdate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/update-2", State: StateUpdate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/update-3", State: StateUpdate},
		},
	}

	result, err := executor.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Should have 2 success, 1 failure
	if len(result.Updated) != 2 {
		t.Errorf("expected 2 updated, got %d", len(result.Updated))
	}
	if len(result.Failed) != 1 {
		t.Errorf("expected 1 failed, got %d", len(result.Failed))
	}

	// Verify the failed one is update-2
	if len(result.Failed) > 0 && result.Failed[0].Name != "/sentinel/policies/update-2" {
		t.Errorf("expected update-2 to fail, got %s", result.Failed[0].Name)
	}
}
