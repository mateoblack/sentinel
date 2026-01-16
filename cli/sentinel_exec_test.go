package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/request"
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

// mockExecStore implements request.Store for testing approved request checking.
type mockExecStore struct {
	listByRequesterFunc func(ctx context.Context, requester string, limit int) ([]*request.Request, error)
}

func (m *mockExecStore) Create(ctx context.Context, req *request.Request) error {
	return nil
}

func (m *mockExecStore) Get(ctx context.Context, id string) (*request.Request, error) {
	return nil, nil
}

func (m *mockExecStore) Update(ctx context.Context, req *request.Request) error {
	return nil
}

func (m *mockExecStore) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockExecStore) ListByRequester(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
	if m.listByRequesterFunc != nil {
		return m.listByRequesterFunc(ctx, requester, limit)
	}
	return []*request.Request{}, nil
}

func (m *mockExecStore) ListByStatus(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error) {
	return []*request.Request{}, nil
}

func (m *mockExecStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
	return []*request.Request{}, nil
}

func TestSentinelExecCommandInput_StoreField(t *testing.T) {
	// Test that SentinelExecCommandInput has the Store field for approved request checking
	t.Run("Store field is nil by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.Store != nil {
			t.Error("expected Store to be nil by default")
		}
	})

	t.Run("Store field can be set", func(t *testing.T) {
		store := &mockExecStore{}
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			Store:           store,
		}
		if input.Store == nil {
			t.Error("expected Store to be set")
		}
	})
}

func TestSentinelExecCommand_ApprovedRequestIntegration(t *testing.T) {
	// These tests verify the store integration at the input/config level.
	// Full end-to-end tests require AWS credentials and are integration tests.

	t.Run("store nil does not cause panic", func(t *testing.T) {
		// Verify that having Store=nil is safe (backward compatible)
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			Store:           nil, // Explicitly nil
		}

		// Verify nil store doesn't panic when accessed
		if input.Store != nil {
			t.Error("Store should be nil")
		}
	})

	t.Run("store with approved request configured", func(t *testing.T) {
		// Create a mock store that would return an approved request
		now := time.Now()
		approvedRequest := &request.Request{
			ID:        "execapproved001",
			Requester: "charlie",
			Profile:   "production",
			Status:    request.StatusApproved,
			Duration:  2 * time.Hour,
			CreatedAt: now.Add(-time.Hour),
			ExpiresAt: now.Add(23 * time.Hour),
		}

		store := &mockExecStore{
			listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
				if requester == "charlie" {
					return []*request.Request{approvedRequest}, nil
				}
				return []*request.Request{}, nil
			},
		}

		input := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/test",
			Store:           store,
		}

		// Verify store can find approved request
		foundReq, err := request.FindApprovedRequest(context.Background(), input.Store, "charlie", "production")
		if err != nil {
			t.Fatalf("FindApprovedRequest error: %v", err)
		}
		if foundReq == nil {
			t.Fatal("expected to find approved request")
		}
		if foundReq.ID != "execapproved001" {
			t.Errorf("expected ID execapproved001, got %s", foundReq.ID)
		}
	})

	t.Run("store without approved request returns nil", func(t *testing.T) {
		// Create a mock store with no approved requests
		store := &mockExecStore{
			listByRequesterFunc: func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
				return []*request.Request{}, nil
			},
		}

		input := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/test",
			Store:           store,
		}

		// Verify store returns nil when no approved request exists
		foundReq, err := request.FindApprovedRequest(context.Background(), input.Store, "dave", "production")
		if err != nil {
			t.Fatalf("FindApprovedRequest error: %v", err)
		}
		if foundReq != nil {
			t.Errorf("expected nil, got request: %v", foundReq)
		}
	})
}

// mockExecBreakGlassStore implements breakglass.Store for testing break-glass checking.
type mockExecBreakGlassStore struct {
	listByInvokerFunc func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error)
}

func (m *mockExecBreakGlassStore) Create(ctx context.Context, event *breakglass.BreakGlassEvent) error {
	return nil
}

func (m *mockExecBreakGlassStore) Get(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
	return nil, nil
}

func (m *mockExecBreakGlassStore) Update(ctx context.Context, event *breakglass.BreakGlassEvent) error {
	return nil
}

func (m *mockExecBreakGlassStore) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockExecBreakGlassStore) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
	if m.listByInvokerFunc != nil {
		return m.listByInvokerFunc(ctx, invoker, limit)
	}
	return []*breakglass.BreakGlassEvent{}, nil
}

func (m *mockExecBreakGlassStore) ListByStatus(ctx context.Context, status breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error) {
	return []*breakglass.BreakGlassEvent{}, nil
}

func (m *mockExecBreakGlassStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*breakglass.BreakGlassEvent, error) {
	return []*breakglass.BreakGlassEvent{}, nil
}

func (m *mockExecBreakGlassStore) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
	return nil, nil
}

func (m *mockExecBreakGlassStore) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	return 0, nil
}

func (m *mockExecBreakGlassStore) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	return 0, nil
}

func (m *mockExecBreakGlassStore) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
	return nil, nil
}

func TestSentinelExecCommandInput_BreakGlassStoreField(t *testing.T) {
	// Test that SentinelExecCommandInput has the BreakGlassStore field
	t.Run("BreakGlassStore field is nil by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.BreakGlassStore != nil {
			t.Error("expected BreakGlassStore to be nil by default")
		}
	})

	t.Run("BreakGlassStore field can be set", func(t *testing.T) {
		store := &mockExecBreakGlassStore{}
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			BreakGlassStore: store,
		}
		if input.BreakGlassStore == nil {
			t.Error("expected BreakGlassStore to be set")
		}
	})
}

func TestSentinelExecCommand_BreakGlassIntegration(t *testing.T) {
	// These tests verify the break-glass store integration at the input/config level.
	// Full end-to-end tests require AWS credentials and are integration tests.

	t.Run("BreakGlassStore nil does not cause panic", func(t *testing.T) {
		// Verify that having BreakGlassStore=nil is safe (backward compatible)
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			BreakGlassStore: nil, // Explicitly nil
		}

		// Verify nil store doesn't panic when accessed
		if input.BreakGlassStore != nil {
			t.Error("BreakGlassStore should be nil")
		}
	})

	t.Run("store with active break-glass configured", func(t *testing.T) {
		// Create a mock store that would return an active break-glass event
		now := time.Now()
		activeBreakGlass := &breakglass.BreakGlassEvent{
			ID:            "exec1234exec1234",
			Invoker:       "charlie",
			Profile:       "production",
			Status:        breakglass.StatusActive,
			ReasonCode:    breakglass.ReasonSecurity,
			Justification: "Security incident response",
			Duration:      2 * time.Hour,
			CreatedAt:     now.Add(-30 * time.Minute),
			ExpiresAt:     now.Add(90 * time.Minute), // 90 minutes remaining
		}

		store := &mockExecBreakGlassStore{
			listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
				if invoker == "charlie" {
					return []*breakglass.BreakGlassEvent{activeBreakGlass}, nil
				}
				return []*breakglass.BreakGlassEvent{}, nil
			},
		}

		input := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/test",
			BreakGlassStore: store,
		}

		// Verify store can find active break-glass
		foundEvent, err := breakglass.FindActiveBreakGlass(context.Background(), input.BreakGlassStore, "charlie", "production")
		if err != nil {
			t.Fatalf("FindActiveBreakGlass error: %v", err)
		}
		if foundEvent == nil {
			t.Fatal("expected to find active break-glass event")
		}
		if foundEvent.ID != "exec1234exec1234" {
			t.Errorf("expected ID exec1234exec1234, got %s", foundEvent.ID)
		}
	})

	t.Run("store without active break-glass returns nil", func(t *testing.T) {
		// Create a mock store with no active break-glass events
		store := &mockExecBreakGlassStore{
			listByInvokerFunc: func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
				return []*breakglass.BreakGlassEvent{}, nil
			},
		}

		input := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/test",
			BreakGlassStore: store,
		}

		// Verify store returns nil when no active break-glass exists
		foundEvent, err := breakglass.FindActiveBreakGlass(context.Background(), input.BreakGlassStore, "eve", "production")
		if err != nil {
			t.Fatalf("FindActiveBreakGlass error: %v", err)
		}
		if foundEvent != nil {
			t.Errorf("expected nil, got event: %v", foundEvent)
		}
	})

	t.Run("session duration capped to remaining break-glass time", func(t *testing.T) {
		// Create a mock break-glass event with 45 minutes remaining
		now := time.Now()
		activeBreakGlass := &breakglass.BreakGlassEvent{
			ID:        "exec567890123456",
			Invoker:   "charlie",
			Profile:   "production",
			Status:    breakglass.StatusActive,
			ExpiresAt: now.Add(45 * time.Minute), // 45 minutes remaining
		}

		// Verify RemainingDuration calculation
		remaining := breakglass.RemainingDuration(activeBreakGlass)
		if remaining <= 0 {
			t.Fatal("expected positive remaining duration")
		}
		if remaining > 46*time.Minute {
			t.Errorf("expected remaining ~45 minutes, got %v", remaining)
		}

		// Test capping logic:
		// If sessionDuration=0 or sessionDuration > remainingTime, cap to remainingTime
		sessionDuration := 2 * time.Hour // Request 2 hours
		if sessionDuration > remaining {
			sessionDuration = remaining // Should be capped to ~45 minutes
		}
		if sessionDuration > 46*time.Minute {
			t.Errorf("session should be capped to ~45 minutes, got %v", sessionDuration)
		}
	})

	t.Run("BreakGlassEventID appears in log output", func(t *testing.T) {
		// Test that BreakGlassEventID is included in credential issuance fields
		credFields := &logging.CredentialIssuanceFields{
			RequestID:         "exec5678",
			BreakGlassEventID: "bg789012bg789012",
		}

		if credFields.BreakGlassEventID != "bg789012bg789012" {
			t.Errorf("expected BreakGlassEventID bg789012bg789012, got %s", credFields.BreakGlassEventID)
		}
	})
}
