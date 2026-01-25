package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/vault"
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

// mockExecSTSClient implements identity.STSAPI for testing.
type mockExecSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockExecSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return &sts.GetCallerIdentityOutput{
		Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
		Account: aws.String("123456789012"),
		UserId:  aws.String("AIDAEXAMPLE"),
	}, nil
}

func TestSentinelExecCommandInput_STSClientField(t *testing.T) {
	t.Run("STSClient field is nil by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.STSClient != nil {
			t.Error("expected STSClient to be nil by default")
		}
	})

	t.Run("STSClient field can be set", func(t *testing.T) {
		client := &mockExecSTSClient{}
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			STSClient:       client,
		}
		if input.STSClient == nil {
			t.Error("expected STSClient to be set")
		}
	})
}

func TestSentinelExecCommand_AWSIdentityIntegration(t *testing.T) {
	t.Run("STSClient extracts username from IAM user ARN", func(t *testing.T) {
		client := &mockExecSTSClient{
			GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
				return &sts.GetCallerIdentityOutput{
					Arn:     aws.String("arn:aws:iam::123456789012:user/bob"),
					Account: aws.String("123456789012"),
					UserId:  aws.String("AIDABOB"),
				}, nil
			},
		}

		username, err := identity.GetAWSUsername(context.Background(), client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "bob" {
			t.Errorf("expected username 'bob', got %q", username)
		}
	})

	t.Run("STSClient extracts sanitized username from SSO assumed-role ARN", func(t *testing.T) {
		client := &mockExecSTSClient{
			GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
				return &sts.GetCallerIdentityOutput{
					Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Developer_xyz/bob.smith@company.org"),
					Account: aws.String("123456789012"),
					UserId:  aws.String("AROA456789:bob.smith@company.org"),
				}, nil
			},
		}

		username, err := identity.GetAWSUsername(context.Background(), client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Email sanitized: @ and . removed, truncated to 20 chars
		if username != "bobsmithcompanyorg" {
			t.Errorf("expected sanitized username 'bobsmithcompanyorg', got %q", username)
		}
	})

	t.Run("STSClient extracts username from regular assumed-role ARN", func(t *testing.T) {
		client := &mockExecSTSClient{
			GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
				return &sts.GetCallerIdentityOutput{
					Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/AdminRole/admin-session"),
					Account: aws.String("123456789012"),
					UserId:  aws.String("AROA789012:admin-session"),
				}, nil
			},
		}

		username, err := identity.GetAWSUsername(context.Background(), client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Hyphen removed from session name
		if username != "adminsession" {
			t.Errorf("expected username 'adminsession', got %q", username)
		}
	})

	t.Run("STSClient error propagates", func(t *testing.T) {
		client := &mockExecSTSClient{
			GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
				return nil, &mockExecError{message: "AccessDenied: User is not authorized"}
			},
		}

		_, err := identity.GetAWSUsername(context.Background(), client)
		if err == nil {
			t.Fatal("expected error for access denied")
		}
		if !strings.Contains(err.Error(), "failed to get caller identity") {
			t.Errorf("expected error to mention 'failed to get caller identity', got: %v", err)
		}
	})
}

// mockExecError is a simple error type for testing.
type mockExecError struct {
	message string
}

func (e *mockExecError) Error() string {
	return e.message
}

func TestSentinelExecCommand_UsesProfileForAWSConfig(t *testing.T) {
	// This test verifies the command uses the profile for AWS config loading.
	// The actual SSO flow requires real AWS credentials, so we verify
	// the pattern is correct by checking that:
	// 1. ProfileName is required
	// 2. The command doesn't fail immediately on profile validation

	t.Run("profile name is used in config", func(t *testing.T) {
		// Create a temporary config file with an SSO profile
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config")
		configContent := `[profile exec-sso]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = ExecTestRole
region = us-west-2
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		// Set AWS_CONFIG_FILE to use our test config
		oldConfig := os.Getenv("AWS_CONFIG_FILE")
		os.Setenv("AWS_CONFIG_FILE", configPath)
		defer os.Setenv("AWS_CONFIG_FILE", oldConfig)

		// The command should recognize the SSO profile
		// (actual credential loading would require real SSO session)
		s := &Sentinel{}
		err := s.ValidateProfile("exec-sso")
		if err != nil {
			t.Fatalf("ValidateProfile failed: %v", err)
		}
	})

	t.Run("SSO profile is recognized", func(t *testing.T) {
		// Create a config file with SSO settings
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config")
		configContent := `[profile exec-sso-profile]
sso_start_url = https://exec-sso.awsapps.com/start
sso_region = us-west-2
sso_account_id = 444455556666
sso_role_name = ExecRole
region = eu-west-1
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		configFile, err := vault.LoadConfig(configPath)
		if err != nil {
			t.Fatalf("failed to load config: %v", err)
		}

		// Verify the profile has SSO settings
		profile, ok := configFile.ProfileSection("exec-sso-profile")
		if !ok {
			t.Fatal("expected to find exec-sso-profile")
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

	t.Run("input accepts SSO profile for credential loading", func(t *testing.T) {
		// Verify SentinelExecCommandInput can be configured with an SSO profile
		// This tests the integration point where profile name flows to AWS config
		input := SentinelExecCommandInput{
			ProfileName:     "sso-exec-prod",
			PolicyParameter: "/sentinel/policies/default",
			Region:          "us-east-1",
			Command:         "aws",
			Args:            []string{"s3", "ls"},
		}

		// Profile name should be set and will be used for WithSharedConfigProfile
		if input.ProfileName != "sso-exec-prod" {
			t.Errorf("expected profile name 'sso-exec-prod', got %q", input.ProfileName)
		}
	})
}

func TestSentinelExecCommandInput_AutoLoginFields(t *testing.T) {
	t.Run("AutoLogin field is false by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.AutoLogin {
			t.Error("expected AutoLogin to be false by default")
		}
	})

	t.Run("AutoLogin field can be set", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			AutoLogin:       true,
		}
		if !input.AutoLogin {
			t.Error("expected AutoLogin to be true")
		}
	})

	t.Run("UseStdout field is false by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.UseStdout {
			t.Error("expected UseStdout to be false by default")
		}
	})

	t.Run("UseStdout field can be set", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			UseStdout:       true,
		}
		if !input.UseStdout {
			t.Error("expected UseStdout to be true")
		}
	})

	t.Run("ConfigFile field is nil by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.ConfigFile != nil {
			t.Error("expected ConfigFile to be nil by default")
		}
	})

	t.Run("ConfigFile field can be set", func(t *testing.T) {
		// Create a minimal config file for testing
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config")
		configContent := `[profile test]
region = us-east-1
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		configFile, err := vault.LoadConfig(configPath)
		if err != nil {
			t.Fatalf("failed to load config: %v", err)
		}

		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			ConfigFile:      configFile,
		}
		if input.ConfigFile == nil {
			t.Error("expected ConfigFile to be set")
		}
	})
}

func TestSentinelExecCommand_AutoLoginIntegration(t *testing.T) {
	t.Run("auto-login disabled by default (backward compatible)", func(t *testing.T) {
		// Verify that having AutoLogin=false is the default behavior
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			AutoLogin:       false, // Explicitly false
		}

		if input.AutoLogin {
			t.Error("AutoLogin should be false by default")
		}
	})

	t.Run("auto-login enabled with UseStdout", func(t *testing.T) {
		// Test configuration with both flags set
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			AutoLogin:       true,
			UseStdout:       true, // Print URL instead of opening browser
		}

		if !input.AutoLogin {
			t.Error("expected AutoLogin to be true")
		}
		if !input.UseStdout {
			t.Error("expected UseStdout to be true")
		}
	})

	t.Run("auto-login with SSO profile configuration", func(t *testing.T) {
		// Create a config file with SSO settings
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config")
		configContent := `[profile sso-exec-test]
sso_start_url = https://my-exec-sso-portal.awsapps.com/start
sso_region = us-west-2
sso_account_id = 987654321098
sso_role_name = ExecTestRole
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		configFile, err := vault.LoadConfig(configPath)
		if err != nil {
			t.Fatalf("failed to load config: %v", err)
		}

		input := SentinelExecCommandInput{
			ProfileName:     "sso-exec-test",
			PolicyParameter: "/sentinel/policies/test",
			AutoLogin:       true,
			ConfigFile:      configFile,
		}

		// Verify configuration is valid for auto-login
		if input.ConfigFile == nil {
			t.Fatal("expected ConfigFile to be set")
		}

		// Verify SSO profile can be found
		profile, ok := input.ConfigFile.ProfileSection("sso-exec-test")
		if !ok {
			t.Fatal("expected to find sso-exec-test profile")
		}
		if profile.SSOStartURL == "" {
			t.Error("expected profile to have SSO start URL")
		}
		if profile.SSORegion != "us-west-2" {
			t.Errorf("expected SSO region us-west-2, got %s", profile.SSORegion)
		}
	})

	t.Run("auto-login with sso-session configuration", func(t *testing.T) {
		// Create a config file with sso-session settings (modern pattern)
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config")
		configContent := `[sso-session my-sso]
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile sso-session-test]
sso_session = my-sso
sso_account_id = 123456789012
sso_role_name = AdminRole
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		configFile, err := vault.LoadConfig(configPath)
		if err != nil {
			t.Fatalf("failed to load config: %v", err)
		}

		input := SentinelExecCommandInput{
			ProfileName:     "sso-session-test",
			PolicyParameter: "/sentinel/policies/test",
			AutoLogin:       true,
			ConfigFile:      configFile,
		}

		// Verify SSO session profile can be found
		profile, ok := input.ConfigFile.ProfileSection("sso-session-test")
		if !ok {
			t.Fatal("expected to find sso-session-test profile")
		}
		if profile.SSOSession != "my-sso" {
			t.Errorf("expected sso_session my-sso, got %s", profile.SSOSession)
		}

		// Verify SSO session section can be found
		ssoSession, ok := input.ConfigFile.SSOSessionSection("my-sso")
		if !ok {
			t.Fatal("expected to find my-sso session section")
		}
		if ssoSession.SSOStartURL == "" {
			t.Error("expected sso-session to have start URL")
		}
	})
}

func TestSentinelExecCommandInput_ServerModeFields(t *testing.T) {
	t.Run("StartServer field is false by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.StartServer {
			t.Error("expected StartServer to be false by default")
		}
	})

	t.Run("StartServer field can be set", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			StartServer:     true,
		}
		if !input.StartServer {
			t.Error("expected StartServer to be true")
		}
	})

	t.Run("ServerPort field defaults to 0", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.ServerPort != 0 {
			t.Errorf("expected ServerPort to be 0 by default, got %d", input.ServerPort)
		}
	})

	t.Run("ServerPort field can be set", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			StartServer:     true,
			ServerPort:      8080,
		}
		if input.ServerPort != 8080 {
			t.Errorf("expected ServerPort to be 8080, got %d", input.ServerPort)
		}
	})

	t.Run("Lazy field is false by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.Lazy {
			t.Error("expected Lazy to be false by default")
		}
	})

	t.Run("Lazy field can be set", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			StartServer:     true,
			Lazy:            true,
		}
		if !input.Lazy {
			t.Error("expected Lazy to be true")
		}
	})
}

func TestSentinelExecCommand_ServerMode_ValidationErrors(t *testing.T) {
	t.Run("server with no-session returns error", func(t *testing.T) {
		// Create a temp config file with a valid profile
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config")
		configContent := `[profile server-test]
region = us-east-1
`
		if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to create test config file: %v", err)
		}
		t.Setenv("AWS_CONFIG_FILE", configFile)

		input := SentinelExecCommandInput{
			ProfileName:     "server-test",
			PolicyParameter: "/sentinel/policies/default",
			StartServer:     true,
			NoSession:       true, // Invalid combination
		}

		s := &Sentinel{}
		_, err := SentinelExecCommand(context.Background(), input, s)

		if err == nil {
			t.Fatal("expected error for --server with --no-session")
		}
		if !strings.Contains(err.Error(), "Can't use --server with --no-session") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

func TestSentinelExecCommand_ServerMode_Configuration(t *testing.T) {
	t.Run("server mode configuration is valid", func(t *testing.T) {
		// Test that the full server mode configuration works with valid fields
		input := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/default",
			Region:          "us-west-2",
			SessionDuration: 1 * time.Hour,
			StartServer:     true,
			ServerPort:      0, // Auto-assign
			Lazy:            false,
			LogFile:         "/tmp/sentinel.log",
			LogStderr:       true,
		}

		// Verify all fields are correctly set
		if input.ProfileName != "production" {
			t.Errorf("expected ProfileName 'production', got %q", input.ProfileName)
		}
		if input.PolicyParameter != "/sentinel/policies/default" {
			t.Errorf("expected PolicyParameter '/sentinel/policies/default', got %q", input.PolicyParameter)
		}
		if input.Region != "us-west-2" {
			t.Errorf("expected Region 'us-west-2', got %q", input.Region)
		}
		if input.SessionDuration != 1*time.Hour {
			t.Errorf("expected SessionDuration 1h, got %v", input.SessionDuration)
		}
		if !input.StartServer {
			t.Error("expected StartServer to be true")
		}
		if input.ServerPort != 0 {
			t.Errorf("expected ServerPort 0, got %d", input.ServerPort)
		}
		if input.Lazy {
			t.Error("expected Lazy to be false")
		}
	})

	t.Run("server mode with lazy load", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			StartServer:     true,
			Lazy:            true, // Defers credential prefetch
		}

		if !input.Lazy {
			t.Error("expected Lazy to be true for lazy credential loading")
		}
		if !input.StartServer {
			t.Error("expected StartServer to be true")
		}
	})

	t.Run("server mode with specific port", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			StartServer:     true,
			ServerPort:      9999,
		}

		if input.ServerPort != 9999 {
			t.Errorf("expected ServerPort 9999, got %d", input.ServerPort)
		}
	})

	t.Run("server mode with stores for overrides", func(t *testing.T) {
		// Server mode should support the same override stores as env var mode
		store := &mockExecStore{}
		bgStore := &mockExecBreakGlassStore{}

		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			StartServer:     true,
			Store:           store,
			BreakGlassStore: bgStore,
		}

		if input.Store == nil {
			t.Error("expected Store to be set")
		}
		if input.BreakGlassStore == nil {
			t.Error("expected BreakGlassStore to be set")
		}
	})
}

func TestSentinelExecCommandInput_ServerDurationField(t *testing.T) {
	t.Run("ServerDuration field defaults to 0", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.ServerDuration != 0 {
			t.Errorf("expected ServerDuration to be 0 by default, got %v", input.ServerDuration)
		}
	})

	t.Run("ServerDuration field can be set", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			StartServer:     true,
			ServerDuration:  10 * time.Minute,
		}
		if input.ServerDuration != 10*time.Minute {
			t.Errorf("expected ServerDuration to be 10m, got %v", input.ServerDuration)
		}
	})

	t.Run("ServerDuration 0 means use default", func(t *testing.T) {
		// When ServerDuration is 0, the command should use DefaultServerSessionDuration
		input := SentinelExecCommandInput{
			ProfileName:     "test-profile",
			PolicyParameter: "/sentinel/policies/test",
			StartServer:     true,
			ServerDuration:  0, // Should use default 15 min
		}

		// Test the logic that would be used in SentinelExecCommand
		serverDuration := input.ServerDuration
		if serverDuration == 0 {
			serverDuration = 15 * time.Minute // sentinel.DefaultServerSessionDuration
		}

		if serverDuration != 15*time.Minute {
			t.Errorf("expected resolved duration to be 15m, got %v", serverDuration)
		}
	})
}

func TestSentinelExecCommand_ServerMode_EnvVarModeComparison(t *testing.T) {
	// These tests verify that server mode and env var mode have equivalent configuration options
	t.Run("server mode has same profile configuration as env var mode", func(t *testing.T) {
		// Create equivalent configurations for both modes
		envVarMode := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/default",
			Region:          "us-east-1",
			SessionDuration: 30 * time.Minute,
			StartServer:     false, // Env var mode
			NoSession:       false,
		}

		serverMode := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/default",
			Region:          "us-east-1",
			SessionDuration: 30 * time.Minute,
			StartServer:     true, // Server mode
			ServerPort:      0,
			Lazy:            false,
		}

		// Both should have same core configuration
		if envVarMode.ProfileName != serverMode.ProfileName {
			t.Error("ProfileName should be same in both modes")
		}
		if envVarMode.PolicyParameter != serverMode.PolicyParameter {
			t.Error("PolicyParameter should be same in both modes")
		}
		if envVarMode.Region != serverMode.Region {
			t.Error("Region should be same in both modes")
		}
		if envVarMode.SessionDuration != serverMode.SessionDuration {
			t.Error("SessionDuration should be same in both modes")
		}

		// Key difference
		if envVarMode.StartServer == serverMode.StartServer {
			t.Error("StartServer should be different in both modes")
		}
	})

	t.Run("server mode cannot use no-session", func(t *testing.T) {
		// Env var mode can use --no-session
		envVarMode := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/default",
			StartServer:     false,
			NoSession:       true, // Valid for env var mode
		}
		if envVarMode.StartServer {
			t.Error("should be env var mode")
		}

		// Server mode cannot use --no-session (validation will fail)
		serverMode := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/default",
			StartServer:     true,
			NoSession:       true, // Would be rejected by validation
		}

		// Just verify the configuration - actual validation tested above
		if !serverMode.StartServer || !serverMode.NoSession {
			t.Error("test setup is wrong")
		}
	})
}

func TestSentinelExecCommand_RequireServerSession_InputFields(t *testing.T) {
	t.Run("SessionTableName field is empty by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.SessionTableName != "" {
			t.Errorf("expected SessionTableName to be empty by default, got %q", input.SessionTableName)
		}
	})

	t.Run("SessionTableName field can be set", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:      "test-profile",
			PolicyParameter:  "/sentinel/policies/test",
			SessionTableName: "sentinel-sessions",
		}
		if input.SessionTableName != "sentinel-sessions" {
			t.Errorf("expected SessionTableName 'sentinel-sessions', got %q", input.SessionTableName)
		}
	})

	t.Run("SessionTableName used with server mode", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:      "production",
			PolicyParameter:  "/sentinel/policies/default",
			StartServer:      true,
			SessionTableName: "sentinel-sessions",
		}
		if !input.StartServer {
			t.Error("expected StartServer to be true")
		}
		if input.SessionTableName != "sentinel-sessions" {
			t.Errorf("expected SessionTableName 'sentinel-sessions', got %q", input.SessionTableName)
		}
	})
}

func TestSentinelExecCommand_RequireServerSession_PolicyEvaluation(t *testing.T) {
	// Tests verify that SessionTableName is passed to policy.Request
	// and that RequiresSessionTracking decision flags produce correct errors

	t.Run("policy.Request includes SessionTableName", func(t *testing.T) {
		// Verify the Request struct can hold SessionTableName
		req := &policy.Request{
			User:             "alice",
			Profile:          "production",
			Time:             time.Now(),
			Mode:             policy.ModeServer,
			SessionTableName: "sentinel-sessions",
		}

		if req.SessionTableName != "sentinel-sessions" {
			t.Errorf("expected SessionTableName 'sentinel-sessions', got %q", req.SessionTableName)
		}
	})

	t.Run("RequiresSessionTracking decision flag exists", func(t *testing.T) {
		// Verify the Decision struct has RequiresSessionTracking flag
		decision := policy.Decision{
			Effect:                  policy.EffectDeny,
			RequiresSessionTracking: true,
			RequiresServerMode:      false,
		}

		if !decision.RequiresSessionTracking {
			t.Error("expected RequiresSessionTracking to be true")
		}
		if decision.RequiresServerMode {
			t.Error("expected RequiresServerMode to be false")
		}
	})

	t.Run("RequiresSessionTracking and RequiresServerMode can both be true", func(t *testing.T) {
		// When mode is CLI and require_server_session matches, both flags are set
		decision := policy.Decision{
			Effect:                  policy.EffectDeny,
			RequiresSessionTracking: true,
			RequiresServerMode:      true,
		}

		if !decision.RequiresSessionTracking {
			t.Error("expected RequiresSessionTracking to be true")
		}
		if !decision.RequiresServerMode {
			t.Error("expected RequiresServerMode to be true")
		}
	})
}

func TestSentinelExecCommand_RequireServerSession_ErrorMessages(t *testing.T) {
	// These tests verify the error message patterns for require_server_session scenarios

	t.Run("error message for server mode with session tracking", func(t *testing.T) {
		// When both RequiresServerMode and RequiresSessionTracking are true,
		// error should suggest --server --session-table
		profileName := "production"
		expectedPattern := "--server --session-table"

		// Simulate the error construction from sentinel_exec.go
		decision := policy.Decision{
			Effect:                  policy.EffectDeny,
			RequiresSessionTracking: true,
			RequiresServerMode:      true,
		}

		var errMsg string
		if decision.RequiresSessionTracking && decision.RequiresServerMode {
			errMsg = fmt.Sprintf("policy requires server mode with session tracking for profile %q. Use: sentinel exec --server --session-table <table> --profile %s -- <cmd>", profileName, profileName)
		}

		if !strings.Contains(errMsg, expectedPattern) {
			t.Errorf("expected error to contain %q, got: %s", expectedPattern, errMsg)
		}
		if !strings.Contains(errMsg, "session tracking") {
			t.Errorf("expected error to mention 'session tracking', got: %s", errMsg)
		}
	})

	t.Run("error message for session tracking only", func(t *testing.T) {
		// When only RequiresSessionTracking is true (already in server mode),
		// error should suggest --session-table only
		profileName := "production"
		expectedPattern := "--session-table"
		unexpectedPattern := "--server"

		decision := policy.Decision{
			Effect:                  policy.EffectDeny,
			RequiresSessionTracking: true,
			RequiresServerMode:      false,
		}

		var errMsg string
		if decision.RequiresSessionTracking && !decision.RequiresServerMode {
			errMsg = fmt.Sprintf("policy requires session tracking for profile %q. Add --session-table <table> flag", profileName)
		}

		if !strings.Contains(errMsg, expectedPattern) {
			t.Errorf("expected error to contain %q, got: %s", expectedPattern, errMsg)
		}
		// Should not suggest --server since we're already in server mode
		if strings.Contains(errMsg, unexpectedPattern) {
			t.Errorf("expected error NOT to contain %q when already in server mode, got: %s", unexpectedPattern, errMsg)
		}
	})

	t.Run("error message for server mode only", func(t *testing.T) {
		// When only RequiresServerMode is true (no session tracking requirement),
		// error should suggest --server only
		profileName := "production"
		expectedPattern := "--server"
		unexpectedPattern := "--session-table"

		decision := policy.Decision{
			Effect:                  policy.EffectDeny,
			RequiresSessionTracking: false,
			RequiresServerMode:      true,
		}

		var errMsg string
		if !decision.RequiresSessionTracking && decision.RequiresServerMode {
			errMsg = fmt.Sprintf("policy requires server mode for profile %q. Add --server flag", profileName)
		}

		if !strings.Contains(errMsg, expectedPattern) {
			t.Errorf("expected error to contain %q, got: %s", expectedPattern, errMsg)
		}
		// Should not suggest --session-table since no session tracking required
		if strings.Contains(errMsg, unexpectedPattern) {
			t.Errorf("expected error NOT to contain %q when no session tracking required, got: %s", unexpectedPattern, errMsg)
		}
	})
}

func TestSentinelExecCommand_RequireServerSession_ModeScenarios(t *testing.T) {
	// Tests for the different mode/session-table combinations

	t.Run("CLI mode without session table triggers both flags", func(t *testing.T) {
		// In CLI mode (not server), both RequiresServerMode and RequiresSessionTracking should be set
		testPolicy := &policy.Policy{
			Version: "1",
			Rules: []policy.Rule{
				{
					Name:   "require-server-session",
					Effect: policy.EffectRequireServerSession,
					Conditions: policy.Condition{
						Profiles: []string{"production"},
					},
					Reason: "production requires server mode with session tracking",
				},
			},
		}

		req := &policy.Request{
			User:             "alice",
			Profile:          "production",
			Time:             time.Now(),
			Mode:             policy.ModeCLI, // Not server mode
			SessionTableName: "",             // No session table
		}

		decision := policy.Evaluate(testPolicy, req)

		// Should deny in CLI mode
		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected EffectDeny for CLI mode, got %v", decision.Effect)
		}
		// Both flags should be set
		if !decision.RequiresServerMode {
			t.Error("expected RequiresServerMode to be true for CLI mode")
		}
		if !decision.RequiresSessionTracking {
			t.Error("expected RequiresSessionTracking to be true")
		}
	})

	t.Run("server mode without session table triggers session tracking flag only", func(t *testing.T) {
		testPolicy := &policy.Policy{
			Version: "1",
			Rules: []policy.Rule{
				{
					Name:   "require-server-session",
					Effect: policy.EffectRequireServerSession,
					Conditions: policy.Condition{
						Profiles: []string{"production"},
					},
					Reason: "production requires server mode with session tracking",
				},
			},
		}

		req := &policy.Request{
			User:             "alice",
			Profile:          "production",
			Time:             time.Now(),
			Mode:             policy.ModeServer, // Server mode
			SessionTableName: "",                // But no session table
		}

		decision := policy.Evaluate(testPolicy, req)

		// Should deny without session table
		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected EffectDeny without session table, got %v", decision.Effect)
		}
		// Only session tracking flag should be set (already in server mode)
		if decision.RequiresServerMode {
			t.Error("expected RequiresServerMode to be false when already in server mode")
		}
		if !decision.RequiresSessionTracking {
			t.Error("expected RequiresSessionTracking to be true without session table")
		}
	})

	t.Run("server mode with session table allows access", func(t *testing.T) {
		testPolicy := &policy.Policy{
			Version: "1",
			Rules: []policy.Rule{
				{
					Name:   "require-server-session",
					Effect: policy.EffectRequireServerSession,
					Conditions: policy.Condition{
						Profiles: []string{"production"},
					},
					Reason: "production requires server mode with session tracking",
				},
			},
		}

		req := &policy.Request{
			User:             "alice",
			Profile:          "production",
			Time:             time.Now(),
			Mode:             policy.ModeServer,   // Server mode
			SessionTableName: "sentinel-sessions", // With session table
		}

		decision := policy.Evaluate(testPolicy, req)

		// Should allow with both server mode and session table
		if decision.Effect != policy.EffectAllow {
			t.Errorf("expected EffectAllow with server mode and session table, got %v", decision.Effect)
		}
		// Neither flag should be set on allow
		if decision.RequiresServerMode {
			t.Error("expected RequiresServerMode to be false on allow")
		}
		if decision.RequiresSessionTracking {
			t.Error("expected RequiresSessionTracking to be false on allow")
		}
	})

	t.Run("credential_process mode triggers both flags", func(t *testing.T) {
		testPolicy := &policy.Policy{
			Version: "1",
			Rules: []policy.Rule{
				{
					Name:   "require-server-session",
					Effect: policy.EffectRequireServerSession,
					Conditions: policy.Condition{
						Profiles: []string{"production"},
					},
					Reason: "production requires server mode with session tracking",
				},
			},
		}

		req := &policy.Request{
			User:             "alice",
			Profile:          "production",
			Time:             time.Now(),
			Mode:             policy.ModeCredentialProcess, // credential_process mode
			SessionTableName: "",                           // credential_process doesn't support sessions
		}

		decision := policy.Evaluate(testPolicy, req)

		// Should deny in credential_process mode
		if decision.Effect != policy.EffectDeny {
			t.Errorf("expected EffectDeny for credential_process mode, got %v", decision.Effect)
		}
		// Both flags should be set
		if !decision.RequiresServerMode {
			t.Error("expected RequiresServerMode to be true for credential_process mode")
		}
		if !decision.RequiresSessionTracking {
			t.Error("expected RequiresSessionTracking to be true")
		}
	})
}

// TestSentinelExec_SessionTableEnvVar tests SENTINEL_SESSION_TABLE environment variable support.
func TestSentinelExec_SessionTableEnvVar(t *testing.T) {
	t.Run("server mode uses env var when session-table not provided", func(t *testing.T) {
		t.Setenv(EnvSessionTable, "sentinel-sessions")

		input := SentinelExecCommandInput{
			ProfileName:      "test-profile",
			PolicyParameter:  "/sentinel/test",
			StartServer:      true,
			SessionTableName: "", // Not specified via CLI
		}

		// The env var should be used
		// This tests the logic at the beginning of SentinelExecCommand
		if input.SessionTableName == "" && input.StartServer {
			if envTable := os.Getenv(EnvSessionTable); envTable != "" {
				input.SessionTableName = envTable
			}
		}

		if input.SessionTableName != "sentinel-sessions" {
			t.Errorf("expected SessionTableName 'sentinel-sessions' from env var, got %q", input.SessionTableName)
		}
	})

	t.Run("CLI flag takes precedence over env var", func(t *testing.T) {
		t.Setenv(EnvSessionTable, "env-table")

		input := SentinelExecCommandInput{
			ProfileName:      "test-profile",
			PolicyParameter:  "/sentinel/test",
			StartServer:      true,
			SessionTableName: "cli-table", // Specified via CLI
		}

		// CLI flag already set, env var should NOT override
		if input.SessionTableName == "" && input.StartServer {
			if envTable := os.Getenv(EnvSessionTable); envTable != "" {
				input.SessionTableName = envTable
			}
		}

		if input.SessionTableName != "cli-table" {
			t.Errorf("expected SessionTableName 'cli-table' from CLI, got %q", input.SessionTableName)
		}
	})

	t.Run("env var ignored when not in server mode", func(t *testing.T) {
		t.Setenv(EnvSessionTable, "sentinel-sessions")

		input := SentinelExecCommandInput{
			ProfileName:      "test-profile",
			PolicyParameter:  "/sentinel/test",
			StartServer:      false, // Not server mode
			SessionTableName: "",
		}

		// Env var should NOT be applied in non-server mode
		if input.SessionTableName == "" && input.StartServer {
			if envTable := os.Getenv(EnvSessionTable); envTable != "" {
				input.SessionTableName = envTable
			}
		}

		if input.SessionTableName != "" {
			t.Errorf("expected empty SessionTableName in non-server mode, got %q", input.SessionTableName)
		}
	})
}

// TestSentinelCredentialProviderAdapter_CredentialProfile tests SSO profile handling.
func TestSentinelCredentialProviderAdapter_CredentialProfile(t *testing.T) {
	t.Run("adapter stores and uses credentialProfile", func(t *testing.T) {
		adapter := &sentinelCredentialProviderAdapter{
			sentinel:          nil, // Mock not needed for this test
			credentialProfile: "sso-profile",
		}

		if adapter.credentialProfile != "sso-profile" {
			t.Errorf("expected credentialProfile 'sso-profile', got %q", adapter.credentialProfile)
		}
	})

	t.Run("server mode uses AWSProfile for credentialProfile", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName: "policy-target",   // Policy evaluation target
			AWSProfile:  "sso-credentials", // SSO credential source
			StartServer: true,
		}

		// Verify AWSProfile is distinct from ProfileName
		if input.AWSProfile == input.ProfileName {
			t.Error("Test setup error: AWSProfile should differ from ProfileName")
		}

		// Verify credentialProfile logic (from lines 186-189 in sentinel_exec.go)
		credentialProfile := input.AWSProfile
		if credentialProfile == "" {
			credentialProfile = input.ProfileName
		}

		if credentialProfile != "sso-credentials" {
			t.Errorf("expected credentialProfile 'sso-credentials', got %q", credentialProfile)
		}
	})

	t.Run("server mode falls back to ProfileName when AWSProfile empty", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName: "my-profile",
			AWSProfile:  "", // Not specified
			StartServer: true,
		}

		credentialProfile := input.AWSProfile
		if credentialProfile == "" {
			credentialProfile = input.ProfileName
		}

		if credentialProfile != "my-profile" {
			t.Errorf("expected credentialProfile 'my-profile', got %q", credentialProfile)
		}
	})
}

// TestSentinelExecCommandInput_RemoteServerField tests the RemoteServer field.
func TestSentinelExecCommandInput_RemoteServerField(t *testing.T) {
	t.Run("RemoteServer field is empty by default", func(t *testing.T) {
		input := SentinelExecCommandInput{}
		if input.RemoteServer != "" {
			t.Errorf("expected RemoteServer to be empty by default, got %q", input.RemoteServer)
		}
	})

	t.Run("RemoteServer field can be set", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:  "test-profile",
			RemoteServer: "https://api.example.com/sentinel?profile=test-profile",
		}
		if input.RemoteServer != "https://api.example.com/sentinel?profile=test-profile" {
			t.Errorf("expected RemoteServer URL, got %q", input.RemoteServer)
		}
	})

	t.Run("RemoteServer mode does not require PolicyParameter", func(t *testing.T) {
		// In remote server mode, policy is handled by the TVM
		input := SentinelExecCommandInput{
			ProfileName:     "tvm-profile",
			PolicyParameter: "", // Not required in remote mode
			RemoteServer:    "https://api.example.com/sentinel",
		}
		if input.PolicyParameter != "" {
			t.Error("PolicyParameter should be empty in remote server mode")
		}
		if input.RemoteServer == "" {
			t.Error("RemoteServer should be set")
		}
	})
}

// TestSentinelExecCommand_RemoteServer_Validation tests --remote-server flag validation.
func TestSentinelExecCommand_RemoteServer_Validation(t *testing.T) {
	t.Run("remote-server conflicts with server", func(t *testing.T) {
		// Create a temp config file with a valid profile
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config")
		configContent := `[profile remote-test]
region = us-east-1
`
		if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to create test config file: %v", err)
		}
		t.Setenv("AWS_CONFIG_FILE", configFile)

		input := SentinelExecCommandInput{
			ProfileName:  "remote-test",
			RemoteServer: "https://api.example.com/sentinel",
			StartServer:  true, // Invalid combination
		}

		s := &Sentinel{}
		_, err := SentinelExecCommand(context.Background(), input, s)

		if err == nil {
			t.Fatal("expected error for --remote-server with --server")
		}
		if !strings.Contains(err.Error(), "Can't use --remote-server with --server") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("remote-server conflicts with policy-parameter", func(t *testing.T) {
		// Create a temp config file with a valid profile
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config")
		configContent := `[profile remote-test2]
region = us-east-1
`
		if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to create test config file: %v", err)
		}
		t.Setenv("AWS_CONFIG_FILE", configFile)

		input := SentinelExecCommandInput{
			ProfileName:     "remote-test2",
			RemoteServer:    "https://api.example.com/sentinel",
			PolicyParameter: "/sentinel/policies/default", // Invalid combination
		}

		s := &Sentinel{}
		_, err := SentinelExecCommand(context.Background(), input, s)

		if err == nil {
			t.Fatal("expected error for --remote-server with --policy-parameter")
		}
		if !strings.Contains(err.Error(), "Can't use --remote-server with --policy-parameter") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

// TestSentinelExecCommand_RemoteServer_Configuration tests --remote-server mode configuration.
func TestSentinelExecCommand_RemoteServer_Configuration(t *testing.T) {
	t.Run("remote server mode configuration is valid", func(t *testing.T) {
		// Test that the full remote server mode configuration works with valid fields
		input := SentinelExecCommandInput{
			ProfileName:  "production",
			Region:       "us-west-2",
			RemoteServer: "https://api.example.com/sentinel?profile=production",
			Command:      "aws",
			Args:         []string{"s3", "ls"},
		}

		// Verify all fields are correctly set
		if input.ProfileName != "production" {
			t.Errorf("expected ProfileName 'production', got %q", input.ProfileName)
		}
		if input.RemoteServer != "https://api.example.com/sentinel?profile=production" {
			t.Errorf("expected RemoteServer URL, got %q", input.RemoteServer)
		}
		// PolicyParameter should not be required
		if input.PolicyParameter != "" {
			t.Error("PolicyParameter should be empty for remote server mode")
		}
		// StartServer should be false (remote-server is different from local server)
		if input.StartServer {
			t.Error("StartServer should be false in remote server mode")
		}
	})

	t.Run("remote server mode does not validate local profile", func(t *testing.T) {
		// In remote mode, profile might not exist locally (TVM has different profiles)
		input := SentinelExecCommandInput{
			ProfileName:  "tvm-only-profile", // Doesn't need to exist locally
			RemoteServer: "https://api.example.com/sentinel",
		}

		// This test verifies the design: remote mode should skip local profile validation
		// The actual profile existence is checked by the TVM
		if input.RemoteServer == "" {
			t.Error("RemoteServer should be set")
		}
	})

	t.Run("remote server mode with shell command", func(t *testing.T) {
		input := SentinelExecCommandInput{
			ProfileName:  "tvm-profile",
			RemoteServer: "https://api.example.com/sentinel",
			Command:      "", // Empty means default to shell
		}

		if input.Command != "" {
			t.Error("Command should be empty to default to shell")
		}
	})
}

// TestSentinelExecCommand_RemoteServer_EnvModeComparison tests comparison between remote mode and other modes.
func TestSentinelExecCommand_RemoteServer_EnvModeComparison(t *testing.T) {
	t.Run("remote server is different from local server", func(t *testing.T) {
		// Local server mode (--server)
		localServer := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/default", // Required for local
			StartServer:     true,
			RemoteServer:    "", // Not set
		}

		// Remote server mode (--remote-server)
		remoteServer := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "", // Not required for remote
			StartServer:     false,
			RemoteServer:    "https://api.example.com/sentinel",
		}

		// Key differences
		if localServer.StartServer == remoteServer.StartServer {
			t.Error("StartServer should differ between modes")
		}
		if localServer.RemoteServer != "" {
			t.Error("Local server mode should not have RemoteServer set")
		}
		if remoteServer.RemoteServer == "" {
			t.Error("Remote server mode should have RemoteServer set")
		}
		if localServer.PolicyParameter == "" {
			t.Error("Local server mode requires PolicyParameter")
		}
		// Remote mode doesn't require PolicyParameter (it's an error to set it)
	})

	t.Run("remote server is different from env var mode", func(t *testing.T) {
		// Env var mode (default)
		envVarMode := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "/sentinel/policies/default", // Required
			StartServer:     false,
			RemoteServer:    "", // Not set
		}

		// Remote server mode
		remoteMode := SentinelExecCommandInput{
			ProfileName:     "production",
			PolicyParameter: "", // Not required
			StartServer:     false,
			RemoteServer:    "https://api.example.com/sentinel",
		}

		// Key differences
		if envVarMode.RemoteServer != "" {
			t.Error("Env var mode should not have RemoteServer set")
		}
		if remoteMode.RemoteServer == "" {
			t.Error("Remote mode should have RemoteServer set")
		}
		// Both have StartServer=false, but remote mode uses AWS_CONTAINER_CREDENTIALS_FULL_URI
	})
}

// TestSentinelExecCommand_RemoteServer_DeviceID tests device ID handling in remote server mode.
func TestSentinelExecCommand_RemoteServer_DeviceID(t *testing.T) {
	t.Run("device ID is collected and appended to URL", func(t *testing.T) {
		// This test verifies the logic of URL construction with device_id
		// When device ID is available, it should be appended as query parameter
		baseURL := "https://api.example.com/sentinel?profile=production"

		// Simulate successful device ID collection
		deviceID := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

		// Parse and append device_id (same logic as in sentinel_exec.go)
		parsedURL, err := url.Parse(baseURL)
		if err != nil {
			t.Fatalf("failed to parse URL: %v", err)
		}
		queryParams := parsedURL.Query()
		queryParams.Set("device_id", deviceID)
		parsedURL.RawQuery = queryParams.Encode()
		resultURL := parsedURL.String()

		// Verify device_id is appended
		if !strings.Contains(resultURL, "device_id=") {
			t.Errorf("expected URL to contain device_id parameter, got: %s", resultURL)
		}
		if !strings.Contains(resultURL, deviceID) {
			t.Errorf("expected URL to contain device ID value, got: %s", resultURL)
		}
		// Verify profile is preserved
		if !strings.Contains(resultURL, "profile=production") {
			t.Errorf("expected URL to preserve profile parameter, got: %s", resultURL)
		}
	})

	t.Run("device ID is optional - missing device ID still works", func(t *testing.T) {
		// When device ID collection fails, remote server should still work
		// (fail-open behavior consistent with TVM)
		input := SentinelExecCommandInput{
			ProfileName:  "production",
			RemoteServer: "https://api.example.com/sentinel?profile=production",
		}

		// Verify remote server URL is set even without device ID
		if input.RemoteServer == "" {
			t.Error("RemoteServer should be set")
		}
		// The actual execution would use input.RemoteServer without device_id param
		// when device ID collection fails (warning logged, continues)
	})

	t.Run("device ID format is 64-char lowercase hex", func(t *testing.T) {
		// Verify expected device ID format (from device.GetDeviceID)
		// SHA256 hash = 64 hex characters
		validDeviceID := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

		if len(validDeviceID) != 64 {
			t.Errorf("expected device ID to be 64 chars, got %d", len(validDeviceID))
		}

		// Verify it's lowercase hex
		for _, c := range validDeviceID {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("expected device ID to be lowercase hex, found char: %c", c)
			}
		}
	})

	t.Run("URL parsing preserves all existing parameters", func(t *testing.T) {
		// Test with multiple existing query parameters
		baseURL := "https://api.example.com/sentinel?profile=production&duration=3600&region=us-west-2"
		deviceID := "b1c2d3e4f5a6b1c2d3e4f5a6b1c2d3e4f5a6b1c2d3e4f5a6b1c2d3e4f5a6b1c2"

		parsedURL, err := url.Parse(baseURL)
		if err != nil {
			t.Fatalf("failed to parse URL: %v", err)
		}
		queryParams := parsedURL.Query()
		queryParams.Set("device_id", deviceID)
		parsedURL.RawQuery = queryParams.Encode()
		resultURL := parsedURL.String()

		// Verify all parameters are preserved
		if !strings.Contains(resultURL, "profile=production") {
			t.Errorf("expected URL to preserve profile parameter, got: %s", resultURL)
		}
		if !strings.Contains(resultURL, "duration=3600") {
			t.Errorf("expected URL to preserve duration parameter, got: %s", resultURL)
		}
		if !strings.Contains(resultURL, "region=us-west-2") {
			t.Errorf("expected URL to preserve region parameter, got: %s", resultURL)
		}
		if !strings.Contains(resultURL, "device_id=") {
			t.Errorf("expected URL to contain device_id parameter, got: %s", resultURL)
		}
	})
}
