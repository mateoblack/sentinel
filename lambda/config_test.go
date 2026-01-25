package lambda

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestEnvVariableNames(t *testing.T) {
	// Verify environment variable names match documentation and conventions
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"PolicyParameter", EnvPolicyParameter, "SENTINEL_POLICY_PARAMETER"},
		{"ApprovalTable", EnvApprovalTable, "SENTINEL_APPROVAL_TABLE"},
		{"BreakGlassTable", EnvBreakGlassTable, "SENTINEL_BREAKGLASS_TABLE"},
		{"SessionTable", EnvSessionTable, "SENTINEL_SESSION_TABLE"},
		{"Region", EnvRegion, "AWS_REGION"},
		{"MDMAPISecretID", EnvMDMAPISecretID, "SENTINEL_MDM_API_SECRET_ID"},
		{"MDMAPIToken", EnvMDMAPIToken, "SENTINEL_MDM_API_TOKEN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.constant)
			}
		})
	}
}

func TestTVMConfig_Defaults(t *testing.T) {
	cfg := &TVMConfig{}

	// Verify nil stores don't cause issues (optional = nil)
	if cfg.ApprovalStore != nil {
		t.Error("expected nil ApprovalStore by default")
	}
	if cfg.BreakGlassStore != nil {
		t.Error("expected nil BreakGlassStore by default")
	}
	if cfg.SessionStore != nil {
		t.Error("expected nil SessionStore by default")
	}
	if cfg.Logger != nil {
		t.Error("expected nil Logger by default")
	}
	if cfg.PolicyLoader != nil {
		t.Error("expected nil PolicyLoader by default")
	}
	if cfg.STSClient != nil {
		t.Error("expected nil STSClient by default")
	}
}

func TestDefaultTVMDuration(t *testing.T) {
	// Verify default duration matches server mode (15 minutes)
	expected := 15 * time.Minute
	if DefaultTVMDuration != expected {
		t.Errorf("DefaultTVMDuration: expected %v, got %v", expected, DefaultTVMDuration)
	}
}

func TestDefaultPolicyCacheTTL(t *testing.T) {
	// Verify cache TTL is reasonable (30 seconds)
	expected := 30 * time.Second
	if DefaultPolicyCacheTTL != expected {
		t.Errorf("DefaultPolicyCacheTTL: expected %v, got %v", expected, DefaultPolicyCacheTTL)
	}
}

func TestTVMConfig_MirrorsSentinelServerConfig(t *testing.T) {
	// Verify TVMConfig has the essential fields from SentinelServerConfig
	// This is a compile-time check via type instantiation

	cfg := &TVMConfig{
		PolicyParameter:  "/sentinel/policy",
		SessionTableName: "sentinel-sessions",
		Region:           "us-west-2",
		DefaultDuration:  15 * time.Minute,
	}

	// Verify fields are set correctly
	if cfg.PolicyParameter != "/sentinel/policy" {
		t.Errorf("PolicyParameter: expected /sentinel/policy, got %s", cfg.PolicyParameter)
	}
	if cfg.SessionTableName != "sentinel-sessions" {
		t.Errorf("SessionTableName: expected sentinel-sessions, got %s", cfg.SessionTableName)
	}
	if cfg.Region != "us-west-2" {
		t.Errorf("Region: expected us-west-2, got %s", cfg.Region)
	}
	if cfg.DefaultDuration != 15*time.Minute {
		t.Errorf("DefaultDuration: expected 15m, got %v", cfg.DefaultDuration)
	}
}

// Note: LoadConfigFromEnv cannot be fully tested without AWS credentials.
// The function requires actual AWS SDK config loading which would fail
// in test environments without proper credentials. Integration tests
// should cover this path.

func TestTVMConfig_SecretsLoader(t *testing.T) {
	// Verify SecretsLoader field exists and is optional
	cfg := &TVMConfig{}

	if cfg.SecretsLoader != nil {
		t.Error("expected nil SecretsLoader by default")
	}

	// Verify it can be set
	mock := NewMockSecretsLoader(map[string]string{"test": "value"})
	cfg.SecretsLoader = mock

	if cfg.SecretsLoader == nil {
		t.Error("expected SecretsLoader to be set")
	}
}

func TestLoadMDMAPIToken_FromSecretsManager(t *testing.T) {
	ctx := context.Background()
	awsCfg := aws.Config{}

	// Setup: Set secret ID, clear env token
	os.Setenv(EnvMDMAPISecretID, "test-secret-id")
	os.Unsetenv(EnvMDMAPIToken)
	defer os.Unsetenv(EnvMDMAPISecretID)

	// Create mock secrets loader
	mock := NewMockSecretsLoader(map[string]string{
		"test-secret-id": "secret-api-token-from-sm",
	})

	// Load token
	token, err := loadMDMAPIToken(ctx, awsCfg, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "secret-api-token-from-sm" {
		t.Errorf("expected secret-api-token-from-sm, got %s", token)
	}

	// Verify mock was called with correct secret ID
	if len(mock.GetSecretCalls) != 1 || mock.GetSecretCalls[0] != "test-secret-id" {
		t.Errorf("expected GetSecret to be called with test-secret-id, got %v", mock.GetSecretCalls)
	}
}

func TestLoadMDMAPIToken_EnvVarDeprecationFallback(t *testing.T) {
	ctx := context.Background()
	awsCfg := aws.Config{}

	// Setup: Clear secret ID, set env token
	os.Unsetenv(EnvMDMAPISecretID)
	os.Setenv(EnvMDMAPIToken, "env-var-token")
	defer os.Unsetenv(EnvMDMAPIToken)

	// Load token (mock won't be used since no secret ID)
	token, err := loadMDMAPIToken(ctx, awsCfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "env-var-token" {
		t.Errorf("expected env-var-token, got %s", token)
	}
}

func TestLoadMDMAPIToken_NeitherConfigured(t *testing.T) {
	ctx := context.Background()
	awsCfg := aws.Config{}

	// Setup: Clear both
	os.Unsetenv(EnvMDMAPISecretID)
	os.Unsetenv(EnvMDMAPIToken)

	// Load token
	token, err := loadMDMAPIToken(ctx, awsCfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "" {
		t.Errorf("expected empty token, got %s", token)
	}
}

func TestLoadMDMAPIToken_SecretsManagerError(t *testing.T) {
	ctx := context.Background()
	awsCfg := aws.Config{}

	// Setup: Set secret ID
	os.Setenv(EnvMDMAPISecretID, "nonexistent-secret")
	defer os.Unsetenv(EnvMDMAPISecretID)

	// Create mock secrets loader that returns error
	mock := NewMockSecretsLoader(nil) // No secrets configured

	// Load token - should fail
	_, err := loadMDMAPIToken(ctx, awsCfg, mock)
	if err == nil {
		t.Error("expected error for nonexistent secret")
	}
}

func TestLoadMDMAPIToken_PrefersSecretsManagerOverEnvVar(t *testing.T) {
	ctx := context.Background()
	awsCfg := aws.Config{}

	// Setup: Set both secret ID and env token
	os.Setenv(EnvMDMAPISecretID, "test-secret")
	os.Setenv(EnvMDMAPIToken, "env-var-token-ignored")
	defer os.Unsetenv(EnvMDMAPISecretID)
	defer os.Unsetenv(EnvMDMAPIToken)

	// Create mock secrets loader
	mock := NewMockSecretsLoader(map[string]string{
		"test-secret": "secrets-manager-token",
	})

	// Load token
	token, err := loadMDMAPIToken(ctx, awsCfg, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should use Secrets Manager value, not env var
	if token != "secrets-manager-token" {
		t.Errorf("expected secrets-manager-token, got %s", token)
	}
}
