package lambda

import (
	"context"
	"os"
	"strings"
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

// ============================================================================
// Policy Signing Configuration Tests
// ============================================================================

func TestTVMConfig_ValidateSigning_MissingKey(t *testing.T) {
	// EnforcePolicySigning=true but no key set should error
	cfg := &TVMConfig{
		EnforcePolicySigning: true,
		PolicySigningKeyID:   "",
	}

	err := cfg.ValidateSigning()
	if err == nil {
		t.Error("expected error when EnforcePolicySigning=true but PolicySigningKeyID is empty")
	}

	expectedErr := "SENTINEL_POLICY_SIGNING_KEY required when SENTINEL_ENFORCE_POLICY_SIGNING=true"
	if err.Error() != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, err.Error())
	}
}

func TestTVMConfig_ValidateSigning_Valid(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *TVMConfig
		wantErr bool
	}{
		{
			name: "enforce_true_with_key",
			cfg: &TVMConfig{
				EnforcePolicySigning: true,
				PolicySigningKeyID:   "arn:aws:kms:us-east-1:123456789012:key/test-key",
			},
			wantErr: false,
		},
		{
			name: "enforce_false_without_key",
			cfg: &TVMConfig{
				EnforcePolicySigning: false,
				PolicySigningKeyID:   "",
			},
			wantErr: false,
		},
		{
			name: "enforce_false_with_key",
			cfg: &TVMConfig{
				EnforcePolicySigning: false,
				PolicySigningKeyID:   "arn:aws:kms:us-east-1:123456789012:key/test-key",
			},
			wantErr: false,
		},
		{
			name: "key_alias_format",
			cfg: &TVMConfig{
				EnforcePolicySigning: true,
				PolicySigningKeyID:   "alias/sentinel-policy-signing",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.ValidateSigning()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestTVMConfig_SigningFieldsExist(t *testing.T) {
	// Verify signing fields are accessible on TVMConfig
	cfg := &TVMConfig{
		PolicySigningKeyID:   "test-key-id",
		EnforcePolicySigning: true,
	}

	if cfg.PolicySigningKeyID != "test-key-id" {
		t.Errorf("PolicySigningKeyID = %s, want test-key-id", cfg.PolicySigningKeyID)
	}

	if !cfg.EnforcePolicySigning {
		t.Error("EnforcePolicySigning should be true")
	}
}

func TestEnvVariableNames_PolicySigning(t *testing.T) {
	// Verify environment variable names for policy signing
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"PolicySigningKey", EnvPolicySigningKey, "SENTINEL_POLICY_SIGNING_KEY"},
		{"EnforcePolicySigning", EnvEnforcePolicySigning, "SENTINEL_ENFORCE_POLICY_SIGNING"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.constant)
			}
		})
	}
}

// ============================================================================
// Log Signing and CloudWatch Configuration Tests
// ============================================================================

func TestEnvVariableNames_LoggingConfig(t *testing.T) {
	// Verify environment variable names for logging configuration
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"LogSigningKey", EnvLogSigningKey, "SENTINEL_LOG_SIGNING_KEY"},
		{"LogSigningKeyID", EnvLogSigningKeyID, "SENTINEL_LOG_SIGNING_KEY_ID"},
		{"CloudWatchGroup", EnvCloudWatchGroup, "SENTINEL_CLOUDWATCH_LOG_GROUP"},
		{"CloudWatchStream", EnvCloudWatchStream, "SENTINEL_CLOUDWATCH_STREAM"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.constant)
			}
		})
	}
}

func TestTVMConfig_LoggingFieldsExist(t *testing.T) {
	// Verify logging fields are accessible on TVMConfig
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i)
	}

	cfg := &TVMConfig{
		LogSigningKey:      testKey,
		LogSigningKeyID:    "key-v1",
		CloudWatchLogGroup: "/aws/lambda/sentinel",
		CloudWatchStream:   "test-stream",
	}

	if len(cfg.LogSigningKey) != 32 {
		t.Errorf("LogSigningKey length = %d, want 32", len(cfg.LogSigningKey))
	}
	if cfg.LogSigningKeyID != "key-v1" {
		t.Errorf("LogSigningKeyID = %s, want key-v1", cfg.LogSigningKeyID)
	}
	if cfg.CloudWatchLogGroup != "/aws/lambda/sentinel" {
		t.Errorf("CloudWatchLogGroup = %s, want /aws/lambda/sentinel", cfg.CloudWatchLogGroup)
	}
	if cfg.CloudWatchStream != "test-stream" {
		t.Errorf("CloudWatchStream = %s, want test-stream", cfg.CloudWatchStream)
	}
}

func TestConfigureLogger_DefaultsToJSONLogger(t *testing.T) {
	// Clean environment
	os.Unsetenv(EnvLogSigningKey)
	os.Unsetenv(EnvLogSigningKeyID)
	os.Unsetenv(EnvCloudWatchGroup)
	os.Unsetenv(EnvCloudWatchStream)
	os.Unsetenv("AWS_LAMBDA_FUNCTION_NAME")

	cfg := &TVMConfig{}
	awsCfg := aws.Config{}

	logger, err := configureLogger(awsCfg, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logger == nil {
		t.Error("expected logger to be created")
	}

	// Verify fields not set on config
	if len(cfg.LogSigningKey) != 0 {
		t.Error("expected empty LogSigningKey")
	}
	if cfg.CloudWatchLogGroup != "" {
		t.Error("expected empty CloudWatchLogGroup")
	}
}

func TestConfigureLogger_SignedLoggerToStdout(t *testing.T) {
	// Valid 32-byte key as hex (64 chars)
	validKeyHex := "0001020304050607080910111213141516171819202122232425262728293031"

	os.Setenv(EnvLogSigningKey, validKeyHex)
	os.Setenv(EnvLogSigningKeyID, "test-key-v1")
	os.Unsetenv(EnvCloudWatchGroup)
	os.Unsetenv(EnvCloudWatchStream)
	defer os.Unsetenv(EnvLogSigningKey)
	defer os.Unsetenv(EnvLogSigningKeyID)

	cfg := &TVMConfig{}
	awsCfg := aws.Config{}

	logger, err := configureLogger(awsCfg, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logger == nil {
		t.Error("expected logger to be created")
	}

	// Verify signing key was parsed
	if len(cfg.LogSigningKey) != 32 {
		t.Errorf("LogSigningKey length = %d, want 32", len(cfg.LogSigningKey))
	}
	if cfg.LogSigningKeyID != "test-key-v1" {
		t.Errorf("LogSigningKeyID = %s, want test-key-v1", cfg.LogSigningKeyID)
	}
}

func TestConfigureLogger_InvalidHexKey(t *testing.T) {
	os.Setenv(EnvLogSigningKey, "not-valid-hex!")
	defer os.Unsetenv(EnvLogSigningKey)

	cfg := &TVMConfig{}
	awsCfg := aws.Config{}

	_, err := configureLogger(awsCfg, cfg)
	if err == nil {
		t.Error("expected error for invalid hex key")
	}
	if !strings.Contains(err.Error(), "must be hex-encoded") {
		t.Errorf("expected hex error, got: %v", err)
	}
}

func TestConfigureLogger_KeyTooShort(t *testing.T) {
	// 16-byte key (32 hex chars) - too short
	shortKeyHex := "00010203040506070809101112131415"

	os.Setenv(EnvLogSigningKey, shortKeyHex)
	defer os.Unsetenv(EnvLogSigningKey)

	cfg := &TVMConfig{}
	awsCfg := aws.Config{}

	_, err := configureLogger(awsCfg, cfg)
	if err == nil {
		t.Error("expected error for short key")
	}
	if !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Errorf("expected key length error, got: %v", err)
	}
}

func TestConfigureLogger_CloudWatchWithSigning(t *testing.T) {
	// Valid 32-byte key as hex (64 chars)
	validKeyHex := "0001020304050607080910111213141516171819202122232425262728293031"

	os.Setenv(EnvLogSigningKey, validKeyHex)
	os.Setenv(EnvLogSigningKeyID, "test-key-v2")
	os.Setenv(EnvCloudWatchGroup, "/aws/lambda/sentinel-tvm")
	os.Setenv(EnvCloudWatchStream, "custom-stream")
	defer os.Unsetenv(EnvLogSigningKey)
	defer os.Unsetenv(EnvLogSigningKeyID)
	defer os.Unsetenv(EnvCloudWatchGroup)
	defer os.Unsetenv(EnvCloudWatchStream)

	cfg := &TVMConfig{}
	awsCfg := aws.Config{}

	logger, err := configureLogger(awsCfg, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logger == nil {
		t.Error("expected logger to be created")
	}

	// Verify config fields
	if cfg.CloudWatchLogGroup != "/aws/lambda/sentinel-tvm" {
		t.Errorf("CloudWatchLogGroup = %s, want /aws/lambda/sentinel-tvm", cfg.CloudWatchLogGroup)
	}
	if cfg.CloudWatchStream != "custom-stream" {
		t.Errorf("CloudWatchStream = %s, want custom-stream", cfg.CloudWatchStream)
	}
	if len(cfg.LogSigningKey) != 32 {
		t.Errorf("LogSigningKey length = %d, want 32", len(cfg.LogSigningKey))
	}
}

func TestConfigureLogger_CloudWatchWithoutSigning(t *testing.T) {
	os.Unsetenv(EnvLogSigningKey)
	os.Unsetenv(EnvLogSigningKeyID)
	os.Setenv(EnvCloudWatchGroup, "/aws/lambda/sentinel-unsigned")
	os.Setenv(EnvCloudWatchStream, "unsigned-stream")
	defer os.Unsetenv(EnvCloudWatchGroup)
	defer os.Unsetenv(EnvCloudWatchStream)

	cfg := &TVMConfig{}
	awsCfg := aws.Config{}

	logger, err := configureLogger(awsCfg, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logger == nil {
		t.Error("expected logger to be created")
	}

	// Verify CloudWatch configured without signing
	if cfg.CloudWatchLogGroup != "/aws/lambda/sentinel-unsigned" {
		t.Errorf("CloudWatchLogGroup = %s, want /aws/lambda/sentinel-unsigned", cfg.CloudWatchLogGroup)
	}
	if len(cfg.LogSigningKey) != 0 {
		t.Error("expected empty LogSigningKey for unsigned CloudWatch")
	}
}

func TestConfigureLogger_DefaultStreamFromLambdaName(t *testing.T) {
	os.Unsetenv(EnvLogSigningKey)
	os.Setenv(EnvCloudWatchGroup, "/aws/lambda/test")
	os.Unsetenv(EnvCloudWatchStream)
	os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "sentinel-tvm-prod")
	defer os.Unsetenv(EnvCloudWatchGroup)
	defer os.Unsetenv("AWS_LAMBDA_FUNCTION_NAME")

	cfg := &TVMConfig{}
	awsCfg := aws.Config{}

	_, err := configureLogger(awsCfg, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify stream defaults to Lambda function name
	if cfg.CloudWatchStream != "sentinel-tvm-prod" {
		t.Errorf("CloudWatchStream = %s, want sentinel-tvm-prod", cfg.CloudWatchStream)
	}
}

