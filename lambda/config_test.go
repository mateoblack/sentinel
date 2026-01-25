package lambda

import (
	"testing"
	"time"
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
