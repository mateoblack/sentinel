package sso

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/byteness/aws-vault/v7/vault"
)

// createMockConfigFile creates a ConfigFile for testing with optional SSO settings
func createMockConfigFile(t *testing.T, hasSSO bool) *vault.ConfigFile {
	t.Helper()

	// Create a temporary config file
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")

	var content string
	if hasSSO {
		content = `[profile test-sso]
sso_start_url = https://my-sso-portal.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = TestRole

[profile test-no-sso]
region = us-west-2
`
	} else {
		content = `[profile test-no-sso]
region = us-west-2
`
	}

	// Write config file
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	cfg, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	return cfg
}

func TestGetSSOConfigForProfile(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		hasSSO      bool
		wantURL     string
		wantRegion  string
		wantNil     bool
		wantErr     bool
		nilConfig   bool
	}{
		{
			name:        "SSO profile returns config",
			profileName: "test-sso",
			hasSSO:      true,
			wantURL:     "https://my-sso-portal.awsapps.com/start",
			wantRegion:  "us-east-1",
			wantNil:     false,
			wantErr:     false,
		},
		{
			name:        "Non-SSO profile returns nil",
			profileName: "test-no-sso",
			hasSSO:      true,
			wantNil:     true,
			wantErr:     false,
		},
		{
			name:        "Missing profile returns nil (no error)",
			profileName: "nonexistent",
			hasSSO:      true,
			wantNil:     true,
			wantErr:     false,
		},
		{
			name:        "Nil config file returns error",
			profileName: "test",
			nilConfig:   true,
			wantNil:     true,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var configFile *vault.ConfigFile
			if !tt.nilConfig {
				configFile = createMockConfigFile(t, tt.hasSSO)
			}

			config, err := GetSSOConfigForProfile(configFile, tt.profileName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("GetSSOConfigForProfile() expected error, got nil")
				}
				return
			}

			if err != nil && !tt.wantErr {
				t.Errorf("GetSSOConfigForProfile() unexpected error: %v", err)
				return
			}

			if tt.wantNil {
				if config != nil {
					t.Errorf("GetSSOConfigForProfile() expected nil, got %+v", config)
				}
				return
			}

			if config == nil {
				t.Fatalf("GetSSOConfigForProfile() expected non-nil config")
			}

			if config.StartURL != tt.wantURL {
				t.Errorf("StartURL = %q, want %q", config.StartURL, tt.wantURL)
			}
			if config.Region != tt.wantRegion {
				t.Errorf("Region = %q, want %q", config.Region, tt.wantRegion)
			}
		})
	}
}

func TestWithAutoLogin_SuccessfulOperation(t *testing.T) {
	// Test that successful operations pass through without triggering login
	config := AutoLoginConfig{
		ProfileName: "test",
		ConfigFile:  nil, // Will cause SSO config lookup to fail, which is fine for success case
		Stderr:      &bytes.Buffer{},
	}

	expectedResult := "success"
	callCount := 0

	result, err := WithAutoLogin(context.Background(), config, func() (string, error) {
		callCount++
		return expectedResult, nil
	})

	if err != nil {
		t.Errorf("WithAutoLogin() unexpected error: %v", err)
	}
	if result != expectedResult {
		t.Errorf("WithAutoLogin() result = %q, want %q", result, expectedResult)
	}
	if callCount != 1 {
		t.Errorf("Function was called %d times, expected 1", callCount)
	}
}

func TestWithAutoLogin_NonSSOError(t *testing.T) {
	// Test that non-SSO errors are returned immediately without retry
	config := AutoLoginConfig{
		ProfileName: "test",
		ConfigFile:  nil,
		Stderr:      &bytes.Buffer{},
	}

	expectedErr := errors.New("some non-SSO error")
	callCount := 0

	result, err := WithAutoLogin(context.Background(), config, func() (string, error) {
		callCount++
		return "", expectedErr
	})

	if err != expectedErr {
		t.Errorf("WithAutoLogin() error = %v, want %v", err, expectedErr)
	}
	if result != "" {
		t.Errorf("WithAutoLogin() result = %q, want empty string", result)
	}
	if callCount != 1 {
		t.Errorf("Function was called %d times, expected 1", callCount)
	}
}

func TestWithAutoLogin_SSOErrorNoSSOProfile(t *testing.T) {
	// Test that SSO errors on non-SSO profiles return original error
	configFile := createMockConfigFile(t, true)

	stderrBuf := &bytes.Buffer{}
	config := AutoLoginConfig{
		ProfileName: "test-no-sso", // Profile without SSO config
		ConfigFile:  configFile,
		Stderr:      stderrBuf,
	}

	// Create an SSO-like error
	ssoErr := errors.New("The SSO session associated with this profile has expired")
	callCount := 0

	result, err := WithAutoLogin(context.Background(), config, func() (string, error) {
		callCount++
		return "", ssoErr
	})

	if err != ssoErr {
		t.Errorf("WithAutoLogin() error = %v, want %v", err, ssoErr)
	}
	if result != "" {
		t.Errorf("WithAutoLogin() result = %q, want empty string", result)
	}
	if callCount != 1 {
		t.Errorf("Function was called %d times, expected 1 (no retry for non-SSO profile)", callCount)
	}
}

func TestWithAutoLogin_DefaultStderr(t *testing.T) {
	// Test that nil Stderr defaults to os.Stderr (doesn't panic)
	config := AutoLoginConfig{
		ProfileName: "test",
		ConfigFile:  nil,
		Stderr:      nil, // Should default to os.Stderr
	}

	// This should not panic
	_, _ = WithAutoLogin(context.Background(), config, func() (string, error) {
		return "ok", nil
	})
}

func TestWithAutoLogin_SSOErrorMissingProfile(t *testing.T) {
	// Test that SSO errors with missing profile return original error
	// (profile not found = no SSO config = can't auto-login)
	configFile := createMockConfigFile(t, true)

	stderrBuf := &bytes.Buffer{}
	config := AutoLoginConfig{
		ProfileName: "nonexistent-profile", // Profile doesn't exist
		ConfigFile:  configFile,
		Stderr:      stderrBuf,
	}

	// Create an SSO-like error
	ssoErr := errors.New("The SSO session associated with this profile has expired")
	callCount := 0

	result, err := WithAutoLogin(context.Background(), config, func() (string, error) {
		callCount++
		return "", ssoErr
	})

	// Should return original error (missing profile = no SSO config available)
	if err != ssoErr {
		t.Errorf("WithAutoLogin() error = %v, want %v", err, ssoErr)
	}
	if result != "" {
		t.Errorf("WithAutoLogin() result = %q, want empty string", result)
	}
	if callCount != 1 {
		t.Errorf("Function was called %d times, expected 1 (no retry for missing profile)", callCount)
	}
}

func TestWithAutoLogin_NilConfigFile(t *testing.T) {
	// Test that SSO errors with nil config file return original error
	stderrBuf := &bytes.Buffer{}
	config := AutoLoginConfig{
		ProfileName: "test",
		ConfigFile:  nil, // Nil config file
		Stderr:      stderrBuf,
	}

	// Create an SSO-like error
	ssoErr := errors.New("The SSO session associated with this profile has expired")
	callCount := 0

	result, err := WithAutoLogin(context.Background(), config, func() (string, error) {
		callCount++
		return "", ssoErr
	})

	// Should return original error (can't get SSO config with nil ConfigFile)
	if err != ssoErr {
		t.Errorf("WithAutoLogin() error = %v, want %v", err, ssoErr)
	}
	if result != "" {
		t.Errorf("WithAutoLogin() result = %q, want empty string", result)
	}
	if callCount != 1 {
		t.Errorf("Function was called %d times, expected 1 (no retry with nil config)", callCount)
	}
}
