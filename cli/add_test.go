package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// makeAddSessionKey creates a properly formatted session key for testing
func makeAddSessionKey(sessionType, profileName, mfaSerial string, expiration time.Time) string {
	b64profile := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(profileName))
	b64mfa := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(mfaSerial))
	return fmt.Sprintf("%s,%s,%s,%d", sessionType, b64profile, b64mfa, expiration.Unix())
}

func ExampleAddCommand() {
	f, err := os.CreateTemp("", "aws-config")
	if err != nil {
		panic(err)
	}
	defer os.Remove(f.Name())

	os.Setenv("AWS_CONFIG_FILE", f.Name())
	os.Setenv("AWS_ACCESS_KEY_ID", "llamas")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "rock")
	os.Setenv("AWS_VAULT_BACKEND", "file")
	os.Setenv("AWS_VAULT_FILE_PASSPHRASE", "password")

	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_VAULT_BACKEND")
	defer os.Unsetenv("AWS_VAULT_FILE_PASSPHRASE")

	app := kingpin.New(`aws-vault`, ``)
	ConfigureAddCommand(app, ConfigureGlobals(app))
	kingpin.MustParse(app.Parse([]string{"add", "--debug", "--env", "foo"}))

	// Output:
	// Added credentials to profile "foo" in vault
}

func TestAddCommand_FromEnv(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := AddCommandInput{
		ProfileName: "test-profile",
		FromEnv:     true,
		AddConfig:   false,
	}

	err = AddCommand(input, kr, configFile)
	if err != nil {
		t.Fatalf("AddCommand failed: %v", err)
	}

	// Verify credentials were added
	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}

	found := false
	for _, key := range keys {
		if key == "test-profile" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected credentials to be stored under 'test-profile'")
	}
}

func TestAddCommand_FromEnv_MissingAccessKeyID(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)
	// Don't set AWS_ACCESS_KEY_ID
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")

	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := AddCommandInput{
		ProfileName: "test-profile",
		FromEnv:     true,
		AddConfig:   false,
	}

	err = AddCommand(input, kr, configFile)
	if err == nil {
		t.Error("expected error when AWS_ACCESS_KEY_ID is missing")
	}
}

func TestAddCommand_FromEnv_MissingSecretKey(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	// Don't set AWS_SECRET_ACCESS_KEY

	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := AddCommandInput{
		ProfileName: "test-profile",
		FromEnv:     true,
		AddConfig:   false,
	}

	err = AddCommand(input, kr, configFile)
	if err == nil {
		t.Error("expected error when AWS_SECRET_ACCESS_KEY is missing")
	}
}

func TestAddCommand_SourceProfileError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile child]
source_profile = parent
role_arn = arn:aws:iam::123456789012:role/Test
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := AddCommandInput{
		ProfileName: "child",
		FromEnv:     true,
		AddConfig:   false,
	}

	err = AddCommand(input, kr, configFile)
	if err == nil {
		t.Error("expected error when adding to profile with source_profile")
	}
}

func TestAddCommand_ClearsExistingSessions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	futureTime := time.Now().Add(time.Hour)
	myprofileSessionKey := makeAddSessionKey("sts.GetSessionToken", "myprofile", "", futureTime)

	// Keyring with existing session for the profile
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: myprofileSessionKey, Data: []byte(`{"AccessKeyId":"ASIA1","SecretAccessKey":"secret1","SessionToken":"token1","Expiration":"2099-01-01T00:00:00Z"}`)},
	})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := AddCommandInput{
		ProfileName: "myprofile",
		FromEnv:     true,
		AddConfig:   false,
	}

	err = AddCommand(input, kr, configFile)
	if err != nil {
		t.Fatalf("AddCommand failed: %v", err)
	}

	// Verify session was cleared
	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}

	for _, key := range keys {
		if key == myprofileSessionKey {
			t.Error("expected existing session to be cleared")
		}
	}
}

func TestAddCommand_WithAddConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := AddCommandInput{
		ProfileName: "newprofile",
		FromEnv:     true,
		AddConfig:   true,
	}

	err = AddCommand(input, kr, configFile)
	if err != nil {
		t.Fatalf("AddCommand failed: %v", err)
	}

	// Reload config to check if profile was added
	configFile, err = vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to reload config: %v", err)
	}

	_, hasProfile, _ := configFile.ProfileSection("newprofile")
	if !hasProfile {
		t.Error("expected profile to be added to config file")
	}
}

func TestAddCommand_ExistingProfile_NoAddConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile existing]
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := AddCommandInput{
		ProfileName: "existing",
		FromEnv:     true,
		AddConfig:   true, // Should not modify since profile exists
	}

	err = AddCommand(input, kr, configFile)
	if err != nil {
		t.Fatalf("AddCommand failed: %v", err)
	}

	// Credentials should be added
	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}

	found := false
	for _, key := range keys {
		if key == "existing" {
			found = true
		}
	}
	if !found {
		t.Error("expected credentials to be stored")
	}
}

func TestAddCommandInput_Defaults(t *testing.T) {
	input := AddCommandInput{}

	if input.ProfileName != "" {
		t.Errorf("expected empty ProfileName, got %q", input.ProfileName)
	}
	if input.FromEnv {
		t.Error("expected FromEnv to be false")
	}
	if input.AddConfig {
		t.Error("expected AddConfig to be false")
	}
}
