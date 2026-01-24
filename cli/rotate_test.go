package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func TestRotateCommandInput_Defaults(t *testing.T) {
	input := RotateCommandInput{}

	if input.ProfileName != "" {
		t.Errorf("expected empty ProfileName, got %q", input.ProfileName)
	}
	if input.NoSession {
		t.Error("expected NoSession to be false")
	}
}

func TestRotateCommandInput_WithValues(t *testing.T) {
	input := RotateCommandInput{
		ProfileName: "production",
		NoSession:   true,
	}

	if input.ProfileName != "production" {
		t.Errorf("expected ProfileName 'production', got %q", input.ProfileName)
	}
	if !input.NoSession {
		t.Error("expected NoSession to be true")
	}
}

func TestGetProfilesInChain_SingleProfile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile standalone]
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	configLoader := vault.NewConfigLoader(vault.ProfileConfig{}, configFile, "standalone")
	profiles, err := getProfilesInChain("standalone", configLoader)
	if err != nil {
		t.Fatalf("getProfilesInChain failed: %v", err)
	}

	if len(profiles) != 1 {
		t.Errorf("expected 1 profile in chain, got %d", len(profiles))
	}
	if profiles[0] != "standalone" {
		t.Errorf("expected 'standalone', got %q", profiles[0])
	}
}

func TestGetProfilesInChain_WithSourceProfile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile base]
region = us-east-1

[profile derived]
role_arn = arn:aws:iam::123456789012:role/MyRole
source_profile = base
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	configLoader := vault.NewConfigLoader(vault.ProfileConfig{}, configFile, "derived")
	profiles, err := getProfilesInChain("derived", configLoader)
	if err != nil {
		t.Fatalf("getProfilesInChain failed: %v", err)
	}

	if len(profiles) != 2 {
		t.Errorf("expected 2 profiles in chain, got %d", len(profiles))
	}
	if profiles[0] != "derived" {
		t.Errorf("expected first profile 'derived', got %q", profiles[0])
	}
	if profiles[1] != "base" {
		t.Errorf("expected second profile 'base', got %q", profiles[1])
	}
}

func TestGetProfilesInChain_DeepChain(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile root]
region = us-east-1

[profile middle]
role_arn = arn:aws:iam::111111111111:role/Middle
source_profile = root
region = us-east-1

[profile leaf]
role_arn = arn:aws:iam::222222222222:role/Leaf
source_profile = middle
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	configLoader := vault.NewConfigLoader(vault.ProfileConfig{}, configFile, "leaf")
	profiles, err := getProfilesInChain("leaf", configLoader)
	if err != nil {
		t.Fatalf("getProfilesInChain failed: %v", err)
	}

	if len(profiles) != 3 {
		t.Errorf("expected 3 profiles in chain, got %d: %v", len(profiles), profiles)
	}
	expected := []string{"leaf", "middle", "root"}
	for i, want := range expected {
		if profiles[i] != want {
			t.Errorf("profiles[%d] = %q, want %q", i, profiles[i], want)
		}
	}
}

func TestRetry_Success(t *testing.T) {
	attempts := 0
	err := retry(time.Second*5, time.Millisecond*10, func() error {
		attempts++
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestRetry_EventualSuccess(t *testing.T) {
	attempts := 0
	err := retry(time.Second*5, time.Millisecond*10, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary error")
		}
		return nil
	})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetry_Timeout(t *testing.T) {
	attempts := 0
	err := retry(time.Millisecond*50, time.Millisecond*20, func() error {
		attempts++
		return errors.New("persistent error")
	})

	if err == nil {
		t.Error("expected error after timeout")
	}
	// Should have multiple attempts before timeout
	if attempts < 2 {
		t.Errorf("expected at least 2 attempts, got %d", attempts)
	}
}

func TestRotateCommand_MissingCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile nocreds]
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	// Empty keyring - no credentials
	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := RotateCommandInput{
		ProfileName: "nocreds",
		NoSession:   true,
	}

	err = RotateCommand(input, configFile, kr)
	// Should fail because there are no credentials to rotate
	if err == nil {
		t.Error("expected error when rotating without credentials")
	}
}

func TestRotateCommand_NonExistentProfile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile existing]
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := RotateCommandInput{
		ProfileName: "nonexistent",
		NoSession:   true,
	}

	err = RotateCommand(input, configFile, kr)
	// Should fail for non-existent profile
	if err == nil {
		t.Error("expected error for non-existent profile")
	}
}

func TestGetProfilesInChain_NonExistentProfile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile existing]
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	configLoader := vault.NewConfigLoader(vault.ProfileConfig{}, configFile, "nonexistent")
	profiles, err := getProfilesInChain("nonexistent", configLoader)

	// Should return the profile name even if it doesn't exist
	// The error happens later when trying to load its config
	if err != nil {
		// If there's an error, that's also acceptable behavior
		t.Logf("getProfilesInChain error (acceptable): %v", err)
	} else if len(profiles) < 1 || profiles[0] != "nonexistent" {
		t.Errorf("expected at least 'nonexistent' in chain, got %v", profiles)
	}
}
