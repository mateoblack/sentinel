package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/vault"
)

func TestCredentialProcessOutputJSONMarshaling(t *testing.T) {
	// Test that CredentialProcessOutput marshals with correct AWS field names
	output := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
		Expiration:      "2026-01-14T10:00:00Z",
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal CredentialProcessOutput: %v", err)
	}

	jsonStr := string(jsonBytes)

	// Verify Version is 1
	if output.Version != 1 {
		t.Errorf("Version should be 1, got %d", output.Version)
	}

	// Verify field names match AWS spec (AccessKeyId not AccessKeyID)
	if !contains(jsonStr, `"AccessKeyId"`) {
		t.Errorf("JSON should contain 'AccessKeyId' (AWS spec), got: %s", jsonStr)
	}
	if !contains(jsonStr, `"SecretAccessKey"`) {
		t.Errorf("JSON should contain 'SecretAccessKey', got: %s", jsonStr)
	}
	if !contains(jsonStr, `"SessionToken"`) {
		t.Errorf("JSON should contain 'SessionToken', got: %s", jsonStr)
	}
	if !contains(jsonStr, `"Expiration"`) {
		t.Errorf("JSON should contain 'Expiration', got: %s", jsonStr)
	}
	if !contains(jsonStr, `"Version"`) {
		t.Errorf("JSON should contain 'Version', got: %s", jsonStr)
	}
}

func TestCredentialProcessOutputWithTemporaryCredentials(t *testing.T) {
	// Test output with temporary credentials (has expiration)
	expiration := time.Now().Add(1 * time.Hour)
	expirationStr := iso8601.Format(expiration)

	output := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
		Expiration:      expirationStr,
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal CredentialProcessOutput: %v", err)
	}

	jsonStr := string(jsonBytes)

	// Verify Expiration field is present
	if !contains(jsonStr, `"Expiration"`) {
		t.Errorf("JSON should contain 'Expiration' for temporary credentials, got: %s", jsonStr)
	}

	// Verify Expiration format is RFC3339 (ISO8601)
	// Parse the JSON back and check the format
	var parsed CredentialProcessOutput
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal CredentialProcessOutput: %v", err)
	}

	// RFC3339 format should parse without error
	_, err = time.Parse(time.RFC3339, parsed.Expiration)
	if err != nil {
		t.Errorf("Expiration should be RFC3339 format, got: %s, error: %v", parsed.Expiration, err)
	}
}

func TestCredentialProcessOutputWithLongLivedCredentials(t *testing.T) {
	// Test output with long-lived credentials (no expiration, no session token)
	output := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "", // Empty - omitempty should exclude it
		Expiration:      "", // Empty - omitempty should exclude it
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal CredentialProcessOutput: %v", err)
	}

	jsonStr := string(jsonBytes)

	// Verify Expiration field is omitted (omitempty)
	if contains(jsonStr, `"Expiration"`) {
		t.Errorf("JSON should NOT contain 'Expiration' for long-lived credentials, got: %s", jsonStr)
	}

	// Verify SessionToken field is omitted (omitempty)
	if contains(jsonStr, `"SessionToken"`) {
		t.Errorf("JSON should NOT contain 'SessionToken' for long-lived credentials, got: %s", jsonStr)
	}

	// Verify required fields are present
	if !contains(jsonStr, `"Version"`) {
		t.Errorf("JSON should contain 'Version', got: %s", jsonStr)
	}
	if !contains(jsonStr, `"AccessKeyId"`) {
		t.Errorf("JSON should contain 'AccessKeyId', got: %s", jsonStr)
	}
	if !contains(jsonStr, `"SecretAccessKey"`) {
		t.Errorf("JSON should contain 'SecretAccessKey', got: %s", jsonStr)
	}
}

func TestCredentialProcessOutputVersionIsOne(t *testing.T) {
	// AWS credential_process spec requires Version to be 1
	output := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal CredentialProcessOutput: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	version, ok := parsed["Version"].(float64) // JSON numbers unmarshal as float64
	if !ok {
		t.Fatalf("Version should be a number")
	}

	if int(version) != 1 {
		t.Errorf("Version should be 1, got %d", int(version))
	}
}

func TestCredentialProcessOutputMarshalIndent(t *testing.T) {
	// Test that MarshalIndent produces readable output
	output := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "token",
		Expiration:      "2026-01-14T10:00:00Z",
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatalf("Failed to MarshalIndent CredentialProcessOutput: %v", err)
	}

	jsonStr := string(jsonBytes)

	// Should contain newlines (indented output)
	if !contains(jsonStr, "\n") {
		t.Errorf("MarshalIndent should produce indented output with newlines, got: %s", jsonStr)
	}
}

// contains checks if substr is in s
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestCredentialsCommandInput_LoggingFields(t *testing.T) {
	// Test that CredentialsCommandInput has all expected logging fields
	input := CredentialsCommandInput{
		ProfileName:     "test-profile",
		PolicyParameter: "/sentinel/policies/test",
		LogFile:         "/tmp/decisions.log",
		LogStderr:       true,
	}

	// Verify LogFile field exists and is set correctly
	if input.LogFile != "/tmp/decisions.log" {
		t.Errorf("expected LogFile '/tmp/decisions.log', got %q", input.LogFile)
	}

	// Verify LogStderr field exists and is set correctly
	if !input.LogStderr {
		t.Error("expected LogStderr to be true")
	}

	// Test default values
	defaultInput := CredentialsCommandInput{}
	if defaultInput.LogFile != "" {
		t.Errorf("expected empty LogFile by default, got %q", defaultInput.LogFile)
	}
	if defaultInput.LogStderr {
		t.Error("expected LogStderr to be false by default")
	}
	if defaultInput.Logger != nil {
		t.Error("expected Logger to be nil by default")
	}
}

func TestCredentialsCommand_LoggerCreation(t *testing.T) {
	t.Run("creates logger when log-file is set", func(t *testing.T) {
		// Create temp directory for test
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "decisions.log")

		// Test that file logger can be created
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Failed to open log file: %v", err)
		}
		defer f.Close()

		// Create logger and write entry
		logger := logging.NewJSONLogger(f)
		entry := logging.DecisionLogEntry{
			Timestamp:  "2026-01-14T10:00:00Z",
			User:       "alice",
			Profile:    "production",
			Effect:     "allow",
			Rule:       "allow-production",
			RuleIndex:  0,
			PolicyPath: "/sentinel/policies/default",
		}
		logger.LogDecision(entry)

		// Verify file was written
		f.Close()
		content, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("Failed to read log file: %v", err)
		}

		if len(content) == 0 {
			t.Error("expected log file to have content")
		}

		// Verify it's valid JSON
		var parsed logging.DecisionLogEntry
		if err := json.Unmarshal(bytes.TrimSpace(content), &parsed); err != nil {
			t.Errorf("log file should contain valid JSON, got error: %v", err)
		}
	})

	t.Run("creates logger when log-stderr is set", func(t *testing.T) {
		// Test that stderr logger can be created
		var buf bytes.Buffer
		logger := logging.NewJSONLogger(&buf)

		entry := logging.DecisionLogEntry{
			Timestamp: "2026-01-14T10:00:00Z",
			User:      "bob",
			Profile:   "staging",
			Effect:    "deny",
			RuleIndex: -1,
		}
		logger.LogDecision(entry)

		if buf.Len() == 0 {
			t.Error("expected buffer to have content")
		}
	})

	t.Run("creates MultiWriter for both destinations", func(t *testing.T) {
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "decisions.log")

		// Create file and buffer
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Failed to open log file: %v", err)
		}
		defer f.Close()

		var stderrBuf bytes.Buffer

		// Create MultiWriter just like credentials.go does
		writers := []io.Writer{&stderrBuf, f}
		logger := logging.NewJSONLogger(io.MultiWriter(writers...))

		entry := logging.DecisionLogEntry{
			Timestamp:  "2026-01-14T10:00:00Z",
			User:       "charlie",
			Profile:    "development",
			Effect:     "allow",
			Rule:       "allow-dev",
			RuleIndex:  0,
			PolicyPath: "/sentinel/policies/default",
		}
		logger.LogDecision(entry)

		// Verify both destinations received the log
		if stderrBuf.Len() == 0 {
			t.Error("expected stderr buffer to have content")
		}

		f.Close()
		fileContent, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("Failed to read log file: %v", err)
		}

		if len(fileContent) == 0 {
			t.Error("expected log file to have content")
		}

		// Verify both have the same content
		if stderrBuf.String() != string(fileContent) {
			t.Errorf("expected identical content in both destinations:\nstderr: %q\nfile: %q",
				stderrBuf.String(), string(fileContent))
		}
	})

	t.Run("file logging appends to existing file", func(t *testing.T) {
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "decisions.log")

		// Write first entry
		f1, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Failed to open log file: %v", err)
		}
		logger1 := logging.NewJSONLogger(f1)
		logger1.LogDecision(logging.DecisionLogEntry{
			Timestamp: "2026-01-14T10:00:00Z",
			User:      "alice",
			Effect:    "allow",
		})
		f1.Close()

		// Write second entry (new file handle, simulating new command execution)
		f2, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Failed to open log file: %v", err)
		}
		logger2 := logging.NewJSONLogger(f2)
		logger2.LogDecision(logging.DecisionLogEntry{
			Timestamp: "2026-01-14T10:01:00Z",
			User:      "bob",
			Effect:    "deny",
		})
		f2.Close()

		// Verify file has both entries (JSON Lines format)
		content, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("Failed to read log file: %v", err)
		}

		lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
		if len(lines) != 2 {
			t.Errorf("expected 2 log lines (appended), got %d", len(lines))
		}
	})
}

func TestSentinel_ValidateProfile(t *testing.T) {
	// Create a temp config file with known profiles
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config")

	configContent := `[profile production]
region = us-east-1

[profile staging]
region = us-west-2

[default]
region = us-east-1
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Set AWS_CONFIG_FILE to use our test config
	originalEnv := os.Getenv("AWS_CONFIG_FILE")
	os.Setenv("AWS_CONFIG_FILE", configFile)
	defer os.Setenv("AWS_CONFIG_FILE", originalEnv)

	t.Run("returns nil for existing profile", func(t *testing.T) {
		s := &Sentinel{}

		err := s.ValidateProfile("production")
		if err != nil {
			t.Errorf("expected nil error for existing profile, got: %v", err)
		}
	})

	t.Run("returns nil for default profile", func(t *testing.T) {
		// Need a fresh Sentinel to reload config
		s := &Sentinel{}

		err := s.ValidateProfile("default")
		if err != nil {
			t.Errorf("expected nil error for default profile, got: %v", err)
		}
	})

	t.Run("returns error for missing profile with available profiles", func(t *testing.T) {
		// Need a fresh Sentinel to reload config
		s := &Sentinel{}

		err := s.ValidateProfile("nonexistent")
		if err == nil {
			t.Fatal("expected error for nonexistent profile, got nil")
		}

		errStr := err.Error()

		// Check that error mentions the profile name
		if !strings.Contains(errStr, "nonexistent") {
			t.Errorf("error should mention the profile name, got: %s", errStr)
		}

		// Check that error mentions "not found"
		if !strings.Contains(errStr, "not found") {
			t.Errorf("error should mention 'not found', got: %s", errStr)
		}

		// Check that error lists available profiles
		if !strings.Contains(errStr, "production") || !strings.Contains(errStr, "staging") {
			t.Errorf("error should list available profiles (production, staging), got: %s", errStr)
		}
	})

	t.Run("caches config file across calls", func(t *testing.T) {
		s := &Sentinel{}

		// First call loads config
		_ = s.ValidateProfile("production")

		// Config should be cached
		if s.awsConfigFile == nil {
			t.Error("expected awsConfigFile to be cached after first call")
		}

		// Second call should use cached config
		cachedConfig := s.awsConfigFile
		_ = s.ValidateProfile("staging")

		if s.awsConfigFile != cachedConfig {
			t.Error("expected awsConfigFile to remain cached between calls")
		}
	})
}

func TestSentinel_ValidateProfile_WithLoadedConfig(t *testing.T) {
	// Test using a pre-loaded config (simulates how credentials command works)
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config")

	configContent := `[profile dev]
region = eu-west-1
`
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Load config manually
	loadedConfig, err := vault.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	s := &Sentinel{
		awsConfigFile: loadedConfig,
	}

	// Validate existing profile
	if err := s.ValidateProfile("dev"); err != nil {
		t.Errorf("expected nil for existing profile, got: %v", err)
	}

	// Validate missing profile
	err = s.ValidateProfile("missing")
	if err == nil {
		t.Fatal("expected error for missing profile")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error should mention profile name, got: %s", err.Error())
	}
}
