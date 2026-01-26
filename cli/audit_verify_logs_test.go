package cli

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/logging"
)

// testKey is a 32-byte key for testing (hex-encoded = 64 chars)
var testKey = []byte("01234567890123456789012345678901")
var testKeyHex = hex.EncodeToString(testKey)

// createTestLogFile creates a temporary log file with signed entries.
func createTestLogFile(t *testing.T, entries []any, config *logging.SignatureConfig) string {
	t.Helper()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("failed to create test log file: %v", err)
	}
	defer f.Close()

	for _, entry := range entries {
		signed, err := logging.NewSignedEntry(entry, config)
		if err != nil {
			t.Fatalf("failed to sign entry: %v", err)
		}
		data, err := json.Marshal(signed)
		if err != nil {
			t.Fatalf("failed to marshal signed entry: %v", err)
		}
		f.Write(data)
		f.Write([]byte("\n"))
	}

	return logPath
}

func TestAuditVerifyLogs_ValidFile(t *testing.T) {
	config := &logging.SignatureConfig{
		KeyID:     "test-key-1",
		SecretKey: testKey,
	}

	entries := []any{
		map[string]any{"action": "login", "user": "alice"},
		map[string]any{"action": "logout", "user": "bob"},
		map[string]any{"action": "access", "resource": "secrets"},
	}

	logPath := createTestLogFile(t, entries, config)

	// Run verification
	err := AuditVerifyLogsCommand(logPath, testKeyHex, "")
	if err != nil {
		t.Errorf("AuditVerifyLogsCommand() error = %v, want nil (all valid)", err)
	}
}

func TestAuditVerifyLogs_TamperedEntry(t *testing.T) {
	config := &logging.SignatureConfig{
		KeyID:     "test-key-1",
		SecretKey: testKey,
	}

	// Create a valid log file first
	entries := []any{
		map[string]any{"action": "login", "user": "alice"},
	}
	logPath := createTestLogFile(t, entries, config)

	// Now tamper with it - modify the entry content
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	// Replace "alice" with "evil!" to simulate tampering
	tampered := strings.Replace(string(data), "alice", "evil!", 1)
	if err := os.WriteFile(logPath, []byte(tampered), 0644); err != nil {
		t.Fatalf("failed to write tampered log: %v", err)
	}

	// Run verification - should fail
	err = AuditVerifyLogsCommand(logPath, testKeyHex, "")
	if err == nil {
		t.Error("AuditVerifyLogsCommand() error = nil, want error for tampered entry")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("error should mention invalid signature, got: %v", err)
	}
}

func TestAuditVerifyLogs_MissingSignature(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	// Write entry without signature
	entry := map[string]any{
		"entry":     `{"action":"test"}`,
		"key_id":    "test-key-1",
		"timestamp": "2026-01-26T00:00:00Z",
		// signature field missing
	}
	data, _ := json.Marshal(entry)

	if err := os.WriteFile(logPath, append(data, '\n'), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	// Run verification - should fail with parse error
	err := AuditVerifyLogsCommand(logPath, testKeyHex, "")
	if err == nil {
		t.Error("AuditVerifyLogsCommand() error = nil, want error for missing signature")
	}
	if !strings.Contains(err.Error(), "parse error") {
		t.Errorf("error should mention parse error, got: %v", err)
	}
}

func TestAuditVerifyLogs_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	// Write invalid JSON
	if err := os.WriteFile(logPath, []byte("not valid json\n"), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	// Run verification - should fail with parse error
	err := AuditVerifyLogsCommand(logPath, testKeyHex, "")
	if err == nil {
		t.Error("AuditVerifyLogsCommand() error = nil, want error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse error") {
		t.Errorf("error should mention parse error, got: %v", err)
	}
}

func TestAuditVerifyLogs_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	// Write empty file
	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	// Run verification - should succeed (0 entries verified)
	err := AuditVerifyLogsCommand(logPath, testKeyHex, "")
	if err != nil {
		t.Errorf("AuditVerifyLogsCommand() error = %v, want nil for empty file", err)
	}
}

func TestAuditVerifyLogs_KeyFromFile(t *testing.T) {
	config := &logging.SignatureConfig{
		KeyID:     "test-key-1",
		SecretKey: testKey,
	}

	entries := []any{
		map[string]any{"action": "test"},
	}
	logPath := createTestLogFile(t, entries, config)

	// Create key file
	tmpDir := t.TempDir()
	keyFilePath := filepath.Join(tmpDir, "key.txt")
	if err := os.WriteFile(keyFilePath, []byte(testKeyHex+"\n"), 0644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Run verification with key from file
	err := AuditVerifyLogsCommand(logPath, "", keyFilePath)
	if err != nil {
		t.Errorf("AuditVerifyLogsCommand() with key file error = %v, want nil", err)
	}
}

func TestAuditVerifyLogs_MissingKey(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	// Run verification without key
	err := AuditVerifyLogsCommand(logPath, "", "")
	if err == nil {
		t.Error("AuditVerifyLogsCommand() error = nil, want error for missing key")
	}
	if !strings.Contains(err.Error(), "--key or --key-file is required") {
		t.Errorf("error should mention missing key, got: %v", err)
	}
}

func TestAuditVerifyLogs_InvalidHexKey(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	// Run verification with invalid hex key
	err := AuditVerifyLogsCommand(logPath, "not-valid-hex!", "")
	if err == nil {
		t.Error("AuditVerifyLogsCommand() error = nil, want error for invalid hex")
	}
	if !strings.Contains(err.Error(), "invalid hex key") {
		t.Errorf("error should mention invalid hex, got: %v", err)
	}
}

func TestAuditVerifyLogs_KeyTooShort(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	// Run verification with short key (16 bytes instead of 32)
	shortKey := hex.EncodeToString([]byte("0123456789012345"))
	err := AuditVerifyLogsCommand(logPath, shortKey, "")
	if err == nil {
		t.Error("AuditVerifyLogsCommand() error = nil, want error for short key")
	}
	if !strings.Contains(err.Error(), "at least") && !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("error should mention key length, got: %v", err)
	}
}

func TestAuditVerifyLogs_WrongKey(t *testing.T) {
	config := &logging.SignatureConfig{
		KeyID:     "test-key-1",
		SecretKey: testKey,
	}

	entries := []any{
		map[string]any{"action": "test"},
	}
	logPath := createTestLogFile(t, entries, config)

	// Use a different key for verification
	differentKey := []byte("different-key-different-key-1234")
	differentKeyHex := hex.EncodeToString(differentKey)

	// Run verification with wrong key - should fail
	err := AuditVerifyLogsCommand(logPath, differentKeyHex, "")
	if err == nil {
		t.Error("AuditVerifyLogsCommand() error = nil, want error for wrong key")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("error should mention invalid signature, got: %v", err)
	}
}

func TestAuditVerifyLogs_MixedValidAndInvalid(t *testing.T) {
	config := &logging.SignatureConfig{
		KeyID:     "test-key-1",
		SecretKey: testKey,
	}

	// Create valid entries
	entries := []any{
		map[string]any{"action": "valid1"},
		map[string]any{"action": "valid2"},
	}
	logPath := createTestLogFile(t, entries, config)

	// Append invalid entry
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open log file: %v", err)
	}

	// Add an entry with invalid signature
	invalid := map[string]any{
		"entry":     json.RawMessage(`{"action":"tampered"}`),
		"signature": "0000000000000000000000000000000000000000000000000000000000000000",
		"key_id":    "test-key-1",
		"timestamp": "2026-01-26T00:00:00Z",
	}
	data, _ := json.Marshal(invalid)
	f.Write(data)
	f.Write([]byte("\n"))
	f.Close()

	// Run verification - should fail
	err = AuditVerifyLogsCommand(logPath, testKeyHex, "")
	if err == nil {
		t.Error("AuditVerifyLogsCommand() error = nil, want error for mixed valid/invalid")
	}
}

func TestLoadVerifyKey_WithWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	keyFilePath := filepath.Join(tmpDir, "key.txt")

	// Write key with various whitespace
	keyWithWhitespace := "  " + testKeyHex + "  \n\t"
	if err := os.WriteFile(keyFilePath, []byte(keyWithWhitespace), 0644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	key, err := loadVerifyKey("", keyFilePath)
	if err != nil {
		t.Errorf("loadVerifyKey() error = %v, want nil", err)
	}
	if len(key) != 32 {
		t.Errorf("loadVerifyKey() key length = %d, want 32", len(key))
	}
}

func TestTrimKeyWhitespace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abc123", "abc123"},
		{" abc123 ", "abc123"},
		{"\tabc123\n", "abc123"},
		{"  ab  cd  ", "abcd"},
		{"\r\n\tabc\r\n", "abc"},
	}

	for _, tt := range tests {
		got := trimKeyWhitespace(tt.input)
		if got != tt.want {
			t.Errorf("trimKeyWhitespace(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
