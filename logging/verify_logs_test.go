package logging

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testVerifyKey is a 32-byte key for testing (hex-encoded = 64 chars)
var testVerifyKey = []byte("01234567890123456789012345678901")
var testVerifyKeyHex = hex.EncodeToString(testVerifyKey)

// createTestVerifyLogFile creates a temporary log file with signed entries.
func createTestVerifyLogFile(t *testing.T, entries []any, config *SignatureConfig) string {
	t.Helper()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("failed to create test log file: %v", err)
	}
	defer f.Close()

	for _, entry := range entries {
		signed, err := NewSignedEntry(entry, config)
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

// VerifyLogsResult contains the results of log verification.
// This is a duplicate for testing purposes since cli package can't be imported.
type VerifyLogsResult struct {
	FilePath    string              `json:"file_path"`
	TotalLines  int                 `json:"total_lines"`
	VerifiedOK  int                 `json:"verified_ok"`
	InvalidSig  int                 `json:"invalid_sig"`
	ParseErrors int                 `json:"parse_errors"`
	Failures    []VerifyLogsFailure `json:"failures,omitempty"`
}

// VerifyLogsFailure represents a single verification failure.
type VerifyLogsFailure struct {
	Line    int    `json:"line"`
	Type    string `json:"type"` // "invalid_signature" or "parse_error"
	Message string `json:"message"`
}

const maxDetailedVerifyFailures = 10

// verifyLogFileForTest reads and verifies all entries in a log file.
// This is a testing version of the CLI command logic.
func verifyLogFileForTest(logPath string, key []byte) (*VerifyLogsResult, error) {
	result := &VerifyLogsResult{
		FilePath: logPath,
		Failures: make([]VerifyLogsFailure, 0),
	}

	f, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines
		if line == "" {
			continue
		}

		result.TotalLines++

		// Parse as SignedEntry
		var entry SignedEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			result.ParseErrors++
			if len(result.Failures) < maxDetailedVerifyFailures {
				result.Failures = append(result.Failures, VerifyLogsFailure{
					Line:    lineNum,
					Type:    "parse_error",
					Message: "invalid JSON",
				})
			}
			continue
		}

		// Check for missing signature
		if entry.Signature == "" {
			result.ParseErrors++
			if len(result.Failures) < maxDetailedVerifyFailures {
				result.Failures = append(result.Failures, VerifyLogsFailure{
					Line:    lineNum,
					Type:    "parse_error",
					Message: "missing signature field",
				})
			}
			continue
		}

		// Verify signature
		valid, err := entry.Verify(key)
		if err != nil {
			result.ParseErrors++
			if len(result.Failures) < maxDetailedVerifyFailures {
				result.Failures = append(result.Failures, VerifyLogsFailure{
					Line:    lineNum,
					Type:    "parse_error",
					Message: "verification error",
				})
			}
			continue
		}

		if !valid {
			result.InvalidSig++
			if len(result.Failures) < maxDetailedVerifyFailures {
				result.Failures = append(result.Failures, VerifyLogsFailure{
					Line:    lineNum,
					Type:    "invalid_signature",
					Message: "invalid signature (possible tampering)",
				})
			}
			continue
		}

		result.VerifiedOK++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func TestVerifyLogs_ValidFile(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "test-key-1",
		SecretKey: testVerifyKey,
	}

	entries := []any{
		map[string]any{"action": "login", "user": "alice"},
		map[string]any{"action": "logout", "user": "bob"},
		map[string]any{"action": "access", "resource": "secrets"},
	}

	logPath := createTestVerifyLogFile(t, entries, config)

	result, err := verifyLogFileForTest(logPath, testVerifyKey)
	if err != nil {
		t.Fatalf("verifyLogFileForTest() error = %v", err)
	}

	if result.TotalLines != 3 {
		t.Errorf("TotalLines = %d, want 3", result.TotalLines)
	}
	if result.VerifiedOK != 3 {
		t.Errorf("VerifiedOK = %d, want 3", result.VerifiedOK)
	}
	if result.InvalidSig != 0 {
		t.Errorf("InvalidSig = %d, want 0", result.InvalidSig)
	}
	if result.ParseErrors != 0 {
		t.Errorf("ParseErrors = %d, want 0", result.ParseErrors)
	}
}

func TestVerifyLogs_TamperedEntry(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "test-key-1",
		SecretKey: testVerifyKey,
	}

	// Create a valid log file first
	entries := []any{
		map[string]any{"action": "login", "user": "alice"},
	}
	logPath := createTestVerifyLogFile(t, entries, config)

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

	// Run verification - should detect invalid signature
	result, err := verifyLogFileForTest(logPath, testVerifyKey)
	if err != nil {
		t.Fatalf("verifyLogFileForTest() error = %v", err)
	}

	if result.InvalidSig != 1 {
		t.Errorf("InvalidSig = %d, want 1 (tampering should be detected)", result.InvalidSig)
	}
}

func TestVerifyLogs_MissingSignature(t *testing.T) {
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

	result, err := verifyLogFileForTest(logPath, testVerifyKey)
	if err != nil {
		t.Fatalf("verifyLogFileForTest() error = %v", err)
	}

	if result.ParseErrors != 1 {
		t.Errorf("ParseErrors = %d, want 1 (missing signature should be detected)", result.ParseErrors)
	}
}

func TestVerifyLogs_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	// Write invalid JSON
	if err := os.WriteFile(logPath, []byte("not valid json\n"), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	result, err := verifyLogFileForTest(logPath, testVerifyKey)
	if err != nil {
		t.Fatalf("verifyLogFileForTest() error = %v", err)
	}

	if result.ParseErrors != 1 {
		t.Errorf("ParseErrors = %d, want 1 (invalid JSON should be detected)", result.ParseErrors)
	}
}

func TestVerifyLogs_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	// Write empty file
	if err := os.WriteFile(logPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write log file: %v", err)
	}

	result, err := verifyLogFileForTest(logPath, testVerifyKey)
	if err != nil {
		t.Fatalf("verifyLogFileForTest() error = %v", err)
	}

	if result.TotalLines != 0 {
		t.Errorf("TotalLines = %d, want 0", result.TotalLines)
	}
	if result.VerifiedOK != 0 {
		t.Errorf("VerifiedOK = %d, want 0", result.VerifiedOK)
	}
}

func TestVerifyLogs_WrongKey(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "test-key-1",
		SecretKey: testVerifyKey,
	}

	entries := []any{
		map[string]any{"action": "test"},
	}
	logPath := createTestVerifyLogFile(t, entries, config)

	// Use a different key for verification
	differentKey := []byte("different-key-different-key-1234")

	result, err := verifyLogFileForTest(logPath, differentKey)
	if err != nil {
		t.Fatalf("verifyLogFileForTest() error = %v", err)
	}

	if result.InvalidSig != 1 {
		t.Errorf("InvalidSig = %d, want 1 (wrong key should fail verification)", result.InvalidSig)
	}
}

func TestVerifyLogs_MixedValidAndInvalid(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "test-key-1",
		SecretKey: testVerifyKey,
	}

	// Create valid entries
	entries := []any{
		map[string]any{"action": "valid1"},
		map[string]any{"action": "valid2"},
	}
	logPath := createTestVerifyLogFile(t, entries, config)

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

	result, err := verifyLogFileForTest(logPath, testVerifyKey)
	if err != nil {
		t.Fatalf("verifyLogFileForTest() error = %v", err)
	}

	if result.VerifiedOK != 2 {
		t.Errorf("VerifiedOK = %d, want 2", result.VerifiedOK)
	}
	if result.InvalidSig != 1 {
		t.Errorf("InvalidSig = %d, want 1", result.InvalidSig)
	}
}
