package cli

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/iso8601"
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
