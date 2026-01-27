// Package device provides fuzz tests for device ID validation.
// Fuzz tests help discover edge cases in device ID validation
// that could allow invalid or dangerous inputs.
//
// Run fuzz tests:
//
//	go test -fuzz=FuzzValidateDeviceID -fuzztime=30s ./device/...
//	go test -fuzz=FuzzNewDeviceID -fuzztime=30s ./device/...
package device

import (
	"strings"
	"testing"
	"time"
)

// FuzzValidateDeviceID tests device ID validation with random inputs.
// Device IDs should be 32-character lowercase hexadecimal strings.
//
// Run: go test -fuzz=FuzzValidateDeviceID -fuzztime=30s ./device/...
func FuzzValidateDeviceID(f *testing.F) {
	seeds := []string{
		// Valid 32-char lowercase hex
		"0123456789abcdef0123456789abcdef",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffff",

		// Invalid - wrong case
		"ABCDEF0123456789ABCDEF0123456789",
		"0123456789ABCDEF0123456789ABCDEF",
		"0123456789AbCdEf0123456789abcdef",

		// Invalid - wrong length
		"",
		"short",
		"0123456789abcdef",                  // 16 chars
		"0123456789abcdef01234567",          // 24 chars
		"0123456789abcdef0123456789abcdef0", // 33 chars
		strings.Repeat("a", 31),
		strings.Repeat("a", 33),
		strings.Repeat("a", 64),
		strings.Repeat("a", 1000),

		// Invalid - non-hex characters
		"ghijklmnopqrstuvwxyzghijklmnopqr", // g-z are not hex
		"0123456789abcdef0123456789abcdeg",
		"0123456789abcdef0123456789abcde!",
		"0123456789abcdef0123456789abcde ",
		"0123456789abcdef0123456789abcde\n",
		"0123456789abcdef0123456789abcde\x00",

		// Injection attempts (wrong length anyway)
		"0123456789abcdef0123456789ab; rm",
		"0123456789abcdef0123456789abc\n12",
		"0123456789abcdef0123456789abc`id",
		"0123456789abcdef0123456789abc$()12",

		// Unicode that looks like hex
		"０１２３４５６７８９ａｂｃｄｅｆ０１２３４５６７８９ａｂｃｄｅｆ", // fullwidth

		// Null bytes embedded
		"0123456789abcdef\x000123456789abcde",
		"\x000123456789abcdef0123456789abcde",
		"0123456789abcdef0123456789abcde\x00",

		// Whitespace
		" 0123456789abcdef0123456789abcdef",
		"0123456789abcdef0123456789abcdef ",
		"0123456789abcdef 0123456789abcdef",
		"\t0123456789abcdef0123456789abcde",
		"0123456789abcdef0123456789abcde\t",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Validation should never panic
		valid := ValidateDeviceID(input)

		if valid {
			// If valid, must be exactly 32 lowercase hex chars
			if len(input) != DeviceIDLength {
				t.Errorf("ValidateDeviceID accepted non-%d-char string: len=%d input=%q", DeviceIDLength, len(input), input)
			}

			// Must be valid lowercase hex
			for i, c := range input {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("ValidateDeviceID accepted non-lowercase-hex char at pos %d: char=%q input=%q", i, c, input)
				}
			}

			// Must not contain any dangerous characters
			dangerous := []string{";", "`", "$", "(", ")", "|", "&", "\n", "\r", "\x00", " ", "\t"}
			for _, d := range dangerous {
				if strings.Contains(input, d) {
					t.Errorf("ValidateDeviceID accepted input with dangerous char %q: %q", d, input)
				}
			}
		}
	})
}

// FuzzNewDeviceID tests that generated device IDs are always valid.
//
// Run: go test -fuzz=FuzzNewDeviceID -fuzztime=10s ./device/...
func FuzzNewDeviceID(f *testing.F) {
	// Seed with dummy values (the function doesn't take input, but we need seeds for iterations)
	f.Add(0)
	f.Add(1)
	f.Add(100)
	f.Add(999999)

	f.Fuzz(func(t *testing.T, _ int) {
		// Generate should never panic
		id := NewDeviceID()

		// Generated ID should always be valid
		if !ValidateDeviceID(id) {
			t.Errorf("NewDeviceID generated invalid ID: %q", id)
		}

		// Should be exactly 32 chars
		if len(id) != DeviceIDLength {
			t.Errorf("NewDeviceID generated ID with wrong length: len=%d id=%q", len(id), id)
		}

		// Should be lowercase hex
		for i, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("NewDeviceID generated non-lowercase-hex char at pos %d: char=%q id=%q", i, c, id)
			}
		}
	})
}

// FuzzDevicePostureValidate tests DevicePosture validation with random inputs.
//
// Run: go test -fuzz=FuzzDevicePostureValidate -fuzztime=30s ./device/...
func FuzzDevicePostureValidate(f *testing.F) {
	// Seed with various device ID and status combinations
	seeds := []struct {
		deviceID string
		status   string
	}{
		{"0123456789abcdef0123456789abcdef", "compliant"},
		{"0123456789abcdef0123456789abcdef", "non_compliant"},
		{"0123456789abcdef0123456789abcdef", "unknown"},
		{"", "compliant"},
		{"short", "compliant"},
		{"0123456789abcdef0123456789abcdef", ""},
		{"0123456789abcdef0123456789abcdef", "invalid_status"},
		{"INVALID_CASE_DEVICEID_1234567890", "compliant"},
	}

	for _, seed := range seeds {
		f.Add(seed.deviceID, seed.status)
	}

	f.Fuzz(func(t *testing.T, deviceID, status string) {
		// Create posture with fuzzed values
		posture := &DevicePosture{
			DeviceID:    deviceID,
			Status:      PostureStatus(status),
			CollectedAt: time.Now(),
		}

		// Validate should never panic
		err := posture.Validate()

		if err == nil {
			// If validation passes, verify constraints
			if !ValidateDeviceID(posture.DeviceID) {
				t.Errorf("DevicePosture.Validate() passed for invalid device ID: %q", deviceID)
			}

			if !posture.Status.IsValid() {
				t.Errorf("DevicePosture.Validate() passed for invalid status: %q", status)
			}
		}
	})
}

// FuzzPostureStatusIsValid tests PostureStatus validation.
//
// Run: go test -fuzz=FuzzPostureStatusIsValid -fuzztime=10s ./device/...
func FuzzPostureStatusIsValid(f *testing.F) {
	seeds := []string{
		"compliant",
		"non_compliant",
		"unknown",
		"",
		"COMPLIANT",
		"Compliant",
		"invalid",
		"compliant; rm -rf /",
		"compliant\x00",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		status := PostureStatus(input)

		// Should never panic
		valid := status.IsValid()

		// Only known statuses should be valid
		knownStatuses := map[string]bool{
			"compliant":     true,
			"non_compliant": true,
			"unknown":       true,
		}

		if valid && !knownStatuses[input] {
			t.Errorf("PostureStatus.IsValid() returned true for unknown status: %q", input)
		}

		if !valid && knownStatuses[input] {
			t.Errorf("PostureStatus.IsValid() returned false for known status: %q", input)
		}
	})
}
