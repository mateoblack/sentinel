package device

import (
	"testing"

	"github.com/denisbrodbeck/machineid"
)

func TestGetDeviceID_Stable(t *testing.T) {
	// Call GetDeviceID twice and verify both calls return identical value
	id1, err1 := GetDeviceID()
	if err1 != nil {
		t.Fatalf("GetDeviceID() first call error = %v", err1)
	}

	id2, err2 := GetDeviceID()
	if err2 != nil {
		t.Fatalf("GetDeviceID() second call error = %v", err2)
	}

	// Verify both calls return identical value (stable across calls)
	if id1 != id2 {
		t.Errorf("GetDeviceID() not stable: first=%q, second=%q", id1, id2)
	}

	// Verify returned ID is 64 hex characters
	if len(id1) != 64 {
		t.Errorf("GetDeviceID() length = %d, want 64", len(id1))
	}
}

func TestGetDeviceID_Format(t *testing.T) {
	id, err := GetDeviceID()
	if err != nil {
		t.Fatalf("GetDeviceID() error = %v", err)
	}

	// Verify output is exactly 64 characters (SHA256 = 32 bytes = 64 hex chars)
	if len(id) != 64 {
		t.Errorf("GetDeviceID() length = %d, want 64 (SHA256 output)", len(id))
	}

	// Verify output is lowercase hex
	for i, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("GetDeviceID() char %d = %q is not lowercase hex", i, string(c))
		}
	}

	// Verify it passes our validator
	if !ValidateDeviceIdentifier(id) {
		t.Errorf("GetDeviceID() = %q failed ValidateDeviceIdentifier", id)
	}
}

func TestValidateDeviceIdentifier(t *testing.T) {
	testCases := []struct {
		name  string
		id    string
		valid bool
	}{
		{
			name:  "valid - 64 lowercase hex digits",
			id:    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			valid: true,
		},
		{
			name:  "valid - all lowercase hex letters",
			id:    "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			valid: true,
		},
		{
			name:  "valid - all digits",
			id:    "1234567890123456789012345678901234567890123456789012345678901234",
			valid: true,
		},
		{
			name:  "valid - all zeros",
			id:    "0000000000000000000000000000000000000000000000000000000000000000",
			valid: true,
		},
		{
			name:  "invalid - empty string",
			id:    "",
			valid: false,
		},
		{
			name:  "invalid - 63 chars (one short)",
			id:    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde",
			valid: false,
		},
		{
			name:  "invalid - 65 chars (one extra)",
			id:    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1",
			valid: false,
		},
		{
			name:  "invalid - 32 chars (DeviceID length, not device identifier)",
			id:    "1234567890abcdef1234567890abcdef",
			valid: false,
		},
		{
			name:  "invalid - uppercase hex",
			id:    "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
			valid: false,
		},
		{
			name:  "invalid - mixed case",
			id:    "1234567890AbCdEf1234567890AbCdEf1234567890AbCdEf1234567890AbCdEf",
			valid: false,
		},
		{
			name:  "invalid - non-hex letters (g)",
			id:    "1234567890abcdefg234567890abcdef1234567890abcdef1234567890abcdef",
			valid: false,
		},
		{
			name:  "invalid - special characters",
			id:    "1234-5678-90ab-cdef-1234-5678-90ab-cdef-1234-5678-90ab-cdef-1234",
			valid: false,
		},
		{
			name:  "invalid - spaces",
			id:    "1234 5678 90ab cdef 1234 5678 90ab cdef 1234 5678 90ab cdef 1234",
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateDeviceIdentifier(tc.id)
			if got != tc.valid {
				t.Errorf("ValidateDeviceIdentifier(%q) = %v, want %v", tc.id, got, tc.valid)
			}
		})
	}
}

func TestGetDeviceID_NotRawMachineID(t *testing.T) {
	// Get the device ID from our function
	deviceID, err := GetDeviceID()
	if err != nil {
		t.Fatalf("GetDeviceID() error = %v", err)
	}

	// Get the raw machine ID directly
	rawID, err := machineid.ID()
	if err != nil {
		// On some systems (e.g., containers), machineid.ID() may fail
		// In that case, we can't compare, so skip this test
		t.Skipf("machineid.ID() failed (possibly in container): %v", err)
	}

	// Verify GetDeviceID() output differs from raw machineid.ID()
	// This confirms we're using the hashed/protected version
	if deviceID == rawID {
		t.Errorf("GetDeviceID() returned raw machine ID, expected hashed version")
	}

	// Additional verification: raw ID is typically NOT 64 chars
	// (it's the actual machine UUID/GUID which varies by platform)
	// Our hashed version should always be 64 chars (SHA256)
	if len(deviceID) != 64 {
		t.Errorf("GetDeviceID() length = %d, want 64 (SHA256 hash)", len(deviceID))
	}
}

func TestAppID_Constant(t *testing.T) {
	// Verify AppID is set correctly
	if AppID != "sentinel-device-posture" {
		t.Errorf("AppID = %q, want %q", AppID, "sentinel-device-posture")
	}
}
