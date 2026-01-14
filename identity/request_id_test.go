package identity

import (
	"testing"
)

func TestNewRequestID_Format(t *testing.T) {
	id := NewRequestID()

	// Must be exactly 8 characters
	if len(id) != RequestIDLength {
		t.Errorf("NewRequestID() length = %d, want %d", len(id), RequestIDLength)
	}

	// Must be valid according to ValidateRequestID
	if !ValidateRequestID(id) {
		t.Errorf("NewRequestID() = %q is not valid", id)
	}

	// Must be lowercase hex
	for i, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("NewRequestID() char %d = %q is not lowercase hex", i, string(c))
		}
	}
}

func TestNewRequestID_Uniqueness(t *testing.T) {
	// Generate 1000 IDs and verify no collisions
	const count = 1000
	seen := make(map[string]bool, count)

	for i := 0; i < count; i++ {
		id := NewRequestID()
		if seen[id] {
			t.Errorf("collision detected: %q generated more than once in %d iterations", id, i+1)
			return
		}
		seen[id] = true
	}
}

func TestValidateRequestID(t *testing.T) {
	var testCases = []struct {
		name  string
		id    string
		valid bool
	}{
		{
			name:  "valid - all digits",
			id:    "12345678",
			valid: true,
		},
		{
			name:  "valid - all lowercase hex letters",
			id:    "abcdef12",
			valid: true,
		},
		{
			name:  "valid - mixed",
			id:    "a1b2c3d4",
			valid: true,
		},
		{
			name:  "valid - all zeros",
			id:    "00000000",
			valid: true,
		},
		{
			name:  "valid - deadbeef",
			id:    "deadbeef",
			valid: true,
		},
		{
			name:  "invalid - too short",
			id:    "1234567",
			valid: false,
		},
		{
			name:  "invalid - too long",
			id:    "123456789",
			valid: false,
		},
		{
			name:  "invalid - empty",
			id:    "",
			valid: false,
		},
		{
			name:  "invalid - uppercase",
			id:    "ABCDEF12",
			valid: false,
		},
		{
			name:  "invalid - mixed case",
			id:    "AbCdEf12",
			valid: false,
		},
		{
			name:  "invalid - non-hex letters",
			id:    "ghijklmn",
			valid: false,
		},
		{
			name:  "invalid - special characters",
			id:    "1234-567",
			valid: false,
		},
		{
			name:  "invalid - spaces",
			id:    "1234 567",
			valid: false,
		},
		{
			name:  "invalid - unicode",
			id:    "12345678\u00e9",
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateRequestID(tc.id)
			if got != tc.valid {
				t.Errorf("ValidateRequestID(%q) = %v, want %v", tc.id, got, tc.valid)
			}
		})
	}
}

func TestNewRequestID_MultipleCalls(t *testing.T) {
	// Verify multiple calls produce different results
	ids := make([]string, 10)
	for i := range ids {
		ids[i] = NewRequestID()
	}

	// Check all are unique
	seen := make(map[string]bool)
	for _, id := range ids {
		if seen[id] {
			t.Error("duplicate ID generated")
		}
		seen[id] = true
	}

	// Check all are valid
	for i, id := range ids {
		if !ValidateRequestID(id) {
			t.Errorf("id[%d] = %q is invalid", i, id)
		}
	}
}
