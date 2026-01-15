package request

import (
	"testing"
)

func TestRequestStatusIsValid(t *testing.T) {
	testCases := []struct {
		name   string
		status RequestStatus
		valid  bool
	}{
		{
			name:   "pending is valid",
			status: StatusPending,
			valid:  true,
		},
		{
			name:   "approved is valid",
			status: StatusApproved,
			valid:  true,
		},
		{
			name:   "denied is valid",
			status: StatusDenied,
			valid:  true,
		},
		{
			name:   "expired is valid",
			status: StatusExpired,
			valid:  true,
		},
		{
			name:   "cancelled is valid",
			status: StatusCancelled,
			valid:  true,
		},
		{
			name:   "empty is invalid",
			status: "",
			valid:  false,
		},
		{
			name:   "unknown status is invalid",
			status: "unknown",
			valid:  false,
		},
		{
			name:   "PENDING uppercase is invalid",
			status: "PENDING",
			valid:  false,
		},
		{
			name:   "partial match is invalid",
			status: "pend",
			valid:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.status.IsValid()
			if got != tc.valid {
				t.Errorf("RequestStatus(%q).IsValid() = %v, want %v", tc.status, got, tc.valid)
			}
		})
	}
}

func TestRequestStatusString(t *testing.T) {
	testCases := []struct {
		status RequestStatus
		want   string
	}{
		{StatusPending, "pending"},
		{StatusApproved, "approved"},
		{StatusDenied, "denied"},
		{StatusExpired, "expired"},
		{StatusCancelled, "cancelled"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.status.String()
			if got != tc.want {
				t.Errorf("RequestStatus(%q).String() = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestRequestStatusIsTerminal(t *testing.T) {
	testCases := []struct {
		name     string
		status   RequestStatus
		terminal bool
	}{
		{
			name:     "pending is not terminal",
			status:   StatusPending,
			terminal: false,
		},
		{
			name:     "approved is terminal",
			status:   StatusApproved,
			terminal: true,
		},
		{
			name:     "denied is terminal",
			status:   StatusDenied,
			terminal: true,
		},
		{
			name:     "expired is terminal",
			status:   StatusExpired,
			terminal: true,
		},
		{
			name:     "cancelled is terminal",
			status:   StatusCancelled,
			terminal: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.status.IsTerminal()
			if got != tc.terminal {
				t.Errorf("RequestStatus(%q).IsTerminal() = %v, want %v", tc.status, got, tc.terminal)
			}
		})
	}
}

func TestNewRequestID_Format(t *testing.T) {
	id := NewRequestID()

	// Must be exactly 16 characters
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
	testCases := []struct {
		name  string
		id    string
		valid bool
	}{
		{
			name:  "valid - all digits",
			id:    "1234567890123456",
			valid: true,
		},
		{
			name:  "valid - all lowercase hex letters",
			id:    "abcdefabcdefabcd",
			valid: true,
		},
		{
			name:  "valid - mixed",
			id:    "a1b2c3d4e5f67890",
			valid: true,
		},
		{
			name:  "valid - all zeros",
			id:    "0000000000000000",
			valid: true,
		},
		{
			name:  "valid - deadbeefcafe",
			id:    "deadbeefcafe1234",
			valid: true,
		},
		{
			name:  "invalid - too short (15 chars)",
			id:    "123456789012345",
			valid: false,
		},
		{
			name:  "invalid - too long (17 chars)",
			id:    "12345678901234567",
			valid: false,
		},
		{
			name:  "invalid - 8 chars (identity length)",
			id:    "12345678",
			valid: false,
		},
		{
			name:  "invalid - empty",
			id:    "",
			valid: false,
		},
		{
			name:  "invalid - uppercase",
			id:    "ABCDEFABCDEFABCD",
			valid: false,
		},
		{
			name:  "invalid - mixed case",
			id:    "AbCdEfAbCdEfAbCd",
			valid: false,
		},
		{
			name:  "invalid - non-hex letters",
			id:    "ghijklmnghijklmn",
			valid: false,
		},
		{
			name:  "invalid - special characters",
			id:    "1234-5678-9012-34",
			valid: false,
		},
		{
			name:  "invalid - spaces",
			id:    "1234 5678 9012 34",
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
