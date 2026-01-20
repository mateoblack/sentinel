package session

import (
	"testing"
)

func TestNewSessionID(t *testing.T) {
	t.Run("generates valid 16-char hex string", func(t *testing.T) {
		id := NewSessionID()

		// Must be exactly 16 characters
		if len(id) != SessionIDLength {
			t.Errorf("NewSessionID() length = %d, want %d", len(id), SessionIDLength)
		}

		// Must be valid according to ValidateSessionID
		if !ValidateSessionID(id) {
			t.Errorf("NewSessionID() = %q is not valid", id)
		}

		// Must be lowercase hex
		for i, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("NewSessionID() char %d = %q is not lowercase hex", i, string(c))
			}
		}
	})

	t.Run("multiple calls produce unique IDs", func(t *testing.T) {
		const count = 1000
		seen := make(map[string]bool, count)

		for i := 0; i < count; i++ {
			id := NewSessionID()
			if seen[id] {
				t.Errorf("collision detected: %q generated more than once in %d iterations", id, i+1)
				return
			}
			seen[id] = true
		}
	})

	t.Run("ID passes ValidateSessionID", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			id := NewSessionID()
			if !ValidateSessionID(id) {
				t.Errorf("NewSessionID() iteration %d: %q failed validation", i, id)
			}
		}
	})
}

func TestValidateSessionID(t *testing.T) {
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
			name:  "invalid - 8 chars",
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
			got := ValidateSessionID(tc.id)
			if got != tc.valid {
				t.Errorf("ValidateSessionID(%q) = %v, want %v", tc.id, got, tc.valid)
			}
		})
	}
}

func TestSessionStatus_IsValid(t *testing.T) {
	testCases := []struct {
		name   string
		status SessionStatus
		valid  bool
	}{
		{
			name:   "active is valid",
			status: StatusActive,
			valid:  true,
		},
		{
			name:   "revoked is valid",
			status: StatusRevoked,
			valid:  true,
		},
		{
			name:   "expired is valid",
			status: StatusExpired,
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
			name:   "ACTIVE uppercase is invalid",
			status: "ACTIVE",
			valid:  false,
		},
		{
			name:   "partial match is invalid",
			status: "act",
			valid:  false,
		},
		{
			name:   "pending (not a session status) is invalid",
			status: "pending",
			valid:  false,
		},
		{
			name:   "closed (breakglass status) is invalid",
			status: "closed",
			valid:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.status.IsValid()
			if got != tc.valid {
				t.Errorf("SessionStatus(%q).IsValid() = %v, want %v", tc.status, got, tc.valid)
			}
		})
	}
}

func TestSessionStatus_IsTerminal(t *testing.T) {
	testCases := []struct {
		name     string
		status   SessionStatus
		terminal bool
	}{
		{
			name:     "active is not terminal",
			status:   StatusActive,
			terminal: false,
		},
		{
			name:     "revoked is terminal",
			status:   StatusRevoked,
			terminal: true,
		},
		{
			name:     "expired is terminal",
			status:   StatusExpired,
			terminal: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.status.IsTerminal()
			if got != tc.terminal {
				t.Errorf("SessionStatus(%q).IsTerminal() = %v, want %v", tc.status, got, tc.terminal)
			}
		})
	}
}

func TestSessionStatus_String(t *testing.T) {
	testCases := []struct {
		status SessionStatus
		want   string
	}{
		{StatusActive, "active"},
		{StatusRevoked, "revoked"},
		{StatusExpired, "expired"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.status.String()
			if got != tc.want {
				t.Errorf("SessionStatus(%q).String() = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}
