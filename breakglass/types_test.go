package breakglass

import (
	"testing"
)

func TestBreakGlassStatusIsValid(t *testing.T) {
	testCases := []struct {
		name   string
		status BreakGlassStatus
		valid  bool
	}{
		{
			name:   "active is valid",
			status: StatusActive,
			valid:  true,
		},
		{
			name:   "closed is valid",
			status: StatusClosed,
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
			name:   "pending (request status) is invalid",
			status: "pending",
			valid:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.status.IsValid()
			if got != tc.valid {
				t.Errorf("BreakGlassStatus(%q).IsValid() = %v, want %v", tc.status, got, tc.valid)
			}
		})
	}
}

func TestBreakGlassStatusString(t *testing.T) {
	testCases := []struct {
		status BreakGlassStatus
		want   string
	}{
		{StatusActive, "active"},
		{StatusClosed, "closed"},
		{StatusExpired, "expired"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.status.String()
			if got != tc.want {
				t.Errorf("BreakGlassStatus(%q).String() = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestBreakGlassStatusIsTerminal(t *testing.T) {
	testCases := []struct {
		name     string
		status   BreakGlassStatus
		terminal bool
	}{
		{
			name:     "active is not terminal",
			status:   StatusActive,
			terminal: false,
		},
		{
			name:     "closed is terminal",
			status:   StatusClosed,
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
				t.Errorf("BreakGlassStatus(%q).IsTerminal() = %v, want %v", tc.status, got, tc.terminal)
			}
		})
	}
}

func TestReasonCodeIsValid(t *testing.T) {
	testCases := []struct {
		name  string
		code  ReasonCode
		valid bool
	}{
		{
			name:  "incident is valid",
			code:  ReasonIncident,
			valid: true,
		},
		{
			name:  "maintenance is valid",
			code:  ReasonMaintenance,
			valid: true,
		},
		{
			name:  "security is valid",
			code:  ReasonSecurity,
			valid: true,
		},
		{
			name:  "recovery is valid",
			code:  ReasonRecovery,
			valid: true,
		},
		{
			name:  "other is valid",
			code:  ReasonOther,
			valid: true,
		},
		{
			name:  "empty is invalid",
			code:  "",
			valid: false,
		},
		{
			name:  "unknown code is invalid",
			code:  "unknown",
			valid: false,
		},
		{
			name:  "INCIDENT uppercase is invalid",
			code:  "INCIDENT",
			valid: false,
		},
		{
			name:  "partial match is invalid",
			code:  "inc",
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.code.IsValid()
			if got != tc.valid {
				t.Errorf("ReasonCode(%q).IsValid() = %v, want %v", tc.code, got, tc.valid)
			}
		})
	}
}

func TestReasonCodeString(t *testing.T) {
	testCases := []struct {
		code ReasonCode
		want string
	}{
		{ReasonIncident, "incident"},
		{ReasonMaintenance, "maintenance"},
		{ReasonSecurity, "security"},
		{ReasonRecovery, "recovery"},
		{ReasonOther, "other"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.code.String()
			if got != tc.want {
				t.Errorf("ReasonCode(%q).String() = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

func TestNewBreakGlassID_Format(t *testing.T) {
	id := NewBreakGlassID()

	// Must be exactly 16 characters
	if len(id) != BreakGlassIDLength {
		t.Errorf("NewBreakGlassID() length = %d, want %d", len(id), BreakGlassIDLength)
	}

	// Must be valid according to ValidateBreakGlassID
	if !ValidateBreakGlassID(id) {
		t.Errorf("NewBreakGlassID() = %q is not valid", id)
	}

	// Must be lowercase hex
	for i, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("NewBreakGlassID() char %d = %q is not lowercase hex", i, string(c))
		}
	}
}

func TestNewBreakGlassID_Uniqueness(t *testing.T) {
	// Generate 1000 IDs and verify no collisions
	const count = 1000
	seen := make(map[string]bool, count)

	for i := 0; i < count; i++ {
		id := NewBreakGlassID()
		if seen[id] {
			t.Errorf("collision detected: %q generated more than once in %d iterations", id, i+1)
			return
		}
		seen[id] = true
	}
}

func TestValidateBreakGlassID(t *testing.T) {
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
			got := ValidateBreakGlassID(tc.id)
			if got != tc.valid {
				t.Errorf("ValidateBreakGlassID(%q) = %v, want %v", tc.id, got, tc.valid)
			}
		})
	}
}

func TestNewBreakGlassID_MultipleCalls(t *testing.T) {
	// Verify multiple calls produce different results
	ids := make([]string, 10)
	for i := range ids {
		ids[i] = NewBreakGlassID()
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
		if !ValidateBreakGlassID(id) {
			t.Errorf("id[%d] = %q is invalid", i, id)
		}
	}
}
