package identity

import (
	"strings"
	"testing"
)

func TestSourceIdentity_Format(t *testing.T) {
	var testCases = []struct {
		name      string
		user      string
		requestID string
		want      string
	}{
		{
			name:      "standard user and request-id",
			user:      "alice",
			requestID: "a1b2c3d4",
			want:      "sentinel:alice:a1b2c3d4",
		},
		{
			name:      "maximum length user",
			user:      "abcdefghij0123456789",
			requestID: "12345678",
			want:      "sentinel:abcdefghij0123456789:12345678",
		},
		{
			name:      "single character user",
			user:      "a",
			requestID: "deadbeef",
			want:      "sentinel:a:deadbeef",
		},
		{
			name:      "numeric user",
			user:      "12345",
			requestID: "00000000",
			want:      "sentinel:12345:00000000",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			si := &SourceIdentity{
				User:      tc.user,
				RequestID: tc.requestID,
			}

			got := si.Format()
			if got != tc.want {
				t.Errorf("Format() = %q, want %q", got, tc.want)
			}

			// Also test String() returns same value
			if si.String() != tc.want {
				t.Errorf("String() = %q, want %q", si.String(), tc.want)
			}
		})
	}
}

func TestSourceIdentity_IsValid(t *testing.T) {
	var testCases = []struct {
		name      string
		user      string
		requestID string
		wantValid bool
		wantErr   string
	}{
		{
			name:      "valid - standard",
			user:      "alice",
			requestID: "a1b2c3d4",
			wantValid: true,
			wantErr:   "",
		},
		{
			name:      "valid - max length user",
			user:      "abcdefghij0123456789",
			requestID: "12345678",
			wantValid: true,
			wantErr:   "",
		},
		{
			name:      "invalid - empty user",
			user:      "",
			requestID: "a1b2c3d4",
			wantValid: false,
			wantErr:   "empty",
		},
		{
			name:      "invalid - user too long",
			user:      "abcdefghij01234567890",
			requestID: "a1b2c3d4",
			wantValid: false,
			wantErr:   "exceeds maximum",
		},
		{
			name:      "invalid - user with special chars underscore",
			user:      "alice_bob",
			requestID: "a1b2c3d4",
			wantValid: false,
			wantErr:   "alphanumeric",
		},
		{
			name:      "invalid - user with special chars hyphen",
			user:      "alice-bob",
			requestID: "a1b2c3d4",
			wantValid: false,
			wantErr:   "alphanumeric",
		},
		{
			name:      "invalid - user with special chars at",
			user:      "alice@example",
			requestID: "a1b2c3d4",
			wantValid: false,
			wantErr:   "alphanumeric",
		},
		{
			name:      "invalid - user with space",
			user:      "alice bob",
			requestID: "a1b2c3d4",
			wantValid: false,
			wantErr:   "alphanumeric",
		},
		{
			name:      "invalid - request-id too short",
			user:      "alice",
			requestID: "a1b2c3",
			wantValid: false,
			wantErr:   "request-id",
		},
		{
			name:      "invalid - request-id too long",
			user:      "alice",
			requestID: "a1b2c3d4e5",
			wantValid: false,
			wantErr:   "request-id",
		},
		{
			name:      "invalid - request-id uppercase",
			user:      "alice",
			requestID: "A1B2C3D4",
			wantValid: false,
			wantErr:   "request-id",
		},
		{
			name:      "invalid - request-id non-hex",
			user:      "alice",
			requestID: "ghijklmn",
			wantValid: false,
			wantErr:   "request-id",
		},
		{
			name:      "invalid - empty request-id",
			user:      "alice",
			requestID: "",
			wantValid: false,
			wantErr:   "request-id",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			si := &SourceIdentity{
				User:      tc.user,
				RequestID: tc.requestID,
			}

			gotValid := si.IsValid()
			if gotValid != tc.wantValid {
				t.Errorf("IsValid() = %v, want %v", gotValid, tc.wantValid)
			}

			err := si.Validate()
			if tc.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestParse(t *testing.T) {
	var testCases = []struct {
		name      string
		input     string
		wantUser  string
		wantReqID string
		wantErr   string
	}{
		{
			name:      "valid - standard",
			input:     "sentinel:alice:a1b2c3d4",
			wantUser:  "alice",
			wantReqID: "a1b2c3d4",
			wantErr:   "",
		},
		{
			name:      "valid - numeric user",
			input:     "sentinel:12345:deadbeef",
			wantUser:  "12345",
			wantReqID: "deadbeef",
			wantErr:   "",
		},
		{
			name:      "invalid - wrong prefix",
			input:     "aws:alice:a1b2c3d4",
			wantErr:   "start with 'sentinel:'",
		},
		{
			name:      "invalid - missing prefix",
			input:     "alice:a1b2c3d4",
			wantErr:   "start with 'sentinel:'",
		},
		{
			name:      "invalid - too few parts",
			input:     "sentinel:alice",
			wantErr:   "invalid SourceIdentity format",
		},
		{
			name:      "invalid - too many parts",
			input:     "sentinel:alice:a1b2c3d4:extra",
			wantErr:   "invalid SourceIdentity format",
		},
		{
			name:      "invalid - empty string",
			input:     "",
			wantErr:   "start with 'sentinel:'",
		},
		{
			name:      "invalid - empty user in parsed string",
			input:     "sentinel::a1b2c3d4",
			wantErr:   "empty",
		},
		{
			name:      "invalid - bad request-id in parsed string",
			input:     "sentinel:alice:badid",
			wantErr:   "request-id",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			si, err := Parse(tc.input)

			if tc.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if si.User != tc.wantUser {
				t.Errorf("User = %q, want %q", si.User, tc.wantUser)
			}
			if si.RequestID != tc.wantReqID {
				t.Errorf("RequestID = %q, want %q", si.RequestID, tc.wantReqID)
			}
		})
	}
}

func TestParse_RoundTrip(t *testing.T) {
	// Test that Format -> Parse -> Format produces identical result
	original := &SourceIdentity{
		User:      "alice",
		RequestID: "a1b2c3d4",
	}

	formatted := original.Format()
	parsed, err := Parse(formatted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.User != original.User {
		t.Errorf("User = %q, want %q", parsed.User, original.User)
	}
	if parsed.RequestID != original.RequestID {
		t.Errorf("RequestID = %q, want %q", parsed.RequestID, original.RequestID)
	}
	if parsed.Format() != formatted {
		t.Errorf("Format() = %q, want %q", parsed.Format(), formatted)
	}
}

func TestSourceIdentity_LengthConstraint(t *testing.T) {
	// AWS SourceIdentity max length is 64 characters
	// Our format: sentinel:<user>:<request-id>
	// Max: sentinel: (9) + user (20) + : (1) + request-id (8) = 38 chars

	si := &SourceIdentity{
		User:      "abcdefghij0123456789", // 20 chars (max)
		RequestID: "12345678",              // 8 chars (fixed)
	}

	formatted := si.Format()

	if len(formatted) > MaxSourceIdentityLength {
		t.Errorf("Format() length %d exceeds AWS max %d", len(formatted), MaxSourceIdentityLength)
	}

	// Should be exactly 38 chars
	expectedLen := len("sentinel:") + MaxUserLength + 1 + RequestIDLength
	if len(formatted) != expectedLen {
		t.Errorf("Format() length = %d, expected %d for max-length user", len(formatted), expectedLen)
	}
}

func TestNew(t *testing.T) {
	var testCases = []struct {
		name      string
		user      string
		requestID string
		wantErr   bool
	}{
		{
			name:      "valid creation",
			user:      "alice",
			requestID: "a1b2c3d4",
			wantErr:   false,
		},
		{
			name:      "invalid user",
			user:      "",
			requestID: "a1b2c3d4",
			wantErr:   true,
		},
		{
			name:      "invalid request-id",
			user:      "alice",
			requestID: "bad",
			wantErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			si, err := New(tc.user, tc.requestID)

			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if si != nil {
					t.Error("expected nil SourceIdentity on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if si == nil {
					t.Error("expected SourceIdentity, got nil")
				}
			}
		})
	}
}

func TestSanitizeUser(t *testing.T) {
	var testCases = []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "already valid",
			input:   "alice",
			want:    "alice",
			wantErr: false,
		},
		{
			name:    "remove special chars",
			input:   "alice_bob",
			want:    "alicebob",
			wantErr: false,
		},
		{
			name:    "remove hyphen",
			input:   "alice-bob",
			want:    "alicebob",
			wantErr: false,
		},
		{
			name:    "remove at symbol",
			input:   "alice@example.com",
			want:    "aliceexamplecom",
			wantErr: false,
		},
		{
			name:    "remove spaces",
			input:   "alice bob",
			want:    "alicebob",
			wantErr: false,
		},
		{
			name:    "truncate long username",
			input:   "abcdefghij01234567890123456789",
			want:    "abcdefghij0123456789",
			wantErr: false,
		},
		{
			name:    "empty after sanitization",
			input:   "!@#$%",
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "preserve case",
			input:   "AliceBob",
			want:    "AliceBob",
			wantErr: false,
		},
		{
			name:    "mixed valid and invalid",
			input:   "alice.bob@example_test",
			want:    "alicebobexampletest",
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeUser(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if got != tc.want {
				t.Errorf("SanitizeUser(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
