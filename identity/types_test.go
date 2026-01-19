package identity

import (
	"errors"
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
			name:    "invalid - wrong prefix",
			input:   "aws:alice:a1b2c3d4",
			wantErr: "start with 'sentinel:'",
		},
		{
			name:    "invalid - missing prefix",
			input:   "alice:a1b2c3d4",
			wantErr: "start with 'sentinel:'",
		},
		{
			name:    "invalid - too few parts",
			input:   "sentinel:alice",
			wantErr: "invalid SourceIdentity format",
		},
		{
			name:    "invalid - too many parts",
			input:   "sentinel:alice:a1b2c3d4:extra",
			wantErr: "invalid SourceIdentity format",
		},
		{
			name:    "invalid - empty string",
			input:   "",
			wantErr: "start with 'sentinel:'",
		},
		{
			name:    "invalid - empty user in parsed string",
			input:   "sentinel::a1b2c3d4",
			wantErr: "empty",
		},
		{
			name:    "invalid - bad request-id in parsed string",
			input:   "sentinel:alice:badid",
			wantErr: "request-id",
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
		RequestID: "12345678",             // 8 chars (fixed)
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

// =============================================================================
// Security Edge Case Tests
// =============================================================================

// TestSourceIdentity_AWSConstraintBoundary tests AWS SourceIdentity length constraints.
func TestSourceIdentity_AWSConstraintBoundary(t *testing.T) {
	t.Run("MaxSourceIdentityLength is never exceeded", func(t *testing.T) {
		// Test with max-length user (20 chars) - this is the worst case
		si := &SourceIdentity{
			User:      "abcdefghij0123456789", // 20 chars (max)
			RequestID: "12345678",             // 8 chars (fixed)
		}

		formatted := si.Format()
		if len(formatted) > MaxSourceIdentityLength {
			t.Errorf("Format() length %d exceeds AWS max %d", len(formatted), MaxSourceIdentityLength)
		}

		// Expected: sentinel:(9) + user(20) + :(1) + request-id(8) = 38
		if len(formatted) != 38 {
			t.Errorf("Max-length format is %d chars, expected 38", len(formatted))
		}
	})

	t.Run("formatted length calculation for all user lengths", func(t *testing.T) {
		// Test each valid user length (1 to 20)
		for userLen := 1; userLen <= MaxUserLength; userLen++ {
			user := strings.Repeat("a", userLen)
			si := &SourceIdentity{
				User:      user,
				RequestID: "12345678",
			}

			formatted := si.Format()
			expectedLen := len("sentinel:") + userLen + 1 + RequestIDLength // +1 for second separator

			if len(formatted) != expectedLen {
				t.Errorf("User length %d: format length = %d, expected %d", userLen, len(formatted), expectedLen)
			}

			if len(formatted) > MaxSourceIdentityLength {
				t.Errorf("User length %d: format length %d exceeds AWS max %d", userLen, len(formatted), MaxSourceIdentityLength)
			}
		}
	})

	t.Run("unicode sanitization counts multi-byte chars correctly", func(t *testing.T) {
		// Unicode chars should be stripped by SanitizeUser, not counted as multiple chars
		// Input with unicode that sanitizes to exactly 20 chars
		input := "abcdefghij0123456789" + "éàü" // 20 alphanumeric + unicode
		sanitized, err := SanitizeUser(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Unicode should be stripped, leaving exactly 20 chars
		if len(sanitized) != 20 {
			t.Errorf("sanitized length = %d, want 20", len(sanitized))
		}

		// Result should only contain alphanumeric
		if sanitized != "abcdefghij0123456789" {
			t.Errorf("sanitized = %q, want alphanumeric only", sanitized)
		}
	})
}

// TestParse_SecurityInjection tests Parse against injection and malformed inputs.
func TestParse_SecurityInjection(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "separator injection - user containing colon",
			input:   "sentinel:alice:bob:a1b2c3d4",
			wantErr: "invalid SourceIdentity format",
		},
		{
			name:    "separator injection - empty middle part",
			input:   "sentinel::alice:a1b2c3d4",
			wantErr: "invalid SourceIdentity format",
		},
		{
			name:    "null byte in input",
			input:   "sentinel:alice\x00:a1b2c3d4",
			wantErr: "alphanumeric",
		},
		{
			name:    "control character - tab in user",
			input:   "sentinel:alice\tbob:a1b2c3d4",
			wantErr: "alphanumeric", // Tab splits parsing, user validation fails
		},
		{
			name:    "control character - newline in user",
			input:   "sentinel:alice\nbob:a1b2c3d4",
			wantErr: "alphanumeric", // Newline in user fails validation
		},
		{
			name:    "control character - carriage return in user",
			input:   "sentinel:alice\rbob:a1b2c3d4",
			wantErr: "alphanumeric", // CR in user fails validation
		},
		{
			name:    "only separators",
			input:   ":::",
			wantErr: "start with 'sentinel:'",
		},
		{
			name:    "just prefix with extra colons",
			input:   "sentinel::::",
			wantErr: "invalid SourceIdentity format",
		},
		{
			name:    "unicode in user field",
			input:   "sentinel:alicé:a1b2c3d4",
			wantErr: "alphanumeric",
		},
		{
			name:    "special chars in user field",
			input:   "sentinel:alice@bob:a1b2c3d4",
			wantErr: "alphanumeric",
		},
		{
			name:    "request-id injection attempt with colons",
			input:   "sentinel:alice:a1b2:c3d4",
			wantErr: "invalid SourceIdentity format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.input)
			if err == nil {
				t.Errorf("expected error containing %q, got nil", tc.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestSanitizeUser_SecurityEdgeCases tests SanitizeUser with security-focused inputs.
func TestSanitizeUser_SecurityEdgeCases(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "unicode beyond BMP - emoji",
			input:   "alice😀bob",
			want:    "alicebob",
			wantErr: false,
		},
		{
			name:    "unicode beyond BMP - musical symbol",
			input:   "alice𝄞bob",
			want:    "alicebob",
			wantErr: false,
		},
		{
			name:    "mixed direction text RTL+LTR",
			input:   "alice\u200Fbob\u200E", // RTL and LTR marks
			want:    "alicebob",
			wantErr: false,
		},
		{
			name:    "arabic with latin",
			input:   "aliceمرحباbob",
			want:    "alicebob",
			wantErr: false,
		},
		{
			name:    "very long username truncation",
			input:   strings.Repeat("a", 1000),
			want:    strings.Repeat("a", MaxUserLength),
			wantErr: false,
		},
		{
			name:    "extremely long username",
			input:   strings.Repeat("x", 100000),
			want:    strings.Repeat("x", MaxUserLength),
			wantErr: false,
		},
		{
			name:    "repeated special characters only",
			input:   strings.Repeat("!@#$%", 100),
			want:    "",
			wantErr: true,
		},
		{
			name:    "null bytes only",
			input:   "\x00\x00\x00",
			want:    "",
			wantErr: true,
		},
		{
			name:    "control characters only",
			input:   "\t\n\r",
			want:    "",
			wantErr: true,
		},
		{
			name:    "zero-width characters",
			input:   "alice\u200Bbob", // zero-width space
			want:    "alicebob",
			wantErr: false,
		},
		{
			name:    "homoglyph attack - cyrillic a",
			input:   "аlice", // first 'a' is cyrillic а (U+0430)
			want:    "lice",
			wantErr: false,
		},
		{
			name:    "combining characters",
			input:   "alice\u0301bob", // combining acute accent
			want:    "alicebob",
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeUser(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
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

			// Verify result doesn't exceed max length
			if len(got) > MaxUserLength {
				t.Errorf("result length %d exceeds MaxUserLength %d", len(got), MaxUserLength)
			}
		})
	}
}

// TestValidate_ErrorOrdering tests that Validate() checks user before request-id.
func TestValidate_ErrorOrdering(t *testing.T) {
	t.Run("empty user error returned before invalid request-id", func(t *testing.T) {
		si := &SourceIdentity{
			User:      "",       // Invalid - empty
			RequestID: "badid!", // Invalid - non-hex
		}

		err := si.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// User error should be reported first
		if !errors.Is(err, ErrEmptyUser) {
			t.Errorf("expected ErrEmptyUser first, got: %v", err)
		}
	})

	t.Run("user too long error returned before invalid request-id", func(t *testing.T) {
		si := &SourceIdentity{
			User:      strings.Repeat("a", MaxUserLength+1), // Invalid - too long
			RequestID: "badid!",                             // Invalid - non-hex
		}

		err := si.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// User error should be reported first
		if !errors.Is(err, ErrUserTooLong) {
			t.Errorf("expected ErrUserTooLong first, got: %v", err)
		}
	})

	t.Run("invalid user chars error returned before invalid request-id", func(t *testing.T) {
		si := &SourceIdentity{
			User:      "alice_bob", // Invalid - underscore
			RequestID: "badid!",    // Invalid - non-hex
		}

		err := si.Validate()
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// User error should be reported first
		if !errors.Is(err, ErrInvalidUserChars) {
			t.Errorf("expected ErrInvalidUserChars first, got: %v", err)
		}
	})
}

// TestNew_ReturnsNilOnFirstFailure verifies New() returns nil on first validation failure.
func TestNew_ReturnsNilOnFirstFailure(t *testing.T) {
	testCases := []struct {
		name      string
		user      string
		requestID string
		wantErr   error
	}{
		{
			name:      "empty user",
			user:      "",
			requestID: "a1b2c3d4",
			wantErr:   ErrEmptyUser,
		},
		{
			name:      "user too long",
			user:      strings.Repeat("a", MaxUserLength+1),
			requestID: "a1b2c3d4",
			wantErr:   ErrUserTooLong,
		},
		{
			name:      "invalid user chars",
			user:      "alice_bob",
			requestID: "a1b2c3d4",
			wantErr:   ErrInvalidUserChars,
		},
		{
			name:      "invalid request-id",
			user:      "alice",
			requestID: "badid",
			wantErr:   ErrInvalidRequestID,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			si, err := New(tc.user, tc.requestID)

			// New() should return nil on error
			if si != nil {
				t.Error("expected nil SourceIdentity on error, got non-nil")
			}

			// Error should match expected
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}
