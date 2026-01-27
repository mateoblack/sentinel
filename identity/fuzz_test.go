// Package identity provides fuzz tests for SourceIdentity and ARN parsing.
// Fuzz tests help discover parsing edge cases and injection attempts
// in identity string handling.
//
// Run fuzz tests:
//
//	go test -fuzz=FuzzParse -fuzztime=30s ./identity/...
//	go test -fuzz=FuzzSanitizeUser -fuzztime=30s ./identity/...
package identity

import (
	"strings"
	"testing"
)

// FuzzParse tests SourceIdentity parsing with random inputs
// to catch parsing edge cases and injection attempts.
//
// Run: go test -fuzz=FuzzParse -fuzztime=30s ./identity/...
func FuzzParse(f *testing.F) {
	seeds := []string{
		// Valid new format (4-part)
		"sentinel:alice:abcd1234:a1b2c3d4",
		"sentinel:bob:direct:12345678",
		"sentinel:user123:00000000:ffffffff",

		// Valid legacy format (3-part)
		"sentinel:alice:a1b2c3d4",
		"sentinel:bob:12345678",

		// Invalid - wrong prefix
		"",
		"notsentinel:user:request",
		"SENTINEL:user:direct:a1b2c3d4",
		"Sentinel:user:direct:a1b2c3d4",
		"sentinel",
		"sentinel:",
		"sentinel::",
		"sentinel:::",

		// Invalid - wrong number of parts
		"sentinel:user",
		"sentinel:user:approval:request:extra",
		"sentinel:user:approval:request:extra:more",

		// Invalid - bad user
		"sentinel::direct:a1b2c3d4",
		"sentinel:user with spaces:direct:a1b2c3d4",
		"sentinel:user;injection:direct:a1b2c3d4",
		"sentinel:user\ninjection:direct:a1b2c3d4",
		"sentinel:user\x00null:direct:a1b2c3d4",
		"sentinel:" + strings.Repeat("a", 100) + ":direct:a1b2c3d4",

		// Invalid - bad request-id
		"sentinel:user:direct:",
		"sentinel:user:direct:short",
		"sentinel:user:direct:toolongid",
		"sentinel:user:direct:ABCD1234",
		"sentinel:user:direct:notahexid",
		"sentinel:user:direct:1234567",
		"sentinel:user:direct:123456789",

		// Invalid - bad approval-id
		"sentinel:user:SHORT:a1b2c3d4",
		"sentinel:user:NOTLOWER:a1b2c3d4",
		"sentinel:user:toolongapprovalid:a1b2c3d4",
		"sentinel:user:1234567:a1b2c3d4",
		"sentinel:user:123456789:a1b2c3d4",

		// Injection attempts
		"sentinel:user; rm -rf /:direct:a1b2c3d4",
		"sentinel:user$(whoami):direct:a1b2c3d4",
		"sentinel:user`id`:direct:a1b2c3d4",
		"sentinel:user|cat /etc/passwd:direct:a1b2c3d4",
		"sentinel:../../../etc/passwd:direct:a1b2c3d4",

		// Unicode
		"sentinel:用户:direct:a1b2c3d4",
		"sentinel:пользователь:direct:a1b2c3d4",

		// Control characters
		"sentinel:user\x00:direct:a1b2c3d4",
		"sentinel:user\r\n:direct:a1b2c3d4",
		"sentinel:user\t:direct:a1b2c3d4",

		// Colons in components
		"sentinel:user:with:colons:a1b2c3d4",
		"sentinel::::::a1b2c3d4",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Parse should never panic
		si, err := Parse(input)

		if err == nil && si != nil {
			// If parsing succeeds, verify components are safe
			// User should be alphanumeric only
			for _, r := range si.User {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
					t.Errorf("Parse accepted non-alphanumeric user char %q: input=%q", r, input)
				}
			}

			// User should not exceed max length
			if len(si.User) > MaxUserLength {
				t.Errorf("Parse accepted user longer than %d: input=%q", MaxUserLength, input)
			}

			// User should not be empty
			if si.User == "" {
				t.Errorf("Parse accepted empty user: input=%q", input)
			}

			// RequestID should be exactly 8 lowercase hex chars
			if len(si.RequestID) != RequestIDLength {
				t.Errorf("Parse accepted request-id with length %d (expected %d): input=%q", len(si.RequestID), RequestIDLength, input)
			}
			for _, r := range si.RequestID {
				if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
					t.Errorf("Parse accepted non-lowercase-hex request-id char %q: input=%q", r, input)
				}
			}

			// ApprovalID if present should be 8 lowercase hex chars
			if si.ApprovalID != "" {
				if len(si.ApprovalID) != ApprovalIDLength {
					t.Errorf("Parse accepted approval-id with length %d (expected %d): input=%q", len(si.ApprovalID), ApprovalIDLength, input)
				}
				for _, r := range si.ApprovalID {
					if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
						t.Errorf("Parse accepted non-lowercase-hex approval-id char %q: input=%q", r, input)
					}
				}
			}

			// The formatted output should be parseable back
			formatted := si.Format()
			reparsed, err := Parse(formatted)
			if err != nil {
				t.Errorf("Round-trip failed: original=%q formatted=%q error=%v", input, formatted, err)
			} else {
				if reparsed.User != si.User || reparsed.ApprovalID != si.ApprovalID || reparsed.RequestID != si.RequestID {
					t.Errorf("Round-trip mismatch: original=%v reparsed=%v", si, reparsed)
				}
			}
		}
	})
}

// FuzzSanitizeUser tests username sanitization with random inputs.
//
// Run: go test -fuzz=FuzzSanitizeUser -fuzztime=30s ./identity/...
func FuzzSanitizeUser(f *testing.F) {
	seeds := []string{
		"alice",
		"bob123",
		"USER",
		"",
		"user with spaces",
		"user-with-dashes",
		"user_with_underscores",
		"user.with.dots",
		"user@example.com",
		"user; rm -rf /",
		"user$(whoami)",
		"user\x00null",
		"user\ninjection",
		"日本語ユーザー",
		strings.Repeat("a", 100),
		"!!!###$$$",
		"\x00\x01\x02",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Should never panic
		sanitized, err := SanitizeUser(input)

		if err == nil {
			// If sanitization succeeds, verify constraints
			if sanitized == "" {
				t.Errorf("SanitizeUser returned empty for non-empty input: %q", input)
			}

			// Should be at most MaxUserLength
			if len(sanitized) > MaxUserLength {
				t.Errorf("SanitizeUser output exceeds max length: len=%d input=%q", len(sanitized), input)
			}

			// Should be alphanumeric only
			for _, r := range sanitized {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
					t.Errorf("SanitizeUser output contains non-alphanumeric char %q: input=%q output=%q", r, input, sanitized)
				}
			}

			// Should not contain dangerous chars
			dangerous := []string{";", "`", "$", "(", ")", "|", "&", "\n", "\r", "\x00", ".."}
			for _, d := range dangerous {
				if strings.Contains(sanitized, d) {
					t.Errorf("SanitizeUser output contains dangerous char %q: input=%q output=%q", d, input, sanitized)
				}
			}
		} else {
			// Error case: check that it's ErrEmptyUser (the only expected error)
			// The input must have had no alphanumeric characters
			hasAlnum := false
			for _, r := range input {
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
					hasAlnum = true
					break
				}
			}
			if hasAlnum {
				t.Errorf("SanitizeUser returned error for input with alphanumeric chars: input=%q error=%v", input, err)
			}
		}
	})
}

// FuzzNew tests SourceIdentity creation with random inputs.
//
// Run: go test -fuzz=FuzzNew -fuzztime=30s ./identity/...
func FuzzNew(f *testing.F) {
	// Seed with various user/approval/request combinations
	f.Add("alice", "abcd1234", "12345678")
	f.Add("bob", "", "a1b2c3d4")
	f.Add("", "abcd1234", "12345678")
	f.Add("user", "INVALID", "12345678")
	f.Add("user", "abcd1234", "INVALID")
	f.Add(strings.Repeat("a", 100), "abcd1234", "12345678")
	f.Add("user; rm -rf", "abcd1234", "12345678")

	f.Fuzz(func(t *testing.T, user, approvalID, requestID string) {
		// Should never panic
		si, err := New(user, approvalID, requestID)

		if err == nil && si != nil {
			// If creation succeeds, verify it validates
			if validateErr := si.Validate(); validateErr != nil {
				t.Errorf("New returned valid SourceIdentity that fails Validate: user=%q approval=%q request=%q error=%v",
					user, approvalID, requestID, validateErr)
			}

			// Should be formattable and parseable
			formatted := si.Format()
			_, parseErr := Parse(formatted)
			if parseErr != nil {
				t.Errorf("New returned SourceIdentity that fails round-trip: formatted=%q error=%v", formatted, parseErr)
			}
		}
	})
}

// FuzzValidateRequestID tests request-id validation with random inputs.
//
// Run: go test -fuzz=FuzzValidateRequestID -fuzztime=30s ./identity/...
func FuzzValidateRequestID(f *testing.F) {
	seeds := []string{
		"abcd1234",
		"00000000",
		"ffffffff",
		"ABCD1234",
		"",
		"short",
		"toolongid",
		"notahex!",
		"1234567",
		"123456789",
		"abcd\x00123",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Should never panic
		valid := ValidateRequestID(input)

		if valid {
			// If valid, verify constraints
			if len(input) != RequestIDLength {
				t.Errorf("ValidateRequestID accepted length %d (expected %d): %q", len(input), RequestIDLength, input)
			}
			for _, r := range input {
				if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
					t.Errorf("ValidateRequestID accepted non-lowercase-hex char %q in: %q", r, input)
				}
			}
		}
	})
}
