// Package validate provides fuzz tests for input validation functions.
// Fuzz tests help discover edge cases and security vulnerabilities
// that manual testing may miss.
//
// Run fuzz tests:
//
//	go test -fuzz=FuzzValidateProfileName -fuzztime=30s ./validate/...
//	go test -fuzz=FuzzSanitizeForLog -fuzztime=30s ./validate/...
package validate

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzValidateProfileName tests profile name validation with random inputs
// to catch injection vulnerabilities and edge cases.
//
// Run: go test -fuzz=FuzzValidateProfileName -fuzztime=30s ./validate/...
func FuzzValidateProfileName(f *testing.F) {
	// Seed corpus with known edge cases
	seeds := []string{
		"",                        // empty
		"valid-profile",           // normal
		"profile_with_underscore", // underscore
		"Profile123",              // numbers
		"a",                       // single char
		strings.Repeat("a", 100),  // long
		strings.Repeat("a", 256),  // at max length
		strings.Repeat("a", 257),  // exceeds max
		strings.Repeat("a", 1000), // very long
		"profile; rm -rf /",       // command injection attempt
		"profile\ncommand",        // newline injection
		"profile`id`",             // backtick injection
		"profile$(whoami)",        // subshell injection
		"profile\x00null",         // null byte
		"../../../etc/passwd",     // path traversal
		"profile\t\ttabs",         // tabs
		"profile\r\nCRLF",         // CRLF injection
		"profile with spaces",     // spaces
		"prod/role/admin",         // forward slashes (valid SSM path)
		"/sentinel/policies/prod", // SSM-style path
		"profile//double",         // double slash (traversal)
		"profile/../sibling",      // parent directory traversal
		"日本語プロファイル",               // unicode (should be rejected)
		"\xff\xfe",                // invalid UTF-8
		"profile\x1b[31mred",      // ANSI escape
		"profile|cat /etc/passwd", // pipe injection
		"profile&whoami",          // background command
		"profile\x00",             // trailing null
		"\x00profile",             // leading null
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Call the validation function - should never panic
		err := ValidateProfileName(input)

		// If validation passes, verify it's actually safe
		if err == nil {
			// Must be valid UTF-8
			if !utf8.ValidString(input) {
				t.Errorf("ValidateProfileName accepted invalid UTF-8: %q", input)
			}

			// Must not contain shell metacharacters
			shellMetachars := []string{";", "`", "$", "(", ")", "|", "&", "\n", "\r", "\x00"}
			for _, meta := range shellMetachars {
				if strings.Contains(input, meta) {
					t.Errorf("ValidateProfileName accepted shell metachar %q in: %q", meta, input)
				}
			}

			// Must not contain path traversal
			if strings.Contains(input, "..") {
				t.Errorf("ValidateProfileName accepted path traversal in: %q", input)
			}

			// Must not contain double slashes
			if strings.Contains(input, "//") {
				t.Errorf("ValidateProfileName accepted double slash in: %q", input)
			}

			// Must not be empty after validation
			if len(input) == 0 {
				t.Error("ValidateProfileName accepted empty string")
			}

			// Must not exceed max length
			if len(input) > MaxProfileNameLength {
				t.Errorf("ValidateProfileName accepted string longer than %d: len=%d", MaxProfileNameLength, len(input))
			}

			// Must be ASCII only (non-ASCII rejected to prevent homoglyph attacks)
			for _, r := range input {
				if r > 127 {
					t.Errorf("ValidateProfileName accepted non-ASCII char %U in: %q", r, input)
				}
			}

			// Must not contain control characters
			for _, r := range input {
				if r < 32 || r == 127 {
					t.Errorf("ValidateProfileName accepted control char %U in: %q", r, input)
				}
			}
		}
	})
}

// FuzzValidateSafeString tests general string validation with random inputs.
//
// Run: go test -fuzz=FuzzValidateSafeString -fuzztime=30s ./validate/...
func FuzzValidateSafeString(f *testing.F) {
	// Seed corpus with edge cases
	seeds := []string{
		"",                              // empty
		"normal string",                 // normal
		"string\x00with\x00nulls",       // null bytes
		"string\nwith\nnewlines",        // newlines (allowed)
		"string\twith\ttabs",            // tabs (allowed)
		"string\rwith\rcarriage",        // carriage return (allowed)
		"string\x01\x02control",         // control chars (not allowed)
		strings.Repeat("a", 1000),       // long string
		strings.Repeat("a", 2000),       // very long string
		"日本語文字列",                        // unicode
		"\xff\xfe\xfd",                  // invalid UTF-8 bytes
		"string\x1b[31mwith\x1b[0mANSI", // ANSI escape
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Test with various max lengths
		maxLens := []int{0, 10, 100, 1024, 10000}

		for _, maxLen := range maxLens {
			// Should never panic
			err := ValidateSafeString(input, maxLen)

			if err == nil {
				// If valid, verify constraints
				if len(input) > maxLen {
					t.Errorf("ValidateSafeString(maxLen=%d) accepted string of len %d", maxLen, len(input))
				}

				// Must not contain null bytes
				if strings.ContainsRune(input, '\x00') {
					t.Errorf("ValidateSafeString accepted null byte in: %q", input)
				}

				// Must not contain control chars (except tab, newline, carriage return)
				for _, r := range input {
					if r < 32 && r != '\t' && r != '\n' && r != '\r' {
						t.Errorf("ValidateSafeString accepted control char %U in: %q", r, input)
					}
				}
			}
		}
	})
}

// FuzzSanitizeForLog tests log sanitization with random inputs.
// The sanitize function should always return safe output, never panic.
//
// Run: go test -fuzz=FuzzSanitizeForLog -fuzztime=30s ./validate/...
func FuzzSanitizeForLog(f *testing.F) {
	// Seed corpus
	seeds := []string{
		"",                             // empty
		"normal log entry",             // normal
		"entry\nwith\nnewlines",        // newline injection
		"entry\x00with\x00nulls",       // null bytes
		"entry\twith\ttabs",            // tabs
		"entry\r\nwith\r\nCRLF",        // CRLF
		"entry\x1b[31mwith\x1b[0mANSI", // ANSI escape
		`entry"with"quotes`,            // quotes
		`entry\with\backslashes`,       // backslashes
		"entry\x01\x02\x03control",     // control chars
		"日本語ログ",                        // unicode
		strings.Repeat("a", 10000),     // very long
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Test with various max lengths
		maxLens := []int{0, 10, 50, 100, 500}

		for _, maxLen := range maxLens {
			// Should never panic
			sanitized := SanitizeForLog(input, maxLen)

			// Output should never contain raw control characters
			// (they should be escaped as \uXXXX)
			for i, r := range sanitized {
				if r < 32 || r == 127 {
					// Check if this might be part of an escape sequence
					// The escape format is \uXXXX, so 'u' and hex digits are expected
					// after a backslash in the output
					// Raw control chars should not appear
					t.Errorf("SanitizeForLog output contains raw control char %U at position %d: input=%q output=%q", r, i, input, sanitized)
				}
			}

			// When maxLen is 0, output should be empty
			if maxLen == 0 && sanitized != "" {
				t.Errorf("SanitizeForLog(maxLen=0) returned non-empty: %q", sanitized)
			}
		}
	})
}
