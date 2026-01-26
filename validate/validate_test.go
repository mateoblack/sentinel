package validate

import (
	"strings"
	"testing"
)

// ============================================================================
// ValidateProfileName Tests
// ============================================================================

func TestValidateProfileName_Valid(t *testing.T) {
	tests := []struct {
		name    string
		profile string
	}{
		{
			name:    "simple name",
			profile: "production",
		},
		{
			name:    "with hyphens",
			profile: "prod-role",
		},
		{
			name:    "with underscores",
			profile: "prod_role",
		},
		{
			name:    "with path",
			profile: "/sentinel/policies/production",
		},
		{
			name:    "role ARN",
			profile: "arn:aws:iam::123456789012:role/prod-role",
		},
		{
			name:    "nested path",
			profile: "/sentinel/policies/team1/production",
		},
		{
			name:    "single character",
			profile: "a",
		},
		{
			name:    "alphanumeric",
			profile: "prod123",
		},
		{
			name:    "uppercase",
			profile: "PRODUCTION",
		},
		{
			name:    "mixed case",
			profile: "ProdRole",
		},
		{
			name:    "with colons",
			profile: "arn:aws:iam::123456789012:role/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProfileName(tt.profile)
			if err != nil {
				t.Errorf("ValidateProfileName(%q) = %v, want nil", tt.profile, err)
			}
		})
	}
}

func TestValidateProfileName_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		profile     string
		wantErr     error
		description string
	}{
		{
			name:        "empty",
			profile:     "",
			wantErr:     ErrProfileNameEmpty,
			description: "empty string should be rejected",
		},
		{
			name:        "too long",
			profile:     strings.Repeat("a", 257),
			wantErr:     ErrProfileNameTooLong,
			description: "exceeds 256 character limit",
		},
		{
			name:        "path traversal double dot",
			profile:     "../../../etc/passwd",
			wantErr:     ErrProfileNamePathTraversal,
			description: "path traversal attack",
		},
		{
			name:        "path traversal in middle",
			profile:     "/sentinel/../secrets",
			wantErr:     ErrProfileNamePathTraversal,
			description: "path traversal in middle of path",
		},
		{
			name:        "double slash",
			profile:     "/sentinel//policies",
			wantErr:     ErrProfileNamePathTraversal,
			description: "double slash path manipulation",
		},
		{
			name:        "null byte",
			profile:     "profile\x00admin",
			wantErr:     ErrProfileNameNullByte,
			description: "null byte injection",
		},
		{
			name:        "tab character",
			profile:     "profile\tadmin",
			wantErr:     ErrProfileNameControlChars,
			description: "tab control character",
		},
		{
			name:        "newline",
			profile:     "profile\nadmin",
			wantErr:     ErrProfileNameControlChars,
			description: "newline control character",
		},
		{
			name:        "carriage return",
			profile:     "profile\radmin",
			wantErr:     ErrProfileNameControlChars,
			description: "carriage return control character",
		},
		{
			name:        "unicode cyrillic",
			profile:     "\u0430lice", // Cyrillic 'a'
			wantErr:     ErrProfileNameNonASCII,
			description: "unicode homoglyph attack",
		},
		{
			name:        "unicode emoji",
			profile:     "prod\U0001F600role",
			wantErr:     ErrProfileNameNonASCII,
			description: "unicode emoji",
		},
		{
			name:        "semicolon",
			profile:     "profile;rm -rf /",
			wantErr:     ErrProfileNameInvalidChars,
			description: "command injection attempt",
		},
		{
			name:        "backtick",
			profile:     "profile`whoami`",
			wantErr:     ErrProfileNameInvalidChars,
			description: "command substitution attempt",
		},
		{
			name:        "dollar sign",
			profile:     "profile$HOME",
			wantErr:     ErrProfileNameInvalidChars,
			description: "environment variable expansion",
		},
		{
			name:        "ampersand",
			profile:     "profile&admin",
			wantErr:     ErrProfileNameInvalidChars,
			description: "shell command chaining",
		},
		{
			name:        "pipe",
			profile:     "profile|admin",
			wantErr:     ErrProfileNameInvalidChars,
			description: "shell pipe",
		},
		{
			name:        "space",
			profile:     "prod role",
			wantErr:     ErrProfileNameInvalidChars,
			description: "space character",
		},
		{
			name:        "current directory",
			profile:     "./profile",
			wantErr:     ErrProfileNamePathTraversal,
			description: "current directory reference",
		},
		{
			name:        "hidden directory",
			profile:     "/.hidden/profile",
			wantErr:     ErrProfileNamePathTraversal,
			description: "hidden directory attempt",
		},
		{
			name:        "backslash",
			profile:     "profile\\admin",
			wantErr:     ErrProfileNamePathTraversal,
			description: "windows path separator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProfileName(tt.profile)
			if err == nil {
				t.Errorf("ValidateProfileName(%q) = nil, want error (%s)", tt.profile, tt.description)
				return
			}
			if err != tt.wantErr {
				t.Errorf("ValidateProfileName(%q) = %v, want %v (%s)", tt.profile, err, tt.wantErr, tt.description)
			}
		})
	}
}

func TestValidateProfileName_MaxLength(t *testing.T) {
	// Test at exact limit (256 chars)
	maxLengthProfile := strings.Repeat("a", MaxProfileNameLength)
	if err := ValidateProfileName(maxLengthProfile); err != nil {
		t.Errorf("ValidateProfileName(256 chars) = %v, want nil", err)
	}

	// Test one over limit (257 chars)
	overLengthProfile := strings.Repeat("a", MaxProfileNameLength+1)
	if err := ValidateProfileName(overLengthProfile); err != ErrProfileNameTooLong {
		t.Errorf("ValidateProfileName(257 chars) = %v, want ErrProfileNameTooLong", err)
	}
}

// ============================================================================
// ValidateSafeString Tests
// ============================================================================

func TestValidateSafeString_Valid(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
	}{
		{
			name:   "normal string",
			input:  "hello world",
			maxLen: 100,
		},
		{
			name:   "with tab",
			input:  "hello\tworld",
			maxLen: 100,
		},
		{
			name:   "with newline",
			input:  "hello\nworld",
			maxLen: 100,
		},
		{
			name:   "with carriage return",
			input:  "hello\rworld",
			maxLen: 100,
		},
		{
			name:   "empty string",
			input:  "",
			maxLen: 100,
		},
		{
			name:   "at max length",
			input:  strings.Repeat("a", 100),
			maxLen: 100,
		},
		{
			name:   "unicode printable",
			input:  "hello \u4e16\u754c", // "hello world" in Chinese
			maxLen: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSafeString(tt.input, tt.maxLen)
			if err != nil {
				t.Errorf("ValidateSafeString(%q, %d) = %v, want nil", tt.input, tt.maxLen, err)
			}
		})
	}
}

func TestValidateSafeString_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maxLen  int
		wantErr error
	}{
		{
			name:    "null byte",
			input:   "hello\x00world",
			maxLen:  100,
			wantErr: ErrStringNullByte,
		},
		{
			name:    "control char bell",
			input:   "hello\x07world",
			maxLen:  100,
			wantErr: ErrStringControlChars,
		},
		{
			name:    "control char escape",
			input:   "hello\x1bworld",
			maxLen:  100,
			wantErr: ErrStringControlChars,
		},
		{
			name:    "too long",
			input:   strings.Repeat("a", 101),
			maxLen:  100,
			wantErr: ErrStringTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSafeString(tt.input, tt.maxLen)
			if err == nil {
				t.Errorf("ValidateSafeString(%q, %d) = nil, want error", tt.input, tt.maxLen)
				return
			}
			// Check if error contains expected error (since some errors are wrapped)
			if !strings.Contains(err.Error(), tt.wantErr.Error()) {
				t.Errorf("ValidateSafeString(%q, %d) = %v, want error containing %v", tt.input, tt.maxLen, err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// SanitizeForLog Tests
// ============================================================================

func TestSanitizeForLog_Basic(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "normal string",
			input:  "hello world",
			maxLen: 100,
			want:   "hello world",
		},
		{
			name:   "truncate",
			input:  "hello world",
			maxLen: 5,
			want:   "hello",
		},
		{
			name:   "empty input",
			input:  "",
			maxLen: 100,
			want:   "",
		},
		{
			name:   "zero maxLen",
			input:  "hello",
			maxLen: 0,
			want:   "",
		},
		{
			name:   "negative maxLen",
			input:  "hello",
			maxLen: -1,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeForLog(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("SanitizeForLog(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestSanitizeForLog_ControlCharacters(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "null byte",
			input:  "hello\x00world",
			maxLen: 100,
			want:   "hello\\u0000world",
		},
		{
			name:   "tab",
			input:  "hello\tworld",
			maxLen: 100,
			want:   "hello\\u0009world",
		},
		{
			name:   "newline",
			input:  "hello\nworld",
			maxLen: 100,
			want:   "hello\\u000aworld",
		},
		{
			name:   "carriage return",
			input:  "hello\rworld",
			maxLen: 100,
			want:   "hello\\u000dworld",
		},
		{
			name:   "escape sequence",
			input:  "hello\x1b[31mred\x1b[0m",
			maxLen: 100,
			want:   "hello\\u001b[31mred\\u001b[0m",
		},
		{
			name:   "bell character",
			input:  "hello\x07world",
			maxLen: 100,
			want:   "hello\\u0007world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeForLog(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("SanitizeForLog(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestSanitizeForLog_JSONSafety(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "double quote",
			input:  `hello"world`,
			maxLen: 100,
			want:   `hello\"world`,
		},
		{
			name:   "backslash",
			input:  `hello\world`,
			maxLen: 100,
			want:   `hello\\world`,
		},
		{
			name:   "both",
			input:  `hello\"world`,
			maxLen: 100,
			want:   `hello\\\"world`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeForLog(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("SanitizeForLog(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestSanitizeForLog_Unicode(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
	}{
		{
			name:   "printable unicode preserved",
			input:  "hello \u4e16\u754c", // "hello world" in Chinese
			maxLen: 100,
		},
		{
			name:   "emoji preserved",
			input:  "hello \U0001F600", // smiling emoji
			maxLen: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeForLog(tt.input, tt.maxLen)
			// Should contain the original printable unicode
			if !strings.Contains(got, "hello") {
				t.Errorf("SanitizeForLog(%q, %d) = %q, should preserve 'hello'", tt.input, tt.maxLen, got)
			}
		})
	}
}

func TestSanitizeForLog_TruncationWithEscapes(t *testing.T) {
	// When string has escapes, we should truncate based on output length, not input length
	input := "a\nb\nc\nd"             // 7 chars input, but escapes expand
	got := SanitizeForLog(input, 10) // maxLen 10

	// The output should be at most 10 chars
	if len(got) > 10 {
		t.Errorf("SanitizeForLog(%q, 10) = %q (len=%d), should be at most 10 chars", input, got, len(got))
	}
}

// ============================================================================
// Constants Tests
// ============================================================================

func TestConstants(t *testing.T) {
	// Verify constants match documented values
	if MaxProfileNameLength != 256 {
		t.Errorf("MaxProfileNameLength = %d, want 256", MaxProfileNameLength)
	}

	if MaxQueryParamLength != 1024 {
		t.Errorf("MaxQueryParamLength = %d, want 1024", MaxQueryParamLength)
	}
}
