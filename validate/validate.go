// Package validate provides centralized input validation utilities for preventing
// injection attacks across Sentinel's API boundaries.
//
// The package includes validators for profile names, safe strings, and log sanitization
// to prevent command injection, path traversal, and log injection attacks.
package validate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Validation constants for input limits.
const (
	// MaxProfileNameLength is the maximum length for SSM-style profile names.
	// Based on AWS SSM parameter path limits.
	MaxProfileNameLength = 256

	// MaxQueryParamLength is the maximum length for general query parameters.
	MaxQueryParamLength = 1024
)

// Validation errors for input validation failures.
var (
	// ErrProfileNameEmpty indicates the profile name is empty.
	ErrProfileNameEmpty = errors.New("profile name cannot be empty")

	// ErrProfileNameTooLong indicates the profile name exceeds MaxProfileNameLength.
	ErrProfileNameTooLong = errors.New("profile name exceeds maximum length of 256 characters")

	// ErrProfileNameInvalidChars indicates the profile name contains invalid characters.
	ErrProfileNameInvalidChars = errors.New("profile name contains invalid characters; allowed: alphanumeric, hyphen, underscore, forward slash")

	// ErrProfileNamePathTraversal indicates the profile name contains path traversal sequences.
	ErrProfileNamePathTraversal = errors.New("profile name contains path traversal sequence")

	// ErrProfileNameControlChars indicates the profile name contains control characters.
	ErrProfileNameControlChars = errors.New("profile name contains control characters")

	// ErrProfileNameNullByte indicates the profile name contains null bytes.
	ErrProfileNameNullByte = errors.New("profile name contains null byte")

	// ErrProfileNameNonASCII indicates the profile name contains non-ASCII characters.
	ErrProfileNameNonASCII = errors.New("profile name contains non-ASCII characters")

	// ErrStringTooLong indicates a string exceeds the maximum length.
	ErrStringTooLong = errors.New("string exceeds maximum length")

	// ErrStringNullByte indicates a string contains null bytes.
	ErrStringNullByte = errors.New("string contains null byte")

	// ErrStringControlChars indicates a string contains control characters.
	ErrStringControlChars = errors.New("string contains control characters")
)

// profileNameRegex matches valid profile name characters: alphanumeric, hyphen, underscore, forward slash.
// This allows SSM-style paths like "/sentinel/policies/production" or simple names like "prod-role".
var profileNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_/:-]+$`)

// pathTraversalPatterns are dangerous path sequences to reject.
var pathTraversalPatterns = []string{
	"..",   // Parent directory traversal
	"//",   // Double slash (potential path manipulation)
	"./",   // Current directory (unnecessary, could be exploited)
	"/.",   // Hidden directory attempt
	"\\",   // Windows path separator (should not appear in SSM paths)
	"\x00", // Null byte
}

// ValidateProfileName validates an SSM-style profile name.
// It checks:
//   - Max 256 characters (SSM parameter path limit)
//   - Only allows: alphanumeric, hyphen, underscore, forward slash, colon
//   - No path traversal sequences (../ or //)
//   - No null bytes or control characters
//   - No non-ASCII characters (security: prevent homoglyph attacks)
//
// Returns nil if valid, or a descriptive error.
func ValidateProfileName(name string) error {
	// Check for empty
	if name == "" {
		return ErrProfileNameEmpty
	}

	// Check length
	if len(name) > MaxProfileNameLength {
		return ErrProfileNameTooLong
	}

	// Check for null bytes (early, before other checks)
	if strings.ContainsRune(name, '\x00') {
		return ErrProfileNameNullByte
	}

	// Check for control characters and non-ASCII
	for _, r := range name {
		// Reject non-ASCII characters (homoglyph attack prevention)
		if r > 127 {
			return ErrProfileNameNonASCII
		}

		// Reject control characters (ASCII 0-31 and 127)
		if r < 32 || r == 127 {
			return ErrProfileNameControlChars
		}
	}

	// Check for path traversal patterns
	for _, pattern := range pathTraversalPatterns {
		if strings.Contains(name, pattern) {
			return ErrProfileNamePathTraversal
		}
	}

	// Check for valid characters
	if !profileNameRegex.MatchString(name) {
		return ErrProfileNameInvalidChars
	}

	return nil
}

// ValidateSafeString validates a general string for safe use.
// It checks:
//   - No null bytes (\x00)
//   - No control characters (ASCII 0-31 except \t\n\r)
//   - Within maxLen limit
//
// Returns nil if valid, or a descriptive error.
func ValidateSafeString(s string, maxLen int) error {
	// Check length
	if len(s) > maxLen {
		return fmt.Errorf("%w: %d > %d", ErrStringTooLong, len(s), maxLen)
	}

	// Check for null bytes
	if strings.ContainsRune(s, '\x00') {
		return ErrStringNullByte
	}

	// Check for control characters (except tab, newline, carriage return)
	for _, r := range s {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return ErrStringControlChars
		}
	}

	return nil
}

// SanitizeForLog sanitizes a string for safe logging.
// It replaces control characters with unicode escapes, truncates to maxLen,
// and ensures the result is safe for JSON/structured logging.
//
// Use this when logging potentially malicious input to prevent:
//   - Log injection (newline injection for log splitting)
//   - JSON injection in structured logs
//   - ANSI escape sequence injection
func SanitizeForLog(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}

	var result strings.Builder
	result.Grow(min(len(s), maxLen))

	runeCount := 0
	for _, r := range s {
		if runeCount >= maxLen {
			break
		}

		// Replace control characters with unicode escapes
		if r < 32 || r == 127 {
			// Format as \uXXXX escape
			escape := fmt.Sprintf("\\u%04x", r)
			if runeCount+len(escape) > maxLen {
				break
			}
			result.WriteString(escape)
			runeCount += len(escape)
		} else if r == '\\' {
			// Escape backslashes to prevent escape sequence injection
			if runeCount+2 > maxLen {
				break
			}
			result.WriteString("\\\\")
			runeCount += 2
		} else if r == '"' {
			// Escape quotes for JSON safety
			if runeCount+2 > maxLen {
				break
			}
			result.WriteString("\\\"")
			runeCount += 2
		} else if r > 127 && !unicode.IsPrint(r) {
			// Replace non-printable unicode with escapes
			escape := fmt.Sprintf("\\u%04x", r)
			if runeCount+len(escape) > maxLen {
				break
			}
			result.WriteString(escape)
			runeCount += len(escape)
		} else {
			result.WriteRune(r)
			runeCount++
		}
	}

	// Indicate truncation if string was longer
	sanitized := result.String()
	if len(s) > len(sanitized) && maxLen > 3 && len(sanitized) > 3 {
		// Check if we actually truncated (not just escaped to longer)
		originalRuneCount := 0
		for range s {
			originalRuneCount++
		}
		if originalRuneCount > maxLen {
			// Already truncated, no need to add ellipsis
		}
	}

	return sanitized
}

// min returns the smaller of a or b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
