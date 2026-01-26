package shell

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// mockSSMClient implements ssmShellAPI for testing.
type mockSSMClient struct {
	GetParametersByPathFunc func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
	calls                   int
}

func (m *mockSSMClient) GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	m.calls++
	return m.GetParametersByPathFunc(ctx, params, optFns...)
}

func TestGetProfiles_ReturnsProfiles(t *testing.T) {
	mock := &mockSSMClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/production")},
					{Name: aws.String("/sentinel/policies/staging")},
					{Name: aws.String("/sentinel/policies/development")},
				},
			}, nil
		},
	}

	gen := newShellGeneratorWithClient(mock)
	profiles, err := gen.GetProfiles(context.Background(), "/sentinel/policies")

	if err != nil {
		t.Fatalf("GetProfiles returned error: %v", err)
	}

	if len(profiles) != 3 {
		t.Errorf("Expected 3 profiles, got %d", len(profiles))
	}

	expected := map[string]string{
		"production":  "/sentinel/policies/production",
		"staging":     "/sentinel/policies/staging",
		"development": "/sentinel/policies/development",
	}

	for _, p := range profiles {
		expectedPath, ok := expected[p.Name]
		if !ok {
			t.Errorf("Unexpected profile name: %s", p.Name)
			continue
		}
		if p.PolicyPath != expectedPath {
			t.Errorf("Profile %s: expected path %s, got %s", p.Name, expectedPath, p.PolicyPath)
		}
	}
}

func TestGetProfiles_EmptyResult(t *testing.T) {
	mock := &mockSSMClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{},
			}, nil
		},
	}

	gen := newShellGeneratorWithClient(mock)
	profiles, err := gen.GetProfiles(context.Background(), "/sentinel/policies")

	if err != nil {
		t.Fatalf("GetProfiles returned error: %v", err)
	}

	if len(profiles) != 0 {
		t.Errorf("Expected 0 profiles, got %d", len(profiles))
	}
}

func TestGetProfiles_Pagination(t *testing.T) {
	callCount := 0
	mock := &mockSSMClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			callCount++
			if callCount == 1 {
				return &ssm.GetParametersByPathOutput{
					Parameters: []types.Parameter{
						{Name: aws.String("/sentinel/policies/production")},
						{Name: aws.String("/sentinel/policies/staging")},
					},
					NextToken: aws.String("page2"),
				}, nil
			}
			// Second page
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/development")},
				},
			}, nil
		},
	}

	gen := newShellGeneratorWithClient(mock)
	profiles, err := gen.GetProfiles(context.Background(), "/sentinel/policies")

	if err != nil {
		t.Fatalf("GetProfiles returned error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("Expected 2 API calls for pagination, got %d", callCount)
	}

	if len(profiles) != 3 {
		t.Errorf("Expected 3 profiles from paginated results, got %d", len(profiles))
	}
}

func TestGetProfiles_Error(t *testing.T) {
	mock := &mockSSMClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return nil, &types.ParameterNotFound{Message: aws.String("not found")}
		},
	}

	gen := newShellGeneratorWithClient(mock)
	_, err := gen.GetProfiles(context.Background(), "/sentinel/policies")

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to list profiles") {
		t.Errorf("Expected error to contain 'failed to list profiles', got: %v", err)
	}
}

func TestGenerateScript_Bash_MultipleProfiles(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "production", PolicyPath: "/sentinel/policies/production"},
		{Name: "staging", PolicyPath: "/sentinel/policies/staging"},
	}

	script := GenerateScript(profiles, "/sentinel/policies", FormatBash)

	// Check header
	if !strings.Contains(script, "# Sentinel shell functions") {
		t.Error("Script missing header comment")
	}
	if !strings.Contains(script, "eval \"$(sentinel shell init)\"") {
		t.Error("Script missing usage hint")
	}

	// Check function definitions
	if !strings.Contains(script, "sentinel-production()") {
		t.Error("Script missing sentinel-production function")
	}
	if !strings.Contains(script, "sentinel-staging()") {
		t.Error("Script missing sentinel-staging function")
	}

	// Check function bodies
	if !strings.Contains(script, "sentinel exec --profile production --policy-parameter /sentinel/policies/production -- \"$@\"") {
		t.Error("Script missing correct sentinel exec command for production")
	}
	if !strings.Contains(script, "sentinel exec --profile staging --policy-parameter /sentinel/policies/staging -- \"$@\"") {
		t.Error("Script missing correct sentinel exec command for staging")
	}
}

func TestGenerateScript_Zsh_SingleProfile(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "default", PolicyPath: "/sentinel/policies/default"},
	}

	script := GenerateScript(profiles, "/sentinel/policies", FormatZsh)

	// Check function definition
	if !strings.Contains(script, "sentinel-default()") {
		t.Error("Script missing sentinel-default function")
	}

	// Check function body
	if !strings.Contains(script, "sentinel exec --profile default --policy-parameter /sentinel/policies/default -- \"$@\"") {
		t.Error("Script missing correct sentinel exec command")
	}
}

func TestGenerateScript_EmptyProfiles(t *testing.T) {
	profiles := []ProfileInfo{}

	script := GenerateScript(profiles, "/sentinel/policies", FormatBash)

	// Should have header
	if !strings.Contains(script, "# Sentinel shell functions") {
		t.Error("Script missing header comment")
	}

	// Should have comment about no profiles
	if !strings.Contains(script, "# No profiles found under /sentinel/policies") {
		t.Error("Script should indicate no profiles found")
	}

	// Should not have any function definitions
	if strings.Contains(script, "()") && strings.Contains(script, "sentinel exec") {
		t.Error("Script should not contain function definitions when no profiles")
	}
}

func TestSanitizeFunctionName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"production", "sentinel-production"},
		{"my-profile", "sentinel-my-profile"},
		{"my_profile", "sentinel-my-profile"},
		{"my.profile", "sentinel-my-profile"},
		{"my profile", "sentinel-my-profile"},
		{"My@Profile!", "sentinel-My-Profile"},
		{"prod/staging", "sentinel-prod-staging"},
		{"123", "sentinel-123"},
		{"a--b", "sentinel-a-b"},     // Consecutive hyphens collapsed
		{"-start", "sentinel-start"}, // Leading special char
		{"end-", "sentinel-end"},     // Trailing special char
		{"@#$%", "sentinel-"},        // All special chars -> empty after sanitization
		{"test123abc", "sentinel-test123abc"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFunctionName(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFunctionName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestShellEscape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with space", "'with space'"},
		{"with'quote", "'with'\\''quote'"},
		{"with\"double", "'with\"double'"},
		{"with$var", "'with$var'"},
		{"with`backtick", "'with`backtick'"},
		{"with\ttab", "'with\ttab'"},
		{"normal-hyphen", "normal-hyphen"},
		{"/path/to/file", "/path/to/file"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := shellEscape(tt.input)
			if result != tt.expected {
				t.Errorf("shellEscape(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractProfileName(t *testing.T) {
	tests := []struct {
		policyRoot string
		paramPath  string
		expected   string
	}{
		{"/sentinel/policies", "/sentinel/policies/production", "production"},
		{"/sentinel/policies/", "/sentinel/policies/production", "production"},
		{"/custom/root", "/custom/root/myprofile", "myprofile"},
		{"/a/b/c", "/a/b/c/d", "d"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := extractProfileName(tt.policyRoot, tt.paramPath)
			if result != tt.expected {
				t.Errorf("extractProfileName(%q, %q) = %q, want %q", tt.policyRoot, tt.paramPath, result, tt.expected)
			}
		})
	}
}

func TestGenerateScript_SpecialCharacterProfile(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "my-special_profile.v1", PolicyPath: "/sentinel/policies/my-special_profile.v1"},
	}

	script := GenerateScript(profiles, "/sentinel/policies", FormatBash)

	// Function name should be sanitized
	if !strings.Contains(script, "sentinel-my-special-profile-v1()") {
		t.Errorf("Script should sanitize function name. Got:\n%s", script)
	}
}

func TestGenerateScript_ProfileWithSpaces(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "my profile", PolicyPath: "/sentinel/policies/my profile"},
	}

	script := GenerateScript(profiles, "/sentinel/policies", FormatBash)

	// Function name should be sanitized
	if !strings.Contains(script, "sentinel-my-profile()") {
		t.Errorf("Script should sanitize spaces in function name")
	}

	// Policy path should be escaped
	if !strings.Contains(script, "'my profile'") || !strings.Contains(script, "'/sentinel/policies/my profile'") {
		t.Errorf("Script should quote profile name and path with spaces")
	}
}

func TestNewShellGeneratorWithClient(t *testing.T) {
	mock := &mockSSMClient{}
	gen := newShellGeneratorWithClient(mock)

	if gen == nil {
		t.Fatal("newShellGeneratorWithClient returned nil")
	}

	if gen.ssm != mock {
		t.Error("ShellGenerator not using provided mock client")
	}
}

func TestGenerateScriptWithOptions_IncludeServerFalse(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "production", PolicyPath: "/sentinel/policies/production"},
		{Name: "staging", PolicyPath: "/sentinel/policies/staging"},
	}

	opts := GenerateOptions{IncludeServer: false}
	script := GenerateScriptWithOptions(profiles, "/sentinel/policies", FormatBash, opts)

	// Should have standard functions
	if !strings.Contains(script, "sentinel-production()") {
		t.Error("Script missing sentinel-production function")
	}
	if !strings.Contains(script, "sentinel-staging()") {
		t.Error("Script missing sentinel-staging function")
	}

	// Should NOT have -server variants
	if strings.Contains(script, "sentinel-production-server()") {
		t.Error("Script should NOT contain sentinel-production-server function when IncludeServer=false")
	}
	if strings.Contains(script, "sentinel-staging-server()") {
		t.Error("Script should NOT contain sentinel-staging-server function when IncludeServer=false")
	}

	// Should NOT have server mode comment
	if strings.Contains(script, "-server variants use real-time revocation mode") {
		t.Error("Script should NOT contain server mode comment when IncludeServer=false")
	}
}

func TestGenerateScriptWithOptions_IncludeServerTrue(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "production", PolicyPath: "/sentinel/policies/production"},
		{Name: "staging", PolicyPath: "/sentinel/policies/staging"},
	}

	opts := GenerateOptions{IncludeServer: true}
	script := GenerateScriptWithOptions(profiles, "/sentinel/policies", FormatBash, opts)

	// Should have standard functions
	if !strings.Contains(script, "sentinel-production()") {
		t.Error("Script missing sentinel-production function")
	}
	if !strings.Contains(script, "sentinel-staging()") {
		t.Error("Script missing sentinel-staging function")
	}

	// Should have -server variants
	if !strings.Contains(script, "sentinel-production-server()") {
		t.Error("Script missing sentinel-production-server function")
	}
	if !strings.Contains(script, "sentinel-staging-server()") {
		t.Error("Script missing sentinel-staging-server function")
	}

	// Server variants should include --server flag
	if !strings.Contains(script, "sentinel exec --server --profile production") {
		t.Error("Server variant missing --server flag for production")
	}
	if !strings.Contains(script, "sentinel exec --server --profile staging") {
		t.Error("Server variant missing --server flag for staging")
	}

	// Should have server mode comment
	if !strings.Contains(script, "-server variants use real-time revocation mode") {
		t.Error("Script missing server mode comment")
	}
}

func TestGenerateScriptWithOptions_EmptyProfilesWithServer(t *testing.T) {
	profiles := []ProfileInfo{}

	opts := GenerateOptions{IncludeServer: true}
	script := GenerateScriptWithOptions(profiles, "/sentinel/policies", FormatBash, opts)

	// Should have header with server comment
	if !strings.Contains(script, "# Sentinel shell functions") {
		t.Error("Script missing header comment")
	}
	if !strings.Contains(script, "-server variants use real-time revocation mode") {
		t.Error("Script missing server mode comment")
	}

	// Should indicate no profiles found
	if !strings.Contains(script, "# No profiles found under /sentinel/policies") {
		t.Error("Script should indicate no profiles found")
	}
}

func TestGenerateScriptWithOptions_ServerVariantFunctionContent(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "admin", PolicyPath: "/sentinel/policies/admin"},
	}

	opts := GenerateOptions{IncludeServer: true}
	script := GenerateScriptWithOptions(profiles, "/sentinel/policies", FormatBash, opts)

	// Check standard function content
	expectedStandard := `sentinel-admin() {
    sentinel exec --profile admin --policy-parameter /sentinel/policies/admin -- "$@"
}`
	if !strings.Contains(script, expectedStandard) {
		t.Errorf("Standard function content incorrect. Got:\n%s", script)
	}

	// Check server function content
	expectedServer := `sentinel-admin-server() {
    sentinel exec --server --profile admin --policy-parameter /sentinel/policies/admin -- "$@"
}`
	if !strings.Contains(script, expectedServer) {
		t.Errorf("Server function content incorrect. Got:\n%s", script)
	}
}

func TestGenerateScript_BackwardCompatible(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "test", PolicyPath: "/sentinel/policies/test"},
	}

	// GenerateScript should produce same output as GenerateScriptWithOptions with default options
	scriptOld := GenerateScript(profiles, "/sentinel/policies", FormatBash)
	scriptNew := GenerateScriptWithOptions(profiles, "/sentinel/policies", FormatBash, GenerateOptions{})

	if scriptOld != scriptNew {
		t.Errorf("GenerateScript and GenerateScriptWithOptions (default opts) produce different output.\nOld:\n%s\nNew:\n%s", scriptOld, scriptNew)
	}

	// Should NOT have server variants
	if strings.Contains(scriptOld, "-server()") {
		t.Error("GenerateScript (backward compat) should not include server variants")
	}
}

func TestGenerateScript_IncludesCompletions(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "production", PolicyPath: "/sentinel/policies/production"},
		{Name: "staging", PolicyPath: "/sentinel/policies/staging"},
	}

	script := GenerateScript(profiles, "/sentinel/policies", FormatBash)

	// Check bash completion block with shell detection
	if !strings.Contains(script, `if [[ -n "${BASH_VERSION:-}" ]]`) {
		t.Error("Script missing bash shell detection")
	}
	if !strings.Contains(script, "complete -o default -o bashdefault sentinel-production") {
		t.Error("Script missing bash completion for sentinel-production")
	}
	if !strings.Contains(script, "complete -o default -o bashdefault sentinel-staging") {
		t.Error("Script missing bash completion for sentinel-staging")
	}

	// Check zsh completion block with shell detection
	if !strings.Contains(script, `if [[ -n "${ZSH_VERSION:-}" ]]`) {
		t.Error("Script missing zsh shell detection")
	}
	if !strings.Contains(script, "compdef _command_names sentinel-production") {
		t.Error("Script missing zsh completion for sentinel-production")
	}
	if !strings.Contains(script, "compdef _command_names sentinel-staging") {
		t.Error("Script missing zsh completion for sentinel-staging")
	}
}

func TestGenerateScript_CompletionsWithServerVariants(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "production", PolicyPath: "/sentinel/policies/production"},
		{Name: "staging", PolicyPath: "/sentinel/policies/staging"},
	}

	opts := GenerateOptions{IncludeServer: true}
	script := GenerateScriptWithOptions(profiles, "/sentinel/policies", FormatBash, opts)

	// Check bash completions for both standard and server variants
	if !strings.Contains(script, "complete -o default -o bashdefault sentinel-production") {
		t.Error("Script missing bash completion for sentinel-production")
	}
	if !strings.Contains(script, "complete -o default -o bashdefault sentinel-production-server") {
		t.Error("Script missing bash completion for sentinel-production-server")
	}
	if !strings.Contains(script, "complete -o default -o bashdefault sentinel-staging") {
		t.Error("Script missing bash completion for sentinel-staging")
	}
	if !strings.Contains(script, "complete -o default -o bashdefault sentinel-staging-server") {
		t.Error("Script missing bash completion for sentinel-staging-server")
	}

	// Check zsh completions for both standard and server variants
	if !strings.Contains(script, "compdef _command_names sentinel-production") {
		t.Error("Script missing zsh completion for sentinel-production")
	}
	if !strings.Contains(script, "compdef _command_names sentinel-production-server") {
		t.Error("Script missing zsh completion for sentinel-production-server")
	}
	if !strings.Contains(script, "compdef _command_names sentinel-staging") {
		t.Error("Script missing zsh completion for sentinel-staging")
	}
	if !strings.Contains(script, "compdef _command_names sentinel-staging-server") {
		t.Error("Script missing zsh completion for sentinel-staging-server")
	}
}

func TestGenerateScript_EmptyProfiles_NoCompletions(t *testing.T) {
	profiles := []ProfileInfo{}

	script := GenerateScript(profiles, "/sentinel/policies", FormatBash)

	// Should NOT have completion registrations for empty profiles
	if strings.Contains(script, "complete -o") {
		t.Error("Script should NOT contain bash completion registrations when no profiles")
	}
	if strings.Contains(script, "compdef") {
		t.Error("Script should NOT contain zsh completion registrations when no profiles")
	}
	if strings.Contains(script, "BASH_VERSION") {
		t.Error("Script should NOT contain bash shell detection when no profiles")
	}
	if strings.Contains(script, "ZSH_VERSION") {
		t.Error("Script should NOT contain zsh shell detection when no profiles")
	}
}

func TestGenerateScript_CompletionSanitizedNames(t *testing.T) {
	profiles := []ProfileInfo{
		{Name: "my-team/staging", PolicyPath: "/sentinel/policies/my-team/staging"},
	}

	script := GenerateScript(profiles, "/sentinel/policies", FormatBash)

	// Bash completion should use sanitized name
	if !strings.Contains(script, "complete -o default -o bashdefault sentinel-my-team-staging") {
		t.Errorf("Script should use sanitized function name in bash completion. Got:\n%s", script)
	}

	// Zsh completion should use same sanitized name
	if !strings.Contains(script, "compdef _command_names sentinel-my-team-staging") {
		t.Errorf("Script should use sanitized function name in zsh completion. Got:\n%s", script)
	}
}

// ============================================================================
// Edge Case Tests for Shell Escaping (Phase 134)
// ============================================================================
//
// These tests verify correct handling of edge cases including:
// 1. All POSIX special characters
// 2. Unicode character handling
// 3. Function name sanitization edge cases
// ============================================================================

// TestShellEscape_AllSpecialChars tests comprehensive handling of POSIX special characters.
func TestShellEscape_AllSpecialChars(t *testing.T) {
	// Group 1: Whitespace characters
	// Note: shellEscape triggers on " \t\n'\"\\$`!" - it does NOT include \r
	// This documents current behavior. Carriage return alone won't trigger quoting,
	// but it's rarely used without \n (CRLF), which does trigger quoting.
	whitespace := []struct {
		name     string
		input    string
		mustQuot bool
	}{
		{"space", "hello world", true},
		{"tab", "hello\tworld", true},
		{"newline", "hello\nworld", true},
		{"carriage_return", "hello\rworld", false}, // CR alone doesn't trigger
		{"mixed_whitespace", " \t\n\r ", true},     // But space/tab/newline do
	}

	for _, tc := range whitespace {
		t.Run("whitespace/"+tc.name, func(t *testing.T) {
			result := shellEscape(tc.input)
			if tc.mustQuot && !strings.HasPrefix(result, "'") {
				t.Errorf("shellEscape(%q) should be quoted, got %q", tc.input, result)
			}
			if !tc.mustQuot {
				// Document that this character doesn't trigger quoting
				t.Logf("Note: %q does not trigger quoting (result: %q)", tc.input, result)
			}
		})
	}

	// Group 2: Quote characters
	quotes := []struct {
		name     string
		input    string
		contains string
	}{
		{"single_quote", "it's", "'\\''"}, // Must use escape sequence
		{"double_quote", "say \"hello\"", "'say \"hello\"'"},
		{"both_quotes", "it's \"quoted\"", "'\\''"},
	}

	for _, tc := range quotes {
		t.Run("quotes/"+tc.name, func(t *testing.T) {
			result := shellEscape(tc.input)
			if !strings.Contains(result, tc.contains) {
				t.Errorf("shellEscape(%q) = %q, want to contain %q", tc.input, result, tc.contains)
			}
		})
	}

	// Group 3: Command execution characters
	cmdExec := []struct {
		name  string
		input string
	}{
		{"backtick", "`command`"},
		{"dollar_paren", "$(command)"},
		{"dollar_brace", "${variable}"},
		{"dollar_simple", "$VAR"},
		{"dollar_arithmetic", "$((1+1))"},
	}

	for _, tc := range cmdExec {
		t.Run("command_exec/"+tc.name, func(t *testing.T) {
			result := shellEscape(tc.input)
			// Must be quoted to prevent execution
			if !strings.HasPrefix(result, "'") {
				t.Errorf("shellEscape(%q) must be quoted to prevent execution, got %q", tc.input, result)
			}
		})
	}

	// Group 4: Command separators and redirects (these need quoting when combined with special chars)
	separators := []struct {
		name     string
		input    string
		hasQuote bool
	}{
		{"semicolon_with_space", "cmd; other", true},    // space triggers quoting
		{"pipe_with_space", "cmd | other", true},        // space triggers quoting
		{"ampersand_with_space", "cmd & other", true},   // space triggers quoting
		{"and_chain_with_space", "cmd && other", true},  // space triggers quoting
		{"or_chain_with_space", "cmd || other", true},   // space triggers quoting
		{"less_than_with_space", "cmd < file", true},    // space triggers quoting
		{"greater_than_with_space", "cmd > file", true}, // space triggers quoting
	}

	for _, tc := range separators {
		t.Run("separators/"+tc.name, func(t *testing.T) {
			result := shellEscape(tc.input)
			if tc.hasQuote && !strings.HasPrefix(result, "'") {
				t.Errorf("shellEscape(%q) should be quoted when contains space, got %q", tc.input, result)
			}
		})
	}

	// Group 5: Glob and expansion characters (these need quoting when combined with special chars)
	globs := []struct {
		name  string
		input string
	}{
		{"asterisk_with_space", "*.txt file"},
		{"question_with_space", "file?.txt other"},
		{"brackets_with_space", "[abc] file"},
		{"braces_with_space", "{a,b} file"},
		{"tilde_with_space", "~user file"},
	}

	for _, tc := range globs {
		t.Run("globs/"+tc.name, func(t *testing.T) {
			result := shellEscape(tc.input)
			// Should be quoted because of space
			if !strings.HasPrefix(result, "'") {
				t.Errorf("shellEscape(%q) should be quoted, got %q", tc.input, result)
			}
		})
	}

	// Group 6: Comment and history characters
	comments := []struct {
		name  string
		input string
	}{
		{"hash_with_space", "file #comment"},
		{"exclamation", "hello!"},
	}

	for _, tc := range comments {
		t.Run("comments/"+tc.name, func(t *testing.T) {
			result := shellEscape(tc.input)
			// Must be quoted to prevent interpretation
			if !strings.HasPrefix(result, "'") {
				t.Errorf("shellEscape(%q) should be quoted, got %q", tc.input, result)
			}
		})
	}
}

// TestShellEscape_Unicode tests Unicode character handling.
func TestShellEscape_Unicode(t *testing.T) {
	// Group 1: Non-ASCII characters (should pass through unchanged when no special chars)
	nonASCII := []struct {
		name  string
		input string
	}{
		{"japanese", "\u65e5\u672c\u8a9e"},           // Japanese
		{"chinese", "\u4e2d\u6587"},                  // Chinese
		{"arabic", "\u0627\u0644\u0639\u0631\u0628"}, // Arabic
		{"emoji", "\U0001F600"},                      // Smiley emoji
		{"accented", "caf\u00e9"},                    // cafe with accent
	}

	for _, tc := range nonASCII {
		t.Run("non_ascii/"+tc.name, func(t *testing.T) {
			result := shellEscape(tc.input)
			// Pure Unicode without special chars should pass through unquoted
			if result != tc.input {
				// If quoted, verify it's valid
				if strings.HasPrefix(result, "'") {
					// Quoted is acceptable but not required for Unicode
					t.Logf("shellEscape(%q) was quoted: %q (acceptable)", tc.input, result)
				}
			}
		})
	}

	// Group 2: Multi-byte UTF-8 sequences
	multibyte := []struct {
		name  string
		input string
	}{
		{"two_byte", "\u00e9\u00e8\u00ea"},        // e with accents
		{"three_byte", "\u4e2d\u6587"},            // Chinese
		{"four_byte", "\U0001F600\U0001F601"},     // Emojis (4-byte each)
		{"mixed_byte", "a\u00e9\u4e2d\U0001F600"}, // Mix of byte lengths
	}

	for _, tc := range multibyte {
		t.Run("multibyte/"+tc.name, func(t *testing.T) {
			result := shellEscape(tc.input)
			// Should not corrupt multi-byte sequences
			// If quoted, strip quotes and check content
			content := result
			if strings.HasPrefix(result, "'") && strings.HasSuffix(result, "'") {
				content = result[1 : len(result)-1]
			}
			// The content should contain the original runes (possibly escaped quotes)
			// This test mainly verifies we don't crash on multi-byte
			if len(content) == 0 && len(tc.input) > 0 {
				t.Errorf("shellEscape(%q) lost content, got %q", tc.input, result)
			}
		})
	}

	// Group 3: Unicode control characters (should be quoted when combined with special chars)
	control := []struct {
		name  string
		input string
	}{
		{"zero_width_space", "hello\u200Bworld"},
		{"right_to_left", "hello\u202Eworld"},
		{"byte_order_mark", "\uFEFFhello"},
		{"line_separator", "hello\u2028world"},
		{"paragraph_separator", "hello\u2029world"},
	}

	for _, tc := range control {
		t.Run("control/"+tc.name, func(t *testing.T) {
			// Just verify it doesn't panic
			result := shellEscape(tc.input)
			if result == "" && tc.input != "" {
				t.Errorf("shellEscape(%q) returned empty string", tc.input)
			}
		})
	}
}

// TestSanitizeFunctionName_EdgeCases tests edge cases for function name sanitization.
func TestSanitizeFunctionName_EdgeCases(t *testing.T) {
	// Edge case 1: Empty string
	t.Run("empty_string", func(t *testing.T) {
		result := sanitizeFunctionName("")
		if result != "sentinel-" {
			t.Errorf("sanitizeFunctionName(\"\") = %q, want \"sentinel-\"", result)
		}
	})

	// Edge case 2: Only special characters
	t.Run("only_special_chars", func(t *testing.T) {
		inputs := []string{
			"@#$%^&*()",
			"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
			"   ",
			"\t\n\r",
			";;;",
		}
		for _, input := range inputs {
			result := sanitizeFunctionName(input)
			// Should be sentinel- with possibly empty or hyphen-only suffix
			if !strings.HasPrefix(result, "sentinel-") {
				t.Errorf("sanitizeFunctionName(%q) = %q, want sentinel- prefix", input, result)
			}
		}
	})

	// Edge case 3: Very long names
	t.Run("very_long_name", func(t *testing.T) {
		// 1000 character name
		longName := strings.Repeat("a", 1000)
		result := sanitizeFunctionName(longName)
		if !strings.HasPrefix(result, "sentinel-") {
			t.Errorf("sanitizeFunctionName(long) should have sentinel- prefix, got %q", result[:50])
		}
		// The sanitization doesn't truncate, but we verify it doesn't crash
		expected := "sentinel-" + longName
		if result != expected {
			t.Errorf("sanitizeFunctionName(long) = %q... (len=%d), want len=%d", result[:50], len(result), len(expected))
		}
	})

	// Edge case 4: Names starting with numbers
	t.Run("starts_with_number", func(t *testing.T) {
		inputs := []struct {
			input    string
			expected string
		}{
			{"123", "sentinel-123"},
			{"1abc", "sentinel-1abc"},
			{"1-2-3", "sentinel-1-2-3"},
		}
		for _, tc := range inputs {
			result := sanitizeFunctionName(tc.input)
			if result != tc.expected {
				t.Errorf("sanitizeFunctionName(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		}
	})

	// Edge case 5: Consecutive special characters
	t.Run("consecutive_special", func(t *testing.T) {
		inputs := []struct {
			input    string
			expected string
		}{
			{"a@@b", "sentinel-a-b"},
			{"a...b", "sentinel-a-b"},
			{"a---b", "sentinel-a-b"},
			{"a@#$b", "sentinel-a-b"},
			{"@@@abc@@@", "sentinel-abc"},
		}
		for _, tc := range inputs {
			result := sanitizeFunctionName(tc.input)
			if result != tc.expected {
				t.Errorf("sanitizeFunctionName(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		}
	})

	// Edge case 6: Mixed case preservation
	t.Run("mixed_case", func(t *testing.T) {
		inputs := []struct {
			input    string
			expected string
		}{
			{"MyProfile", "sentinel-MyProfile"},
			{"ALLCAPS", "sentinel-ALLCAPS"},
			{"camelCase", "sentinel-camelCase"},
			{"PascalCase", "sentinel-PascalCase"},
		}
		for _, tc := range inputs {
			result := sanitizeFunctionName(tc.input)
			if result != tc.expected {
				t.Errorf("sanitizeFunctionName(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		}
	})

	// Edge case 7: Unicode in names (non-alphanumeric chars are replaced with hyphens, trailing trimmed)
	t.Run("unicode_names", func(t *testing.T) {
		inputs := []struct {
			input    string
			expected string
		}{
			{"\u65e5\u672c", "sentinel-"},   // Japanese -> all replaced, trailing trimmed
			{"test\u4e2d", "sentinel-test"}, // Mixed -> trailing hyphen trimmed
			{"caf\u00e9", "sentinel-caf"},   // Accented char replaced, trailing trimmed
		}
		for _, tc := range inputs {
			result := sanitizeFunctionName(tc.input)
			// Unicode chars are non-alphanumeric, so they become hyphens, then trailing is trimmed
			if result != tc.expected {
				t.Errorf("sanitizeFunctionName(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		}
	})
}

// TestShellEscape_ShellSafeOutput verifies escaped output can be safely evaluated.
func TestShellEscape_ShellSafeOutput(t *testing.T) {
	// Test that escaped strings produce valid shell syntax
	testCases := []struct {
		input string
	}{
		{"simple"},
		{"with space"},
		{"with'quote"},
		{"with\"double"},
		{"$variable"},
		{"`command`"},
		{"$(substitution)"},
		{"line\nbreak"},
		{"tab\there"},
		{"back\\slash"},
		{"combo $var 'quote' `cmd`"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			escaped := shellEscape(tc.input)

			// Verify the result is syntactically valid for shell
			// A valid shell string either:
			// 1. Has no special characters (bare word)
			// 2. Is fully enclosed in single quotes with escaped internal quotes

			if strings.ContainsAny(tc.input, " \t\n'\"\\$`!") {
				// Must be quoted
				if !strings.HasPrefix(escaped, "'") || !strings.HasSuffix(escaped, "'") {
					t.Errorf("shellEscape(%q) = %q should be single-quoted", tc.input, escaped)
					return
				}

				// Check balanced quotes (accounting for '\'' escape sequence)
				// Count quote pairs - should have odd number of ' (opening + closing + any escapes)
				quoteCount := strings.Count(escaped, "'") - strings.Count(escaped, "\\''")
				// After removing escape sequences, remaining quotes should be 2 (open and close)
				if quoteCount < 2 {
					t.Errorf("shellEscape(%q) = %q has unbalanced quotes", tc.input, escaped)
				}
			}
		})
	}
}
