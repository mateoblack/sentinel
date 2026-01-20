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
		{"a--b", "sentinel-a-b"},      // Consecutive hyphens collapsed
		{"-start", "sentinel-start"},  // Leading special char
		{"end-", "sentinel-end"},      // Trailing special char
		{"@#$%", "sentinel-"},         // All special chars -> empty after sanitization
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
