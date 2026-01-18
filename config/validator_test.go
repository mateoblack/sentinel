package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate_Policy(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantValid   bool
		wantErrors  int
		wantWarning bool
	}{
		{
			name: "valid policy",
			content: `
version: "1"
rules:
  - name: allow-dev
    effect: allow
    conditions:
      profiles:
        - dev
`,
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name:       "empty content",
			content:    "",
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "no rules",
			content: `
version: "1"
rules: []
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "rule missing name",
			content: `
version: "1"
rules:
  - effect: allow
    conditions:
      profiles:
        - dev
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "invalid effect",
			content: `
version: "1"
rules:
  - name: test
    effect: invalid
    conditions:
      profiles:
        - dev
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "rule with no conditions - warning",
			content: `
version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions: {}
`,
			wantValid:   false, // no conditions is an error
			wantErrors:  1,
			wantWarning: false,
		},
		{
			name: "invalid yaml",
			content: `
version: "1"
rules:
  - name: test
    effect: [invalid yaml
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "valid policy with require_approval",
			content: `
version: "1"
rules:
  - name: require-approval-prod
    effect: require_approval
    conditions:
      profiles:
        - prod
`,
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "warning for empty profiles and users",
			content: `
version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      time:
        days:
          - monday
`,
			wantValid:   true,
			wantWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Validate(ConfigTypePolicy, []byte(tt.content), "test.yaml")

			if result.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", result.Valid, tt.wantValid)
			}

			errorCount := 0
			warningCount := 0
			for _, issue := range result.Issues {
				if issue.Severity == SeverityError {
					errorCount++
				}
				if issue.Severity == SeverityWarning {
					warningCount++
				}
			}

			if errorCount != tt.wantErrors {
				t.Errorf("error count = %d, want %d", errorCount, tt.wantErrors)
				for _, issue := range result.Issues {
					t.Logf("  issue: %s - %s", issue.Severity, issue.Message)
				}
			}

			if tt.wantWarning && warningCount == 0 {
				t.Error("expected at least one warning, got none")
			}
		})
	}
}

func TestValidate_Approval(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantValid   bool
		wantErrors  int
		wantWarning bool
	}{
		{
			name: "valid approval policy",
			content: `
version: "1"
rules:
  - name: prod-approval
    profiles:
      - prod
    approvers:
      - admin
`,
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "missing approvers",
			content: `
version: "1"
rules:
  - name: prod-approval
    profiles:
      - prod
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "missing name",
			content: `
version: "1"
rules:
  - profiles:
      - prod
    approvers:
      - admin
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "warning for empty profiles",
			content: `
version: "1"
rules:
  - name: global
    approvers:
      - admin
`,
			wantValid:   true,
			wantWarning: true,
		},
		{
			name: "with auto_approve",
			content: `
version: "1"
rules:
  - name: dev-approval
    profiles:
      - dev
    approvers:
      - admin
    auto_approve:
      users:
        - senior-dev
      max_duration: 1h
`,
			wantValid:  true,
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Validate(ConfigTypeApproval, []byte(tt.content), "test.yaml")

			if result.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", result.Valid, tt.wantValid)
			}

			errorCount := 0
			warningCount := 0
			for _, issue := range result.Issues {
				if issue.Severity == SeverityError {
					errorCount++
				}
				if issue.Severity == SeverityWarning {
					warningCount++
				}
			}

			if errorCount != tt.wantErrors {
				t.Errorf("error count = %d, want %d", errorCount, tt.wantErrors)
			}

			if tt.wantWarning && warningCount == 0 {
				t.Error("expected at least one warning, got none")
			}
		})
	}
}

func TestValidate_BreakGlass(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantValid   bool
		wantErrors  int
		wantWarning bool
	}{
		{
			name: "valid break-glass policy",
			content: `
version: "1"
rules:
  - name: emergency-access
    profiles:
      - prod
    users:
      - oncall
    allowed_reason_codes:
      - incident
`,
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "missing users",
			content: `
version: "1"
rules:
  - name: emergency-access
    profiles:
      - prod
    allowed_reason_codes:
      - incident
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "invalid reason code",
			content: `
version: "1"
rules:
  - name: emergency-access
    users:
      - oncall
    allowed_reason_codes:
      - invalid_code
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "warning for empty profiles",
			content: `
version: "1"
rules:
  - name: emergency-access
    users:
      - oncall
    allowed_reason_codes:
      - incident
`,
			wantValid:   true,
			wantWarning: true, // empty profiles
		},
		{
			name: "warning for empty reason codes",
			content: `
version: "1"
rules:
  - name: emergency-access
    profiles:
      - prod
    users:
      - oncall
`,
			wantValid:   true,
			wantWarning: true, // empty allowed_reason_codes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Validate(ConfigTypeBreakGlass, []byte(tt.content), "test.yaml")

			if result.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", result.Valid, tt.wantValid)
			}

			errorCount := 0
			warningCount := 0
			for _, issue := range result.Issues {
				if issue.Severity == SeverityError {
					errorCount++
				}
				if issue.Severity == SeverityWarning {
					warningCount++
				}
			}

			if errorCount != tt.wantErrors {
				t.Errorf("error count = %d, want %d", errorCount, tt.wantErrors)
			}

			if tt.wantWarning && warningCount == 0 {
				t.Error("expected at least one warning, got none")
			}
		})
	}
}

func TestValidate_RateLimit(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantValid   bool
		wantErrors  int
		wantWarning bool
	}{
		{
			name: "valid rate limit policy",
			content: `
version: "1"
rules:
  - name: standard-limit
    profiles:
      - prod
    cooldown: 5m
    max_per_user: 3
    quota_window: 24h
`,
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "missing quota_window",
			content: `
version: "1"
rules:
  - name: standard-limit
    max_per_user: 3
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "no limits defined",
			content: `
version: "1"
rules:
  - name: no-limits
    profiles:
      - prod
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "warning for short cooldown",
			content: `
version: "1"
rules:
  - name: quick-limit
    profiles:
      - dev
    cooldown: 30s
`,
			wantValid:   true,
			wantWarning: true, // cooldown < 1m
		},
		{
			name: "warning for empty profiles",
			content: `
version: "1"
rules:
  - name: global-limit
    cooldown: 5m
`,
			wantValid:   true,
			wantWarning: true, // empty profiles
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Validate(ConfigTypeRateLimit, []byte(tt.content), "test.yaml")

			if result.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", result.Valid, tt.wantValid)
			}

			errorCount := 0
			warningCount := 0
			for _, issue := range result.Issues {
				if issue.Severity == SeverityError {
					errorCount++
				}
				if issue.Severity == SeverityWarning {
					warningCount++
				}
			}

			if errorCount != tt.wantErrors {
				t.Errorf("error count = %d, want %d", errorCount, tt.wantErrors)
			}

			if tt.wantWarning && warningCount == 0 {
				t.Error("expected at least one warning, got none")
			}
		})
	}
}

func TestValidate_Bootstrap(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantValid  bool
		wantErrors int
	}{
		{
			name: "valid bootstrap config",
			content: `
policy_root: /sentinel/policies
profiles:
  - name: dev
  - name: prod
`,
			wantValid:  true,
			wantErrors: 0,
		},
		{
			name: "missing policy_root",
			content: `
profiles:
  - name: dev
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "missing profiles",
			content: `
policy_root: /sentinel/policies
profiles: []
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "invalid policy_root",
			content: `
policy_root: sentinel/policies
profiles:
  - name: dev
`,
			wantValid:  false,
			wantErrors: 1,
		},
		{
			name: "profile missing name",
			content: `
policy_root: /sentinel/policies
profiles:
  - description: no name
`,
			wantValid:  false,
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Validate(ConfigTypeBootstrap, []byte(tt.content), "test.yaml")

			if result.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", result.Valid, tt.wantValid)
			}

			errorCount := 0
			for _, issue := range result.Issues {
				if issue.Severity == SeverityError {
					errorCount++
				}
			}

			if errorCount != tt.wantErrors {
				t.Errorf("error count = %d, want %d", errorCount, tt.wantErrors)
			}
		})
	}
}

func TestValidate_UnknownType(t *testing.T) {
	result := Validate(ConfigType("unknown"), []byte("test: value"), "test.yaml")

	if result.Valid {
		t.Error("Valid = true, want false for unknown type")
	}

	if len(result.Issues) != 1 {
		t.Errorf("issue count = %d, want 1", len(result.Issues))
	}

	if result.Issues[0].Severity != SeverityError {
		t.Errorf("severity = %v, want error", result.Issues[0].Severity)
	}
}

func TestDetectConfigType(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected ConfigType
	}{
		{
			name: "detect policy by effect",
			content: `
rules:
  - name: test
    effect: allow
    conditions:
      profiles:
        - dev
`,
			expected: ConfigTypePolicy,
		},
		{
			name: "detect approval by approvers",
			content: `
rules:
  - name: test
    approvers:
      - admin
`,
			expected: ConfigTypeApproval,
		},
		{
			name: "detect breakglass by users and allowed_reason_codes",
			content: `
rules:
  - name: test
    users:
      - oncall
    allowed_reason_codes:
      - incident
`,
			expected: ConfigTypeBreakGlass,
		},
		{
			name: "detect ratelimit by cooldown",
			content: `
rules:
  - name: test
    cooldown: 5m
`,
			expected: ConfigTypeRateLimit,
		},
		{
			name: "detect ratelimit by max_per_user",
			content: `
rules:
  - name: test
    max_per_user: 3
    quota_window: 24h
`,
			expected: ConfigTypeRateLimit,
		},
		{
			name: "detect bootstrap by policy_root",
			content: `
policy_root: /sentinel/policies
profiles:
  - name: dev
`,
			expected: ConfigTypeBootstrap,
		},
		{
			name: "detect bootstrap by profiles only",
			content: `
profiles:
  - name: dev
  - name: prod
`,
			expected: ConfigTypeBootstrap,
		},
		{
			name:     "default to policy for empty rules",
			content:  `rules: []`,
			expected: ConfigTypePolicy,
		},
		{
			name:     "default to policy for invalid yaml",
			content:  `[invalid yaml`,
			expected: ConfigTypePolicy,
		},
		{
			name:     "default to policy for empty content",
			content:  ``,
			expected: ConfigTypePolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectConfigType([]byte(tt.content))
			if got != tt.expected {
				t.Errorf("DetectConfigType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestValidateFile(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "config-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a valid policy file
	validPolicy := `
version: "1"
rules:
  - name: allow-dev
    effect: allow
    conditions:
      profiles:
        - dev
`
	validPath := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte(validPolicy), 0644); err != nil {
		t.Fatalf("failed to write valid file: %v", err)
	}

	// Create an invalid policy file
	invalidPolicy := `
version: "1"
rules: []
`
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte(invalidPolicy), 0644); err != nil {
		t.Fatalf("failed to write invalid file: %v", err)
	}

	t.Run("valid file", func(t *testing.T) {
		result, err := ValidateFile(validPath, ConfigTypePolicy)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !result.Valid {
			t.Error("Valid = false, want true")
		}
		if result.Source != validPath {
			t.Errorf("Source = %v, want %v", result.Source, validPath)
		}
	})

	t.Run("invalid file", func(t *testing.T) {
		result, err := ValidateFile(invalidPath, ConfigTypePolicy)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result.Valid {
			t.Error("Valid = true, want false")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		result, err := ValidateFile("/nonexistent/path.yaml", ConfigTypePolicy)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
		if result.Valid {
			t.Error("Valid = true, want false")
		}
		if len(result.Issues) == 0 {
			t.Error("expected at least one issue")
		}
	})
}

func TestExtractLocation(t *testing.T) {
	tests := []struct {
		errMsg   string
		expected string
	}{
		{"rule at index 0 missing name", "rules[0]"},
		{"rule at index 5 missing name", "rules[5]"},
		{"profile at index 2 error", "profiles[2]"},
		{"some error at index 3", "index[3]"},
		{"no index mentioned", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.errMsg, func(t *testing.T) {
			got := extractLocation(tt.errMsg)
			if got != tt.expected {
				t.Errorf("extractLocation(%q) = %q, want %q", tt.errMsg, got, tt.expected)
			}
		})
	}
}

func TestSuggestPolicyFix(t *testing.T) {
	tests := []struct {
		errMsg      string
		wantContain string
	}{
		{"policy must have at least one rule", "at least one rule"},
		{"rule at index 0 missing name", "name"},
		{"invalid effect 'bad'", "allow"},
		{"no conditions", "condition"},
		{"invalid weekday 'badday'", "lowercase"},
		{"invalid timezone 'bad/tz'", "IANA"},
		{"invalid hour format", "HH:MM"},
		{"some unknown error", "review"},
	}

	for _, tt := range tests {
		t.Run(tt.errMsg, func(t *testing.T) {
			got := suggestPolicyFix(tt.errMsg)
			if got == "" {
				t.Error("suggestion should not be empty")
			}
		})
	}
}

func TestSuggestApprovalFix(t *testing.T) {
	tests := []struct {
		errMsg string
	}{
		{"policy must have at least one rule"},
		{"missing name"},
		{"at least one approver"},
		{"at least one condition"},
		{"exceeds maximum"},
		{"some unknown error"},
	}

	for _, tt := range tests {
		t.Run(tt.errMsg, func(t *testing.T) {
			got := suggestApprovalFix(tt.errMsg)
			if got == "" {
				t.Error("suggestion should not be empty")
			}
		})
	}
}

func TestSuggestBreakGlassFix(t *testing.T) {
	tests := []struct {
		errMsg string
	}{
		{"at least one rule"},
		{"missing name"},
		{"at least one user"},
		{"invalid reason code"},
		{"negative max_duration"},
		{"exceeds maximum"},
		{"unknown error"},
	}

	for _, tt := range tests {
		t.Run(tt.errMsg, func(t *testing.T) {
			got := suggestBreakGlassFix(tt.errMsg)
			if got == "" {
				t.Error("suggestion should not be empty")
			}
		})
	}
}

func TestSuggestRateLimitFix(t *testing.T) {
	tests := []struct {
		errMsg string
	}{
		{"at least one rule"},
		{"missing name"},
		{"negative cooldown"},
		{"negative max_per_user"},
		{"negative max_per_profile"},
		{"quota_window"},
		{"at least one limit"},
		{"unknown error"},
	}

	for _, tt := range tests {
		t.Run(tt.errMsg, func(t *testing.T) {
			got := suggestRateLimitFix(tt.errMsg)
			if got == "" {
				t.Error("suggestion should not be empty")
			}
		})
	}
}

func TestSuggestBootstrapFix(t *testing.T) {
	tests := []struct {
		errMsg string
	}{
		{"policy_root cannot be empty"},
		{"must start with '/'"},
		{"exceeds maximum length"},
		{"invalid characters"},
		{"at least one profile"},
		{"name cannot be empty"},
		{"not valid YAML"},
		{"unknown error"},
	}

	for _, tt := range tests {
		t.Run(tt.errMsg, func(t *testing.T) {
			got := suggestBootstrapFix(tt.errMsg)
			if got == "" {
				t.Error("suggestion should not be empty")
			}
		})
	}
}

func TestConfigTypeStrings(t *testing.T) {
	strs := configTypeStrings()
	if len(strs) != 5 {
		t.Errorf("configTypeStrings() returned %d items, want 5", len(strs))
	}

	expected := []string{"policy", "approval", "breakglass", "ratelimit", "bootstrap"}
	for i, s := range expected {
		found := false
		for _, got := range strs {
			if got == s {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("configTypeStrings() missing %q (index %d)", s, i)
		}
	}
}
