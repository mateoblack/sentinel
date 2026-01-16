package bootstrap

import (
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/policy"
)

func TestGenerateSamplePolicy(t *testing.T) {
	tests := []struct {
		name        string
		profile     string
		description string
		wantErr     bool
		errMsg      string
		checks      []func(t *testing.T, output string)
	}{
		{
			name:        "valid profile generates valid YAML",
			profile:     "production",
			description: "",
			wantErr:     false,
			checks: []func(t *testing.T, output string){
				func(t *testing.T, output string) {
					if !strings.Contains(output, "version:") {
						t.Error("output missing version field")
					}
				},
				func(t *testing.T, output string) {
					if !strings.Contains(output, "rules:") {
						t.Error("output missing rules field")
					}
				},
				func(t *testing.T, output string) {
					if !strings.Contains(output, "production") {
						t.Error("output missing profile name in conditions")
					}
				},
			},
		},
		{
			name:        "valid profile with description includes description in header",
			profile:     "staging",
			description: "Staging environment for testing",
			wantErr:     false,
			checks: []func(t *testing.T, output string){
				func(t *testing.T, output string) {
					if !strings.Contains(output, "# Staging environment for testing") {
						t.Error("output missing description in header")
					}
				},
				func(t *testing.T, output string) {
					if !strings.Contains(output, "# Sentinel policy for profile: staging") {
						t.Error("output missing profile header")
					}
				},
			},
		},
		{
			name:        "empty profile name returns error",
			profile:     "",
			description: "",
			wantErr:     true,
			errMsg:      "profile name cannot be empty",
		},
		{
			name:        "header includes Generated timestamp",
			profile:     "dev",
			description: "",
			wantErr:     false,
			checks: []func(t *testing.T, output string){
				func(t *testing.T, output string) {
					if !strings.Contains(output, "# Generated:") {
						t.Error("output missing Generated timestamp")
					}
				},
			},
		},
		{
			name:        "header includes customization note",
			profile:     "dev",
			description: "",
			wantErr:     false,
			checks: []func(t *testing.T, output string){
				func(t *testing.T, output string) {
					if !strings.Contains(output, "# Customize this policy") {
						t.Error("output missing customization note")
					}
				},
			},
		},
		{
			name:        "profile with hyphens works",
			profile:     "prod-us-east-1",
			description: "",
			wantErr:     false,
			checks: []func(t *testing.T, output string){
				func(t *testing.T, output string) {
					if !strings.Contains(output, "prod-us-east-1") {
						t.Error("output missing hyphenated profile name")
					}
				},
			},
		},
		{
			name:        "profile with underscores works",
			profile:     "prod_us_east_1",
			description: "",
			wantErr:     false,
			checks: []func(t *testing.T, output string){
				func(t *testing.T, output string) {
					if !strings.Contains(output, "prod_us_east_1") {
						t.Error("output missing underscored profile name")
					}
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := GenerateSamplePolicy(tt.profile, tt.description)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			for _, check := range tt.checks {
				check(t, output)
			}
		})
	}
}

func TestGenerateSamplePolicy_RoundtripValidation(t *testing.T) {
	// Test that generated policy can be parsed and validated
	tests := []struct {
		name        string
		profile     string
		description string
	}{
		{
			name:        "simple profile",
			profile:     "production",
			description: "",
		},
		{
			name:        "profile with description",
			profile:     "staging",
			description: "Staging environment",
		},
		{
			name:        "complex profile name",
			profile:     "my-org-prod-123",
			description: "Production account for my-org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate policy
			output, err := GenerateSamplePolicy(tt.profile, tt.description)
			if err != nil {
				t.Fatalf("GenerateSamplePolicy failed: %v", err)
			}

			// Parse the generated YAML
			parsed, err := policy.ParsePolicy([]byte(output))
			if err != nil {
				t.Fatalf("ParsePolicy failed: %v", err)
			}

			// Validate the parsed policy
			if err := parsed.Validate(); err != nil {
				t.Fatalf("Validate failed: %v", err)
			}

			// Check structure
			if parsed.Version != PolicyVersion {
				t.Errorf("Version = %q, want %q", parsed.Version, PolicyVersion)
			}

			if len(parsed.Rules) != 1 {
				t.Errorf("Rules count = %d, want 1", len(parsed.Rules))
			}

			rule := parsed.Rules[0]
			if rule.Name != "default-deny" {
				t.Errorf("Rule.Name = %q, want %q", rule.Name, "default-deny")
			}

			if rule.Effect != policy.EffectDeny {
				t.Errorf("Rule.Effect = %q, want %q", rule.Effect, policy.EffectDeny)
			}

			if len(rule.Conditions.Profiles) != 1 || rule.Conditions.Profiles[0] != tt.profile {
				t.Errorf("Rule.Conditions.Profiles = %v, want [%q]", rule.Conditions.Profiles, tt.profile)
			}
		})
	}
}

func TestGenerateSamplePolicy_OutputStructure(t *testing.T) {
	output, err := GenerateSamplePolicy("test-profile", "Test description")
	if err != nil {
		t.Fatalf("GenerateSamplePolicy failed: %v", err)
	}

	// Verify YAML structure contains expected elements
	expectedElements := []string{
		"version:",
		"rules:",
		"- name: default-deny",
		"effect: deny",
		"conditions:",
		"profiles:",
		"- test-profile",
		"reason:",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(output, elem) {
			t.Errorf("output missing expected element: %q", elem)
		}
	}

	// Verify header structure
	lines := strings.Split(output, "\n")
	if len(lines) < 4 {
		t.Fatalf("output has fewer than 4 lines, got %d", len(lines))
	}

	// First line should be profile comment
	if !strings.HasPrefix(lines[0], "# Sentinel policy for profile:") {
		t.Errorf("first line should be profile comment, got: %q", lines[0])
	}

	// Second line should be description
	if !strings.HasPrefix(lines[1], "# Test description") {
		t.Errorf("second line should be description, got: %q", lines[1])
	}

	// Third line should be Generated timestamp
	if !strings.HasPrefix(lines[2], "# Generated:") {
		t.Errorf("third line should be Generated timestamp, got: %q", lines[2])
	}

	// Fourth line should be customization note
	if !strings.HasPrefix(lines[3], "# Customize") {
		t.Errorf("fourth line should be customization note, got: %q", lines[3])
	}
}
