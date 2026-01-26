package policy

import (
	"strings"
	"testing"
)

func TestParsePolicy(t *testing.T) {
	var testCases = []struct {
		name        string
		input       string
		wantVersion string
		wantRules   int
		wantErr     string
	}{
		{
			name: "valid policy with one allow rule",
			input: `
version: "1"
rules:
  - name: "allow-prod-access"
    effect: allow
    conditions:
      profiles:
        - prod
`,
			wantVersion: "1",
			wantRules:   1,
		},
		{
			name: "valid policy with multiple rules",
			input: `
version: "1"
rules:
  - name: "deny-weekends"
    effect: deny
    conditions:
      time:
        days:
          - saturday
          - sunday
  - name: "allow-all"
    effect: allow
    conditions:
      profiles:
        - "*"
`,
			wantVersion: "1",
			wantRules:   2,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: "empty policy",
		},
		{
			name:    "whitespace only input",
			input:   "   \n\t\n  ",
			wantErr: "empty policy",
		},
		{
			name:    "invalid yaml syntax",
			input:   "invalid: yaml: here:",
			wantErr: "yaml",
		},
		{
			name: "missing version field",
			input: `
rules:
  - name: "test"
    effect: allow
    conditions:
      profiles:
        - test
`,
			wantErr: "version",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := ParsePolicy([]byte(tc.input))

			if tc.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if string(policy.Version) != tc.wantVersion {
				t.Errorf("got version %q, want %q", policy.Version, tc.wantVersion)
			}

			if len(policy.Rules) != tc.wantRules {
				t.Errorf("got %d rules, want %d", len(policy.Rules), tc.wantRules)
			}
		})
	}
}

func TestParsePolicyFromReader(t *testing.T) {
	input := `
version: "1"
rules:
  - name: "test-rule"
    effect: allow
    conditions:
      profiles:
        - test
`
	reader := strings.NewReader(input)
	policy, err := ParsePolicyFromReader(reader)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if string(policy.Version) != "1" {
		t.Errorf("got version %q, want %q", policy.Version, "1")
	}

	if len(policy.Rules) != 1 {
		t.Errorf("got %d rules, want 1", len(policy.Rules))
	}

	if policy.Rules[0].Name != "test-rule" {
		t.Errorf("got rule name %q, want %q", policy.Rules[0].Name, "test-rule")
	}
}
