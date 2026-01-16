package bootstrap

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateReaderPolicy(t *testing.T) {
	tests := []struct {
		name       string
		policyRoot string
		wantARN    string
	}{
		{
			name:       "default policy root",
			policyRoot: "/sentinel/policies",
			wantARN:    "arn:aws:ssm:*:*:parameter/sentinel/policies/*",
		},
		{
			name:       "custom policy root",
			policyRoot: "/custom/path",
			wantARN:    "arn:aws:ssm:*:*:parameter/custom/path/*",
		},
		{
			name:       "policy root with trailing slash",
			policyRoot: "/sentinel/policies/",
			wantARN:    "arn:aws:ssm:*:*:parameter/sentinel/policies/*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := GenerateReaderPolicy(tt.policyRoot)

			// Verify Version
			if policy.Version != "2012-10-17" {
				t.Errorf("Version = %q, want %q", policy.Version, "2012-10-17")
			}

			// Verify Statement count
			if len(policy.Statement) != 1 {
				t.Fatalf("Statement count = %d, want 1", len(policy.Statement))
			}

			stmt := policy.Statement[0]

			// Verify Sid
			if stmt.Sid != "SentinelPolicyRead" {
				t.Errorf("Sid = %q, want %q", stmt.Sid, "SentinelPolicyRead")
			}

			// Verify Effect
			if stmt.Effect != "Allow" {
				t.Errorf("Effect = %q, want %q", stmt.Effect, "Allow")
			}

			// Verify all 3 read actions present
			wantActions := []string{
				"ssm:GetParameter",
				"ssm:GetParameters",
				"ssm:GetParametersByPath",
			}
			if len(stmt.Action) != len(wantActions) {
				t.Errorf("Action count = %d, want %d", len(stmt.Action), len(wantActions))
			}
			for _, want := range wantActions {
				found := false
				for _, got := range stmt.Action {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Action %q not found in policy", want)
				}
			}

			// Verify Resource ARN
			if len(stmt.Resource) != 1 {
				t.Fatalf("Resource count = %d, want 1", len(stmt.Resource))
			}
			if stmt.Resource[0] != tt.wantARN {
				t.Errorf("Resource = %q, want %q", stmt.Resource[0], tt.wantARN)
			}
		})
	}
}

func TestGenerateAdminPolicy(t *testing.T) {
	tests := []struct {
		name       string
		policyRoot string
		wantARN    string
	}{
		{
			name:       "default policy root",
			policyRoot: "/sentinel/policies",
			wantARN:    "arn:aws:ssm:*:*:parameter/sentinel/policies/*",
		},
		{
			name:       "custom policy root",
			policyRoot: "/custom/admin/path",
			wantARN:    "arn:aws:ssm:*:*:parameter/custom/admin/path/*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := GenerateAdminPolicy(tt.policyRoot)

			// Verify Version
			if policy.Version != "2012-10-17" {
				t.Errorf("Version = %q, want %q", policy.Version, "2012-10-17")
			}

			// Verify Statement count
			if len(policy.Statement) != 1 {
				t.Fatalf("Statement count = %d, want 1", len(policy.Statement))
			}

			stmt := policy.Statement[0]

			// Verify Sid
			if stmt.Sid != "SentinelPolicyAdmin" {
				t.Errorf("Sid = %q, want %q", stmt.Sid, "SentinelPolicyAdmin")
			}

			// Verify Effect
			if stmt.Effect != "Allow" {
				t.Errorf("Effect = %q, want %q", stmt.Effect, "Allow")
			}

			// Verify all 7 actions present (3 read + 4 write)
			wantActions := []string{
				"ssm:GetParameter",
				"ssm:GetParameters",
				"ssm:GetParametersByPath",
				"ssm:PutParameter",
				"ssm:DeleteParameter",
				"ssm:AddTagsToResource",
				"ssm:RemoveTagsFromResource",
			}
			if len(stmt.Action) != len(wantActions) {
				t.Errorf("Action count = %d, want %d", len(stmt.Action), len(wantActions))
			}
			for _, want := range wantActions {
				found := false
				for _, got := range stmt.Action {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Action %q not found in policy", want)
				}
			}

			// Verify Resource ARN
			if len(stmt.Resource) != 1 {
				t.Fatalf("Resource count = %d, want 1", len(stmt.Resource))
			}
			if stmt.Resource[0] != tt.wantARN {
				t.Errorf("Resource = %q, want %q", stmt.Resource[0], tt.wantARN)
			}
		})
	}
}

func TestFormatIAMPolicy(t *testing.T) {
	t.Run("produces valid JSON", func(t *testing.T) {
		policy := GenerateReaderPolicy("/sentinel/policies")
		formatted, err := FormatIAMPolicy(policy)
		if err != nil {
			t.Fatalf("FormatIAMPolicy() error = %v", err)
		}

		// Verify it's valid JSON
		if !json.Valid([]byte(formatted)) {
			t.Error("FormatIAMPolicy() did not produce valid JSON")
		}
	})

	t.Run("round-trip unmarshals correctly", func(t *testing.T) {
		original := GenerateAdminPolicy("/sentinel/policies")
		formatted, err := FormatIAMPolicy(original)
		if err != nil {
			t.Fatalf("FormatIAMPolicy() error = %v", err)
		}

		var roundTrip IAMPolicyDocument
		if err := json.Unmarshal([]byte(formatted), &roundTrip); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}

		// Verify round-trip matches original
		if roundTrip.Version != original.Version {
			t.Errorf("Round-trip Version = %q, want %q", roundTrip.Version, original.Version)
		}
		if len(roundTrip.Statement) != len(original.Statement) {
			t.Errorf("Round-trip Statement count = %d, want %d", len(roundTrip.Statement), len(original.Statement))
		}
	})

	t.Run("indentation is present", func(t *testing.T) {
		policy := GenerateReaderPolicy("/sentinel/policies")
		formatted, err := FormatIAMPolicy(policy)
		if err != nil {
			t.Fatalf("FormatIAMPolicy() error = %v", err)
		}

		// Verify indentation (newlines present)
		if !strings.Contains(formatted, "\n") {
			t.Error("FormatIAMPolicy() output does not contain newlines")
		}
		// Verify 2-space indent
		if !strings.Contains(formatted, "  ") {
			t.Error("FormatIAMPolicy() output does not contain 2-space indentation")
		}
	})
}

func TestIAMPolicyResourceARN(t *testing.T) {
	tests := []struct {
		name       string
		policyRoot string
		wantARN    string
	}{
		{
			name:       "without trailing slash",
			policyRoot: "/sentinel/policies",
			wantARN:    "arn:aws:ssm:*:*:parameter/sentinel/policies/*",
		},
		{
			name:       "with trailing slash",
			policyRoot: "/sentinel/policies/",
			wantARN:    "arn:aws:ssm:*:*:parameter/sentinel/policies/*",
		},
		{
			name:       "deep path without trailing slash",
			policyRoot: "/org/team/sentinel",
			wantARN:    "arn:aws:ssm:*:*:parameter/org/team/sentinel/*",
		},
		{
			name:       "deep path with trailing slash",
			policyRoot: "/org/team/sentinel/",
			wantARN:    "arn:aws:ssm:*:*:parameter/org/team/sentinel/*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := GenerateReaderPolicy(tt.policyRoot)
			if len(policy.Statement) == 0 || len(policy.Statement[0].Resource) == 0 {
				t.Fatal("Policy has no resource")
			}

			got := policy.Statement[0].Resource[0]
			if got != tt.wantARN {
				t.Errorf("Resource ARN = %q, want %q", got, tt.wantARN)
			}

			// Verify ARN ends with /* for wildcard matching
			if !strings.HasSuffix(got, "/*") {
				t.Errorf("Resource ARN %q does not end with /* for wildcard matching", got)
			}
		})
	}
}
