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

// TestFormatIAMPolicy_EdgeCases tests edge cases for IAM policy JSON formatting.
func TestFormatIAMPolicy_EdgeCases(t *testing.T) {
	t.Run("empty statement Sid", func(t *testing.T) {
		doc := IAMPolicyDocument{
			Version: "2012-10-17",
			Statement: []IAMStatement{
				{
					Sid:      "", // Empty Sid
					Effect:   "Allow",
					Action:   []string{"ssm:GetParameter"},
					Resource: []string{"arn:aws:ssm:*:*:parameter/test/*"},
				},
			},
		}

		formatted, err := FormatIAMPolicy(doc)
		if err != nil {
			t.Fatalf("FormatIAMPolicy() error = %v", err)
		}

		// Verify it's valid JSON
		if !json.Valid([]byte(formatted)) {
			t.Error("FormatIAMPolicy() did not produce valid JSON")
		}

		// Empty Sid should be omitted from JSON (omitempty)
		if strings.Contains(formatted, `"Sid"`) {
			t.Error("Empty Sid should be omitted from JSON output")
		}
	})

	t.Run("multiple statements", func(t *testing.T) {
		doc := IAMPolicyDocument{
			Version: "2012-10-17",
			Statement: []IAMStatement{
				{
					Sid:      "ReadAccess",
					Effect:   "Allow",
					Action:   []string{"ssm:GetParameter"},
					Resource: []string{"arn:aws:ssm:*:*:parameter/read/*"},
				},
				{
					Sid:      "WriteAccess",
					Effect:   "Allow",
					Action:   []string{"ssm:PutParameter"},
					Resource: []string{"arn:aws:ssm:*:*:parameter/write/*"},
				},
			},
		}

		formatted, err := FormatIAMPolicy(doc)
		if err != nil {
			t.Fatalf("FormatIAMPolicy() error = %v", err)
		}

		// Round-trip verification
		var roundTrip IAMPolicyDocument
		if err := json.Unmarshal([]byte(formatted), &roundTrip); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}

		if len(roundTrip.Statement) != 2 {
			t.Errorf("expected 2 statements, got %d", len(roundTrip.Statement))
		}

		if roundTrip.Statement[0].Sid != "ReadAccess" {
			t.Errorf("first statement Sid = %q, want %q", roundTrip.Statement[0].Sid, "ReadAccess")
		}
		if roundTrip.Statement[1].Sid != "WriteAccess" {
			t.Errorf("second statement Sid = %q, want %q", roundTrip.Statement[1].Sid, "WriteAccess")
		}
	})

	t.Run("resource ARN with special characters", func(t *testing.T) {
		doc := IAMPolicyDocument{
			Version: "2012-10-17",
			Statement: []IAMStatement{
				{
					Sid:      "SpecialChars",
					Effect:   "Allow",
					Action:   []string{"ssm:GetParameter"},
					Resource: []string{"arn:aws:ssm:us-east-1:123456789012:parameter/my-app/config/*"},
				},
			},
		}

		formatted, err := FormatIAMPolicy(doc)
		if err != nil {
			t.Fatalf("FormatIAMPolicy() error = %v", err)
		}

		// JSON should preserve the special characters without escaping (hyphens, asterisks)
		if !strings.Contains(formatted, "my-app") {
			t.Error("formatted output should contain hyphen in path")
		}
		if !strings.Contains(formatted, "/*") {
			t.Error("formatted output should contain wildcard")
		}

		// Round-trip to verify
		var roundTrip IAMPolicyDocument
		if err := json.Unmarshal([]byte(formatted), &roundTrip); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}

		expectedResource := "arn:aws:ssm:us-east-1:123456789012:parameter/my-app/config/*"
		if roundTrip.Statement[0].Resource[0] != expectedResource {
			t.Errorf("Resource = %q, want %q", roundTrip.Statement[0].Resource[0], expectedResource)
		}
	})

	t.Run("multiple actions", func(t *testing.T) {
		doc := IAMPolicyDocument{
			Version: "2012-10-17",
			Statement: []IAMStatement{
				{
					Effect:   "Allow",
					Action:   []string{"ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"},
					Resource: []string{"arn:aws:ssm:*:*:parameter/test/*"},
				},
			},
		}

		formatted, err := FormatIAMPolicy(doc)
		if err != nil {
			t.Fatalf("FormatIAMPolicy() error = %v", err)
		}

		// Round-trip to verify action array
		var roundTrip IAMPolicyDocument
		if err := json.Unmarshal([]byte(formatted), &roundTrip); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}

		if len(roundTrip.Statement[0].Action) != 3 {
			t.Errorf("expected 3 actions, got %d", len(roundTrip.Statement[0].Action))
		}
	})

	t.Run("multiple resources", func(t *testing.T) {
		doc := IAMPolicyDocument{
			Version: "2012-10-17",
			Statement: []IAMStatement{
				{
					Effect: "Allow",
					Action: []string{"ssm:GetParameter"},
					Resource: []string{
						"arn:aws:ssm:*:*:parameter/prod/*",
						"arn:aws:ssm:*:*:parameter/staging/*",
					},
				},
			},
		}

		formatted, err := FormatIAMPolicy(doc)
		if err != nil {
			t.Fatalf("FormatIAMPolicy() error = %v", err)
		}

		// Round-trip to verify resource array
		var roundTrip IAMPolicyDocument
		if err := json.Unmarshal([]byte(formatted), &roundTrip); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}

		if len(roundTrip.Statement[0].Resource) != 2 {
			t.Errorf("expected 2 resources, got %d", len(roundTrip.Statement[0].Resource))
		}
	})
}

// TestGenerateReaderPolicy_EdgeCases tests edge cases for reader policy generation.
func TestGenerateReaderPolicy_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		policyRoot string
	}{
		{
			name:       "single character path",
			policyRoot: "/a",
		},
		{
			name:       "very long path",
			policyRoot: "/" + strings.Repeat("a", 100) + "/" + strings.Repeat("b", 100),
		},
		{
			name:       "path with hyphens and underscores",
			policyRoot: "/my-org_v2/sentinel-policies_prod",
		},
		{
			name:       "deeply nested path",
			policyRoot: "/a/b/c/d/e/f/g/h/i/j",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := GenerateReaderPolicy(tt.policyRoot)

			// Verify structure is valid
			if policy.Version != "2012-10-17" {
				t.Errorf("Version = %q, want %q", policy.Version, "2012-10-17")
			}

			if len(policy.Statement) != 1 {
				t.Fatalf("Statement count = %d, want 1", len(policy.Statement))
			}

			stmt := policy.Statement[0]
			if stmt.Effect != "Allow" {
				t.Errorf("Effect = %q, want %q", stmt.Effect, "Allow")
			}

			// Verify actions are read-only
			for _, action := range stmt.Action {
				if strings.Contains(action, "Put") || strings.Contains(action, "Delete") {
					t.Errorf("Reader policy should not have write action: %s", action)
				}
			}

			// Verify resource is properly formed
			if len(stmt.Resource) != 1 {
				t.Fatalf("Resource count = %d, want 1", len(stmt.Resource))
			}
			if !strings.HasPrefix(stmt.Resource[0], "arn:aws:ssm:") {
				t.Errorf("Resource should be SSM ARN, got: %s", stmt.Resource[0])
			}
		})
	}
}

// TestGenerateAdminPolicy_EdgeCases tests edge cases for admin policy generation.
func TestGenerateAdminPolicy_EdgeCases(t *testing.T) {
	t.Run("admin has write actions reader doesn't", func(t *testing.T) {
		policyRoot := "/sentinel/policies"

		reader := GenerateReaderPolicy(policyRoot)
		admin := GenerateAdminPolicy(policyRoot)

		// Admin should have more actions than reader
		if len(admin.Statement[0].Action) <= len(reader.Statement[0].Action) {
			t.Errorf("Admin should have more actions than reader: admin=%d, reader=%d",
				len(admin.Statement[0].Action), len(reader.Statement[0].Action))
		}

		// Admin should have PutParameter
		hasPut := false
		for _, action := range admin.Statement[0].Action {
			if action == "ssm:PutParameter" {
				hasPut = true
				break
			}
		}
		if !hasPut {
			t.Error("Admin policy should have ssm:PutParameter action")
		}

		// Admin should have DeleteParameter
		hasDelete := false
		for _, action := range admin.Statement[0].Action {
			if action == "ssm:DeleteParameter" {
				hasDelete = true
				break
			}
		}
		if !hasDelete {
			t.Error("Admin policy should have ssm:DeleteParameter action")
		}
	})

	t.Run("same resource for admin and reader", func(t *testing.T) {
		policyRoot := "/test/path"

		reader := GenerateReaderPolicy(policyRoot)
		admin := GenerateAdminPolicy(policyRoot)

		// Both should have the same resource ARN
		if reader.Statement[0].Resource[0] != admin.Statement[0].Resource[0] {
			t.Errorf("Reader and Admin should have same resource: reader=%q, admin=%q",
				reader.Statement[0].Resource[0], admin.Statement[0].Resource[0])
		}
	})
}
