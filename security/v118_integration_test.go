// Package security provides integration tests for v1.18 security hardening.
// These tests validate that security features work together across packages.
//
// v1.18 Security Hardening includes:
// - Phase 126: Policy Integrity (KMS signature verification)
// - Phase 127: Break-Glass MFA (TOTP and SMS verification)
// - Phase 128: Audit Log Integrity (signed log entries)
// - Phase 129: Local Server Security (Unix socket authentication)
// - Phase 130: Identity Hardening (ARN validation and sanitization)
// - Phase 131: DynamoDB Security (state transitions and optimistic locking)
// - Phase 132: Keyring Protection (secure credential storage)
// - Phase 133: Rate Limit Hardening (DynamoDB rate limiting)
// - Phase 134: Input Sanitization (profile names, shell escaping)
//
// Tests use TestSecurityRegression_ prefix for CI/CD filtering.
package security

import (
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/validate"
)

// ============================================================================
// Cross-Phase Integration Tests
// ============================================================================

// TestSecurityRegression_InputValidationInIdentityExtraction verifies input
// sanitization (Phase 134) is applied to identity extraction (Phase 130).
// THREAT: Malicious ARN with special characters could bypass sanitization.
// PREVENTION: identity.ExtractUsername applies sanitization to all ARN components.
func TestSecurityRegression_InputValidationInIdentityExtraction(t *testing.T) {
	tests := []struct {
		name        string
		arn         string
		wantErr     bool
		description string
	}{
		{
			name:        "valid_user_arn",
			arn:         "arn:aws:iam::123456789012:user/alice",
			wantErr:     false,
			description: "Standard user ARN should work",
		},
		{
			name:        "valid_role_arn",
			arn:         "arn:aws:sts::123456789012:assumed-role/MyRole/alice",
			wantErr:     false,
			description: "Assumed role ARN should work",
		},
		{
			name:        "valid_govcloud_arn",
			arn:         "arn:aws-us-gov:iam::123456789012:user/alice",
			wantErr:     false,
			description: "GovCloud ARN should work",
		},
		{
			name:        "valid_china_arn",
			arn:         "arn:aws-cn:iam::123456789012:user/alice",
			wantErr:     false,
			description: "China region ARN should work",
		},
		{
			name:        "valid_iso_arn",
			arn:         "arn:aws-iso:iam::123456789012:user/alice",
			wantErr:     false,
			description: "ISO (DoD) partition ARN should work",
		},
		{
			name:        "valid_iso_b_arn",
			arn:         "arn:aws-iso-b:iam::123456789012:user/alice",
			wantErr:     false,
			description: "ISO-B (C2S) partition ARN should work",
		},
		{
			name:        "invalid_partition",
			arn:         "arn:aws-fake:iam::123456789012:user/alice",
			wantErr:     true,
			description: "Invalid partition should be rejected",
		},
		{
			name:        "empty_arn",
			arn:         "",
			wantErr:     true,
			description: "Empty ARN should be rejected",
		},
		{
			name:        "malformed_arn",
			arn:         "not-an-arn",
			wantErr:     true,
			description: "Malformed ARN should be rejected",
		},
		{
			name:        "null_byte_injection",
			arn:         "arn:aws:iam::123456789012:user/alice\x00admin",
			wantErr:     false, // Sanitization strips null bytes, producing "aliceadmin"
			description: "Null byte injection should be sanitized (stripped)",
		},
		{
			name:        "newline_injection",
			arn:         "arn:aws:iam::123456789012:user/alice\nadmin",
			wantErr:     false, // Sanitization strips newlines, producing "aliceadmin"
			description: "Newline injection should be sanitized (stripped)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, err := identity.ExtractUsername(tt.arn)

			if tt.wantErr {
				if err == nil {
					t.Errorf("SECURITY VIOLATION: %s - expected error but got username %q", tt.description, username)
				}
			} else {
				if err != nil {
					t.Errorf("REGRESSION: %s - unexpected error: %v", tt.description, err)
				}
				if username == "" {
					t.Errorf("REGRESSION: %s - empty username returned", tt.description)
				}
				// Verify sanitization was applied - no special characters in output
				if strings.ContainsAny(username, "\x00\n\r\t\\\"'") {
					t.Errorf("SECURITY VIOLATION: Username contains unsanitized special characters: %q", username)
				}
			}
		})
	}
}

// TestSecurityRegression_AllInputVectorsValidated verifies all user input entry
// points use validation (Phase 134).
// THREAT: Unvalidated input could lead to injection attacks.
// PREVENTION: All input vectors have corresponding validation functions.
func TestSecurityRegression_AllInputVectorsValidated(t *testing.T) {
	t.Run("profile_names_validated", func(t *testing.T) {
		// Profile names must be validated
		validProfiles := []string{
			"production",
			"prod-role",
			"prod_role",
			"/sentinel/policies/production",
		}

		for _, profile := range validProfiles {
			if err := validate.ValidateProfileName(profile); err != nil {
				t.Errorf("REGRESSION: Valid profile %q rejected: %v", profile, err)
			}
		}

		invalidProfiles := []string{
			"../../../etc/passwd",
			"profile;rm -rf /",
			"profile`whoami`",
			"profile$(cat /etc/passwd)",
			"profile\x00admin",
			"profile\nadmin",
		}

		for _, profile := range invalidProfiles {
			if err := validate.ValidateProfileName(profile); err == nil {
				t.Errorf("SECURITY VIOLATION: Invalid profile %q not rejected", profile)
			}
		}
	})

	t.Run("arns_validated", func(t *testing.T) {
		// ARNs must be validated via identity package
		// Note: IAM roles (arn:aws:iam::...:role/X) are not supported - only user/ and root
		// Role identities come from STS as assumed-role ARNs
		validARNs := []string{
			"arn:aws:iam::123456789012:user/alice",
			"arn:aws-us-gov:iam::123456789012:user/admin", // GovCloud user, not role
			"arn:aws-cn:sts::123456789012:assumed-role/MyRole/session",
		}

		for _, arn := range validARNs {
			if _, err := identity.ExtractUsername(arn); err != nil {
				t.Errorf("REGRESSION: Valid ARN %q rejected: %v", arn, err)
			}
		}

		invalidARNs := []string{
			"arn:aws-fake:iam::123456789012:user/alice",
			"",
			"not-an-arn",
		}

		for _, arn := range invalidARNs {
			if _, err := identity.ExtractUsername(arn); err == nil {
				t.Errorf("SECURITY VIOLATION: Invalid ARN %q not rejected", arn)
			}
		}
	})

	t.Run("log_messages_sanitized", func(t *testing.T) {
		// Log messages must be sanitized
		dangerousInputs := []string{
			"user\n[ALERT] System compromised!",
			"user\rFake: success",
			"user\x1b[31mRED TEXT\x1b[0m",
			"safe\x00malicious",
		}

		for _, input := range dangerousInputs {
			sanitized := validate.SanitizeForLog(input, 200)

			// Verify control characters are escaped, not present raw
			if strings.ContainsAny(sanitized, "\n\r\x1b\x00") {
				t.Errorf("SECURITY VIOLATION: Log sanitization failed for input %q, got: %q", input, sanitized)
			}
		}
	})
}

// TestSecurityRegression_DynamoDBSecurityAcrossStores verifies state validation
// (Phase 131) works for all DynamoDB stores.
// THREAT: Invalid state transitions could allow unauthorized credential access.
// PREVENTION: All stores validate state transitions and reject invalid ones.
func TestSecurityRegression_DynamoDBSecurityAcrossStores(t *testing.T) {
	t.Run("request_status_transitions", func(t *testing.T) {
		// Valid transitions - from pending to terminal states
		validTransitions := []struct {
			from request.RequestStatus
			to   request.RequestStatus
		}{
			{request.StatusPending, request.StatusApproved},
			{request.StatusPending, request.StatusDenied},
			{request.StatusPending, request.StatusExpired},
			{request.StatusPending, request.StatusCancelled},
		}

		for _, tt := range validTransitions {
			if !tt.from.ValidTransition(tt.to) {
				t.Errorf("REGRESSION: Valid transition %s -> %s rejected", tt.from, tt.to)
			}
		}

		// Invalid transitions - terminal states cannot transition to different states
		invalidTransitions := []struct {
			from request.RequestStatus
			to   request.RequestStatus
			desc string
		}{
			{request.StatusApproved, request.StatusPending, "cannot go back to pending"},
			{request.StatusDenied, request.StatusApproved, "cannot approve after denial"},
			{request.StatusExpired, request.StatusApproved, "cannot approve after expiry"},
			{request.StatusCancelled, request.StatusPending, "cannot reopen cancelled"},
			{request.StatusApproved, request.StatusDenied, "cannot deny after approval"},
		}

		for _, tt := range invalidTransitions {
			if tt.from.ValidTransition(tt.to) {
				t.Errorf("SECURITY VIOLATION: Invalid transition %s -> %s allowed (%s)",
					tt.from, tt.to, tt.desc)
			}
		}
	})

	t.Run("breakglass_status_transitions", func(t *testing.T) {
		// Valid transitions
		validTransitions := []struct {
			from breakglass.BreakGlassStatus
			to   breakglass.BreakGlassStatus
		}{
			{breakglass.StatusActive, breakglass.StatusExpired},
			{breakglass.StatusActive, breakglass.StatusClosed},
		}

		for _, tt := range validTransitions {
			if !tt.from.ValidTransition(tt.to) {
				t.Errorf("REGRESSION: Valid break-glass transition %s -> %s rejected", tt.from, tt.to)
			}
		}

		// Invalid transitions - terminal states cannot transition
		terminalStates := []breakglass.BreakGlassStatus{
			breakglass.StatusExpired,
			breakglass.StatusClosed,
		}

		for _, terminal := range terminalStates {
			// Terminal states should not allow any transition
			if terminal.ValidTransition(breakglass.StatusActive) {
				t.Errorf("SECURITY VIOLATION: Terminal state %s allowed transition to Active", terminal)
			}
		}
	})

	t.Run("request_status_validity", func(t *testing.T) {
		// Valid statuses
		validStatuses := []request.RequestStatus{
			request.StatusPending,
			request.StatusApproved,
			request.StatusDenied,
			request.StatusExpired,
			request.StatusCancelled,
		}

		for _, status := range validStatuses {
			if !status.IsValid() {
				t.Errorf("REGRESSION: Valid status %s rejected", status)
			}
		}

		// Invalid statuses
		invalidStatuses := []request.RequestStatus{
			"",
			"invalid",
			"Pending",  // Wrong case
			"APPROVED", // Wrong case
			"'; DROP TABLE;--",
		}

		for _, status := range invalidStatuses {
			if status.IsValid() {
				t.Errorf("SECURITY VIOLATION: Invalid status %q accepted", status)
			}
		}
	})

	t.Run("breakglass_status_validity", func(t *testing.T) {
		// Valid statuses
		validStatuses := []breakglass.BreakGlassStatus{
			breakglass.StatusActive,
			breakglass.StatusExpired,
			breakglass.StatusClosed,
		}

		for _, status := range validStatuses {
			if !status.IsValid() {
				t.Errorf("REGRESSION: Valid break-glass status %s rejected", status)
			}
		}

		// Invalid statuses
		invalidStatuses := []breakglass.BreakGlassStatus{
			"",
			"invalid",
			"Active",  // Wrong case
			"EXPIRED", // Wrong case
			"'; DROP TABLE;--",
		}

		for _, status := range invalidStatuses {
			if status.IsValid() {
				t.Errorf("SECURITY VIOLATION: Invalid break-glass status %q accepted", status)
			}
		}
	})
}

// TestSecurityRegression_BreakGlassStatusTerminalEnforcement verifies that
// terminal states (Expired, Closed) cannot be used for credential issuance.
// THREAT: Manipulated status field could reactivate expired break-glass.
// PREVENTION: Terminal states are checked and rejected for credential access.
func TestSecurityRegression_BreakGlassStatusTerminalEnforcement(t *testing.T) {
	terminalStatuses := []breakglass.BreakGlassStatus{
		breakglass.StatusExpired,
		breakglass.StatusClosed,
	}

	for _, status := range terminalStatuses {
		t.Run(string(status), func(t *testing.T) {
			if !status.IsTerminal() {
				t.Errorf("SECURITY VIOLATION: Status %s should be terminal", status)
			}

			// Terminal statuses should not transition to different states
			// Note: ValidTransition returns true for same status (idempotent updates)
			otherStatuses := []breakglass.BreakGlassStatus{
				breakglass.StatusActive,
			}
			// Also check transitions between terminal states
			if status == breakglass.StatusExpired {
				otherStatuses = append(otherStatuses, breakglass.StatusClosed)
			} else if status == breakglass.StatusClosed {
				otherStatuses = append(otherStatuses, breakglass.StatusExpired)
			}

			for _, target := range otherStatuses {
				if status.ValidTransition(target) {
					t.Errorf("SECURITY VIOLATION: Terminal status %s should not transition to %s",
						status, target)
				}
			}
		})
	}
}

// TestSecurityRegression_SanitizedUsernameFormatConsistent verifies that
// sanitized usernames follow a consistent format across the codebase.
// THREAT: Inconsistent sanitization could allow injection in some paths.
// PREVENTION: All sanitized usernames are alphanumeric only.
func TestSecurityRegression_SanitizedUsernameFormatConsistent(t *testing.T) {
	// Test that usernames from ARNs are sanitized consistently
	testARNs := []struct {
		arn              string
		containsSpecial  bool
		expectedUsername string // expected sanitized username (alphanumeric only)
	}{
		{
			arn:              "arn:aws:iam::123456789012:user/alice",
			containsSpecial:  false,
			expectedUsername: "alice",
		},
		{
			arn:              "arn:aws:iam::123456789012:user/alice-test",
			containsSpecial:  true, // contains hyphen
			expectedUsername: "alicetest",
		},
		{
			arn:              "arn:aws:iam::123456789012:user/alice_test",
			containsSpecial:  true, // contains underscore
			expectedUsername: "alicetest",
		},
		{
			arn:              "arn:aws:iam::123456789012:user/alice.test",
			containsSpecial:  true, // contains dot
			expectedUsername: "alicetest",
		},
	}

	for _, tc := range testARNs {
		t.Run(tc.arn, func(t *testing.T) {
			// ExtractUsername returns the sanitized username (alphanumeric only)
			username, err := identity.ExtractUsername(tc.arn)
			if err != nil {
				t.Fatalf("ExtractUsername failed: %v", err)
			}

			// Verify sanitized username is alphanumeric only
			for _, r := range username {
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
					t.Errorf("SECURITY VIOLATION: Username %q contains non-alphanumeric char %q",
						username, string(r))
				}
			}

			// Verify the sanitized username matches our expected value
			if username != tc.expectedUsername {
				t.Errorf("SECURITY VIOLATION: Expected username %q, got %q", tc.expectedUsername, username)
			}

			// Double-check that SanitizeUser is idempotent on already-sanitized input
			sanitized, err := identity.SanitizeUser(username)
			if err != nil {
				t.Fatalf("SanitizeUser failed: %v", err)
			}
			if sanitized != username {
				t.Errorf("SanitizeUser not idempotent: %q != %q", sanitized, username)
			}
		})
	}
}

// TestSecurityRegression_ValidationErrorsSanitizedForLogging verifies that
// error messages from validation don't leak sensitive information.
// THREAT: Error messages containing user input could enable log injection.
// PREVENTION: Error messages sanitize user input before including it.
func TestSecurityRegression_ValidationErrorsSanitizedForLogging(t *testing.T) {
	// These inputs contain characters that could be dangerous in logs
	dangerousInputs := []string{
		"profile\n[ALERT] Fake alert",
		"profile\r\n[ERROR] Fake error",
		"profile\x1b[31mRED\x1b[0m",
		"profile\x00truncated",
	}

	for _, input := range dangerousInputs {
		t.Run("", func(t *testing.T) {
			err := validate.ValidateProfileName(input)
			if err == nil {
				t.Skip("Input was not rejected, cannot check error message")
			}

			errMsg := err.Error()

			// Error message should not contain raw control characters
			if strings.ContainsAny(errMsg, "\n\r\x1b\x00") {
				t.Errorf("SECURITY VIOLATION: Error message contains raw control chars: %q", errMsg)
			}
		})
	}
}

// TestSecurityRegression_PartitionValidationComplete verifies all 5 AWS partitions
// are supported and invalid partitions are rejected.
// THREAT: Missing partition support could block legitimate users.
// THREAT: Accepting invalid partitions could allow spoofed identities.
// PREVENTION: Explicit allowlist of valid partitions.
func TestSecurityRegression_PartitionValidationComplete(t *testing.T) {
	// All 5 valid AWS partitions
	validPartitions := []struct {
		partition   string
		description string
	}{
		{"aws", "Commercial AWS"},
		{"aws-cn", "China regions"},
		{"aws-us-gov", "GovCloud"},
		{"aws-iso", "ISO (DoD/IC)"},
		{"aws-iso-b", "ISO-B (C2S)"},
	}

	for _, p := range validPartitions {
		t.Run(p.partition, func(t *testing.T) {
			arn := "arn:" + p.partition + ":iam::123456789012:user/alice"
			_, err := identity.ExtractUsername(arn)
			if err != nil {
				t.Errorf("REGRESSION: Valid partition %s (%s) rejected: %v", p.partition, p.description, err)
			}
		})
	}

	// Invalid partitions
	invalidPartitions := []string{
		"aws-fake",
		"aws-gov", // Missing -us
		"amazon",
		"gcp",
		"azure",
		"",
		"AWS", // Wrong case
	}

	for _, partition := range invalidPartitions {
		t.Run("invalid_"+partition, func(t *testing.T) {
			arn := "arn:" + partition + ":iam::123456789012:user/alice"
			if _, err := identity.ExtractUsername(arn); err == nil {
				t.Errorf("SECURITY VIOLATION: Invalid partition %q accepted", partition)
			}
		})
	}
}

// TestSecurityRegression_ProfileNameSecurityBoundaries tests the security
// boundaries of profile name validation comprehensively.
// THREAT: Profile names are used in SSM paths, shell commands, and file paths.
// PREVENTION: Strict validation prevents injection attacks in all contexts.
func TestSecurityRegression_ProfileNameSecurityBoundaries(t *testing.T) {
	t.Run("path_traversal_blocked", func(t *testing.T) {
		traversalAttempts := []string{
			"../secret",
			"..\\secret",
			"foo/../../../etc/passwd",
			"./hidden",
			"/./sensitive",
			"//double/slash",
		}

		for _, attempt := range traversalAttempts {
			if err := validate.ValidateProfileName(attempt); err == nil {
				t.Errorf("SECURITY VIOLATION: Path traversal %q not blocked", attempt)
			}
		}
	})

	t.Run("shell_metacharacters_blocked", func(t *testing.T) {
		shellInjections := []string{
			"profile;id",
			"profile|cat /etc/passwd",
			"profile`whoami`",
			"profile$(id)",
			"profile&background",
			"profile>output",
			"profile<input",
		}

		for _, attempt := range shellInjections {
			if err := validate.ValidateProfileName(attempt); err == nil {
				t.Errorf("SECURITY VIOLATION: Shell injection %q not blocked", attempt)
			}
		}
	})

	t.Run("control_characters_blocked", func(t *testing.T) {
		for i := 0; i < 32; i++ {
			profile := "test" + string(rune(i)) + "profile"
			if err := validate.ValidateProfileName(profile); err == nil {
				t.Errorf("SECURITY VIOLATION: Control character 0x%02x not blocked", i)
			}
		}
		// DEL character (127)
		if err := validate.ValidateProfileName("test\x7fprofile"); err == nil {
			t.Error("SECURITY VIOLATION: DEL character (0x7f) not blocked")
		}
	})

	t.Run("unicode_homoglyphs_blocked", func(t *testing.T) {
		homoglyphs := []string{
			"\u0430dmin",  // Cyrillic 'a' looks like Latin 'a'
			"r\u03BFot",   // Greek omicron looks like 'o'
			"ad\u200Dmin", // Zero-width joiner
			"admin\u202E", // Right-to-left override
		}

		for _, attempt := range homoglyphs {
			if err := validate.ValidateProfileName(attempt); err == nil {
				t.Errorf("SECURITY VIOLATION: Unicode homoglyph %q not blocked", attempt)
			}
		}
	})

	t.Run("length_limits_enforced", func(t *testing.T) {
		// Verify max length is enforced
		maxLen := validate.MaxProfileNameLength

		atLimit := strings.Repeat("a", maxLen)
		if err := validate.ValidateProfileName(atLimit); err != nil {
			t.Errorf("REGRESSION: Profile at max length (%d) rejected: %v", maxLen, err)
		}

		overLimit := strings.Repeat("a", maxLen+1)
		if err := validate.ValidateProfileName(overLimit); err == nil {
			t.Errorf("SECURITY VIOLATION: Profile over max length (%d) not rejected", maxLen+1)
		}
	})
}
