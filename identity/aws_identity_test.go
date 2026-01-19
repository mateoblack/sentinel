package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestParseARN(t *testing.T) {
	tests := []struct {
		name            string
		arn             string
		wantType        IdentityType
		wantUsername    string
		wantRawUsername string
		wantAccountID   string
		wantErr         bool
		wantErrType     error
	}{
		// IAM User tests
		{
			name:            "IAM user simple",
			arn:             "arn:aws:iam::123456789012:user/alice",
			wantType:        IdentityTypeUser,
			wantUsername:    "alice",
			wantRawUsername: "alice",
			wantAccountID:   "123456789012",
		},
		{
			name:            "IAM user with single path",
			arn:             "arn:aws:iam::123456789012:user/admins/alice",
			wantType:        IdentityTypeUser,
			wantUsername:    "alice",
			wantRawUsername: "alice",
			wantAccountID:   "123456789012",
		},
		{
			name:            "IAM user with deep path",
			arn:             "arn:aws:iam::123456789012:user/division/team/alice",
			wantType:        IdentityTypeUser,
			wantUsername:    "alice",
			wantRawUsername: "alice",
			wantAccountID:   "123456789012",
		},
		{
			name:            "IAM user with very deep path",
			arn:             "arn:aws:iam::123456789012:user/org/division/team/subteam/alice",
			wantType:        IdentityTypeUser,
			wantUsername:    "alice",
			wantRawUsername: "alice",
			wantAccountID:   "123456789012",
		},
		// Assumed role tests
		{
			name:            "SSO assumed role with email",
			arn:             "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_DeveloperAccess_abc/alice@company.com",
			wantType:        IdentityTypeAssumedRole,
			wantUsername:    "alicecompanycom",
			wantRawUsername: "alice@company.com",
			wantAccountID:   "123456789012",
		},
		{
			name:            "SSO assumed role with complex email",
			arn:             "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdminAccess_xyz/alice.bob@sub.company.com",
			wantType:        IdentityTypeAssumedRole,
			wantUsername:    "alicebobsubcompanyco",
			wantRawUsername: "alice.bob@sub.company.com",
			wantAccountID:   "123456789012",
		},
		{
			name:            "Regular assumed role",
			arn:             "arn:aws:sts::123456789012:assumed-role/AdminRole/session123",
			wantType:        IdentityTypeAssumedRole,
			wantUsername:    "session123",
			wantRawUsername: "session123",
			wantAccountID:   "123456789012",
		},
		{
			name:            "Assumed role with simple session name",
			arn:             "arn:aws:sts::123456789012:assumed-role/MyRole/bob",
			wantType:        IdentityTypeAssumedRole,
			wantUsername:    "bob",
			wantRawUsername: "bob",
			wantAccountID:   "123456789012",
		},
		// Federated user tests
		{
			name:            "Federated user",
			arn:             "arn:aws:sts::123456789012:federated-user/alice",
			wantType:        IdentityTypeFederatedUser,
			wantUsername:    "alice",
			wantRawUsername: "alice",
			wantAccountID:   "123456789012",
		},
		{
			name:            "Federated user with special chars",
			arn:             "arn:aws:sts::123456789012:federated-user/alice_bob",
			wantType:        IdentityTypeFederatedUser,
			wantUsername:    "alicebob",
			wantRawUsername: "alice_bob",
			wantAccountID:   "123456789012",
		},
		// Root user tests
		{
			name:            "Root user",
			arn:             "arn:aws:iam::123456789012:root",
			wantType:        IdentityTypeRoot,
			wantUsername:    "root",
			wantRawUsername: "root",
			wantAccountID:   "123456789012",
		},
		// GovCloud partition tests
		{
			name:            "GovCloud IAM user",
			arn:             "arn:aws-us-gov:iam::123456789012:user/alice",
			wantType:        IdentityTypeUser,
			wantUsername:    "alice",
			wantRawUsername: "alice",
			wantAccountID:   "123456789012",
		},
		{
			name:            "GovCloud assumed role",
			arn:             "arn:aws-us-gov:sts::123456789012:assumed-role/MyRole/session",
			wantType:        IdentityTypeAssumedRole,
			wantUsername:    "session",
			wantRawUsername: "session",
			wantAccountID:   "123456789012",
		},
		// China partition tests
		{
			name:            "China IAM user",
			arn:             "arn:aws-cn:iam::123456789012:user/alice",
			wantType:        IdentityTypeUser,
			wantUsername:    "alice",
			wantRawUsername: "alice",
			wantAccountID:   "123456789012",
		},
		{
			name:            "China assumed role",
			arn:             "arn:aws-cn:sts::123456789012:assumed-role/MyRole/session",
			wantType:        IdentityTypeAssumedRole,
			wantUsername:    "session",
			wantRawUsername: "session",
			wantAccountID:   "123456789012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := ParseARN(tt.arn)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseARN() expected error, got nil")
					return
				}
				if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
					t.Errorf("ParseARN() error = %v, wantErrType = %v", err, tt.wantErrType)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseARN() unexpected error = %v", err)
				return
			}

			if identity.Type != tt.wantType {
				t.Errorf("ParseARN() Type = %v, want %v", identity.Type, tt.wantType)
			}
			if identity.Username != tt.wantUsername {
				t.Errorf("ParseARN() Username = %v, want %v", identity.Username, tt.wantUsername)
			}
			if identity.RawUsername != tt.wantRawUsername {
				t.Errorf("ParseARN() RawUsername = %v, want %v", identity.RawUsername, tt.wantRawUsername)
			}
			if identity.AccountID != tt.wantAccountID {
				t.Errorf("ParseARN() AccountID = %v, want %v", identity.AccountID, tt.wantAccountID)
			}
			if identity.ARN != tt.arn {
				t.Errorf("ParseARN() ARN = %v, want %v", identity.ARN, tt.arn)
			}
		})
	}
}

func TestParseARN_Errors(t *testing.T) {
	tests := []struct {
		name        string
		arn         string
		wantErrType error
		wantErrMsg  string
	}{
		{
			name:        "empty ARN",
			arn:         "",
			wantErrType: ErrEmptyARN,
		},
		{
			name:       "missing parts",
			arn:        "arn:aws:iam",
			wantErrMsg: "expected 6 colon-separated parts",
		},
		{
			name:       "not an ARN",
			arn:        "not:an:arn:at:all:really",
			wantErrMsg: "must start with 'arn:'",
		},
		{
			name:       "invalid partition",
			arn:        "arn:aws-invalid:iam::123456789012:user/alice",
			wantErrMsg: "invalid partition",
		},
		{
			name:       "invalid account ID length",
			arn:        "arn:aws:iam::12345:user/alice",
			wantErrMsg: "account ID must be 12 digits",
		},
		{
			name:       "unsupported service",
			arn:        "arn:aws:ec2::123456789012:instance/i-12345",
			wantErrMsg: "unsupported service",
		},
		{
			name:       "unknown IAM resource type",
			arn:        "arn:aws:iam::123456789012:group/admins",
			wantErrMsg: "unknown IAM resource type",
		},
		{
			name:       "unknown STS resource type",
			arn:        "arn:aws:sts::123456789012:session/invalid",
			wantErrMsg: "unknown STS resource type",
		},
		{
			name:       "empty user path",
			arn:        "arn:aws:iam::123456789012:user/",
			wantErrMsg: "user path is empty",
		},
		{
			name:       "assumed role missing session name",
			arn:        "arn:aws:sts::123456789012:assumed-role/RoleName",
			wantErrMsg: "assumed-role must have format",
		},
		{
			name:       "assumed role empty session name",
			arn:        "arn:aws:sts::123456789012:assumed-role/RoleName/",
			wantErrMsg: "session name is empty",
		},
		{
			name:       "federated user empty name",
			arn:        "arn:aws:sts::123456789012:federated-user/",
			wantErrMsg: "federated user name is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := ParseARN(tt.arn)

			if err == nil {
				t.Errorf("ParseARN() expected error, got identity: %+v", identity)
				return
			}

			if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
				t.Errorf("ParseARN() error = %v, wantErrType = %v", err, tt.wantErrType)
			}

			if tt.wantErrMsg != "" && !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("ParseARN() error = %v, want error containing %q", err, tt.wantErrMsg)
			}
		})
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		name         string
		arn          string
		wantUsername string
		wantErr      bool
	}{
		{
			name:         "IAM user",
			arn:          "arn:aws:iam::123456789012:user/alice",
			wantUsername: "alice",
		},
		{
			name:         "assumed role with email",
			arn:          "arn:aws:sts::123456789012:assumed-role/MyRole/user@example.com",
			wantUsername: "userexamplecom",
		},
		{
			name:         "root user",
			arn:          "arn:aws:iam::123456789012:root",
			wantUsername: "root",
		},
		{
			name:    "invalid ARN",
			arn:     "invalid",
			wantErr: true,
		},
		{
			name:    "empty ARN",
			arn:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, err := ExtractUsername(tt.arn)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ExtractUsername() expected error, got username: %s", username)
				}
				return
			}

			if err != nil {
				t.Errorf("ExtractUsername() unexpected error = %v", err)
				return
			}

			if username != tt.wantUsername {
				t.Errorf("ExtractUsername() = %v, want %v", username, tt.wantUsername)
			}
		})
	}
}

func TestIdentityType(t *testing.T) {
	tests := []struct {
		identityType IdentityType
		wantValid    bool
		wantString   string
	}{
		{IdentityTypeUser, true, "user"},
		{IdentityTypeAssumedRole, true, "assumed-role"},
		{IdentityTypeFederatedUser, true, "federated-user"},
		{IdentityTypeRoot, true, "root"},
		{IdentityTypeUnknown, false, "unknown"},
		{IdentityType("invalid"), false, "invalid"},
	}

	for _, tt := range tests {
		t.Run(string(tt.identityType), func(t *testing.T) {
			if got := tt.identityType.IsValid(); got != tt.wantValid {
				t.Errorf("IdentityType.IsValid() = %v, want %v", got, tt.wantValid)
			}
			if got := tt.identityType.String(); got != tt.wantString {
				t.Errorf("IdentityType.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

func TestSanitization(t *testing.T) {
	tests := []struct {
		name         string
		arn          string
		wantUsername string
		description  string
	}{
		{
			name:         "email address sanitization",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/alice@company.com",
			wantUsername: "alicecompanycom",
			description:  "@ and . removed from email",
		},
		{
			name:         "complex email sanitization",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/alice.bob+test@sub.company.io",
			wantUsername: "alicebobtestsubcompa",
			description:  "special chars removed, truncated to 20 chars",
		},
		{
			name:         "underscore removed",
			arn:          "arn:aws:sts::123456789012:federated-user/alice_bob_carol",
			wantUsername: "alicebobcarol",
			description:  "underscores removed",
		},
		{
			name:         "hyphen removed",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/alice-session-123",
			wantUsername: "alicesession123",
			description:  "hyphens removed",
		},
		{
			name:         "long username truncated",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/verylongusernamethatexceedstwentycharacters",
			wantUsername: "verylongusernamethat",
			description:  "truncated to 20 characters",
		},
		{
			name:         "numeric username",
			arn:          "arn:aws:sts::123456789012:assumed-role/Role/12345",
			wantUsername: "12345",
			description:  "numeric usernames allowed",
		},
		{
			name:         "mixed case preserved in sanitization",
			arn:          "arn:aws:iam::123456789012:user/AliceBob",
			wantUsername: "AliceBob",
			description:  "case is preserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := ParseARN(tt.arn)
			if err != nil {
				t.Fatalf("ParseARN() error = %v", err)
			}

			if identity.Username != tt.wantUsername {
				t.Errorf("ParseARN() Username = %q, want %q (%s)", identity.Username, tt.wantUsername, tt.description)
			}
		})
	}
}

// Security tests to ensure no username spoofing via crafted ARNs
func TestSecurityNoUsernameSpoofing(t *testing.T) {
	tests := []struct {
		name        string
		arn         string
		description string
		wantErr     bool
		wantMsg     string
	}{
		{
			name:        "path traversal attempt in user",
			arn:         "arn:aws:iam::123456789012:user/../../../etc/passwd",
			description: "path traversal should not affect username extraction",
			wantErr:     false,
		},
		{
			name:        "null byte injection",
			arn:         "arn:aws:iam::123456789012:user/alice\x00admin",
			description: "null bytes should be sanitized",
			wantErr:     false,
		},
		{
			name:        "control characters",
			arn:         "arn:aws:iam::123456789012:user/alice\t\n\radmin",
			description: "control characters should be sanitized",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := ParseARN(tt.arn)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseARN() expected error for security test: %s", tt.description)
				}
				return
			}

			// For successful parses, verify the username is sanitized properly
			if err != nil {
				// Some invalid ARNs might legitimately fail
				return
			}

			// Verify no dangerous characters remain in username
			for _, c := range identity.Username {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
					t.Errorf("ParseARN() Username contains invalid character %q: %s", c, tt.description)
				}
			}
		})
	}
}

// TestEmailSanitization verifies that @ in email is properly sanitized
func TestEmailSanitization(t *testing.T) {
	tests := []struct {
		name  string
		arn   string
		check func(t *testing.T, identity *AWSIdentity)
	}{
		{
			name: "email @ removed",
			arn:  "arn:aws:sts::123456789012:assumed-role/Role/user@domain.com",
			check: func(t *testing.T, identity *AWSIdentity) {
				if strings.Contains(identity.Username, "@") {
					t.Errorf("Username should not contain @, got: %s", identity.Username)
				}
			},
		},
		{
			name: "email dots removed",
			arn:  "arn:aws:sts::123456789012:assumed-role/Role/user.name@sub.domain.com",
			check: func(t *testing.T, identity *AWSIdentity) {
				if strings.Contains(identity.Username, ".") {
					t.Errorf("Username should not contain ., got: %s", identity.Username)
				}
			},
		},
		{
			name: "raw username preserves email",
			arn:  "arn:aws:sts::123456789012:assumed-role/Role/user@domain.com",
			check: func(t *testing.T, identity *AWSIdentity) {
				if identity.RawUsername != "user@domain.com" {
					t.Errorf("RawUsername should preserve email, got: %s", identity.RawUsername)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := ParseARN(tt.arn)
			if err != nil {
				t.Fatalf("ParseARN() error = %v", err)
			}
			tt.check(t, identity)
		})
	}
}

// TestIdentityTypeFromARN verifies correct type detection for each ARN pattern
func TestIdentityTypeFromARN(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		wantType IdentityType
	}{
		{
			name:     "IAM user type",
			arn:      "arn:aws:iam::123456789012:user/alice",
			wantType: IdentityTypeUser,
		},
		{
			name:     "IAM user with path type",
			arn:      "arn:aws:iam::123456789012:user/path/alice",
			wantType: IdentityTypeUser,
		},
		{
			name:     "assumed role type",
			arn:      "arn:aws:sts::123456789012:assumed-role/Role/session",
			wantType: IdentityTypeAssumedRole,
		},
		{
			name:     "SSO assumed role type",
			arn:      "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/user@company.com",
			wantType: IdentityTypeAssumedRole,
		},
		{
			name:     "federated user type",
			arn:      "arn:aws:sts::123456789012:federated-user/alice",
			wantType: IdentityTypeFederatedUser,
		},
		{
			name:     "root user type",
			arn:      "arn:aws:iam::123456789012:root",
			wantType: IdentityTypeRoot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := ParseARN(tt.arn)
			if err != nil {
				t.Fatalf("ParseARN() error = %v", err)
			}

			if identity.Type != tt.wantType {
				t.Errorf("ParseARN() Type = %v, want %v", identity.Type, tt.wantType)
			}

			// Also verify the type is valid
			if !identity.Type.IsValid() {
				t.Errorf("ParseARN() returned invalid IdentityType: %v", identity.Type)
			}
		})
	}
}

// Benchmark tests
func BenchmarkParseARN_IAMUser(b *testing.B) {
	arn := "arn:aws:iam::123456789012:user/alice"
	for i := 0; i < b.N; i++ {
		_, _ = ParseARN(arn)
	}
}

func BenchmarkParseARN_AssumedRoleWithEmail(b *testing.B) {
	arn := "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/user@company.com"
	for i := 0; i < b.N; i++ {
		_, _ = ParseARN(arn)
	}
}

func BenchmarkExtractUsername(b *testing.B) {
	arn := "arn:aws:sts::123456789012:assumed-role/Role/user@company.com"
	for i := 0; i < b.N; i++ {
		_, _ = ExtractUsername(arn)
	}
}
