package enforce

import (
	"strings"
	"testing"
)

func TestParseTrustPolicy(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    string
		wantStmts  int
		wantEffect string
	}{
		{
			name: "Pattern A - require any sentinel credentials",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "sts:AssumeRole",
						"Condition": {
							"StringLike": {
								"sts:SourceIdentity": "sentinel:*"
							}
						}
					}
				]
			}`,
			wantStmts:  1,
			wantEffect: "Allow",
		},
		{
			name: "Pattern B - sentinel AND specific users",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "sts:AssumeRole",
						"Condition": {
							"StringLike": {
								"sts:SourceIdentity": ["sentinel:alice:*", "sentinel:bob:*"]
							}
						}
					}
				]
			}`,
			wantStmts:  1,
			wantEffect: "Allow",
		},
		{
			name: "Pattern C - migration with multiple statements",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Sid": "AllowSentinelAccess",
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "sts:AssumeRole",
						"Condition": {
							"StringLike": {
								"sts:SourceIdentity": "sentinel:*"
							}
						}
					},
					{
						"Sid": "AllowLegacyAccess",
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:role/LegacyServiceRole"},
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantStmts: 2,
		},
		{
			name: "SCP pattern - deny without sentinel",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Sid": "RequireSentinelSourceIdentity",
						"Effect": "Deny",
						"Action": "sts:AssumeRole",
						"Principal": "*",
						"Condition": {
							"StringNotLike": {
								"sts:SourceIdentity": "sentinel:*"
							}
						}
					}
				]
			}`,
			wantStmts:  1,
			wantEffect: "Deny",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: "empty trust policy",
		},
		{
			name:    "invalid JSON",
			input:   "{invalid json}",
			wantErr: "invalid JSON",
		},
		{
			name: "missing Version",
			input: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantErr: "missing Version",
		},
		{
			name: "missing Statement",
			input: `{
				"Version": "2012-10-17"
			}`,
			wantErr: "missing Statement",
		},
		{
			name: "invalid Effect",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Maybe",
						"Principal": "*",
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantErr: "Effect must be Allow or Deny",
		},
		{
			name: "missing Action",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*"
					}
				]
			}`,
			wantErr: "missing Action",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := ParseTrustPolicy([]byte(tc.input))

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

			if len(doc.Statement) != tc.wantStmts {
				t.Errorf("got %d statements, want %d", len(doc.Statement), tc.wantStmts)
			}

			if tc.wantEffect != "" && doc.Statement[0].Effect != tc.wantEffect {
				t.Errorf("got Effect %q, want %q", doc.Statement[0].Effect, tc.wantEffect)
			}
		})
	}
}

func TestPrincipalVariants(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantWildcard bool
		wantAWS      []string
		wantService  []string
	}{
		{
			name: "wildcard principal",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantWildcard: true,
		},
		{
			name: "single AWS principal",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantAWS: []string{"arn:aws:iam::123456789012:root"},
		},
		{
			name: "multiple AWS principals",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": ["arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"]},
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantAWS: []string{"arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"},
		},
		{
			name: "service principal",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"Service": "ec2.amazonaws.com"},
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantService: []string{"ec2.amazonaws.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := ParseTrustPolicy([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			principal := doc.Statement[0].Principal

			if principal.Wildcard != tc.wantWildcard {
				t.Errorf("got Wildcard %v, want %v", principal.Wildcard, tc.wantWildcard)
			}

			if tc.wantAWS != nil {
				if len(principal.AWS) != len(tc.wantAWS) {
					t.Errorf("got %d AWS principals, want %d", len(principal.AWS), len(tc.wantAWS))
				}
				for i, want := range tc.wantAWS {
					if i >= len(principal.AWS) {
						break
					}
					if principal.AWS[i] != want {
						t.Errorf("AWS[%d] = %q, want %q", i, principal.AWS[i], want)
					}
				}
			}

			if tc.wantService != nil {
				if len(principal.Service) != len(tc.wantService) {
					t.Errorf("got %d Service principals, want %d", len(principal.Service), len(tc.wantService))
				}
				for i, want := range tc.wantService {
					if i >= len(principal.Service) {
						break
					}
					if principal.Service[i] != want {
						t.Errorf("Service[%d] = %q, want %q", i, principal.Service[i], want)
					}
				}
			}
		})
	}
}

func TestConditionBlockSourceIdentity(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		wantHasCondition  bool
		wantHasDeny       bool
	}{
		{
			name: "StringLike sentinel:*",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "sts:AssumeRole",
						"Condition": {
							"StringLike": {
								"sts:SourceIdentity": "sentinel:*"
							}
						}
					}
				]
			}`,
			wantHasCondition: true,
		},
		{
			name: "StringLike sentinel:alice:*",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "sts:AssumeRole",
						"Condition": {
							"StringLike": {
								"sts:SourceIdentity": "sentinel:alice:*"
							}
						}
					}
				]
			}`,
			wantHasCondition: true,
		},
		{
			name: "StringNotLike sentinel:* (SCP pattern)",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Deny",
						"Principal": "*",
						"Action": "sts:AssumeRole",
						"Condition": {
							"StringNotLike": {
								"sts:SourceIdentity": "sentinel:*"
							}
						}
					}
				]
			}`,
			wantHasCondition: false,
			wantHasDeny:      true,
		},
		{
			name: "no SourceIdentity condition",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantHasCondition: false,
			wantHasDeny:      false,
		},
		{
			name: "other condition key",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "sts:AssumeRole",
						"Condition": {
							"StringLike": {
								"aws:RequestTag/Team": "engineering"
							}
						}
					}
				]
			}`,
			wantHasCondition: false,
			wantHasDeny:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := ParseTrustPolicy([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			condition := doc.Statement[0].Condition

			hasCondition := condition.HasSourceIdentityCondition()
			if hasCondition != tc.wantHasCondition {
				t.Errorf("HasSourceIdentityCondition() = %v, want %v", hasCondition, tc.wantHasCondition)
			}

			hasDeny := condition.HasSourceIdentityDeny()
			if hasDeny != tc.wantHasDeny {
				t.Errorf("HasSourceIdentityDeny() = %v, want %v", hasDeny, tc.wantHasDeny)
			}
		})
	}
}

func TestActionVariants(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantActions []string
	}{
		{
			name: "single action string",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "sts:AssumeRole"
					}
				]
			}`,
			wantActions: []string{"sts:AssumeRole"},
		},
		{
			name: "multiple actions array",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": ["sts:AssumeRole", "sts:AssumeRoleWithSAML"]
					}
				]
			}`,
			wantActions: []string{"sts:AssumeRole", "sts:AssumeRoleWithSAML"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := ParseTrustPolicy([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			actions := doc.Statement[0].Action

			if len(actions) != len(tc.wantActions) {
				t.Errorf("got %d actions, want %d", len(actions), len(tc.wantActions))
			}

			for i, want := range tc.wantActions {
				if i >= len(actions) {
					break
				}
				if actions[i] != want {
					t.Errorf("Action[%d] = %q, want %q", i, actions[i], want)
				}
			}
		})
	}
}

func TestStringOrSliceContains(t *testing.T) {
	s := StringOrSlice{"sts:AssumeRole", "sts:AssumeRoleWithSAML"}

	if !s.Contains("sts:AssumeRole") {
		t.Error("Contains(\"sts:AssumeRole\") should be true")
	}

	if s.Contains("sts:AssumeRoleWithWebIdentity") {
		t.Error("Contains(\"sts:AssumeRoleWithWebIdentity\") should be false")
	}
}

func TestEnforcementLevelIsValid(t *testing.T) {
	tests := []struct {
		level EnforcementLevel
		valid bool
	}{
		{EnforcementLevelAdvisory, true},
		{EnforcementLevelTrustPolicy, true},
		{EnforcementLevelSCP, true},
		{EnforcementLevel("invalid"), false},
		{EnforcementLevel(""), false},
	}

	for _, tc := range tests {
		t.Run(string(tc.level), func(t *testing.T) {
			if tc.level.IsValid() != tc.valid {
				t.Errorf("IsValid() = %v, want %v", tc.level.IsValid(), tc.valid)
			}
		})
	}
}

func TestEnforcementStatusIsValid(t *testing.T) {
	tests := []struct {
		status EnforcementStatus
		valid  bool
	}{
		{EnforcementStatusNone, true},
		{EnforcementStatusPartial, true},
		{EnforcementStatusFull, true},
		{EnforcementStatus("invalid"), false},
		{EnforcementStatus(""), false},
	}

	for _, tc := range tests {
		t.Run(string(tc.status), func(t *testing.T) {
			if tc.status.IsValid() != tc.valid {
				t.Errorf("IsValid() = %v, want %v", tc.status.IsValid(), tc.valid)
			}
		})
	}
}
