package enforce

import (
	"testing"
)

// ============================================================================
// ValidateTrustPolicy Tests
// ============================================================================

func TestValidateTrustPolicy_NilPolicy(t *testing.T) {
	result := ValidateTrustPolicy(nil)

	if result.IsCompliant {
		t.Error("expected non-compliant for nil policy")
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].RuleID != "TRUST-00" {
		t.Errorf("expected TRUST-00, got %s", result.Findings[0].RuleID)
	}
	if result.RiskSummary[RiskLevelHigh] != 1 {
		t.Errorf("expected 1 HIGH finding, got %d", result.RiskSummary[RiskLevelHigh])
	}
}

func TestValidateTrustPolicy_TRUST01_WildcardPrincipal(t *testing.T) {
	// Wildcard principal without conditions
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect: "Allow",
				Principal: Principal{
					Wildcard: true,
				},
				Action: StringOrSlice{"sts:AssumeRole"},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	if result.IsCompliant {
		t.Error("expected non-compliant for wildcard principal without conditions")
	}

	// Should have TRUST-01 and TRUST-02 findings
	var hasTrust01 bool
	for _, f := range result.Findings {
		if f.RuleID == "TRUST-01" {
			hasTrust01 = true
			if f.RiskLevel != RiskLevelHigh {
				t.Errorf("TRUST-01 should be HIGH risk, got %s", f.RiskLevel)
			}
		}
	}
	if !hasTrust01 {
		t.Error("expected TRUST-01 finding for wildcard principal")
	}
}

func TestValidateTrustPolicy_TRUST02_MissingSourceIdentity(t *testing.T) {
	// Allow statement without SourceIdentity condition
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	if result.IsCompliant {
		t.Error("expected non-compliant for missing SourceIdentity")
	}

	var hasTrust02 bool
	for _, f := range result.Findings {
		if f.RuleID == "TRUST-02" {
			hasTrust02 = true
			if f.RiskLevel != RiskLevelHigh {
				t.Errorf("TRUST-02 should be HIGH risk, got %s", f.RiskLevel)
			}
		}
	}
	if !hasTrust02 {
		t.Error("expected TRUST-02 finding for missing SourceIdentity")
	}
}

func TestValidateTrustPolicy_TRUST03_InvalidSentinelPattern(t *testing.T) {
	// SourceIdentity pattern that doesn't match sentinel format
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:role/SomeRole"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"custom-prefix:*"},
					},
				},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	var hasTrust03 bool
	for _, f := range result.Findings {
		if f.RuleID == "TRUST-03" {
			hasTrust03 = true
			if f.RiskLevel != RiskLevelMedium {
				t.Errorf("TRUST-03 should be MEDIUM risk, got %s", f.RiskLevel)
			}
		}
	}
	if !hasTrust03 {
		t.Error("expected TRUST-03 finding for invalid sentinel pattern")
	}
}

func TestValidateTrustPolicy_TRUST04_RootWithoutProtection(t *testing.T) {
	// Root principal without ExternalId or SourceIdentity
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	if result.IsCompliant {
		t.Error("expected non-compliant for root principal without protection")
	}

	var hasTrust04 bool
	for _, f := range result.Findings {
		if f.RuleID == "TRUST-04" {
			hasTrust04 = true
			if f.RiskLevel != RiskLevelMedium {
				t.Errorf("TRUST-04 should be MEDIUM risk, got %s", f.RiskLevel)
			}
		}
	}
	if !hasTrust04 {
		t.Error("expected TRUST-04 finding for root principal without protection")
	}
}

func TestValidateTrustPolicy_TRUST05_StringEqualsWithWildcard(t *testing.T) {
	// Using StringEquals with wildcard pattern
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:role/SomeRole"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringEquals": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	var hasTrust05 bool
	for _, f := range result.Findings {
		if f.RuleID == "TRUST-05" {
			hasTrust05 = true
			if f.RiskLevel != RiskLevelLow {
				t.Errorf("TRUST-05 should be LOW risk, got %s", f.RiskLevel)
			}
		}
	}
	if !hasTrust05 {
		t.Error("expected TRUST-05 finding for StringEquals with wildcard")
	}
}

func TestValidateTrustPolicy_CompliantPolicy(t *testing.T) {
	// Fully compliant policy with sentinel:* pattern
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Sid:    "AllowSentinelAccess",
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	if !result.IsCompliant {
		t.Error("expected compliant for valid sentinel policy")
		for _, f := range result.Findings {
			t.Logf("Finding: %s - %s", f.RuleID, f.Message)
		}
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for compliant policy, got %d", len(result.Findings))
	}
}

func TestValidateTrustPolicy_UserSpecificPattern(t *testing.T) {
	// User-specific pattern sentinel:alice:*
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Sid:    "AllowAliceAccess",
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:alice:*"},
					},
				},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	if !result.IsCompliant {
		t.Error("expected compliant for user-specific sentinel pattern")
		for _, f := range result.Findings {
			t.Logf("Finding: %s - %s", f.RuleID, f.Message)
		}
	}
}

func TestValidateTrustPolicy_RootWithExternalId(t *testing.T) {
	// Root principal with ExternalId (protected)
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringEquals": ConditionOperator{
						"sts:ExternalId": StringOrSlice{"my-external-id"},
					},
				},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	// Should not have TRUST-04 because ExternalId is present
	for _, f := range result.Findings {
		if f.RuleID == "TRUST-04" {
			t.Error("should not have TRUST-04 when ExternalId is present")
		}
	}
}

func TestValidateTrustPolicy_DenyStatementIgnored(t *testing.T) {
	// Deny statements should be ignored for validation
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect: "Deny",
				Principal: Principal{
					Wildcard: true,
				},
				Action: StringOrSlice{"sts:AssumeRole"},
			},
			{
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	if !result.IsCompliant {
		t.Error("expected compliant - deny statement should be ignored")
	}
	// TRUST-01 should not fire for Deny statement
	for _, f := range result.Findings {
		if f.RuleID == "TRUST-01" {
			t.Error("TRUST-01 should not fire for Deny statement")
		}
	}
}

func TestValidateTrustPolicy_MultipleStatements(t *testing.T) {
	// Multiple statements with different issues
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Sid:    "GoodStatement",
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
			{
				Sid:    "BadStatement",
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	if result.IsCompliant {
		t.Error("expected non-compliant for mixed policy")
	}

	// Should have findings only for BadStatement
	for _, f := range result.Findings {
		if f.AffectedStatement == "GoodStatement" {
			t.Errorf("unexpected finding for GoodStatement: %s", f.RuleID)
		}
	}
}

func TestValidateTrustPolicy_RiskSummary(t *testing.T) {
	// Policy with multiple issues at different risk levels
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Sid:    "Statement1",
				Effect: "Allow",
				Principal: Principal{
					Wildcard: true,
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringEquals": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	if result.IsCompliant {
		t.Error("expected non-compliant")
	}

	// Should have findings at different risk levels
	if result.RiskSummary[RiskLevelLow] == 0 {
		t.Error("expected at least one LOW finding (TRUST-05)")
	}

	totalFindings := result.RiskSummary[RiskLevelHigh] + result.RiskSummary[RiskLevelMedium] + result.RiskSummary[RiskLevelLow]
	if totalFindings != len(result.Findings) {
		t.Errorf("risk summary count mismatch: %d vs %d findings", totalFindings, len(result.Findings))
	}
}

func TestValidateTrustPolicy_AffectedStatementUsesIndex(t *testing.T) {
	// Statement without Sid should use index
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
			},
		},
	}

	result := ValidateTrustPolicy(policy)

	for _, f := range result.Findings {
		if f.AffectedStatement != "Statement[0]" {
			t.Errorf("expected Statement[0], got %s", f.AffectedStatement)
		}
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestIsValidSentinelPattern(t *testing.T) {
	tests := []struct {
		pattern string
		valid   bool
	}{
		{"sentinel:*", true},
		{"sentinel:alice:*", true},
		{"sentinel:bob:abc123", true},
		{"custom:*", false},
		{"", false},
		{"sentinel", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			got := isValidSentinelPattern(tt.pattern)
			if got != tt.valid {
				t.Errorf("isValidSentinelPattern(%q) = %v, want %v", tt.pattern, got, tt.valid)
			}
		})
	}
}

func TestHasRootPrincipal(t *testing.T) {
	tests := []struct {
		name      string
		principal Principal
		hasRoot   bool
	}{
		{
			name: "root principal",
			principal: Principal{
				AWS: StringOrSlice{"arn:aws:iam::123456789012:root"},
			},
			hasRoot: true,
		},
		{
			name: "role principal",
			principal: Principal{
				AWS: StringOrSlice{"arn:aws:iam::123456789012:role/MyRole"},
			},
			hasRoot: false,
		},
		{
			name: "multiple with root",
			principal: Principal{
				AWS: StringOrSlice{
					"arn:aws:iam::123456789012:role/MyRole",
					"arn:aws:iam::123456789012:root",
				},
			},
			hasRoot: true,
		},
		{
			name:      "empty",
			principal: Principal{},
			hasRoot:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasRootPrincipal(tt.principal)
			if got != tt.hasRoot {
				t.Errorf("hasRootPrincipal() = %v, want %v", got, tt.hasRoot)
			}
		})
	}
}

func TestHasExternalIdCondition(t *testing.T) {
	tests := []struct {
		name    string
		cond    ConditionBlock
		hasExId bool
	}{
		{
			name: "has ExternalId",
			cond: ConditionBlock{
				"StringEquals": ConditionOperator{
					"sts:ExternalId": StringOrSlice{"my-id"},
				},
			},
			hasExId: true,
		},
		{
			name: "no ExternalId",
			cond: ConditionBlock{
				"StringLike": ConditionOperator{
					"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
				},
			},
			hasExId: false,
		},
		{
			name:    "nil condition",
			cond:    nil,
			hasExId: false,
		},
		{
			name:    "empty condition",
			cond:    ConditionBlock{},
			hasExId: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasExternalIdCondition(tt.cond)
			if got != tt.hasExId {
				t.Errorf("hasExternalIdCondition() = %v, want %v", got, tt.hasExId)
			}
		})
	}
}

func TestHasStringEqualsWithWildcard(t *testing.T) {
	tests := []struct {
		name        string
		cond        ConditionBlock
		hasWildcard bool
	}{
		{
			name: "StringEquals with wildcard",
			cond: ConditionBlock{
				"StringEquals": ConditionOperator{
					"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
				},
			},
			hasWildcard: true,
		},
		{
			name: "StringEquals without wildcard",
			cond: ConditionBlock{
				"StringEquals": ConditionOperator{
					"sts:SourceIdentity": StringOrSlice{"sentinel:alice:abc123"},
				},
			},
			hasWildcard: false,
		},
		{
			name: "StringLike with wildcard (not StringEquals)",
			cond: ConditionBlock{
				"StringLike": ConditionOperator{
					"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
				},
			},
			hasWildcard: false,
		},
		{
			name:        "nil condition",
			cond:        nil,
			hasWildcard: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasStringEqualsWithWildcard(tt.cond)
			if got != tt.hasWildcard {
				t.Errorf("hasStringEqualsWithWildcard() = %v, want %v", got, tt.hasWildcard)
			}
		})
	}
}
