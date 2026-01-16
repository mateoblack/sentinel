package enforce

import (
	"testing"
)

func TestAnalyzeTrustPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policy         *TrustPolicyDocument
		wantStatus     EnforcementStatus
		wantHasCondition bool
		wantIssueCount int
		wantRecsCount  int
	}{
		{
			name:             "nil policy",
			policy:           nil,
			wantStatus:       EnforcementStatusNone,
			wantHasCondition: false,
			wantIssueCount:   1,
			wantRecsCount:    1,
		},
		{
			name: "Pattern A: Require any Sentinel",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
				},
			},
			wantStatus:       EnforcementStatusFull,
			wantHasCondition: true,
			wantIssueCount:   0,
			wantRecsCount:    0,
		},
		{
			name: "Pattern B: Require Sentinel + specific users",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:alice:*", "sentinel:bob:*"},
							},
						},
					},
				},
			},
			wantStatus:       EnforcementStatusFull,
			wantHasCondition: true,
			wantIssueCount:   0,
			wantRecsCount:    0,
		},
		{
			name: "Pattern C: Migration mode (OR condition)",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Sid:       "AllowSentinelAccess",
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
					{
						Sid:       "AllowLegacyAccess",
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:role/LegacyServiceRole"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
					},
				},
			},
			wantStatus:       EnforcementStatusPartial,
			wantHasCondition: true,
			wantIssueCount:   1, // Mixed enforcement
			wantRecsCount:    1, // Add condition to all statements
		},
		{
			name: "No enforcement",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
					},
				},
			},
			wantStatus:       EnforcementStatusNone,
			wantHasCondition: false,
			wantIssueCount:   1, // No SourceIdentity condition
			wantRecsCount:    1, // Add StringLike condition
		},
		{
			name: "StringEquals with wildcard pattern (wrong operator)",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringEquals": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
				},
			},
			wantStatus:       EnforcementStatusFull, // Still full since pattern matches
			wantHasCondition: true,
			wantIssueCount:   1, // Using StringEquals with wildcard
			wantRecsCount:    1, // Change to StringLike
		},
		{
			name: "Non-sentinel SourceIdentity pattern",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"other:*"},
							},
						},
					},
				},
			},
			wantStatus:       EnforcementStatusPartial,
			wantHasCondition: true,
			wantIssueCount:   1, // Pattern doesn't match sentinel:*
			wantRecsCount:    1, // Update pattern to sentinel:*
		},
		{
			name: "Multiple statements all enforced",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::111111111111:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::222222222222:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
				},
			},
			wantStatus:       EnforcementStatusFull,
			wantHasCondition: true,
			wantIssueCount:   0,
			wantRecsCount:    0,
		},
		{
			name: "SCP pattern with Deny and StringNotLike",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Sid:    "RequireSentinelSourceIdentity",
						Effect: "Deny",
						Principal: Principal{Wildcard: true},
						Action: StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringNotLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
				},
			},
			wantStatus:       EnforcementStatusNone, // No Allow statements
			wantHasCondition: false,
			wantIssueCount:   1, // No SourceIdentity in Allow statements
			wantRecsCount:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeTrustPolicy(tt.policy)

			if result.Status != tt.wantStatus {
				t.Errorf("Status = %v, want %v", result.Status, tt.wantStatus)
			}

			if result.HasSourceIdentityCondition != tt.wantHasCondition {
				t.Errorf("HasSourceIdentityCondition = %v, want %v", result.HasSourceIdentityCondition, tt.wantHasCondition)
			}

			if len(result.Issues) != tt.wantIssueCount {
				t.Errorf("Issues count = %d (%v), want %d", len(result.Issues), result.Issues, tt.wantIssueCount)
			}

			if len(result.Recommendations) != tt.wantRecsCount {
				t.Errorf("Recommendations count = %d (%v), want %d", len(result.Recommendations), result.Recommendations, tt.wantRecsCount)
			}
		})
	}
}

func TestAnalyzeTrustPolicyPatternA(t *testing.T) {
	// Pattern A from ENFORCEMENT.md: Require ANY Sentinel-Issued Credentials
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect:    "Allow",
				Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
				Action:    StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
		},
	}

	result := AnalyzeTrustPolicy(policy)

	if result.Status != EnforcementStatusFull {
		t.Errorf("Pattern A should be Full enforcement, got %v", result.Status)
	}
	if !result.HasSourceIdentityCondition {
		t.Error("Pattern A should have SourceIdentity condition")
	}
	if len(result.Issues) != 0 {
		t.Errorf("Pattern A should have no issues, got %v", result.Issues)
	}
	if len(result.Recommendations) != 0 {
		t.Errorf("Pattern A should have no recommendations, got %v", result.Recommendations)
	}
}

func TestAnalyzeTrustPolicyPatternB(t *testing.T) {
	// Pattern B from ENFORCEMENT.md: Require Sentinel AND Specific Users
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Effect:    "Allow",
				Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
				Action:    StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:alice:*", "sentinel:bob:*"},
					},
				},
			},
		},
	}

	result := AnalyzeTrustPolicy(policy)

	if result.Status != EnforcementStatusFull {
		t.Errorf("Pattern B should be Full enforcement, got %v", result.Status)
	}
	if !result.HasSourceIdentityCondition {
		t.Error("Pattern B should have SourceIdentity condition")
	}
	if len(result.Issues) != 0 {
		t.Errorf("Pattern B should have no issues, got %v", result.Issues)
	}
}

func TestAnalyzeTrustPolicyPatternC(t *testing.T) {
	// Pattern C from ENFORCEMENT.md: Allow Sentinel OR Legacy (Migration Period)
	policy := &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Sid:       "AllowSentinelAccess",
				Effect:    "Allow",
				Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
				Action:    StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
			{
				Sid:       "AllowLegacyAccess",
				Effect:    "Allow",
				Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:role/LegacyServiceRole"}},
				Action:    StringOrSlice{"sts:AssumeRole"},
			},
		},
	}

	result := AnalyzeTrustPolicy(policy)

	if result.Status != EnforcementStatusPartial {
		t.Errorf("Pattern C should be Partial enforcement, got %v", result.Status)
	}
	if !result.HasSourceIdentityCondition {
		t.Error("Pattern C should have SourceIdentity condition")
	}
	// Should have issue about mixed enforcement
	foundMixedIssue := false
	for _, issue := range result.Issues {
		if issue == "Mixed enforcement: some Allow statements lack SourceIdentity condition (migration mode)" {
			foundMixedIssue = true
			break
		}
	}
	if !foundMixedIssue {
		t.Errorf("Pattern C should have mixed enforcement issue, got %v", result.Issues)
	}
}

func TestIsEnforced(t *testing.T) {
	tests := []struct {
		name   string
		policy *TrustPolicyDocument
		want   bool
	}{
		{
			name:   "nil policy",
			policy: nil,
			want:   false,
		},
		{
			name: "enforced policy",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "non-enforced policy",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
					},
				},
			},
			want: false,
		},
		{
			name: "partial enforcement",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:role/Legacy"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
					},
				},
			},
			want: false, // Partial is not full enforcement
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsEnforced(tt.policy)
			if got != tt.want {
				t.Errorf("IsEnforced() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnalyzeStatement(t *testing.T) {
	tests := []struct {
		name         string
		stmt         *Statement
		wantEnforced bool
		wantPatterns int
	}{
		{
			name:         "nil statement",
			stmt:         nil,
			wantEnforced: false,
			wantPatterns: 0,
		},
		{
			name: "Deny statement",
			stmt: &Statement{
				Effect: "Deny",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringNotLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
			wantEnforced: false,
			wantPatterns: 0,
		},
		{
			name: "Allow with sentinel pattern",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
			wantEnforced: true,
			wantPatterns: 1,
		},
		{
			name: "Allow without condition",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
			},
			wantEnforced: false,
			wantPatterns: 0,
		},
		{
			name: "Allow with non-sentinel pattern",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"other:*"},
					},
				},
			},
			wantEnforced: false,
			wantPatterns: 1,
		},
		{
			name: "Allow with multiple user patterns",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:alice:*", "sentinel:bob:*"},
					},
				},
			},
			wantEnforced: true,
			wantPatterns: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enforced, patterns := AnalyzeStatement(tt.stmt)

			if enforced != tt.wantEnforced {
				t.Errorf("enforced = %v, want %v", enforced, tt.wantEnforced)
			}

			if len(patterns) != tt.wantPatterns {
				t.Errorf("patterns count = %d, want %d", len(patterns), tt.wantPatterns)
			}
		})
	}
}

func TestAnalyzeTrustPolicyRecommendations(t *testing.T) {
	tests := []struct {
		name    string
		policy  *TrustPolicyDocument
		wantRec string
	}{
		{
			name: "no enforcement - recommend adding condition",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
					},
				},
			},
			wantRec: "Add StringLike condition for sts:SourceIdentity with pattern sentinel:* to require Sentinel enforcement",
		},
		{
			name: "partial enforcement - recommend completing migration",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringLike": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:role/Legacy"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
					},
				},
			},
			wantRec: "Add sts:SourceIdentity condition to all Allow statements, or remove legacy statements after migration",
		},
		{
			name: "StringEquals with wildcard - recommend StringLike",
			policy: &TrustPolicyDocument{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect:    "Allow",
						Principal: Principal{AWS: StringOrSlice{"arn:aws:iam::123456789012:root"}},
						Action:    StringOrSlice{"sts:AssumeRole"},
						Condition: ConditionBlock{
							"StringEquals": ConditionOperator{
								"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
							},
						},
					},
				},
			},
			wantRec: "Change StringEquals to StringLike for wildcard patterns (sentinel:*)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeTrustPolicy(tt.policy)

			found := false
			for _, rec := range result.Recommendations {
				if rec == tt.wantRec {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected recommendation %q not found in %v", tt.wantRec, result.Recommendations)
			}
		})
	}
}
