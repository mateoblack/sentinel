package enforce

import (
	"errors"
	"fmt"
)

// TrustPolicyPattern represents the three documented patterns from ENFORCEMENT.md
type TrustPolicyPattern string

const (
	// PatternA represents any Sentinel-issued credentials.
	// Requires SourceIdentity to match sentinel:*
	PatternA TrustPolicyPattern = "any-sentinel"
	// PatternB represents Sentinel + specific users.
	// Requires SourceIdentity to match sentinel:<user>:*
	PatternB TrustPolicyPattern = "specific-users"
	// PatternC represents Sentinel OR legacy (migration period).
	// Includes both Sentinel condition and legacy principal without condition.
	PatternC TrustPolicyPattern = "migration"
)

// IsValid returns true if the pattern is a known value.
func (p TrustPolicyPattern) IsValid() bool {
	return p == PatternA || p == PatternB || p == PatternC
}

// String returns the string representation of the pattern.
func (p TrustPolicyPattern) String() string {
	return string(p)
}

// GenerateInput contains options for trust policy generation.
type GenerateInput struct {
	// Pattern is the trust policy pattern to generate.
	Pattern TrustPolicyPattern
	// PrincipalARN is the AWS principal ARN (e.g., "arn:aws:iam::123456789012:root").
	PrincipalARN string
	// Users is the list of usernames to allow for Pattern B (e.g., ["alice", "bob"]).
	Users []string
	// LegacyPrincipal is the legacy principal ARN for Pattern C.
	LegacyPrincipal string
}

// GenerateOutput contains the generated trust policy.
type GenerateOutput struct {
	// Pattern is the pattern that was used to generate the policy.
	Pattern TrustPolicyPattern `json:"pattern"`
	// Policy is the generated trust policy document.
	Policy *TrustPolicyDocument `json:"policy"`
}

// GenerateTrustPolicy generates a trust policy document based on the input pattern.
// It validates the input and returns an error for invalid combinations.
func GenerateTrustPolicy(input GenerateInput) (*GenerateOutput, error) {
	// Validate pattern
	if !input.Pattern.IsValid() {
		return nil, errors.New("pattern is required: must be one of 'any-sentinel', 'specific-users', or 'migration'")
	}

	// Validate principal ARN
	if input.PrincipalARN == "" {
		return nil, errors.New("principal ARN is required")
	}

	// Pattern-specific validation
	switch input.Pattern {
	case PatternB:
		if len(input.Users) == 0 {
			return nil, errors.New("users list is required for 'specific-users' pattern")
		}
	case PatternC:
		if input.LegacyPrincipal == "" {
			return nil, errors.New("legacy principal is required for 'migration' pattern")
		}
	}

	// Generate policy based on pattern
	var policy *TrustPolicyDocument
	var err error

	switch input.Pattern {
	case PatternA:
		policy, err = generatePatternA(input.PrincipalARN)
	case PatternB:
		policy, err = generatePatternB(input.PrincipalARN, input.Users)
	case PatternC:
		policy, err = generatePatternC(input.PrincipalARN, input.LegacyPrincipal)
	}

	if err != nil {
		return nil, err
	}

	return &GenerateOutput{
		Pattern: input.Pattern,
		Policy:  policy,
	}, nil
}

// generatePatternA creates a trust policy that allows any Sentinel-issued credentials.
// This is Pattern A from ENFORCEMENT.md.
func generatePatternA(principalARN string) (*TrustPolicyDocument, error) {
	return &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Sid:    "AllowSentinelAccess",
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{principalARN},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
		},
	}, nil
}

// generatePatternB creates a trust policy that allows specific Sentinel users.
// This is Pattern B from ENFORCEMENT.md.
func generatePatternB(principalARN string, users []string) (*TrustPolicyDocument, error) {
	if len(users) == 0 {
		return nil, errors.New("at least one user is required for pattern B")
	}

	// Build user-specific patterns: sentinel:alice:*, sentinel:bob:*
	patterns := make(StringOrSlice, len(users))
	for i, user := range users {
		patterns[i] = fmt.Sprintf("sentinel:%s:*", user)
	}

	return &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Sid:    "AllowSentinelUsers",
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{principalARN},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": patterns,
					},
				},
			},
		},
	}, nil
}

// generatePatternC creates a trust policy with both Sentinel and legacy access.
// This is Pattern C from ENFORCEMENT.md (migration mode).
func generatePatternC(principalARN, legacyPrincipal string) (*TrustPolicyDocument, error) {
	return &TrustPolicyDocument{
		Version: "2012-10-17",
		Statement: []Statement{
			{
				Sid:    "AllowSentinelAccess",
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{principalARN},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
			{
				Sid:    "AllowLegacyAccess",
				Effect: "Allow",
				Principal: Principal{
					AWS: StringOrSlice{legacyPrincipal},
				},
				Action: StringOrSlice{"sts:AssumeRole"},
			},
		},
	}, nil
}
