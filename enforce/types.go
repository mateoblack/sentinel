// Package enforce provides types and functions for analyzing IAM trust policy
// enforcement of Sentinel SourceIdentity requirements.
package enforce

// EnforcementLevel indicates the strictness of Sentinel enforcement.
// It represents the three levels documented in ENFORCEMENT.md:
// Advisory (logging only), TrustPolicy (per-role), and SCP (organization-wide).
type EnforcementLevel string

const (
	// EnforcementLevelAdvisory means Sentinel logs decisions but doesn't enforce.
	// AWS accepts any valid credentials regardless of SourceIdentity.
	EnforcementLevelAdvisory EnforcementLevel = "advisory"
	// EnforcementLevelTrustPolicy means individual roles require Sentinel SourceIdentity.
	// Non-Sentinel credentials are rejected by the role's trust policy.
	EnforcementLevelTrustPolicy EnforcementLevel = "trust_policy"
	// EnforcementLevelSCP means organization-wide policies require Sentinel.
	// Applied via Service Control Policies across accounts.
	EnforcementLevelSCP EnforcementLevel = "scp"
)

// IsValid returns true if the EnforcementLevel is a known value.
func (e EnforcementLevel) IsValid() bool {
	return e == EnforcementLevelAdvisory || e == EnforcementLevelTrustPolicy || e == EnforcementLevelSCP
}

// String returns the string representation of the EnforcementLevel.
func (e EnforcementLevel) String() string {
	return string(e)
}

// EnforcementStatus indicates the completeness of Sentinel enforcement.
type EnforcementStatus string

const (
	// EnforcementStatusNone means no Sentinel enforcement is configured.
	// The role accepts credentials without SourceIdentity requirements.
	EnforcementStatusNone EnforcementStatus = "none"
	// EnforcementStatusPartial means some statements enforce Sentinel but not all.
	// This may occur during migration periods (Pattern C from ENFORCEMENT.md).
	EnforcementStatusPartial EnforcementStatus = "partial"
	// EnforcementStatusFull means all Allow statements require Sentinel SourceIdentity.
	// Non-Sentinel credentials cannot assume this role.
	EnforcementStatusFull EnforcementStatus = "full"
)

// IsValid returns true if the EnforcementStatus is a known value.
func (e EnforcementStatus) IsValid() bool {
	return e == EnforcementStatusNone || e == EnforcementStatusPartial || e == EnforcementStatusFull
}

// String returns the string representation of the EnforcementStatus.
func (e EnforcementStatus) String() string {
	return string(e)
}

// AnalysisResult contains the outcome of analyzing a trust policy for Sentinel enforcement.
type AnalysisResult struct {
	// Level indicates the enforcement strictness detected.
	Level EnforcementLevel `json:"level"`
	// Status indicates how completely Sentinel enforcement is configured.
	Status EnforcementStatus `json:"status"`
	// HasSourceIdentityCondition is true if any statement has sts:SourceIdentity condition.
	HasSourceIdentityCondition bool `json:"has_source_identity_condition"`
	// Issues lists problems found during analysis.
	Issues []string `json:"issues,omitempty"`
	// Recommendations suggests improvements for better enforcement.
	Recommendations []string `json:"recommendations,omitempty"`
}

// TrustPolicyDocument represents an IAM trust policy (AssumeRolePolicyDocument).
// AWS trust policies define who can assume a role using sts:AssumeRole.
type TrustPolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement represents a single statement in a trust policy.
// Each statement specifies who (Principal) can perform what (Action)
// under what conditions (Condition).
type Statement struct {
	// Sid is an optional statement identifier for documentation.
	Sid string `json:"Sid,omitempty"`
	// Effect must be "Allow" or "Deny".
	Effect string `json:"Effect"`
	// Principal specifies who can assume the role.
	Principal Principal `json:"Principal"`
	// Action specifies the allowed actions (typically sts:AssumeRole).
	Action StringOrSlice `json:"Action"`
	// Condition specifies additional requirements (like sts:SourceIdentity).
	Condition ConditionBlock `json:"Condition,omitempty"`
}

// Principal represents the Principal element in a trust policy statement.
// AWS allows several formats:
//   - "*" (any principal)
//   - {"AWS": "arn:aws:iam::123456789012:root"}
//   - {"AWS": ["arn1", "arn2"]}
//   - {"Service": "ec2.amazonaws.com"}
//   - {"Federated": "arn:aws:iam::123456789012:saml-provider/ExampleProvider"}
type Principal struct {
	// AWS contains AWS account or IAM principal ARNs.
	AWS StringOrSlice `json:"AWS,omitempty"`
	// Service contains AWS service principals (e.g., ec2.amazonaws.com).
	Service StringOrSlice `json:"Service,omitempty"`
	// Federated contains federated identity provider ARNs.
	Federated StringOrSlice `json:"Federated,omitempty"`
	// Wildcard is true if Principal was "*" (any principal).
	Wildcard bool `json:"-"`
}

// StringOrSlice handles AWS JSON fields that can be a string or []string.
// For example, Action can be "sts:AssumeRole" or ["sts:AssumeRole", "sts:AssumeRoleWithSAML"].
type StringOrSlice []string

// ConditionBlock represents the Condition element in a trust policy statement.
// The structure is: Operator -> ConditionKey -> Values
// Example: {"StringLike": {"sts:SourceIdentity": "sentinel:*"}}
type ConditionBlock map[string]ConditionOperator

// ConditionOperator maps condition keys to their required values.
// Example: {"sts:SourceIdentity": ["sentinel:*"]}
type ConditionOperator map[string]StringOrSlice

// HasSourceIdentityCondition checks if the condition block contains
// an sts:SourceIdentity condition with a sentinel:* pattern.
func (c ConditionBlock) HasSourceIdentityCondition() bool {
	// Check StringLike for sentinel:* pattern
	if stringLike, ok := c["StringLike"]; ok {
		if values, ok := stringLike["sts:SourceIdentity"]; ok {
			for _, v := range values {
				if v == "sentinel:*" || len(v) > 9 && v[:9] == "sentinel:" {
					return true
				}
			}
		}
	}
	return false
}

// HasSourceIdentityDeny checks if the condition block denies requests
// without Sentinel SourceIdentity (using StringNotLike).
func (c ConditionBlock) HasSourceIdentityDeny() bool {
	// Check StringNotLike for sentinel:* pattern (used in SCPs)
	if stringNotLike, ok := c["StringNotLike"]; ok {
		if values, ok := stringNotLike["sts:SourceIdentity"]; ok {
			for _, v := range values {
				if v == "sentinel:*" || len(v) > 9 && v[:9] == "sentinel:" {
					return true
				}
			}
		}
	}
	return false
}
