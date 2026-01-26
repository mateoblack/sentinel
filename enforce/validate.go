package enforce

import (
	"strings"
)

// RiskLevel indicates the severity of a validation finding.
type RiskLevel string

const (
	// RiskLevelHigh indicates a critical security issue requiring immediate attention.
	RiskLevelHigh RiskLevel = "high"
	// RiskLevelMedium indicates a significant security concern that should be addressed.
	RiskLevelMedium RiskLevel = "medium"
	// RiskLevelLow indicates a minor issue or best practice recommendation.
	RiskLevelLow RiskLevel = "low"
)

// ValidationFinding represents a single validation issue found in a trust policy.
type ValidationFinding struct {
	// RuleID is the identifier for the validation rule (e.g., TRUST-01).
	RuleID string `json:"rule_id"`
	// RiskLevel indicates the severity of this finding.
	RiskLevel RiskLevel `json:"risk_level"`
	// Message describes the issue found.
	Message string `json:"message"`
	// Recommendation suggests how to fix the issue.
	Recommendation string `json:"recommendation"`
	// AffectedStatement identifies which statement has the issue (Sid or index).
	AffectedStatement string `json:"affected_statement"`
}

// ValidationResult aggregates all findings from validating a trust policy.
type ValidationResult struct {
	// Findings contains all validation issues found.
	Findings []ValidationFinding `json:"findings"`
	// RiskSummary counts findings by risk level.
	RiskSummary map[RiskLevel]int `json:"risk_summary"`
	// IsCompliant is true if no HIGH or MEDIUM findings exist.
	IsCompliant bool `json:"is_compliant"`
}

// ValidateTrustPolicy validates a trust policy document against Sentinel security requirements.
// It checks for:
//   - TRUST-01: Wildcard principal without conditions (HIGH)
//   - TRUST-02: Allow statements missing sts:SourceIdentity condition (HIGH)
//   - TRUST-03: SourceIdentity pattern doesn't match sentinel:* or sentinel:{user}:* (MEDIUM)
//   - TRUST-04: Principal includes :root without ExternalId or SourceIdentity (MEDIUM)
//   - TRUST-05: Using StringEquals instead of StringLike for wildcard patterns (LOW)
func ValidateTrustPolicy(policy *TrustPolicyDocument) *ValidationResult {
	result := &ValidationResult{
		Findings:    []ValidationFinding{},
		RiskSummary: map[RiskLevel]int{RiskLevelHigh: 0, RiskLevelMedium: 0, RiskLevelLow: 0},
		IsCompliant: true,
	}

	if policy == nil {
		result.Findings = append(result.Findings, ValidationFinding{
			RuleID:            "TRUST-00",
			RiskLevel:         RiskLevelHigh,
			Message:           "Trust policy document is nil",
			Recommendation:    "Provide a valid trust policy document",
			AffectedStatement: "N/A",
		})
		result.RiskSummary[RiskLevelHigh]++
		result.IsCompliant = false
		return result
	}

	for i, stmt := range policy.Statement {
		// Only validate Allow statements
		if stmt.Effect != "Allow" {
			continue
		}

		stmtID := stmt.Sid
		if stmtID == "" {
			stmtID = statementIndex(i)
		}

		// TRUST-01: Wildcard principal without conditions
		if stmt.Principal.Wildcard {
			if len(stmt.Condition) == 0 {
				result.Findings = append(result.Findings, ValidationFinding{
					RuleID:            "TRUST-01",
					RiskLevel:         RiskLevelHigh,
					Message:           "Wildcard principal (\"*\") without any conditions allows anyone to assume this role",
					Recommendation:    "Add StringLike condition for sts:SourceIdentity with pattern sentinel:* or restrict the principal",
					AffectedStatement: stmtID,
				})
			}
		}

		// TRUST-02: Allow statements missing sts:SourceIdentity condition
		if !hasSourceIdentityInCondition(stmt.Condition) {
			result.Findings = append(result.Findings, ValidationFinding{
				RuleID:            "TRUST-02",
				RiskLevel:         RiskLevelHigh,
				Message:           "Allow statement missing sts:SourceIdentity condition - non-Sentinel credentials can assume this role",
				Recommendation:    "Add StringLike condition for sts:SourceIdentity with pattern sentinel:*",
				AffectedStatement: stmtID,
			})
		}

		// TRUST-03: SourceIdentity pattern doesn't match sentinel:* or sentinel:{user}:*
		patterns := GetSourceIdentityPatterns(&stmt)
		if len(patterns) > 0 {
			hasValidSentinelPattern := false
			for _, p := range patterns {
				if isValidSentinelPattern(p) {
					hasValidSentinelPattern = true
					break
				}
			}
			if !hasValidSentinelPattern {
				result.Findings = append(result.Findings, ValidationFinding{
					RuleID:            "TRUST-03",
					RiskLevel:         RiskLevelMedium,
					Message:           "SourceIdentity pattern does not match sentinel:* or sentinel:{user}:* format",
					Recommendation:    "Use pattern sentinel:* for any Sentinel credentials or sentinel:{username}:* for specific users",
					AffectedStatement: stmtID,
				})
			}
		}

		// TRUST-04: Principal includes :root without ExternalId or SourceIdentity
		if hasRootPrincipal(stmt.Principal) {
			if !hasSourceIdentityInCondition(stmt.Condition) && !hasExternalIdCondition(stmt.Condition) {
				result.Findings = append(result.Findings, ValidationFinding{
					RuleID:            "TRUST-04",
					RiskLevel:         RiskLevelMedium,
					Message:           "Root principal without ExternalId or SourceIdentity condition - allows any IAM entity in the account",
					Recommendation:    "Add sts:ExternalId condition or require SourceIdentity with pattern sentinel:*",
					AffectedStatement: stmtID,
				})
			}
		}

		// TRUST-05: Using StringEquals instead of StringLike for wildcard patterns
		if hasStringEqualsWithWildcard(stmt.Condition) {
			result.Findings = append(result.Findings, ValidationFinding{
				RuleID:            "TRUST-05",
				RiskLevel:         RiskLevelLow,
				Message:           "Using StringEquals with wildcard pattern (*) - wildcards require StringLike operator",
				Recommendation:    "Change StringEquals to StringLike for patterns containing * wildcard",
				AffectedStatement: stmtID,
			})
		}
	}

	// Update risk summary and compliance status
	for _, f := range result.Findings {
		result.RiskSummary[f.RiskLevel]++
		if f.RiskLevel == RiskLevelHigh || f.RiskLevel == RiskLevelMedium {
			result.IsCompliant = false
		}
	}

	return result
}

// statementIndex returns a string representation of a statement index.
func statementIndex(i int) string {
	return "Statement[" + itoa(i) + "]"
}

// itoa converts an int to string (simple implementation to avoid fmt import).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// hasSourceIdentityInCondition checks if any condition operator references sts:SourceIdentity.
func hasSourceIdentityInCondition(cond ConditionBlock) bool {
	if cond == nil {
		return false
	}
	// Check StringLike
	if stringLike, ok := cond["StringLike"]; ok {
		if _, hasKey := stringLike["sts:SourceIdentity"]; hasKey {
			return true
		}
	}
	// Check StringEquals
	if stringEquals, ok := cond["StringEquals"]; ok {
		if _, hasKey := stringEquals["sts:SourceIdentity"]; hasKey {
			return true
		}
	}
	return false
}

// isValidSentinelPattern checks if a pattern follows sentinel:* or sentinel:{user}:* format.
func isValidSentinelPattern(pattern string) bool {
	if pattern == "sentinel:*" {
		return true
	}
	// Check for sentinel:{user}:* pattern (user-specific wildcard)
	if strings.HasPrefix(pattern, "sentinel:") {
		parts := strings.Split(pattern, ":")
		if len(parts) >= 2 {
			// sentinel:* - valid
			// sentinel:alice:* - valid (user-specific)
			// sentinel:alice:abc123 - valid (session-specific)
			return true
		}
	}
	return false
}

// hasRootPrincipal checks if the principal includes an account root (:root).
func hasRootPrincipal(principal Principal) bool {
	for _, arn := range principal.AWS {
		if strings.HasSuffix(arn, ":root") {
			return true
		}
	}
	return false
}

// hasExternalIdCondition checks if the condition block has an sts:ExternalId condition.
func hasExternalIdCondition(cond ConditionBlock) bool {
	if cond == nil {
		return false
	}
	// Check StringEquals for ExternalId
	if stringEquals, ok := cond["StringEquals"]; ok {
		if _, hasKey := stringEquals["sts:ExternalId"]; hasKey {
			return true
		}
	}
	return false
}

// hasStringEqualsWithWildcard checks if StringEquals is used with a wildcard pattern.
func hasStringEqualsWithWildcard(cond ConditionBlock) bool {
	if cond == nil {
		return false
	}
	if stringEquals, ok := cond["StringEquals"]; ok {
		if values, hasKey := stringEquals["sts:SourceIdentity"]; hasKey {
			for _, v := range values {
				if strings.Contains(v, "*") {
					return true
				}
			}
		}
	}
	return false
}
