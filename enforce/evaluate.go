package enforce

import (
	"strings"
)

// MatchPattern implements AWS StringLike wildcard matching.
// Wildcards:
//   - "*" matches any sequence of characters (including empty)
//   - "?" matches any single character
//
// Matching is case-sensitive (AWS default behavior).
func MatchPattern(pattern, value string) bool {
	return matchPattern(pattern, value)
}

// matchPattern is a recursive implementation of AWS StringLike matching.
func matchPattern(pattern, value string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Try matching the rest of the pattern with different amounts of consumed value
			// First, skip consecutive stars
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			// If pattern is exhausted after stars, it matches any remaining value
			if len(pattern) == 0 {
				return true
			}
			// Try matching rest of pattern at each position in value
			for i := 0; i <= len(value); i++ {
				if matchPattern(pattern, value[i:]) {
					return true
				}
			}
			return false
		case '?':
			// Must match exactly one character
			if len(value) == 0 {
				return false
			}
			pattern = pattern[1:]
			value = value[1:]
		default:
			// Literal character must match
			if len(value) == 0 || pattern[0] != value[0] {
				return false
			}
			pattern = pattern[1:]
			value = value[1:]
		}
	}
	// Pattern exhausted - value must also be exhausted
	return len(value) == 0
}

// HasSourceIdentityCondition checks if a statement requires sts:SourceIdentity
// with a sentinel:* pattern.
func HasSourceIdentityCondition(stmt *Statement) bool {
	if stmt == nil || stmt.Condition == nil {
		return false
	}

	// Check StringLike operator
	if stringLike, ok := stmt.Condition["StringLike"]; ok {
		if hasSentinelPattern(stringLike, "sts:SourceIdentity") {
			return true
		}
	}

	// Check StringEquals operator (exact match)
	if stringEquals, ok := stmt.Condition["StringEquals"]; ok {
		if hasSentinelPattern(stringEquals, "sts:SourceIdentity") {
			return true
		}
	}

	return false
}

// hasSentinelPattern checks if a condition operator has a sentinel:* pattern
// for the given condition key.
func hasSentinelPattern(op ConditionOperator, key string) bool {
	values, ok := op[key]
	if !ok {
		return false
	}
	for _, v := range values {
		if strings.HasPrefix(v, "sentinel:") {
			return true
		}
	}
	return false
}

// GetSourceIdentityPatterns extracts SourceIdentity patterns from a statement's
// condition block. It checks StringLike and StringEquals operators.
func GetSourceIdentityPatterns(stmt *Statement) []string {
	if stmt == nil || stmt.Condition == nil {
		return nil
	}

	var patterns []string

	// Check StringLike operator
	if stringLike, ok := stmt.Condition["StringLike"]; ok {
		if values, ok := stringLike["sts:SourceIdentity"]; ok {
			patterns = append(patterns, values...)
		}
	}

	// Check StringEquals operator
	if stringEquals, ok := stmt.Condition["StringEquals"]; ok {
		if values, ok := stringEquals["sts:SourceIdentity"]; ok {
			patterns = append(patterns, values...)
		}
	}

	// Check StringNotLike operator (for Deny statements / SCPs)
	if stringNotLike, ok := stmt.Condition["StringNotLike"]; ok {
		if values, ok := stringNotLike["sts:SourceIdentity"]; ok {
			patterns = append(patterns, values...)
		}
	}

	// Check StringNotEquals operator
	if stringNotEquals, ok := stmt.Condition["StringNotEquals"]; ok {
		if values, ok := stringNotEquals["sts:SourceIdentity"]; ok {
			patterns = append(patterns, values...)
		}
	}

	return patterns
}

// EvaluateCondition evaluates a condition against a given value.
// Supports: StringLike, StringNotLike, StringEquals, StringNotEquals
func EvaluateCondition(operator string, pattern, value string) bool {
	switch operator {
	case "StringLike":
		return MatchPattern(pattern, value)
	case "StringNotLike":
		return !MatchPattern(pattern, value)
	case "StringEquals":
		return pattern == value
	case "StringNotEquals":
		return pattern != value
	default:
		return false
	}
}

// HasSentinelWildcardPattern checks if any pattern in the slice is "sentinel:*"
// (the general wildcard pattern for any Sentinel-issued credentials).
func HasSentinelWildcardPattern(patterns []string) bool {
	for _, p := range patterns {
		if p == "sentinel:*" {
			return true
		}
	}
	return false
}

// IsSentinelPattern checks if a pattern matches Sentinel format.
// Valid patterns:
//   - "sentinel:*" (any Sentinel credential)
//   - "sentinel:alice:*" (specific user)
//   - "sentinel:bob:a1b2c3d4" (specific session)
func IsSentinelPattern(pattern string) bool {
	return strings.HasPrefix(pattern, "sentinel:")
}
