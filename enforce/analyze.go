package enforce

// AnalyzeTrustPolicy analyzes a trust policy document to determine its
// Sentinel enforcement status. It examines all statements to determine
// if SourceIdentity conditions are properly configured.
//
// Analysis logic:
//   - Full: At least one Allow statement has sts:SourceIdentity with sentinel:* pattern
//   - Partial: Statements have SourceIdentity but not with sentinel:* pattern
//   - None: No SourceIdentity conditions found
func AnalyzeTrustPolicy(policy *TrustPolicyDocument) *AnalysisResult {
	if policy == nil {
		return &AnalysisResult{
			Level:                      EnforcementLevelAdvisory,
			Status:                     EnforcementStatusNone,
			HasSourceIdentityCondition: false,
			Issues:                     []string{"policy document is nil"},
			Recommendations:            []string{"Provide a valid trust policy document"},
		}
	}

	result := &AnalysisResult{
		Level:                      EnforcementLevelTrustPolicy,
		Status:                     EnforcementStatusNone,
		HasSourceIdentityCondition: false,
		Issues:                     []string{},
		Recommendations:            []string{},
	}

	var (
		hasAnySourceIdentity     bool
		hasSentinelWildcard      bool
		hasUserSpecificPatterns  bool
		hasStringEqualsForWild   bool
		allowStatementsCount     int
		enforcedStatementsCount  int
		legacyStatementsExist    bool
	)

	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			// Deny statements with StringNotLike are SCP patterns
			if stmt.Effect == "Deny" && stmt.Condition.HasSourceIdentityDeny() {
				result.Level = EnforcementLevelSCP
			}
			continue
		}

		allowStatementsCount++
		patterns := GetSourceIdentityPatterns(&stmt)

		if len(patterns) > 0 {
			hasAnySourceIdentity = true
			result.HasSourceIdentityCondition = true

			// Check for sentinel:* wildcard pattern
			if HasSentinelWildcardPattern(patterns) {
				hasSentinelWildcard = true
				enforcedStatementsCount++
			} else {
				// Check if patterns are sentinel user-specific
				for _, p := range patterns {
					if IsSentinelPattern(p) && p != "sentinel:*" {
						hasUserSpecificPatterns = true
						enforcedStatementsCount++
					}
				}
			}

			// Check if StringEquals is used (won't work with dynamic request-id)
			if stringEquals, ok := stmt.Condition["StringEquals"]; ok {
				if values, ok := stringEquals["sts:SourceIdentity"]; ok {
					for _, v := range values {
						if v == "sentinel:*" || (len(v) > 9 && v[:9] == "sentinel:" && v[len(v)-1] == '*') {
							hasStringEqualsForWild = true
						}
					}
				}
			}
		} else {
			// Allow statement without SourceIdentity condition (legacy/migration)
			legacyStatementsExist = true
		}
	}

	// Determine enforcement status
	if hasAnySourceIdentity {
		if hasSentinelWildcard && !legacyStatementsExist {
			result.Status = EnforcementStatusFull
		} else if hasUserSpecificPatterns && !legacyStatementsExist {
			result.Status = EnforcementStatusFull
		} else if enforcedStatementsCount > 0 && legacyStatementsExist {
			result.Status = EnforcementStatusPartial
		} else if enforcedStatementsCount > 0 {
			result.Status = EnforcementStatusFull
		} else {
			result.Status = EnforcementStatusPartial
		}
	} else {
		result.Status = EnforcementStatusNone
		result.Level = EnforcementLevelAdvisory
	}

	// Generate issues
	if !hasAnySourceIdentity {
		result.Issues = append(result.Issues, "No sts:SourceIdentity condition found in any Allow statement")
	}

	if hasAnySourceIdentity && !hasSentinelWildcard && !hasUserSpecificPatterns {
		result.Issues = append(result.Issues, "SourceIdentity condition exists but pattern does not match sentinel:*")
	}

	if hasStringEqualsForWild {
		result.Issues = append(result.Issues, "Using StringEquals with wildcard pattern - use StringLike instead for pattern matching")
	}

	if legacyStatementsExist && hasAnySourceIdentity {
		result.Issues = append(result.Issues, "Mixed enforcement: some Allow statements lack SourceIdentity condition (migration mode)")
	}

	// Generate recommendations
	switch result.Status {
	case EnforcementStatusNone:
		result.Recommendations = append(result.Recommendations,
			"Add StringLike condition for sts:SourceIdentity with pattern sentinel:* to require Sentinel enforcement")
	case EnforcementStatusPartial:
		if legacyStatementsExist {
			result.Recommendations = append(result.Recommendations,
				"Add sts:SourceIdentity condition to all Allow statements, or remove legacy statements after migration")
		}
		if !hasSentinelWildcard && hasUserSpecificPatterns {
			// User-specific patterns are valid full enforcement
			// No recommendation needed
		} else if !hasSentinelWildcard {
			result.Recommendations = append(result.Recommendations,
				"Update SourceIdentity pattern to sentinel:* for full Sentinel enforcement")
		}
	case EnforcementStatusFull:
		// No recommendations for compliant policies
	}

	if hasStringEqualsForWild {
		result.Recommendations = append(result.Recommendations,
			"Change StringEquals to StringLike for wildcard patterns (sentinel:*)")
	}

	return result
}

// IsEnforced returns true if the trust policy has full Sentinel enforcement.
// This is a convenience function for simple compliance checks.
func IsEnforced(policy *TrustPolicyDocument) bool {
	result := AnalyzeTrustPolicy(policy)
	return result.Status == EnforcementStatusFull
}

// AnalyzeStatement analyzes a single statement for Sentinel enforcement.
// Returns true if the statement requires Sentinel SourceIdentity.
func AnalyzeStatement(stmt *Statement) (enforced bool, patterns []string) {
	if stmt == nil || stmt.Effect != "Allow" {
		return false, nil
	}

	patterns = GetSourceIdentityPatterns(stmt)
	if len(patterns) == 0 {
		return false, nil
	}

	// Check if any pattern is a sentinel pattern
	for _, p := range patterns {
		if IsSentinelPattern(p) {
			return true, patterns
		}
	}

	return false, patterns
}
