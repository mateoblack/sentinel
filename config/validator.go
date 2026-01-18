package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/byteness/aws-vault/v7/bootstrap"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/policy"
	"gopkg.in/yaml.v3"
)

// Validate validates config content based on type.
// It performs YAML parsing and semantic validation, returning all issues found.
func Validate(configType ConfigType, content []byte, source string) ValidationResult {
	result := ValidationResult{
		ConfigType: configType,
		Source:     source,
		Valid:      true,
		Issues:     []ValidationIssue{},
	}

	// Check for empty content
	if len(content) == 0 {
		result.Valid = false
		result.Issues = append(result.Issues, ValidationIssue{
			Severity:   SeverityError,
			Location:   "",
			Message:    "empty configuration",
			Suggestion: "provide valid YAML content",
		})
		return result
	}

	// Validate based on type
	switch configType {
	case ConfigTypePolicy:
		validatePolicy(content, &result)
	case ConfigTypeApproval:
		validateApproval(content, &result)
	case ConfigTypeBreakGlass:
		validateBreakGlass(content, &result)
	case ConfigTypeRateLimit:
		validateRateLimit(content, &result)
	case ConfigTypeBootstrap:
		validateBootstrap(content, &result)
	default:
		result.Valid = false
		result.Issues = append(result.Issues, ValidationIssue{
			Severity:   SeverityError,
			Location:   "",
			Message:    fmt.Sprintf("unknown config type: %s", configType),
			Suggestion: fmt.Sprintf("use one of: %s", strings.Join(configTypeStrings(), ", ")),
		})
	}

	return result
}

// ValidateFile validates a local YAML file.
// It reads the file and validates based on the specified config type.
func ValidateFile(path string, configType ConfigType) (ValidationResult, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return ValidationResult{
			ConfigType: configType,
			Source:     path,
			Valid:      false,
			Issues: []ValidationIssue{{
				Severity:   SeverityError,
				Location:   "",
				Message:    fmt.Sprintf("failed to read file: %v", err),
				Suggestion: "verify the file path exists and is readable",
			}},
		}, err
	}

	return Validate(configType, content, path), nil
}

// DetectConfigType attempts to detect config type from YAML content.
// Returns ConfigTypePolicy as default if unable to detect.
func DetectConfigType(content []byte) ConfigType {
	// Try to parse as generic YAML map
	var raw map[string]interface{}
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return ConfigTypePolicy // default
	}

	// Check for rules array
	rules, hasRules := raw["rules"]
	if hasRules {
		rulesSlice, ok := rules.([]interface{})
		if ok && len(rulesSlice) > 0 {
			firstRule, ok := rulesSlice[0].(map[string]interface{})
			if ok {
				// Check for distinctive fields in first rule
				if _, hasEffect := firstRule["effect"]; hasEffect {
					return ConfigTypePolicy
				}
				if _, hasApprovers := firstRule["approvers"]; hasApprovers {
					return ConfigTypeApproval
				}
				if _, hasUsers := firstRule["users"]; hasUsers {
					if _, hasAllowedCodes := firstRule["allowed_reason_codes"]; hasAllowedCodes {
						return ConfigTypeBreakGlass
					}
				}
				if _, hasCooldown := firstRule["cooldown"]; hasCooldown {
					return ConfigTypeRateLimit
				}
				if _, hasMaxPerUser := firstRule["max_per_user"]; hasMaxPerUser {
					return ConfigTypeRateLimit
				}
			}
		}
	}

	// Check for bootstrap indicators
	if _, hasPolicyRoot := raw["policy_root"]; hasPolicyRoot {
		return ConfigTypeBootstrap
	}
	if _, hasProfiles := raw["profiles"]; hasProfiles {
		return ConfigTypeBootstrap
	}

	return ConfigTypePolicy // default
}

// validatePolicy validates an access control policy.
func validatePolicy(content []byte, result *ValidationResult) {
	var p policy.Policy
	if err := yaml.Unmarshal(content, &p); err != nil {
		addYAMLParseError(result, err)
		return
	}

	// Run semantic validation
	if err := p.Validate(); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, ValidationIssue{
			Severity:   SeverityError,
			Location:   extractLocation(err.Error()),
			Message:    err.Error(),
			Suggestion: suggestPolicyFix(err.Error()),
		})
	}

	// Add warnings for suspicious patterns
	addPolicyWarnings(&p, result)
}

// validateApproval validates an approval workflow policy.
func validateApproval(content []byte, result *ValidationResult) {
	var p policy.ApprovalPolicy
	if err := yaml.Unmarshal(content, &p); err != nil {
		addYAMLParseError(result, err)
		return
	}

	// Run semantic validation
	if err := p.Validate(); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, ValidationIssue{
			Severity:   SeverityError,
			Location:   extractLocation(err.Error()),
			Message:    err.Error(),
			Suggestion: suggestApprovalFix(err.Error()),
		})
	}

	// Add warnings for suspicious patterns
	addApprovalWarnings(&p, result)
}

// validateBreakGlass validates a break-glass authorization policy.
func validateBreakGlass(content []byte, result *ValidationResult) {
	var p breakglass.BreakGlassPolicy
	if err := yaml.Unmarshal(content, &p); err != nil {
		addYAMLParseError(result, err)
		return
	}

	// Run semantic validation
	if err := p.Validate(); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, ValidationIssue{
			Severity:   SeverityError,
			Location:   extractLocation(err.Error()),
			Message:    err.Error(),
			Suggestion: suggestBreakGlassFix(err.Error()),
		})
	}

	// Add warnings for suspicious patterns
	addBreakGlassWarnings(&p, result)
}

// validateRateLimit validates a rate limit policy.
func validateRateLimit(content []byte, result *ValidationResult) {
	var p breakglass.RateLimitPolicy
	if err := yaml.Unmarshal(content, &p); err != nil {
		addYAMLParseError(result, err)
		return
	}

	// Run semantic validation
	if err := p.Validate(); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, ValidationIssue{
			Severity:   SeverityError,
			Location:   extractLocation(err.Error()),
			Message:    err.Error(),
			Suggestion: suggestRateLimitFix(err.Error()),
		})
	}

	// Add warnings for suspicious patterns
	addRateLimitWarnings(&p, result)
}

// validateBootstrap validates a bootstrap configuration.
func validateBootstrap(content []byte, result *ValidationResult) {
	var cfg bootstrap.BootstrapConfig
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		addYAMLParseError(result, err)
		return
	}

	// Run semantic validation
	if err := cfg.Validate(); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, ValidationIssue{
			Severity:   SeverityError,
			Location:   extractLocation(err.Error()),
			Message:    err.Error(),
			Suggestion: suggestBootstrapFix(err.Error()),
		})
	}
}

// addYAMLParseError adds a YAML parse error issue to the result.
func addYAMLParseError(result *ValidationResult, err error) {
	result.Valid = false
	result.Issues = append(result.Issues, ValidationIssue{
		Severity:   SeverityError,
		Location:   "",
		Message:    fmt.Sprintf("YAML parse error: %v", err),
		Suggestion: "check YAML syntax for correct indentation and formatting",
	})
}

// addPolicyWarnings adds warnings for suspicious patterns in access control policies.
func addPolicyWarnings(p *policy.Policy, result *ValidationResult) {
	for i, rule := range p.Rules {
		// Warn about empty profiles (matches all)
		if len(rule.Conditions.Profiles) == 0 && len(rule.Conditions.Users) == 0 {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:   SeverityWarning,
				Location:   fmt.Sprintf("rules[%d]", i),
				Message:    fmt.Sprintf("rule '%s' has no profiles or users condition - matches all requests", rule.Name),
				Suggestion: "add explicit conditions or confirm this is intended behavior",
			})
		}

		// Warn about time window with no hours specified
		if rule.Conditions.Time != nil && rule.Conditions.Time.Hours == nil && len(rule.Conditions.Time.Days) > 0 {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:   SeverityWarning,
				Location:   fmt.Sprintf("rules[%d].conditions.time", i),
				Message:    fmt.Sprintf("rule '%s' has days but no hours specified - applies all day", rule.Name),
				Suggestion: "add hours range or confirm 24-hour restriction is intended",
			})
		}
	}
}

// addApprovalWarnings adds warnings for suspicious patterns in approval policies.
func addApprovalWarnings(p *policy.ApprovalPolicy, result *ValidationResult) {
	for i, rule := range p.Rules {
		// Warn about empty profiles (matches all)
		if len(rule.Profiles) == 0 {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:   SeverityWarning,
				Location:   fmt.Sprintf("rules[%d]", i),
				Message:    fmt.Sprintf("rule '%s' has no profiles - applies to all profiles", rule.Name),
				Suggestion: "add explicit profiles or confirm wildcard behavior is intended",
			})
		}

		// Warn about auto_approve with no constraints
		if rule.AutoApprove != nil && len(rule.AutoApprove.Users) == 0 && rule.AutoApprove.Time == nil && rule.AutoApprove.MaxDuration == 0 {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:   SeverityWarning,
				Location:   fmt.Sprintf("rules[%d].auto_approve", i),
				Message:    fmt.Sprintf("rule '%s' auto_approve has no effective constraints", rule.Name),
				Suggestion: "add users, time, or max_duration constraints",
			})
		}
	}
}

// addBreakGlassWarnings adds warnings for suspicious patterns in break-glass policies.
func addBreakGlassWarnings(p *breakglass.BreakGlassPolicy, result *ValidationResult) {
	for i, rule := range p.Rules {
		// Warn about empty profiles (matches all)
		if len(rule.Profiles) == 0 {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:   SeverityWarning,
				Location:   fmt.Sprintf("rules[%d]", i),
				Message:    fmt.Sprintf("rule '%s' has no profiles - applies to all profiles", rule.Name),
				Suggestion: "add explicit profiles or confirm wildcard behavior is intended",
			})
		}

		// Warn about no allowed_reason_codes (allows all)
		if len(rule.AllowedReasonCodes) == 0 {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:   SeverityWarning,
				Location:   fmt.Sprintf("rules[%d]", i),
				Message:    fmt.Sprintf("rule '%s' has no allowed_reason_codes - accepts all reason codes", rule.Name),
				Suggestion: "add explicit reason codes or confirm wildcard behavior is intended",
			})
		}
	}
}

// addRateLimitWarnings adds warnings for suspicious patterns in rate limit policies.
func addRateLimitWarnings(p *breakglass.RateLimitPolicy, result *ValidationResult) {
	for i, rule := range p.Rules {
		// Warn about very short cooldowns (<1m)
		if rule.Cooldown > 0 && rule.Cooldown < time.Minute {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:   SeverityWarning,
				Location:   fmt.Sprintf("rules[%d].cooldown", i),
				Message:    fmt.Sprintf("rule '%s' has very short cooldown (%v)", rule.Name, rule.Cooldown),
				Suggestion: "consider increasing cooldown to at least 1 minute for abuse prevention",
			})
		}

		// Warn about empty profiles (matches all)
		if len(rule.Profiles) == 0 {
			result.Issues = append(result.Issues, ValidationIssue{
				Severity:   SeverityWarning,
				Location:   fmt.Sprintf("rules[%d]", i),
				Message:    fmt.Sprintf("rule '%s' has no profiles - applies to all profiles", rule.Name),
				Suggestion: "add explicit profiles or confirm wildcard behavior is intended",
			})
		}
	}
}

// extractLocation extracts location information from an error message.
func extractLocation(errMsg string) string {
	// Look for "at index X", "rule at index X", etc.
	if strings.Contains(errMsg, "index") {
		// Extract the index
		parts := strings.Split(errMsg, "index")
		if len(parts) >= 2 {
			rest := strings.TrimSpace(parts[1])
			// Find the number
			var idx string
			for _, c := range rest {
				if c >= '0' && c <= '9' {
					idx += string(c)
				} else {
					break
				}
			}
			if idx != "" {
				if strings.Contains(errMsg, "rule") {
					return fmt.Sprintf("rules[%s]", idx)
				}
				if strings.Contains(errMsg, "profile") {
					return fmt.Sprintf("profiles[%s]", idx)
				}
				return fmt.Sprintf("index[%s]", idx)
			}
		}
	}
	return ""
}

// suggestPolicyFix returns a suggestion for fixing a policy error.
func suggestPolicyFix(errMsg string) string {
	switch {
	case strings.Contains(errMsg, "at least one rule"):
		return "add at least one rule to the policy"
	case strings.Contains(errMsg, "missing name"):
		return "add a 'name' field to identify the rule"
	case strings.Contains(errMsg, "invalid effect"):
		return "use 'allow', 'deny', or 'require_approval' for effect"
	case strings.Contains(errMsg, "no conditions"):
		return "add at least one condition (profiles, users, or time)"
	case strings.Contains(errMsg, "invalid weekday"):
		return "use lowercase weekday names: monday, tuesday, etc."
	case strings.Contains(errMsg, "invalid timezone"):
		return "use valid IANA timezone (e.g., 'America/New_York', 'UTC')"
	case strings.Contains(errMsg, "invalid hour format"):
		return "use 24-hour format HH:MM (e.g., '09:00', '17:30')"
	default:
		return "review the error message and correct the configuration"
	}
}

// suggestApprovalFix returns a suggestion for fixing an approval error.
func suggestApprovalFix(errMsg string) string {
	switch {
	case strings.Contains(errMsg, "at least one rule"):
		return "add at least one approval rule"
	case strings.Contains(errMsg, "missing name"):
		return "add a 'name' field to identify the rule"
	case strings.Contains(errMsg, "at least one approver"):
		return "add at least one user to the 'approvers' list"
	case strings.Contains(errMsg, "at least one condition"):
		return "add users, time, or max_duration to auto_approve"
	case strings.Contains(errMsg, "exceeds maximum"):
		return "reduce max_duration to within allowed limits"
	default:
		return "review the error message and correct the configuration"
	}
}

// suggestBreakGlassFix returns a suggestion for fixing a break-glass error.
func suggestBreakGlassFix(errMsg string) string {
	switch {
	case strings.Contains(errMsg, "at least one rule"):
		return "add at least one break-glass rule"
	case strings.Contains(errMsg, "missing name"):
		return "add a 'name' field to identify the rule"
	case strings.Contains(errMsg, "at least one user"):
		return "add at least one user to the 'users' list"
	case strings.Contains(errMsg, "invalid reason code"):
		return "use valid reason codes: incident, on_call, security_response, disaster_recovery"
	case strings.Contains(errMsg, "negative max_duration"):
		return "use a positive duration for max_duration"
	case strings.Contains(errMsg, "exceeds maximum"):
		return "reduce max_duration to within allowed limits"
	default:
		return "review the error message and correct the configuration"
	}
}

// suggestRateLimitFix returns a suggestion for fixing a rate limit error.
func suggestRateLimitFix(errMsg string) string {
	switch {
	case strings.Contains(errMsg, "at least one rule"):
		return "add at least one rate limit rule"
	case strings.Contains(errMsg, "missing name"):
		return "add a 'name' field to identify the rule"
	case strings.Contains(errMsg, "negative cooldown"):
		return "use a positive duration for cooldown"
	case strings.Contains(errMsg, "negative max_per_user"):
		return "use a positive number for max_per_user"
	case strings.Contains(errMsg, "negative max_per_profile"):
		return "use a positive number for max_per_profile"
	case strings.Contains(errMsg, "quota_window"):
		return "specify quota_window when using max_per_user or max_per_profile"
	case strings.Contains(errMsg, "at least one limit"):
		return "add cooldown, max_per_user, or max_per_profile"
	default:
		return "review the error message and correct the configuration"
	}
}

// suggestBootstrapFix returns a suggestion for fixing a bootstrap error.
func suggestBootstrapFix(errMsg string) string {
	switch {
	case strings.Contains(errMsg, "policy_root cannot be empty"):
		return "add policy_root (e.g., '/sentinel/policies')"
	case strings.Contains(errMsg, "must start with"):
		return "policy_root must start with '/'"
	case strings.Contains(errMsg, "exceeds maximum length"):
		return "shorten the path length"
	case strings.Contains(errMsg, "invalid characters"):
		return "use only alphanumeric, '/', '-', '_' characters"
	case strings.Contains(errMsg, "at least one profile"):
		return "add at least one profile configuration"
	case strings.Contains(errMsg, "name cannot be empty"):
		return "add a 'name' field to the profile"
	case strings.Contains(errMsg, "not valid YAML"):
		return "check initial_policy YAML syntax"
	default:
		return "review the error message and correct the configuration"
	}
}

// configTypeStrings returns all config types as strings.
func configTypeStrings() []string {
	types := AllConfigTypes()
	strs := make([]string, len(types))
	for i, t := range types {
		strs[i] = string(t)
	}
	return strs
}
