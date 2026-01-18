// Package config provides configuration validation for Sentinel.
// It validates policy files, approval policies, break-glass policies,
// rate limit policies, and bootstrap configs before runtime.
package config

// ConfigType identifies the type of configuration being validated.
type ConfigType string

const (
	// ConfigTypePolicy is an access control policy.
	ConfigTypePolicy ConfigType = "policy"
	// ConfigTypeApproval is an approval workflow policy.
	ConfigTypeApproval ConfigType = "approval"
	// ConfigTypeBreakGlass is a break-glass authorization policy.
	ConfigTypeBreakGlass ConfigType = "breakglass"
	// ConfigTypeRateLimit is a rate limit policy.
	ConfigTypeRateLimit ConfigType = "ratelimit"
	// ConfigTypeBootstrap is a bootstrap configuration.
	ConfigTypeBootstrap ConfigType = "bootstrap"
)

// IsValid returns true if the ConfigType is a known value.
func (t ConfigType) IsValid() bool {
	switch t {
	case ConfigTypePolicy, ConfigTypeApproval, ConfigTypeBreakGlass, ConfigTypeRateLimit, ConfigTypeBootstrap:
		return true
	}
	return false
}

// String returns the string representation of the ConfigType.
func (t ConfigType) String() string {
	return string(t)
}

// AllConfigTypes returns all valid config type values.
func AllConfigTypes() []ConfigType {
	return []ConfigType{
		ConfigTypePolicy,
		ConfigTypeApproval,
		ConfigTypeBreakGlass,
		ConfigTypeRateLimit,
		ConfigTypeBootstrap,
	}
}

// IssueSeverity indicates the severity of a validation issue.
type IssueSeverity string

const (
	// SeverityError indicates a problem that blocks loading/usage.
	SeverityError IssueSeverity = "error"
	// SeverityWarning indicates a suspicious pattern but works.
	SeverityWarning IssueSeverity = "warning"
)

// ValidationIssue represents a single validation problem.
type ValidationIssue struct {
	Severity   IssueSeverity `json:"severity"`
	Location   string        `json:"location"`             // e.g., "rules[0].name", "profiles[1]"
	Message    string        `json:"message"`
	Suggestion string        `json:"suggestion,omitempty"`
}

// ValidationResult contains all validation findings for a single config.
type ValidationResult struct {
	ConfigType ConfigType        `json:"config_type"`
	Source     string            `json:"source"` // File path or SSM path
	Valid      bool              `json:"valid"`  // True if no errors (warnings OK)
	Issues     []ValidationIssue `json:"issues"`
}

// AllResults aggregates multiple validation results.
type AllResults struct {
	Results []ValidationResult `json:"results"`
	Summary ResultSummary      `json:"summary"`
}

// ResultSummary provides aggregate counts.
type ResultSummary struct {
	Total    int `json:"total"`
	Valid    int `json:"valid"`
	Invalid  int `json:"invalid"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}

// Compute populates the summary from a list of results.
func (s *ResultSummary) Compute(results []ValidationResult) {
	s.Total = len(results)
	s.Valid = 0
	s.Invalid = 0
	s.Errors = 0
	s.Warnings = 0

	for _, r := range results {
		if r.Valid {
			s.Valid++
		} else {
			s.Invalid++
		}
		for _, issue := range r.Issues {
			switch issue.Severity {
			case SeverityError:
				s.Errors++
			case SeverityWarning:
				s.Warnings++
			}
		}
	}
}
