package config

import (
	"testing"
)

func TestConfigType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		ct       ConfigType
		expected bool
	}{
		{"policy", ConfigTypePolicy, true},
		{"approval", ConfigTypeApproval, true},
		{"breakglass", ConfigTypeBreakGlass, true},
		{"ratelimit", ConfigTypeRateLimit, true},
		{"bootstrap", ConfigTypeBootstrap, true},
		{"empty", ConfigType(""), false},
		{"invalid", ConfigType("invalid"), false},
		{"unknown", ConfigType("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ct.IsValid(); got != tt.expected {
				t.Errorf("ConfigType(%q).IsValid() = %v, want %v", tt.ct, got, tt.expected)
			}
		})
	}
}

func TestConfigType_String(t *testing.T) {
	tests := []struct {
		ct       ConfigType
		expected string
	}{
		{ConfigTypePolicy, "policy"},
		{ConfigTypeApproval, "approval"},
		{ConfigTypeBreakGlass, "breakglass"},
		{ConfigTypeRateLimit, "ratelimit"},
		{ConfigTypeBootstrap, "bootstrap"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.ct.String(); got != tt.expected {
				t.Errorf("ConfigType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAllConfigTypes(t *testing.T) {
	types := AllConfigTypes()
	if len(types) != 5 {
		t.Errorf("AllConfigTypes() returned %d types, want 5", len(types))
	}

	// Verify all types are present
	expected := map[ConfigType]bool{
		ConfigTypePolicy:     true,
		ConfigTypeApproval:   true,
		ConfigTypeBreakGlass: true,
		ConfigTypeRateLimit:  true,
		ConfigTypeBootstrap:  true,
	}

	for _, ct := range types {
		if !expected[ct] {
			t.Errorf("unexpected ConfigType: %v", ct)
		}
		delete(expected, ct)
	}

	if len(expected) > 0 {
		t.Errorf("missing ConfigTypes: %v", expected)
	}
}

func TestResultSummary_Compute(t *testing.T) {
	tests := []struct {
		name     string
		results  []ValidationResult
		expected ResultSummary
	}{
		{
			name:    "empty results",
			results: []ValidationResult{},
			expected: ResultSummary{
				Total:    0,
				Valid:    0,
				Invalid:  0,
				Errors:   0,
				Warnings: 0,
			},
		},
		{
			name: "single valid result",
			results: []ValidationResult{
				{ConfigType: ConfigTypePolicy, Valid: true, Issues: []ValidationIssue{}},
			},
			expected: ResultSummary{
				Total:    1,
				Valid:    1,
				Invalid:  0,
				Errors:   0,
				Warnings: 0,
			},
		},
		{
			name: "single invalid result with error",
			results: []ValidationResult{
				{
					ConfigType: ConfigTypePolicy,
					Valid:      false,
					Issues: []ValidationIssue{
						{Severity: SeverityError, Message: "error"},
					},
				},
			},
			expected: ResultSummary{
				Total:    1,
				Valid:    0,
				Invalid:  1,
				Errors:   1,
				Warnings: 0,
			},
		},
		{
			name: "valid result with warning",
			results: []ValidationResult{
				{
					ConfigType: ConfigTypePolicy,
					Valid:      true,
					Issues: []ValidationIssue{
						{Severity: SeverityWarning, Message: "warning"},
					},
				},
			},
			expected: ResultSummary{
				Total:    1,
				Valid:    1,
				Invalid:  0,
				Errors:   0,
				Warnings: 1,
			},
		},
		{
			name: "mixed results",
			results: []ValidationResult{
				{ConfigType: ConfigTypePolicy, Valid: true, Issues: []ValidationIssue{}},
				{
					ConfigType: ConfigTypeApproval,
					Valid:      false,
					Issues: []ValidationIssue{
						{Severity: SeverityError, Message: "error1"},
						{Severity: SeverityError, Message: "error2"},
					},
				},
				{
					ConfigType: ConfigTypeBreakGlass,
					Valid:      true,
					Issues: []ValidationIssue{
						{Severity: SeverityWarning, Message: "warning"},
					},
				},
			},
			expected: ResultSummary{
				Total:    3,
				Valid:    2,
				Invalid:  1,
				Errors:   2,
				Warnings: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s ResultSummary
			s.Compute(tt.results)

			if s.Total != tt.expected.Total {
				t.Errorf("Total = %d, want %d", s.Total, tt.expected.Total)
			}
			if s.Valid != tt.expected.Valid {
				t.Errorf("Valid = %d, want %d", s.Valid, tt.expected.Valid)
			}
			if s.Invalid != tt.expected.Invalid {
				t.Errorf("Invalid = %d, want %d", s.Invalid, tt.expected.Invalid)
			}
			if s.Errors != tt.expected.Errors {
				t.Errorf("Errors = %d, want %d", s.Errors, tt.expected.Errors)
			}
			if s.Warnings != tt.expected.Warnings {
				t.Errorf("Warnings = %d, want %d", s.Warnings, tt.expected.Warnings)
			}
		})
	}
}

func TestValidationIssue_Fields(t *testing.T) {
	issue := ValidationIssue{
		Severity:   SeverityError,
		Location:   "rules[0].name",
		Message:    "missing name",
		Suggestion: "add a 'name' field",
	}

	if issue.Severity != SeverityError {
		t.Errorf("Severity = %v, want %v", issue.Severity, SeverityError)
	}
	if issue.Location != "rules[0].name" {
		t.Errorf("Location = %v, want %v", issue.Location, "rules[0].name")
	}
	if issue.Message != "missing name" {
		t.Errorf("Message = %v, want %v", issue.Message, "missing name")
	}
	if issue.Suggestion != "add a 'name' field" {
		t.Errorf("Suggestion = %v, want %v", issue.Suggestion, "add a 'name' field")
	}
}

func TestValidationResult_Fields(t *testing.T) {
	result := ValidationResult{
		ConfigType: ConfigTypePolicy,
		Source:     "/path/to/policy.yaml",
		Valid:      true,
		Issues:     []ValidationIssue{},
	}

	if result.ConfigType != ConfigTypePolicy {
		t.Errorf("ConfigType = %v, want %v", result.ConfigType, ConfigTypePolicy)
	}
	if result.Source != "/path/to/policy.yaml" {
		t.Errorf("Source = %v, want %v", result.Source, "/path/to/policy.yaml")
	}
	if !result.Valid {
		t.Error("Valid = false, want true")
	}
	if len(result.Issues) != 0 {
		t.Errorf("Issues length = %d, want 0", len(result.Issues))
	}
}

func TestAllResults_Fields(t *testing.T) {
	results := []ValidationResult{
		{ConfigType: ConfigTypePolicy, Valid: true},
		{ConfigType: ConfigTypeApproval, Valid: false},
	}

	all := AllResults{
		Results: results,
		Summary: ResultSummary{Total: 2, Valid: 1, Invalid: 1},
	}

	if len(all.Results) != 2 {
		t.Errorf("Results length = %d, want 2", len(all.Results))
	}
	if all.Summary.Total != 2 {
		t.Errorf("Summary.Total = %d, want 2", all.Summary.Total)
	}
}
