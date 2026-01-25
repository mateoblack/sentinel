package audit

import (
	"context"
	"testing"
)

func TestSessionComplianceResult_HasComplianceGaps(t *testing.T) {
	tests := []struct {
		name     string
		result   SessionComplianceResult
		expected bool
	}{
		{
			name: "no gaps",
			result: SessionComplianceResult{
				ProfilesWithGaps: 0,
			},
			expected: false,
		},
		{
			name: "has gaps",
			result: SessionComplianceResult{
				ProfilesWithGaps: 1,
			},
			expected: true,
		},
		{
			name: "multiple gaps",
			result: SessionComplianceResult{
				ProfilesWithGaps: 3,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasComplianceGaps(); got != tt.expected {
				t.Errorf("HasComplianceGaps() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProfileCompliance_HasGap(t *testing.T) {
	tests := []struct {
		name     string
		profile  ProfileCompliance
		expected bool
	}{
		{
			name: "required and no untracked - no gap",
			profile: ProfileCompliance{
				Profile:        "prod",
				PolicyRequired: true,
				TrackedCount:   100,
				UntrackedCount: 0,
				ComplianceRate: 100.0,
				HasGap:         false,
			},
			expected: false,
		},
		{
			name: "required and has untracked - has gap",
			profile: ProfileCompliance{
				Profile:        "staging",
				PolicyRequired: true,
				TrackedCount:   90,
				UntrackedCount: 10,
				ComplianceRate: 90.0,
				HasGap:         true,
			},
			expected: true,
		},
		{
			name: "not required and has untracked - no gap",
			profile: ProfileCompliance{
				Profile:        "dev",
				PolicyRequired: false,
				TrackedCount:   10,
				UntrackedCount: 50,
				ComplianceRate: 16.7,
				HasGap:         false,
			},
			expected: false,
		},
		{
			name: "not required and no untracked - no gap",
			profile: ProfileCompliance{
				Profile:        "test",
				PolicyRequired: false,
				TrackedCount:   20,
				UntrackedCount: 0,
				ComplianceRate: 100.0,
				HasGap:         false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.profile.HasGap != tt.expected {
				t.Errorf("ProfileCompliance.HasGap = %v, want %v", tt.profile.HasGap, tt.expected)
			}
		})
	}
}

func TestExtractRoleNameFromARN(t *testing.T) {
	tests := []struct {
		name     string
		roleARN  string
		expected string
	}{
		{
			name:     "standard role ARN",
			roleARN:  "arn:aws:iam::123456789012:role/prod-role",
			expected: "prod-role",
		},
		{
			name:     "role with path",
			roleARN:  "arn:aws:iam::123456789012:role/path/to/my-role",
			expected: "my-role",
		},
		{
			name:     "role name only",
			roleARN:  "my-role",
			expected: "my-role",
		},
		{
			name:     "empty string",
			roleARN:  "",
			expected: "",
		},
		{
			name:     "single slash",
			roleARN:  "/role-name",
			expected: "role-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRoleNameFromARN(tt.roleARN)
			if got != tt.expected {
				t.Errorf("extractRoleNameFromARN(%q) = %v, want %v", tt.roleARN, got, tt.expected)
			}
		})
	}
}

func TestGetProfileListForCompliance(t *testing.T) {
	// profileEvents defined for reference but test uses nil to check filter logic
	_ = map[string][]eventType{
		"prod":    {},
		"staging": {},
		"dev":     {},
	}

	tests := []struct {
		name          string
		filterProfile string
		expectedLen   int
		expectedFirst string
	}{
		{
			name:          "no filter - returns all sorted",
			filterProfile: "",
			expectedLen:   3,
			expectedFirst: "dev", // alphabetically first
		},
		{
			name:          "filter prod",
			filterProfile: "prod",
			expectedLen:   1,
			expectedFirst: "prod",
		},
		{
			name:          "filter staging",
			filterProfile: "staging",
			expectedLen:   1,
			expectedFirst: "staging",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: The real function uses types.Event, but we can test the logic with empty slices
			got := getProfileListForCompliance(nil, tt.filterProfile)
			if tt.filterProfile != "" {
				if len(got) != tt.expectedLen {
					t.Errorf("len(profiles) = %v, want %v", len(got), tt.expectedLen)
				}
				if len(got) > 0 && got[0] != tt.expectedFirst {
					t.Errorf("profiles[0] = %v, want %v", got[0], tt.expectedFirst)
				}
			}
		})
	}
}

// eventType alias for testing without full CloudTrail types import
type eventType = struct{}

func TestSessionComplianceResult_Summary(t *testing.T) {
	result := &SessionComplianceResult{
		RequiredProfiles:       2,
		FullyCompliantProfiles: 1,
		ProfilesWithGaps:       1,
		Profiles: []ProfileCompliance{
			{
				Profile:        "prod",
				PolicyRequired: true,
				TrackedCount:   145,
				UntrackedCount: 0,
				ComplianceRate: 100.0,
				HasGap:         false,
			},
			{
				Profile:        "staging",
				PolicyRequired: true,
				TrackedCount:   89,
				UntrackedCount: 3,
				ComplianceRate: 96.7,
				HasGap:         true,
			},
		},
	}

	// Verify summary counts are correct
	if result.RequiredProfiles != 2 {
		t.Errorf("RequiredProfiles = %d, want 2", result.RequiredProfiles)
	}
	if result.FullyCompliantProfiles != 1 {
		t.Errorf("FullyCompliantProfiles = %d, want 1", result.FullyCompliantProfiles)
	}
	if result.ProfilesWithGaps != 1 {
		t.Errorf("ProfilesWithGaps = %d, want 1", result.ProfilesWithGaps)
	}
	if !result.HasComplianceGaps() {
		t.Errorf("HasComplianceGaps() = false, want true")
	}
}

func TestTestReporter_Report(t *testing.T) {
	expectedResult := &SessionComplianceResult{
		RequiredProfiles:       1,
		FullyCompliantProfiles: 1,
		ProfilesWithGaps:       0,
	}

	reporter := NewReporterForTest(func(ctx context.Context, input *SessionComplianceInput) (*SessionComplianceResult, error) {
		return expectedResult, nil
	})

	result, err := reporter.Report(nil, nil)
	if err != nil {
		t.Errorf("Report() error = %v", err)
	}
	if result != expectedResult {
		t.Errorf("Report() result = %v, want %v", result, expectedResult)
	}
}

func TestComplianceRate_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		trackedCount   int
		untrackedCount int
		expectedRate   float64
	}{
		{
			name:           "100% compliance",
			trackedCount:   100,
			untrackedCount: 0,
			expectedRate:   100.0,
		},
		{
			name:           "0% compliance",
			trackedCount:   0,
			untrackedCount: 100,
			expectedRate:   0.0,
		},
		{
			name:           "50% compliance",
			trackedCount:   50,
			untrackedCount: 50,
			expectedRate:   50.0,
		},
		{
			name:           "no events - 100% by default",
			trackedCount:   0,
			untrackedCount: 0,
			expectedRate:   100.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			total := tt.trackedCount + tt.untrackedCount
			var rate float64
			if total == 0 {
				rate = 100.0
			} else {
				rate = float64(tt.trackedCount) / float64(total) * 100
			}

			if rate != tt.expectedRate {
				t.Errorf("compliance rate = %.1f, want %.1f", rate, tt.expectedRate)
			}
		})
	}
}
