package audit

import (
	"testing"
)

func TestUntrackedSessionsResult_ComplianceRate(t *testing.T) {
	tests := []struct {
		name          string
		totalEvents   int
		trackedEvents int
		expected      float64
	}{
		{
			name:          "all tracked",
			totalEvents:   10,
			trackedEvents: 10,
			expected:      100.0,
		},
		{
			name:          "none tracked",
			totalEvents:   10,
			trackedEvents: 0,
			expected:      0.0,
		},
		{
			name:          "70% tracked",
			totalEvents:   10,
			trackedEvents: 7,
			expected:      70.0,
		},
		{
			name:          "no events - returns 100%",
			totalEvents:   0,
			trackedEvents: 0,
			expected:      100.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &UntrackedSessionsResult{
				TotalEvents:   tt.totalEvents,
				TrackedEvents: tt.trackedEvents,
			}
			got := result.ComplianceRate()
			if got != tt.expected {
				t.Errorf("ComplianceRate() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsSentinelSourceIdentity(t *testing.T) {
	tests := []struct {
		name           string
		sourceIdentity string
		expected       bool
	}{
		{
			name:           "valid sentinel format - 3 parts",
			sourceIdentity: "sentinel:alice:direct:a1b2c3d4",
			expected:       true,
		},
		{
			name:           "valid sentinel format - legacy 2 parts",
			sourceIdentity: "sentinel:alice:a1b2c3d4",
			expected:       true,
		},
		{
			name:           "valid sentinel with approval ID",
			sourceIdentity: "sentinel:alice:abcd1234:a1b2c3d4",
			expected:       true,
		},
		{
			name:           "empty string",
			sourceIdentity: "",
			expected:       false,
		},
		{
			name:           "no sentinel prefix",
			sourceIdentity: "alice:direct:a1b2c3d4",
			expected:       false,
		},
		{
			name:           "sentinel prefix but only 1 part",
			sourceIdentity: "sentinel:alice",
			expected:       false,
		},
		{
			name:           "sentinel prefix but too many parts",
			sourceIdentity: "sentinel:alice:direct:a1b2c3d4:extra",
			expected:       false,
		},
		{
			name:           "different prefix",
			sourceIdentity: "SENTINEL:alice:a1b2c3d4",
			expected:       false,
		},
		{
			name:           "aws-assumedrole format",
			sourceIdentity: "aws:assumed-role/TestRole/session",
			expected:       false,
		},
		{
			name:           "custom source identity",
			sourceIdentity: "custom-app:user123",
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSentinelSourceIdentity(tt.sourceIdentity)
			if got != tt.expected {
				t.Errorf("isSentinelSourceIdentity(%q) = %v, want %v", tt.sourceIdentity, got, tt.expected)
			}
		})
	}
}

func TestUntrackedCategory_Values(t *testing.T) {
	// Verify category constants have expected values
	tests := []struct {
		category UntrackedCategory
		expected string
	}{
		{CategoryNoSourceIdentity, "no_source_identity"},
		{CategoryNonSentinel, "non_sentinel_format"},
		{CategoryOrphaned, "orphaned"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.category) != tt.expected {
				t.Errorf("UntrackedCategory = %v, want %v", tt.category, tt.expected)
			}
		})
	}
}
