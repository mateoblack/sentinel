package cli

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "7 days",
			input:    "7d",
			expected: 7 * 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "24 hours",
			input:    "24h",
			expected: 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "30 minutes",
			input:    "30m",
			expected: 30 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "1 day 12 hours",
			input:    "1d12h",
			expected: 36 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "2 days 6 hours 30 minutes",
			input:    "2d6h30m",
			expected: 54*time.Hour + 30*time.Minute,
			wantErr:  false,
		},
		{
			name:     "1 second",
			input:    "1s",
			expected: 1 * time.Second,
			wantErr:  false,
		},
		{
			name:     "100 milliseconds",
			input:    "100ms",
			expected: 100 * time.Millisecond,
			wantErr:  false,
		},
		{
			name:     "0 days",
			input:    "0d",
			expected: 0,
			wantErr:  false,
		},
		{
			name:    "invalid format - letters",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "invalid days format",
			input:   "xd",
			wantErr: true,
		},
		{
			name:    "invalid remainder after days",
			input:   "1dinvalid",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("ParseDuration() = %v, want %v", got, tt.expected)
			}
		})
	}
}
