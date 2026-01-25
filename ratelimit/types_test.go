package ratelimit

import (
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: Config{
				RequestsPerWindow: 100,
				Window:            time.Minute,
			},
			wantErr: false,
		},
		{
			name: "valid config with burst",
			config: Config{
				RequestsPerWindow: 100,
				Window:            time.Minute,
				BurstSize:         150,
			},
			wantErr: false,
		},
		{
			name: "zero requests per window",
			config: Config{
				RequestsPerWindow: 0,
				Window:            time.Minute,
			},
			wantErr: true,
			errMsg:  "RequestsPerWindow must be positive",
		},
		{
			name: "negative requests per window",
			config: Config{
				RequestsPerWindow: -1,
				Window:            time.Minute,
			},
			wantErr: true,
			errMsg:  "RequestsPerWindow must be positive",
		},
		{
			name: "zero window",
			config: Config{
				RequestsPerWindow: 100,
				Window:            0,
			},
			wantErr: true,
			errMsg:  "Window must be positive",
		},
		{
			name: "negative window",
			config: Config{
				RequestsPerWindow: 100,
				Window:            -time.Minute,
			},
			wantErr: true,
			errMsg:  "Window must be positive",
		},
		{
			name: "negative burst size",
			config: Config{
				RequestsPerWindow: 100,
				Window:            time.Minute,
				BurstSize:         -1,
			},
			wantErr: true,
			errMsg:  "BurstSize cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && err.Error()[:len(tt.errMsg)] != tt.errMsg {
					t.Errorf("error message mismatch: expected %q prefix, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfig_EffectiveBurstSize(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected int
	}{
		{
			name: "burst size not set",
			config: Config{
				RequestsPerWindow: 100,
				Window:            time.Minute,
			},
			expected: 100,
		},
		{
			name: "burst size set",
			config: Config{
				RequestsPerWindow: 100,
				Window:            time.Minute,
				BurstSize:         150,
			},
			expected: 150,
		},
		{
			name: "burst size zero uses requests per window",
			config: Config{
				RequestsPerWindow: 100,
				Window:            time.Minute,
				BurstSize:         0,
			},
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.EffectiveBurstSize()
			if got != tt.expected {
				t.Errorf("EffectiveBurstSize() = %d, want %d", got, tt.expected)
			}
		})
	}
}
