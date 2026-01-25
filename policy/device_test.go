package policy

import (
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/device"
)

func TestDeviceCondition_Validate(t *testing.T) {
	testCases := []struct {
		name      string
		condition DeviceCondition
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid - empty condition",
			condition: DeviceCondition{},
			wantErr:   false,
		},
		{
			name: "valid - require encryption only",
			condition: DeviceCondition{
				RequireEncryption: true,
			},
			wantErr: false,
		},
		{
			name: "valid - require MDM only",
			condition: DeviceCondition{
				RequireMDM: true,
			},
			wantErr: false,
		},
		{
			name: "valid - require MDM compliant",
			condition: DeviceCondition{
				RequireMDMCompliant: true,
			},
			wantErr: false,
		},
		{
			name: "valid - require firewall",
			condition: DeviceCondition{
				RequireFirewall: true,
			},
			wantErr: false,
		},
		{
			name: "valid - min OS version semver",
			condition: DeviceCondition{
				MinOSVersion: "14.0.0",
			},
			wantErr: false,
		},
		{
			name: "valid - min OS version simple",
			condition: DeviceCondition{
				MinOSVersion: "14.2",
			},
			wantErr: false,
		},
		{
			name: "valid - min OS version with prerelease",
			condition: DeviceCondition{
				MinOSVersion: "14.0.0-beta1",
			},
			wantErr: false,
		},
		{
			name: "valid - allowed OS types darwin",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"darwin"},
			},
			wantErr: false,
		},
		{
			name: "valid - allowed OS types multiple",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"darwin", "linux"},
			},
			wantErr: false,
		},
		{
			name: "valid - all requirements",
			condition: DeviceCondition{
				RequireEncryption:   true,
				RequireMDM:          true,
				RequireMDMCompliant: true,
				RequireFirewall:     true,
				MinOSVersion:        "14.0.0",
				AllowedOSTypes:      []string{"darwin", "windows", "linux"},
			},
			wantErr: false,
		},
		{
			name: "invalid - min OS version no digit",
			condition: DeviceCondition{
				MinOSVersion: "latest",
			},
			wantErr: true,
			errMsg:  "min_os_version must contain at least one digit",
		},
		{
			name: "invalid - allowed OS types unknown",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"freebsd"},
			},
			wantErr: true,
			errMsg:  "allowed_os_types contains unknown OS type: freebsd; valid types are: darwin, windows, linux",
		},
		{
			name: "invalid - allowed OS types mixed valid and invalid",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"darwin", "android"},
			},
			wantErr: true,
			errMsg:  "allowed_os_types contains unknown OS type: android; valid types are: darwin, windows, linux",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.condition.Validate()
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.errMsg)
				} else if err.Error() != tc.errMsg {
					t.Errorf("expected error %q, got %q", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestDeviceCondition_IsEmpty(t *testing.T) {
	testCases := []struct {
		name      string
		condition DeviceCondition
		want      bool
	}{
		{
			name:      "empty condition",
			condition: DeviceCondition{},
			want:      true,
		},
		{
			name: "require encryption set",
			condition: DeviceCondition{
				RequireEncryption: true,
			},
			want: false,
		},
		{
			name: "require MDM set",
			condition: DeviceCondition{
				RequireMDM: true,
			},
			want: false,
		},
		{
			name: "require MDM compliant set",
			condition: DeviceCondition{
				RequireMDMCompliant: true,
			},
			want: false,
		},
		{
			name: "require firewall set",
			condition: DeviceCondition{
				RequireFirewall: true,
			},
			want: false,
		},
		{
			name: "min OS version set",
			condition: DeviceCondition{
				MinOSVersion: "14.0",
			},
			want: false,
		},
		{
			name: "allowed OS types set",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"darwin"},
			},
			want: false,
		},
		{
			name: "empty allowed OS types slice",
			condition: DeviceCondition{
				AllowedOSTypes: []string{},
			},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.condition.IsEmpty()
			if got != tc.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDeviceCondition_Matches(t *testing.T) {
	now := time.Now()
	boolTrue := true
	boolFalse := false

	// Helper to create a valid base posture
	basePosture := func() *device.DevicePosture {
		return &device.DevicePosture{
			DeviceID:        "a1b2c3d4e5f67890a1b2c3d4e5f67890",
			Status:          device.StatusCompliant,
			DiskEncrypted:   &boolTrue,
			FirewallEnabled: &boolTrue,
			OSVersion:       "14.2.1",
			OSType:          "darwin",
			MDMEnrolled:     &boolTrue,
			MDMCompliant:    &boolTrue,
			CollectedAt:     now,
		}
	}

	testCases := []struct {
		name      string
		condition DeviceCondition
		posture   *device.DevicePosture
		want      bool
	}{
		{
			name:      "empty condition matches anything",
			condition: DeviceCondition{},
			posture:   basePosture(),
			want:      true,
		},
		{
			name:      "empty condition matches nil posture",
			condition: DeviceCondition{},
			posture:   nil,
			want:      true,
		},
		{
			name: "non-empty condition fails nil posture",
			condition: DeviceCondition{
				RequireEncryption: true,
			},
			posture: nil,
			want:    false,
		},
		// Encryption tests
		{
			name: "require encryption - posture has encryption",
			condition: DeviceCondition{
				RequireEncryption: true,
			},
			posture: basePosture(),
			want:    true,
		},
		{
			name: "require encryption - posture has no encryption",
			condition: DeviceCondition{
				RequireEncryption: true,
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.DiskEncrypted = &boolFalse
				return p
			}(),
			want: false,
		},
		{
			name: "require encryption - posture encryption nil",
			condition: DeviceCondition{
				RequireEncryption: true,
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.DiskEncrypted = nil
				return p
			}(),
			want: false,
		},
		// MDM enrollment tests
		{
			name: "require MDM - posture has MDM",
			condition: DeviceCondition{
				RequireMDM: true,
			},
			posture: basePosture(),
			want:    true,
		},
		{
			name: "require MDM - posture has no MDM",
			condition: DeviceCondition{
				RequireMDM: true,
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.MDMEnrolled = &boolFalse
				return p
			}(),
			want: false,
		},
		{
			name: "require MDM - posture MDM nil",
			condition: DeviceCondition{
				RequireMDM: true,
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.MDMEnrolled = nil
				return p
			}(),
			want: false,
		},
		// MDM compliance tests
		{
			name: "require MDM compliant - posture is compliant",
			condition: DeviceCondition{
				RequireMDMCompliant: true,
			},
			posture: basePosture(),
			want:    true,
		},
		{
			name: "require MDM compliant - posture not compliant",
			condition: DeviceCondition{
				RequireMDMCompliant: true,
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.MDMCompliant = &boolFalse
				return p
			}(),
			want: false,
		},
		{
			name: "require MDM compliant - posture compliance nil",
			condition: DeviceCondition{
				RequireMDMCompliant: true,
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.MDMCompliant = nil
				return p
			}(),
			want: false,
		},
		// Firewall tests
		{
			name: "require firewall - posture has firewall",
			condition: DeviceCondition{
				RequireFirewall: true,
			},
			posture: basePosture(),
			want:    true,
		},
		{
			name: "require firewall - posture has no firewall",
			condition: DeviceCondition{
				RequireFirewall: true,
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.FirewallEnabled = &boolFalse
				return p
			}(),
			want: false,
		},
		{
			name: "require firewall - posture firewall nil",
			condition: DeviceCondition{
				RequireFirewall: true,
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.FirewallEnabled = nil
				return p
			}(),
			want: false,
		},
		// OS version tests
		{
			name: "min OS version - posture meets requirement",
			condition: DeviceCondition{
				MinOSVersion: "14.0.0",
			},
			posture: basePosture(), // has 14.2.1
			want:    true,
		},
		{
			name: "min OS version - posture exceeds requirement",
			condition: DeviceCondition{
				MinOSVersion: "13.0.0",
			},
			posture: basePosture(), // has 14.2.1
			want:    true,
		},
		{
			name: "min OS version - posture equal to requirement",
			condition: DeviceCondition{
				MinOSVersion: "14.2.1",
			},
			posture: basePosture(), // has 14.2.1
			want:    true,
		},
		{
			name: "min OS version - posture below requirement",
			condition: DeviceCondition{
				MinOSVersion: "15.0.0",
			},
			posture: basePosture(), // has 14.2.1
			want:    false,
		},
		{
			name: "min OS version - posture has no version",
			condition: DeviceCondition{
				MinOSVersion: "14.0.0",
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.OSVersion = ""
				return p
			}(),
			want: false,
		},
		// OS type tests
		{
			name: "allowed OS types - single type matches",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"darwin"},
			},
			posture: basePosture(), // has darwin
			want:    true,
		},
		{
			name: "allowed OS types - multiple types matches",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"darwin", "linux"},
			},
			posture: basePosture(), // has darwin
			want:    true,
		},
		{
			name: "allowed OS types - type not in list",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"windows", "linux"},
			},
			posture: basePosture(), // has darwin
			want:    false,
		},
		{
			name: "allowed OS types - posture has no OS type",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"darwin"},
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.OSType = ""
				return p
			}(),
			want: false,
		},
		{
			name: "allowed OS types - case insensitive match",
			condition: DeviceCondition{
				AllowedOSTypes: []string{"Darwin"},
			},
			posture: basePosture(), // has darwin (lowercase)
			want:    true,
		},
		// Combined conditions
		{
			name: "multiple conditions - all met",
			condition: DeviceCondition{
				RequireEncryption:   true,
				RequireMDM:          true,
				RequireMDMCompliant: true,
				RequireFirewall:     true,
				MinOSVersion:        "14.0.0",
				AllowedOSTypes:      []string{"darwin"},
			},
			posture: basePosture(),
			want:    true,
		},
		{
			name: "multiple conditions - one not met (encryption)",
			condition: DeviceCondition{
				RequireEncryption: true,
				RequireFirewall:   true,
			},
			posture: func() *device.DevicePosture {
				p := basePosture()
				p.DiskEncrypted = &boolFalse
				return p
			}(),
			want: false,
		},
		{
			name: "multiple conditions - one not met (OS version)",
			condition: DeviceCondition{
				RequireEncryption: true,
				MinOSVersion:      "15.0.0",
			},
			posture: basePosture(),
			want:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.condition.Matches(tc.posture)
			if got != tc.want {
				t.Errorf("Matches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	testCases := []struct {
		v1       string
		v2       string
		wantSign int // -1, 0, or 1
	}{
		{"14.0.0", "14.0.0", 0},
		{"14.0.1", "14.0.0", 1},
		{"14.0.0", "14.0.1", -1},
		{"14.1.0", "14.0.0", 1},
		{"14.0.0", "14.1.0", -1},
		{"15.0.0", "14.0.0", 1},
		{"14.0.0", "15.0.0", -1},
		{"14.2.1", "14.0.0", 1},
		{"14.2", "14.0.0", 1},
		{"14", "14.0.0", 0},
		{"10.15.7", "10.14.6", 1},
		{"10.14.6", "10.15.7", -1},
	}

	for _, tc := range testCases {
		t.Run(tc.v1+"_vs_"+tc.v2, func(t *testing.T) {
			result := compareVersions(tc.v1, tc.v2)
			var gotSign int
			if result < 0 {
				gotSign = -1
			} else if result > 0 {
				gotSign = 1
			}
			if gotSign != tc.wantSign {
				t.Errorf("compareVersions(%q, %q) = %d (sign %d), want sign %d", tc.v1, tc.v2, result, gotSign, tc.wantSign)
			}
		})
	}
}
