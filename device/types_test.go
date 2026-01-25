package device

import (
	"testing"
	"time"
)

func TestNewDeviceID(t *testing.T) {
	t.Run("generates valid 32-char hex string", func(t *testing.T) {
		id := NewDeviceID()

		// Must be exactly 32 characters
		if len(id) != DeviceIDLength {
			t.Errorf("NewDeviceID() length = %d, want %d", len(id), DeviceIDLength)
		}

		// Must be valid according to ValidateDeviceID
		if !ValidateDeviceID(id) {
			t.Errorf("NewDeviceID() = %q is not valid", id)
		}

		// Must be lowercase hex
		for i, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("NewDeviceID() char %d = %q is not lowercase hex", i, string(c))
			}
		}
	})

	t.Run("multiple calls produce unique IDs", func(t *testing.T) {
		const count = 1000
		seen := make(map[string]bool, count)

		for i := 0; i < count; i++ {
			id := NewDeviceID()
			if seen[id] {
				t.Errorf("collision detected: %q generated more than once in %d iterations", id, i+1)
				return
			}
			seen[id] = true
		}
	})

	t.Run("ID passes ValidateDeviceID", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			id := NewDeviceID()
			if !ValidateDeviceID(id) {
				t.Errorf("NewDeviceID() iteration %d: %q failed validation", i, id)
			}
		}
	})
}

func TestValidateDeviceID(t *testing.T) {
	testCases := []struct {
		name  string
		id    string
		valid bool
	}{
		{
			name:  "valid - all digits",
			id:    "12345678901234567890123456789012",
			valid: true,
		},
		{
			name:  "valid - all lowercase hex letters",
			id:    "abcdefabcdefabcdefabcdefabcdefab",
			valid: true,
		},
		{
			name:  "valid - mixed",
			id:    "a1b2c3d4e5f67890a1b2c3d4e5f67890",
			valid: true,
		},
		{
			name:  "valid - all zeros",
			id:    "00000000000000000000000000000000",
			valid: true,
		},
		{
			name:  "valid - deadbeefcafe pattern",
			id:    "deadbeefcafedeadbeefcafe12345678",
			valid: true,
		},
		{
			name:  "invalid - too short (31 chars)",
			id:    "1234567890123456789012345678901",
			valid: false,
		},
		{
			name:  "invalid - too long (33 chars)",
			id:    "123456789012345678901234567890123",
			valid: false,
		},
		{
			name:  "invalid - 16 chars (session ID length)",
			id:    "1234567890123456",
			valid: false,
		},
		{
			name:  "invalid - empty",
			id:    "",
			valid: false,
		},
		{
			name:  "invalid - uppercase",
			id:    "ABCDEFABCDEFABCDEFABCDEFABCDEFAB",
			valid: false,
		},
		{
			name:  "invalid - mixed case",
			id:    "AbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAb",
			valid: false,
		},
		{
			name:  "invalid - non-hex letters",
			id:    "ghijklmnghijklmnghijklmnghijklmn",
			valid: false,
		},
		{
			name:  "invalid - special characters",
			id:    "1234-5678-9012-3456-7890-1234-56",
			valid: false,
		},
		{
			name:  "invalid - spaces",
			id:    "1234 5678 9012 3456 7890 1234 56",
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateDeviceID(tc.id)
			if got != tc.valid {
				t.Errorf("ValidateDeviceID(%q) = %v, want %v", tc.id, got, tc.valid)
			}
		})
	}
}

func TestPostureStatus_IsValid(t *testing.T) {
	testCases := []struct {
		name   string
		status PostureStatus
		valid  bool
	}{
		{
			name:   "compliant is valid",
			status: StatusCompliant,
			valid:  true,
		},
		{
			name:   "non_compliant is valid",
			status: StatusNonCompliant,
			valid:  true,
		},
		{
			name:   "unknown is valid",
			status: StatusUnknown,
			valid:  true,
		},
		{
			name:   "empty is invalid",
			status: "",
			valid:  false,
		},
		{
			name:   "invalid status is invalid",
			status: "invalid",
			valid:  false,
		},
		{
			name:   "COMPLIANT uppercase is invalid",
			status: "COMPLIANT",
			valid:  false,
		},
		{
			name:   "partial match is invalid",
			status: "comp",
			valid:  false,
		},
		{
			name:   "active (session status) is invalid",
			status: "active",
			valid:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.status.IsValid()
			if got != tc.valid {
				t.Errorf("PostureStatus(%q).IsValid() = %v, want %v", tc.status, got, tc.valid)
			}
		})
	}
}

func TestPostureStatus_String(t *testing.T) {
	testCases := []struct {
		status PostureStatus
		want   string
	}{
		{StatusCompliant, "compliant"},
		{StatusNonCompliant, "non_compliant"},
		{StatusUnknown, "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.status.String()
			if got != tc.want {
				t.Errorf("PostureStatus(%q).String() = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestDevicePosture_Validate(t *testing.T) {
	now := time.Now()
	boolTrue := true
	boolFalse := false

	testCases := []struct {
		name    string
		posture DevicePosture
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid - minimal required fields",
			posture: DevicePosture{
				DeviceID:    "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:      StatusCompliant,
				CollectedAt: now,
			},
			wantErr: false,
		},
		{
			name: "valid - all fields populated",
			posture: DevicePosture{
				DeviceID:         "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:           StatusCompliant,
				DiskEncrypted:    &boolTrue,
				FirewallEnabled:  &boolTrue,
				OSVersion:        "14.2.1",
				OSType:           "darwin",
				MDMEnrolled:      &boolTrue,
				MDMCompliant:     &boolTrue,
				CollectedAt:      now,
				CollectorVersion: "1.0.0",
			},
			wantErr: false,
		},
		{
			name: "valid - non_compliant status with false values",
			posture: DevicePosture{
				DeviceID:        "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:          StatusNonCompliant,
				DiskEncrypted:   &boolFalse,
				FirewallEnabled: &boolFalse,
				CollectedAt:     now,
			},
			wantErr: false,
		},
		{
			name: "valid - unknown status",
			posture: DevicePosture{
				DeviceID:    "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:      StatusUnknown,
				CollectedAt: now,
			},
			wantErr: false,
		},
		{
			name: "invalid - empty device_id",
			posture: DevicePosture{
				DeviceID:    "",
				Status:      StatusCompliant,
				CollectedAt: now,
			},
			wantErr: true,
			errMsg:  "device_id is required",
		},
		{
			name: "invalid - malformed device_id (too short)",
			posture: DevicePosture{
				DeviceID:    "a1b2c3d4",
				Status:      StatusCompliant,
				CollectedAt: now,
			},
			wantErr: true,
			errMsg:  "device_id must be 32 lowercase hex characters",
		},
		{
			name: "invalid - malformed device_id (uppercase)",
			posture: DevicePosture{
				DeviceID:    "A1B2C3D4E5F67890A1B2C3D4E5F67890",
				Status:      StatusCompliant,
				CollectedAt: now,
			},
			wantErr: true,
			errMsg:  "device_id must be 32 lowercase hex characters",
		},
		{
			name: "invalid - empty status",
			posture: DevicePosture{
				DeviceID:    "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:      "",
				CollectedAt: now,
			},
			wantErr: true,
			errMsg:  "status must be compliant, non_compliant, or unknown",
		},
		{
			name: "invalid - invalid status",
			posture: DevicePosture{
				DeviceID:    "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:      "pending",
				CollectedAt: now,
			},
			wantErr: true,
			errMsg:  "status must be compliant, non_compliant, or unknown",
		},
		{
			name: "invalid - zero collected_at",
			posture: DevicePosture{
				DeviceID: "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:   StatusCompliant,
				// CollectedAt is zero value
			},
			wantErr: true,
			errMsg:  "collected_at is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.posture.Validate()
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

func TestDevicePosture_IsCompliant(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		name      string
		status    PostureStatus
		compliant bool
	}{
		{
			name:      "compliant status returns true",
			status:    StatusCompliant,
			compliant: true,
		},
		{
			name:      "non_compliant status returns false",
			status:    StatusNonCompliant,
			compliant: false,
		},
		{
			name:      "unknown status returns false",
			status:    StatusUnknown,
			compliant: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			posture := &DevicePosture{
				DeviceID:    "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:      tc.status,
				CollectedAt: now,
			}
			got := posture.IsCompliant()
			if got != tc.compliant {
				t.Errorf("DevicePosture{Status: %q}.IsCompliant() = %v, want %v", tc.status, got, tc.compliant)
			}
		})
	}
}

func TestDevicePosture_HasDiskEncryption(t *testing.T) {
	now := time.Now()
	boolTrue := true
	boolFalse := false

	testCases := []struct {
		name          string
		diskEncrypted *bool
		want          bool
	}{
		{
			name:          "nil returns false (not checked)",
			diskEncrypted: nil,
			want:          false,
		},
		{
			name:          "true returns true",
			diskEncrypted: &boolTrue,
			want:          true,
		},
		{
			name:          "false returns false",
			diskEncrypted: &boolFalse,
			want:          false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			posture := &DevicePosture{
				DeviceID:      "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:        StatusCompliant,
				DiskEncrypted: tc.diskEncrypted,
				CollectedAt:   now,
			}
			got := posture.HasDiskEncryption()
			if got != tc.want {
				t.Errorf("HasDiskEncryption() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDevicePosture_HasFirewall(t *testing.T) {
	now := time.Now()
	boolTrue := true
	boolFalse := false

	testCases := []struct {
		name            string
		firewallEnabled *bool
		want            bool
	}{
		{
			name:            "nil returns false (not checked)",
			firewallEnabled: nil,
			want:            false,
		},
		{
			name:            "true returns true",
			firewallEnabled: &boolTrue,
			want:            true,
		},
		{
			name:            "false returns false",
			firewallEnabled: &boolFalse,
			want:            false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			posture := &DevicePosture{
				DeviceID:        "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:          StatusCompliant,
				FirewallEnabled: tc.firewallEnabled,
				CollectedAt:     now,
			}
			got := posture.HasFirewall()
			if got != tc.want {
				t.Errorf("HasFirewall() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDevicePosture_HasMDMEnrollment(t *testing.T) {
	now := time.Now()
	boolTrue := true
	boolFalse := false

	testCases := []struct {
		name        string
		mdmEnrolled *bool
		want        bool
	}{
		{
			name:        "nil returns false (not checked)",
			mdmEnrolled: nil,
			want:        false,
		},
		{
			name:        "true returns true",
			mdmEnrolled: &boolTrue,
			want:        true,
		},
		{
			name:        "false returns false",
			mdmEnrolled: &boolFalse,
			want:        false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			posture := &DevicePosture{
				DeviceID:    "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:      StatusCompliant,
				MDMEnrolled: tc.mdmEnrolled,
				CollectedAt: now,
			}
			got := posture.HasMDMEnrollment()
			if got != tc.want {
				t.Errorf("HasMDMEnrollment() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDevicePosture_HasMDMCompliance(t *testing.T) {
	now := time.Now()
	boolTrue := true
	boolFalse := false

	testCases := []struct {
		name         string
		mdmCompliant *bool
		want         bool
	}{
		{
			name:         "nil returns false (not checked)",
			mdmCompliant: nil,
			want:         false,
		},
		{
			name:         "true returns true",
			mdmCompliant: &boolTrue,
			want:         true,
		},
		{
			name:         "false returns false",
			mdmCompliant: &boolFalse,
			want:         false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			posture := &DevicePosture{
				DeviceID:     "a1b2c3d4e5f67890a1b2c3d4e5f67890",
				Status:       StatusCompliant,
				MDMCompliant: tc.mdmCompliant,
				CollectedAt:  now,
			}
			got := posture.HasMDMCompliance()
			if got != tc.want {
				t.Errorf("HasMDMCompliance() = %v, want %v", got, tc.want)
			}
		})
	}
}
