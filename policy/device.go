package policy

import (
	"errors"
	"strings"

	"github.com/byteness/aws-vault/v7/device"
)

// KnownOSTypes defines the recognized operating system types for device posture.
var KnownOSTypes = []string{"darwin", "windows", "linux"}

// DeviceCondition defines device posture requirements for a rule.
// All specified requirements must be met for the condition to match.
// Empty/zero values are not checked (permissive by default).
type DeviceCondition struct {
	// RequireEncryption requires disk encryption to be enabled.
	RequireEncryption bool `yaml:"require_encryption,omitempty" json:"require_encryption,omitempty"`

	// RequireMDM requires device to be MDM enrolled.
	RequireMDM bool `yaml:"require_mdm,omitempty" json:"require_mdm,omitempty"`

	// RequireMDMCompliant requires device to be MDM compliant (implies RequireMDM).
	RequireMDMCompliant bool `yaml:"require_mdm_compliant,omitempty" json:"require_mdm_compliant,omitempty"`

	// RequireFirewall requires firewall to be enabled.
	RequireFirewall bool `yaml:"require_firewall,omitempty" json:"require_firewall,omitempty"`

	// MinOSVersion specifies minimum OS version (semver format, e.g., "14.0.0").
	// Version comparison is lexicographic for simplicity.
	MinOSVersion string `yaml:"min_os_version,omitempty" json:"min_os_version,omitempty"`

	// AllowedOSTypes restricts to specific OS types (darwin, windows, linux).
	// Empty list means any OS type allowed.
	AllowedOSTypes []string `yaml:"allowed_os_types,omitempty" json:"allowed_os_types,omitempty"`
}

// Validate checks that the DeviceCondition has valid configuration.
// Returns an error if validation fails.
func (c *DeviceCondition) Validate() error {
	// Validate MinOSVersion format if set
	if c.MinOSVersion != "" {
		// Simple validation: must contain at least one digit and only valid characters
		hasDigit := false
		for _, ch := range c.MinOSVersion {
			if ch >= '0' && ch <= '9' {
				hasDigit = true
			} else if ch != '.' && ch != '-' && ch != '+' && !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) {
				return errors.New("min_os_version contains invalid characters")
			}
		}
		if !hasDigit {
			return errors.New("min_os_version must contain at least one digit")
		}
	}

	// Validate AllowedOSTypes if set
	for _, osType := range c.AllowedOSTypes {
		if !isKnownOSType(osType) {
			return errors.New("allowed_os_types contains unknown OS type: " + osType + "; valid types are: darwin, windows, linux")
		}
	}

	return nil
}

// IsEmpty returns true if no device requirements are set.
func (c *DeviceCondition) IsEmpty() bool {
	return !c.RequireEncryption &&
		!c.RequireMDM &&
		!c.RequireMDMCompliant &&
		!c.RequireFirewall &&
		c.MinOSVersion == "" &&
		len(c.AllowedOSTypes) == 0
}

// Matches checks if the device posture meets all requirements in this condition.
// All specified requirements must be met (AND logic).
// Returns true if posture meets all requirements, false otherwise.
// If posture is nil, returns false for any non-empty condition.
func (c *DeviceCondition) Matches(posture *device.DevicePosture) bool {
	// Nil posture fails any non-empty condition
	if posture == nil {
		return c.IsEmpty()
	}

	// Check encryption requirement
	if c.RequireEncryption {
		if posture.DiskEncrypted == nil || !*posture.DiskEncrypted {
			return false
		}
	}

	// Check MDM enrollment requirement
	if c.RequireMDM {
		if posture.MDMEnrolled == nil || !*posture.MDMEnrolled {
			return false
		}
	}

	// Check MDM compliance requirement (implies MDM enrollment)
	if c.RequireMDMCompliant {
		if posture.MDMCompliant == nil || !*posture.MDMCompliant {
			return false
		}
	}

	// Check firewall requirement
	if c.RequireFirewall {
		if posture.FirewallEnabled == nil || !*posture.FirewallEnabled {
			return false
		}
	}

	// Check minimum OS version
	if c.MinOSVersion != "" {
		if posture.OSVersion == "" {
			return false
		}
		// Simple lexicographic comparison (works for most version formats)
		if compareVersions(posture.OSVersion, c.MinOSVersion) < 0 {
			return false
		}
	}

	// Check allowed OS types
	if len(c.AllowedOSTypes) > 0 {
		if posture.OSType == "" {
			return false
		}
		found := false
		for _, allowed := range c.AllowedOSTypes {
			if strings.EqualFold(posture.OSType, allowed) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// isKnownOSType checks if the given OS type is a known value.
func isKnownOSType(osType string) bool {
	lower := strings.ToLower(osType)
	for _, known := range KnownOSTypes {
		if lower == known {
			return true
		}
	}
	return false
}

// compareVersions compares two version strings.
// Returns negative if v1 < v2, zero if v1 == v2, positive if v1 > v2.
// Uses simple segment-by-segment numeric comparison.
func compareVersions(v1, v2 string) int {
	// Split by common separators
	parts1 := splitVersion(v1)
	parts2 := splitVersion(v2)

	// Compare segment by segment
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		if i < len(parts1) {
			p1 = parseVersionPart(parts1[i])
		}
		if i < len(parts2) {
			p2 = parseVersionPart(parts2[i])
		}

		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}

	return 0
}

// splitVersion splits a version string into parts.
func splitVersion(v string) []string {
	var parts []string
	var current strings.Builder

	for _, ch := range v {
		if ch == '.' || ch == '-' || ch == '+' {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// parseVersionPart parses a version part as an integer.
// Non-numeric parts are treated as 0.
func parseVersionPart(s string) int {
	var n int
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		} else {
			// Stop at first non-digit
			break
		}
	}
	return n
}
