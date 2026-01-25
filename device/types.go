// Package device defines Sentinel's device posture schema for v1.15 Device Posture.
// Device posture is collected from endpoints and evaluated against policy conditions
// to determine whether credential requests should be allowed based on device security state.
//
// # Device Posture Claims
//
// Device posture consists of claims about the device's security configuration:
//   - Disk encryption status
//   - Firewall status
//   - OS type and version
//   - MDM enrollment and compliance status
//
// # Device ID Format
//
// Device IDs are 32-character lowercase hexadecimal strings (128 bits of entropy),
// providing unique identification for device fingerprinting and correlation.
package device

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"time"
)

const (
	// DeviceIDLength is the exact length for device IDs (32 hex chars = 128 bits).
	DeviceIDLength = 32
)

// PostureStatus represents the overall device posture compliance status.
type PostureStatus string

const (
	// StatusCompliant indicates the device meets all policy requirements.
	StatusCompliant PostureStatus = "compliant"
	// StatusNonCompliant indicates the device fails one or more policy requirements.
	StatusNonCompliant PostureStatus = "non_compliant"
	// StatusUnknown indicates the device posture cannot be determined.
	StatusUnknown PostureStatus = "unknown"
)

// IsValid returns true if the PostureStatus is a known value.
func (s PostureStatus) IsValid() bool {
	switch s {
	case StatusCompliant, StatusNonCompliant, StatusUnknown:
		return true
	}
	return false
}

// String returns the string representation of the PostureStatus.
func (s PostureStatus) String() string {
	return string(s)
}

// deviceIDRegex matches valid device IDs (32 lowercase hex chars).
var deviceIDRegex = regexp.MustCompile(`^[0-9a-f]{32}$`)

// NewDeviceID generates a new 32-character lowercase hex device ID.
// It uses crypto/rand for cryptographic randomness.
//
// The device ID provides:
//   - Unique identification per device
//   - Correlation across device posture evaluations
//   - Fingerprinting for security forensics
func NewDeviceID() string {
	// Generate 16 random bytes (128 bits of entropy)
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		// This should never happen with crypto/rand
		// Fall back to zeros rather than panic
		return "00000000000000000000000000000000"
	}

	// Encode as 32-character lowercase hex string
	return hex.EncodeToString(bytes)
}

// ValidateDeviceID checks if the given string is a valid device ID.
// A valid device ID is exactly 32 lowercase hexadecimal characters.
func ValidateDeviceID(id string) bool {
	return deviceIDRegex.MatchString(id)
}

// DevicePosture contains device posture claims collected from an endpoint.
// Use pointer bools for optional fields to distinguish "not checked" (nil)
// from "checked and false" (pointer to false).
type DevicePosture struct {
	// DeviceID is the unique device identifier (32 lowercase hex chars).
	DeviceID string `json:"device_id"`

	// Status is the overall posture compliance status.
	Status PostureStatus `json:"status"`

	// DiskEncrypted indicates whether disk encryption is enabled.
	// nil = not checked, false = checked and disabled, true = enabled.
	DiskEncrypted *bool `json:"disk_encrypted,omitempty"`

	// FirewallEnabled indicates whether the firewall is enabled.
	// nil = not checked, false = checked and disabled, true = enabled.
	FirewallEnabled *bool `json:"firewall_enabled,omitempty"`

	// OSVersion is the operating system version string (e.g., "14.2.1").
	OSVersion string `json:"os_version,omitempty"`

	// OSType is the operating system type (darwin, windows, linux).
	OSType string `json:"os_type,omitempty"`

	// MDMEnrolled indicates whether the device is enrolled in MDM.
	// nil = not checked, false = not enrolled, true = enrolled.
	MDMEnrolled *bool `json:"mdm_enrolled,omitempty"`

	// MDMCompliant indicates whether the device is MDM compliant.
	// nil = not checked, false = not compliant, true = compliant.
	MDMCompliant *bool `json:"mdm_compliant,omitempty"`

	// CollectedAt is when the posture was collected from the device.
	CollectedAt time.Time `json:"collected_at"`

	// CollectorVersion is the version of the posture collector agent.
	CollectorVersion string `json:"collector_version,omitempty"`
}

// Validate checks that the DevicePosture has valid required fields.
// Returns an error if validation fails.
func (p *DevicePosture) Validate() error {
	if p.DeviceID == "" {
		return errors.New("device_id is required")
	}
	if !ValidateDeviceID(p.DeviceID) {
		return errors.New("device_id must be 32 lowercase hex characters")
	}
	if !p.Status.IsValid() {
		return errors.New("status must be compliant, non_compliant, or unknown")
	}
	if p.CollectedAt.IsZero() {
		return errors.New("collected_at is required")
	}
	return nil
}

// IsCompliant returns true if the device posture status is compliant.
func (p *DevicePosture) IsCompliant() bool {
	return p.Status == StatusCompliant
}

// HasDiskEncryption returns true if disk encryption is confirmed enabled.
// Returns false if not checked (nil) or checked and disabled.
func (p *DevicePosture) HasDiskEncryption() bool {
	return p.DiskEncrypted != nil && *p.DiskEncrypted
}

// HasFirewall returns true if the firewall is confirmed enabled.
// Returns false if not checked (nil) or checked and disabled.
func (p *DevicePosture) HasFirewall() bool {
	return p.FirewallEnabled != nil && *p.FirewallEnabled
}

// HasMDMEnrollment returns true if MDM enrollment is confirmed.
// Returns false if not checked (nil) or not enrolled.
func (p *DevicePosture) HasMDMEnrollment() bool {
	return p.MDMEnrolled != nil && *p.MDMEnrolled
}

// HasMDMCompliance returns true if MDM compliance is confirmed.
// Returns false if not checked (nil) or not compliant.
func (p *DevicePosture) HasMDMCompliance() bool {
	return p.MDMCompliant != nil && *p.MDMCompliant
}
