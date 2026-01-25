// Package mdm provides MDM (Mobile Device Management) integration for Sentinel.
// It enables server-side device posture verification by querying MDM providers
// (Jamf, Intune, Kandji) to validate device enrollment and compliance status.
//
// # MDM Device Lookup
//
// MDM providers are queried using device identifiers (UDID, serial number, or
// Sentinel's HMAC-hashed device ID) to retrieve enrollment and compliance status.
//
// # Provider Abstraction
//
// The Provider interface enables multiple MDM backends while maintaining a
// consistent API for TVM (Token Vending Machine) integration.
package mdm

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors for MDM operations.
var (
	// ErrDeviceNotFound is returned when the device ID is not registered in MDM.
	ErrDeviceNotFound = errors.New("device not found in MDM")

	// ErrMDMUnavailable is returned when the MDM API is unreachable.
	ErrMDMUnavailable = errors.New("MDM service unavailable")

	// ErrMDMAuthFailed is returned when MDM authentication fails.
	ErrMDMAuthFailed = errors.New("MDM authentication failed")
)

// MDMDeviceInfo contains device posture information returned by an MDM provider.
// This is the normalized response format across all MDM backends.
type MDMDeviceInfo struct {
	// DeviceID is the hardware identifier (UDID/SerialNumber) mapped to Sentinel's device ID.
	// This is the key used for device lookup in the MDM system.
	DeviceID string `json:"device_id"`

	// Enrolled indicates whether the device is enrolled in MDM.
	Enrolled bool `json:"enrolled"`

	// Compliant indicates whether the device meets MDM compliance policies.
	Compliant bool `json:"compliant"`

	// ComplianceDetails provides the reason for non-compliance if applicable.
	// Empty when compliant.
	ComplianceDetails string `json:"compliance_details,omitempty"`

	// LastCheckIn is when the device last reported to MDM.
	LastCheckIn time.Time `json:"last_check_in"`

	// OSVersion is the OS version reported by MDM (e.g., "14.2.1").
	OSVersion string `json:"os_version,omitempty"`

	// DeviceName is the human-readable device name (e.g., "John's MacBook Pro").
	DeviceName string `json:"device_name,omitempty"`

	// MDMProvider identifies which MDM provider returned this information.
	MDMProvider string `json:"mdm_provider"`
}

// Validate checks that MDMDeviceInfo has valid required fields.
// Returns an error if validation fails.
func (d *MDMDeviceInfo) Validate() error {
	if d.DeviceID == "" {
		return errors.New("device_id is required")
	}
	if d.MDMProvider == "" {
		return errors.New("mdm_provider is required")
	}
	if d.LastCheckIn.IsZero() {
		return errors.New("last_check_in is required")
	}
	return nil
}

// MDMConfig holds configuration for MDM provider initialization.
type MDMConfig struct {
	// ProviderType identifies the MDM provider (jamf, intune, kandji).
	ProviderType string `json:"provider_type"`

	// BaseURL is the MDM API endpoint (e.g., "https://company.jamfcloud.com").
	BaseURL string `json:"base_url"`

	// APIToken is the authentication token for the MDM API.
	// This should be loaded from Secrets Manager, not hardcoded.
	APIToken string `json:"api_token"`

	// TenantID is required for multi-tenant MDMs like Intune.
	// Optional for single-tenant providers like Jamf.
	TenantID string `json:"tenant_id,omitempty"`

	// Timeout is the maximum duration for MDM API calls.
	// Defaults to 10 seconds if not specified.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// DefaultTimeout is the default timeout for MDM API calls.
const DefaultTimeout = 10 * time.Second

// Validate checks that MDMConfig has valid required fields.
// Returns an error if validation fails.
func (c *MDMConfig) Validate() error {
	if c.ProviderType == "" {
		return errors.New("provider_type is required")
	}
	if c.BaseURL == "" {
		return errors.New("base_url is required")
	}
	return nil
}

// GetTimeout returns the configured timeout or the default.
func (c *MDMConfig) GetTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// MDMError is a structured error for MDM operations.
// It wraps the underlying error with provider and device context.
type MDMError struct {
	// Provider is the name of the MDM provider that failed.
	Provider string

	// DeviceID is the device identifier for which the lookup failed.
	DeviceID string

	// Err is the underlying error.
	Err error
}

// Error returns a formatted error string with provider and device context.
func (e *MDMError) Error() string {
	if e.DeviceID != "" {
		return fmt.Sprintf("mdm %s: device %s: %v", e.Provider, e.DeviceID, e.Err)
	}
	return fmt.Sprintf("mdm %s: %v", e.Provider, e.Err)
}

// Unwrap returns the underlying error for error chain compatibility.
func (e *MDMError) Unwrap() error {
	return e.Err
}
