// Package mdm provides MDM integration for Sentinel.
// This file implements the Jamf Pro MDM provider.
package mdm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// jamfAPI is an interface for HTTP operations, enabling test mocking.
type jamfAPI interface {
	Do(req *http.Request) (*http.Response, error)
}

// JamfProvider implements the Provider interface for Jamf Pro MDM.
// It queries the Jamf Pro API v1 to verify device enrollment and compliance.
//
// # Production Deployment Note
//
// Jamf Pro uses hardware UDID or serial number for device identification,
// not Sentinel's HMAC-SHA256 device ID. For production deployment:
//
//  1. Configure a Jamf Extension Attribute named "SentinelDeviceID"
//  2. Populate this attribute during device enrollment with the Sentinel device ID
//  3. The provider queries: extensionAttributes.SentinelDeviceID=={deviceID}
//
// Without this configuration, the provider falls back to serial number matching,
// which requires a separate device ID mapping solution.
type JamfProvider struct {
	httpClient jamfAPI
	baseURL    string
	apiToken   string
	timeout    time.Duration
}

// NewJamfProvider creates a new JamfProvider with the given configuration.
// Returns an error if required configuration is missing.
func NewJamfProvider(cfg *MDMConfig) (*JamfProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base_url is required for Jamf provider")
	}
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("api_token is required for Jamf provider")
	}

	timeout := cfg.GetTimeout()

	return &JamfProvider{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		baseURL:  cfg.BaseURL,
		apiToken: cfg.APIToken,
		timeout:  timeout,
	}, nil
}

// Name returns "jamf" as the provider name.
func (p *JamfProvider) Name() string {
	return "jamf"
}

// LookupDevice queries Jamf Pro for device information by device ID.
// The deviceID should be stored as a Jamf Extension Attribute named "SentinelDeviceID".
//
// Returns:
//   - MDMDeviceInfo on success
//   - ErrDeviceNotFound if device is not registered in Jamf
//   - ErrMDMAuthFailed on 401/403 responses
//   - ErrMDMUnavailable on network errors or timeouts
func (p *JamfProvider) LookupDevice(ctx context.Context, deviceID string) (*MDMDeviceInfo, error) {
	if deviceID == "" {
		return nil, ErrDeviceNotFound
	}

	req, err := p.buildJamfRequest(ctx, deviceID)
	if err != nil {
		return nil, &MDMError{
			Provider: p.Name(),
			DeviceID: deviceID,
			Err:      err,
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, &MDMError{
			Provider: p.Name(),
			DeviceID: deviceID,
			Err:      ErrMDMUnavailable,
		}
	}
	defer resp.Body.Close()

	// Handle HTTP status codes
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &MDMError{
			Provider: p.Name(),
			DeviceID: deviceID,
			Err:      ErrMDMAuthFailed,
		}
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrDeviceNotFound
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, &MDMError{
			Provider: p.Name(),
			DeviceID: deviceID,
			Err:      fmt.Errorf("unexpected status code: %d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &MDMError{
			Provider: p.Name(),
			DeviceID: deviceID,
			Err:      ErrMDMUnavailable,
		}
	}

	info, err := parseJamfResponse(body)
	if err != nil {
		return nil, &MDMError{
			Provider: p.Name(),
			DeviceID: deviceID,
			Err:      err,
		}
	}

	return info, nil
}

// buildJamfRequest creates an HTTP request for the Jamf Pro API.
// It queries the computers-inventory endpoint with a filter for the Sentinel device ID
// stored as an extension attribute.
func (p *JamfProvider) buildJamfRequest(ctx context.Context, deviceID string) (*http.Request, error) {
	// Build the filter query for extension attribute lookup
	// Primary: Extension Attribute named "SentinelDeviceID"
	filter := fmt.Sprintf("extensionAttributes.SentinelDeviceID==%s", url.QueryEscape(deviceID))

	apiURL := fmt.Sprintf("%s/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&filter=%s",
		p.baseURL, url.QueryEscape(filter))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Accept", "application/json")

	return req, nil
}

// JamfComputerResponse represents the Jamf Pro API v1 computers-inventory response.
type JamfComputerResponse struct {
	TotalCount int                 `json:"totalCount"`
	Results    []JamfComputerEntry `json:"results"`
}

// JamfComputerEntry represents a single computer in the Jamf response.
type JamfComputerEntry struct {
	ID       string               `json:"id"`
	General  JamfComputerGeneral  `json:"general,omitempty"`
	Hardware JamfComputerHardware `json:"hardware,omitempty"`
}

// JamfComputerGeneral contains general device information from Jamf.
type JamfComputerGeneral struct {
	Name             string               `json:"name"`
	LastContactTime  string               `json:"lastContactTime"` // ISO8601 format
	Managed          bool                 `json:"managed"`
	ManagementID     string               `json:"managementId"`
	RemoteManagement JamfRemoteManagement `json:"remoteManagement,omitempty"`
}

// JamfRemoteManagement contains remote management settings.
type JamfRemoteManagement struct {
	Managed            bool   `json:"managed"`
	ManagementUsername string `json:"managementUsername,omitempty"`
}

// JamfComputerHardware contains hardware information from Jamf.
type JamfComputerHardware struct {
	SerialNumber string `json:"serialNumber"`
	OsVersion    string `json:"osVersion"`
}

// parseJamfResponse parses the Jamf Pro API response and converts it to MDMDeviceInfo.
func parseJamfResponse(body []byte) (*MDMDeviceInfo, error) {
	var resp JamfComputerResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrMDMUnavailable
	}

	if resp.TotalCount == 0 || len(resp.Results) == 0 {
		return nil, ErrDeviceNotFound
	}

	// Use the first result
	entry := resp.Results[0]

	// Parse the last contact time
	var lastCheckIn time.Time
	if entry.General.LastContactTime != "" {
		parsed, err := time.Parse(time.RFC3339, entry.General.LastContactTime)
		if err != nil {
			// Try alternate format without timezone
			parsed, err = time.Parse("2006-01-02T15:04:05", entry.General.LastContactTime)
			if err != nil {
				// Use zero time if parsing fails
				lastCheckIn = time.Time{}
			} else {
				lastCheckIn = parsed
			}
		} else {
			lastCheckIn = parsed
		}
	}

	// Determine enrollment and compliance status
	// A device is enrolled if it's managed
	enrolled := entry.General.Managed

	// A device is compliant if it's managed and remote management is active
	// In Jamf Pro, a managed device with remote management enabled is considered compliant
	compliant := enrolled && entry.General.RemoteManagement.Managed

	info := &MDMDeviceInfo{
		DeviceID:    entry.ID,
		Enrolled:    enrolled,
		Compliant:   compliant,
		LastCheckIn: lastCheckIn,
		OSVersion:   entry.Hardware.OsVersion,
		DeviceName:  entry.General.Name,
		MDMProvider: "jamf",
	}

	// Add compliance details if not compliant
	if !compliant {
		if !enrolled {
			info.ComplianceDetails = "Device not enrolled in MDM"
		} else if !entry.General.RemoteManagement.Managed {
			info.ComplianceDetails = "Remote management not enabled"
		}
	}

	return info, nil
}

// withHTTPClient sets a custom HTTP client for testing.
// This is an internal method used by tests.
func (p *JamfProvider) withHTTPClient(client jamfAPI) *JamfProvider {
	p.httpClient = client
	return p
}
