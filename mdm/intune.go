// Package mdm provides MDM integration for Sentinel.
// This file implements the Microsoft Intune MDM provider.
package mdm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Constants for Microsoft Graph API and Azure AD.
const (
	// graphAPIBase is the base URL for Microsoft Graph API.
	graphAPIBase = "https://graph.microsoft.com/v1.0"

	// azureADTokenEndpointTemplate is the token endpoint template for Azure AD.
	// The tenant ID is substituted into the template.
	azureADTokenEndpointTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"

	// graphAPIScope is the scope required for Microsoft Graph API access.
	graphAPIScope = "https://graph.microsoft.com/.default"

	// tokenExpiryBuffer is the buffer time before token expiry to trigger refresh.
	// Tokens are refreshed 5 minutes before actual expiry.
	tokenExpiryBuffer = 5 * time.Minute
)

// intuneAPI is an interface for HTTP operations, enabling test mocking.
type intuneAPI interface {
	Do(req *http.Request) (*http.Response, error)
}

// IntuneProvider implements the Provider interface for Microsoft Intune MDM.
// It queries the Microsoft Graph API to verify device enrollment and compliance.
//
// # Authentication
//
// Intune uses OAuth2 client credentials flow for authentication:
//  1. Register an Azure AD application with Microsoft Graph permissions
//  2. Grant "DeviceManagementManagedDevices.Read.All" application permission
//  3. Configure the provider with client_id:client_secret in APIToken
//
// # Device Lookup
//
// Devices are looked up by Azure AD device ID using the managedDevices endpoint.
// The complianceState field determines compliance status.
type IntuneProvider struct {
	httpClient   intuneAPI
	tenantID     string
	clientID     string
	clientSecret string
	timeout      time.Duration

	// Token cache (thread-safe)
	tokenMu     sync.RWMutex
	accessToken string
	tokenExpiry time.Time
}

// NewIntuneProvider creates a new IntuneProvider with the given configuration.
// Returns an error if required configuration is missing.
//
// The APIToken must be in the format "client_id:client_secret" for OAuth2
// client credentials authentication with Azure AD.
func NewIntuneProvider(cfg *MDMConfig) (*IntuneProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required for Intune provider")
	}
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("api_token is required for Intune provider")
	}

	// Parse client_id:client_secret from APIToken
	parts := strings.SplitN(cfg.APIToken, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("api_token must be in format 'client_id:client_secret'")
	}

	timeout := cfg.GetTimeout()

	return &IntuneProvider{
		httpClient: &http.Client{
			Timeout: timeout,
		},
		tenantID:     cfg.TenantID,
		clientID:     parts[0],
		clientSecret: parts[1],
		timeout:      timeout,
	}, nil
}

// Name returns "intune" as the provider name.
func (p *IntuneProvider) Name() string {
	return "intune"
}

// LookupDevice queries Microsoft Graph API for device information by device ID.
// The deviceID should be the Azure AD device ID registered in Intune.
//
// Returns:
//   - MDMDeviceInfo on success
//   - ErrDeviceNotFound if device is not registered in Intune
//   - ErrMDMAuthFailed on 401/403 responses
//   - ErrMDMUnavailable on network errors or timeouts
func (p *IntuneProvider) LookupDevice(ctx context.Context, deviceID string) (*MDMDeviceInfo, error) {
	if deviceID == "" {
		return nil, ErrDeviceNotFound
	}

	// Get access token (handles caching and refresh)
	token, err := p.getAccessToken(ctx)
	if err != nil {
		return nil, &MDMError{
			Provider: p.Name(),
			DeviceID: deviceID,
			Err:      err,
		}
	}

	// Try lookup by azureADDeviceId first
	info, err := p.lookupByFilter(ctx, deviceID, token, fmt.Sprintf("azureADDeviceId eq '%s'", deviceID))
	if err == nil && info != nil {
		return info, nil
	}

	// If not found, try by deviceName as fallback
	if err == ErrDeviceNotFound || (err != nil && isMDMError(err, ErrDeviceNotFound)) {
		info, err = p.lookupByFilter(ctx, deviceID, token, fmt.Sprintf("deviceName eq '%s'", deviceID))
	}

	return info, err
}

// isMDMError checks if an error is an MDMError wrapping a specific sentinel error.
func isMDMError(err error, target error) bool {
	if mdmErr, ok := err.(*MDMError); ok {
		return mdmErr.Err == target
	}
	return false
}

// lookupByFilter queries the Graph API with a specific filter.
func (p *IntuneProvider) lookupByFilter(ctx context.Context, deviceID, token, filter string) (*MDMDeviceInfo, error) {
	// Build request URL
	apiURL := fmt.Sprintf("%s/deviceManagement/managedDevices?$filter=%s",
		graphAPIBase, url.QueryEscape(filter))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, &MDMError{
			Provider: p.Name(),
			DeviceID: deviceID,
			Err:      fmt.Errorf("failed to create request: %w", err),
		}
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

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

	return p.parseIntuneResponse(body)
}

// getAccessToken returns a valid access token, refreshing if needed.
// This method is thread-safe.
func (p *IntuneProvider) getAccessToken(ctx context.Context) (string, error) {
	// Check if we have a valid cached token
	p.tokenMu.RLock()
	if p.accessToken != "" && time.Now().Add(tokenExpiryBuffer).Before(p.tokenExpiry) {
		token := p.accessToken
		p.tokenMu.RUnlock()
		return token, nil
	}
	p.tokenMu.RUnlock()

	// Need to refresh token - acquire write lock
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed)
	if p.accessToken != "" && time.Now().Add(tokenExpiryBuffer).Before(p.tokenExpiry) {
		return p.accessToken, nil
	}

	// Fetch new token
	token, expiry, err := p.fetchToken(ctx)
	if err != nil {
		return "", err
	}

	p.accessToken = token
	p.tokenExpiry = expiry
	return token, nil
}

// fetchToken fetches a new access token from Azure AD.
func (p *IntuneProvider) fetchToken(ctx context.Context) (string, time.Time, error) {
	tokenURL := fmt.Sprintf(azureADTokenEndpointTemplate, p.tenantID)

	// Build form data for client credentials grant
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", p.clientID)
	formData.Set("client_secret", p.clientSecret)
	formData.Set("scope", graphAPIScope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, ErrMDMUnavailable
	}
	defer resp.Body.Close()

	// Handle HTTP status codes
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", time.Time{}, ErrMDMAuthFailed
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, ErrMDMUnavailable
	}

	var tokenResp intuneTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("empty access token in response")
	}

	// Calculate expiry time
	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return tokenResp.AccessToken, expiry, nil
}

// parseIntuneResponse parses the Microsoft Graph API response and converts it to MDMDeviceInfo.
func (p *IntuneProvider) parseIntuneResponse(body []byte) (*MDMDeviceInfo, error) {
	var resp intuneDevicesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, ErrMDMUnavailable
	}

	if len(resp.Value) == 0 {
		return nil, ErrDeviceNotFound
	}

	// Use the first result
	device := resp.Value[0]

	// Parse the last sync time
	var lastCheckIn time.Time
	if device.LastSyncDateTime != "" {
		parsed, err := time.Parse(time.RFC3339, device.LastSyncDateTime)
		if err != nil {
			// Try alternate format without timezone
			parsed, err = time.Parse("2006-01-02T15:04:05", device.LastSyncDateTime)
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

	// Map compliance state
	// Intune complianceState values: "compliant", "noncompliant", "inGracePeriod", "unknown", "configManager"
	compliant := device.ComplianceState == "compliant"

	info := &MDMDeviceInfo{
		DeviceID:    device.AzureADDeviceId,
		Enrolled:    true, // If we found it in Intune, it's enrolled
		Compliant:   compliant,
		LastCheckIn: lastCheckIn,
		OSVersion:   device.OSVersion,
		DeviceName:  device.DeviceName,
		MDMProvider: "intune",
	}

	// Use ID as fallback for DeviceID if AzureADDeviceId is empty
	if info.DeviceID == "" {
		info.DeviceID = device.ID
	}

	// Add compliance details if not compliant
	if !compliant {
		info.ComplianceDetails = fmt.Sprintf("Device compliance state: %s", device.ComplianceState)
	}

	return info, nil
}

// intuneTokenResponse represents the Azure AD OAuth2 token response.
type intuneTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"` // seconds
	TokenType   string `json:"token_type"`
}

// intuneDevicesResponse represents the Microsoft Graph API managedDevices response.
type intuneDevicesResponse struct {
	Value []intuneDevice `json:"value"`
}

// intuneDevice represents a single managed device in the Intune response.
type intuneDevice struct {
	ID               string `json:"id"`
	DeviceName       string `json:"deviceName"`
	ComplianceState  string `json:"complianceState"` // "compliant", "noncompliant", "inGracePeriod", "unknown"
	LastSyncDateTime string `json:"lastSyncDateTime"` // ISO8601
	OperatingSystem  string `json:"operatingSystem"`
	OSVersion        string `json:"osVersion"`
	AzureADDeviceId  string `json:"azureADDeviceId"`
	IsEncrypted      bool   `json:"isEncrypted"`
	JailBroken       string `json:"jailBroken"`
}

// withHTTPClient sets a custom HTTP client for testing.
// This is an internal method used by tests.
func (p *IntuneProvider) withHTTPClient(client intuneAPI) *IntuneProvider {
	p.httpClient = client
	return p
}

// clearTokenCache clears the cached access token.
// This is an internal method used by tests.
func (p *IntuneProvider) clearTokenCache() {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()
	p.accessToken = ""
	p.tokenExpiry = time.Time{}
}
