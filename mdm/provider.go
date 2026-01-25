package mdm

import (
	"context"
	"errors"
)

// Provider defines the interface for MDM device posture queries.
// Implementations query specific MDM backends (Jamf, Intune, Kandji) for
// device enrollment and compliance information.
type Provider interface {
	// LookupDevice queries MDM for device posture by device identifier.
	// The deviceID is typically the HMAC-SHA256 hashed identifier from GetDeviceID(),
	// though the actual format depends on how devices are registered in the MDM.
	//
	// Returns MDMDeviceInfo with enrollment and compliance status, or an error:
	//   - ErrDeviceNotFound: device ID is not registered in MDM
	//   - ErrMDMUnavailable: MDM API is unreachable
	//   - ErrMDMAuthFailed: authentication with MDM failed
	LookupDevice(ctx context.Context, deviceID string) (*MDMDeviceInfo, error)

	// Name returns the provider name for logging (e.g., "jamf", "intune", "noop").
	Name() string
}

// MultiProvider composes multiple MDM providers and queries them in order.
// It implements the Provider interface for consistent usage.
//
// Query semantics:
//   - Tries each provider in order
//   - Returns the first successful result
//   - If all providers fail, returns aggregated errors via errors.Join()
//   - Returns ErrDeviceNotFound only if all providers return that error
type MultiProvider struct {
	providers []Provider
}

// NewMultiProvider creates a new MultiProvider with the given providers.
// Nil providers are filtered out for convenience.
func NewMultiProvider(providers ...Provider) *MultiProvider {
	filtered := make([]Provider, 0, len(providers))
	for _, p := range providers {
		if p != nil {
			filtered = append(filtered, p)
		}
	}
	return &MultiProvider{providers: filtered}
}

// Name returns "multi" as the provider name.
func (m *MultiProvider) Name() string {
	return "multi"
}

// LookupDevice queries all providers in order and returns the first successful result.
// If all providers fail, returns aggregated errors.
func (m *MultiProvider) LookupDevice(ctx context.Context, deviceID string) (*MDMDeviceInfo, error) {
	if len(m.providers) == 0 {
		return nil, ErrDeviceNotFound
	}

	var errs []error
	for _, p := range m.providers {
		info, err := p.LookupDevice(ctx, deviceID)
		if err == nil && info != nil {
			return info, nil
		}
		if err != nil {
			errs = append(errs, &MDMError{
				Provider: p.Name(),
				DeviceID: deviceID,
				Err:      err,
			})
		}
	}

	// All providers failed
	if len(errs) == 0 {
		// No errors but no result either (shouldn't happen with well-behaved providers)
		return nil, ErrDeviceNotFound
	}

	return nil, errors.Join(errs...)
}

// NoopProvider is a no-op MDM provider that always returns ErrDeviceNotFound.
// Useful for testing or when MDM integration is disabled.
type NoopProvider struct{}

// Name returns "noop" as the provider name.
func (n *NoopProvider) Name() string {
	return "noop"
}

// LookupDevice always returns ErrDeviceNotFound.
func (n *NoopProvider) LookupDevice(_ context.Context, _ string) (*MDMDeviceInfo, error) {
	return nil, ErrDeviceNotFound
}

// DeviceIDMapper provides mapping between Sentinel device IDs and MDM identifiers.
// In production, MDM systems may use different device ID formats (UDID, serial number,
// Azure AD device ID, etc.) that need to be mapped to/from Sentinel's HMAC-hashed IDs.
//
// For MVP, this provides a direct mapping placeholder. Future implementations may
// integrate with device registration databases or MDM device attribute lookups.
//
// Limitation (MVP): Assumes direct 1:1 mapping between Sentinel device ID and MDM ID.
// This requires devices to be registered in MDM using the same Sentinel device ID format,
// or a separate device registry to maintain the mapping.
type DeviceIDMapper struct {
	// Future: add database client or MDM client for ID lookups
}

// NewDeviceIDMapper creates a new DeviceIDMapper.
func NewDeviceIDMapper() *DeviceIDMapper {
	return &DeviceIDMapper{}
}

// MapDeviceID maps a Sentinel device ID to an MDM identifier.
// For MVP, this performs direct passthrough (assumes same ID format).
//
// Future implementations may:
//   - Query a device registry database
//   - Look up MDM device attributes
//   - Handle different ID formats per MDM provider
func (m *DeviceIDMapper) MapDeviceID(sentinelID string) (mdmID string, err error) {
	// MVP: Direct passthrough mapping
	// Assumes devices are registered in MDM using Sentinel's device ID format
	if sentinelID == "" {
		return "", errors.New("sentinel device ID is required")
	}
	return sentinelID, nil
}
