// Package device provides device posture collection for Sentinel.
// Collectors gather device security state from various sources (local system, MDM, EDR)
// and return posture claims for policy evaluation.

package device

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Sentinel errors for device posture collection.
var (
	// ErrCollectionFailed is returned when posture collection fails.
	ErrCollectionFailed = errors.New("device posture collection failed")

	// ErrCollectionTimeout is returned when collection exceeds context deadline.
	ErrCollectionTimeout = errors.New("device posture collection timed out")
)

// Collector defines the interface for device posture collection.
// Implementations gather security state from specific sources (local system, MDM APIs, EDR agents).
type Collector interface {
	// Collect gathers device posture claims from this collector source.
	// Returns error if collection fails (permission denied, service unavailable, etc.).
	Collect(ctx context.Context) (*DevicePosture, error)

	// Name returns a human-readable name for this collector (e.g., "local", "jamf-mdm").
	Name() string
}

// CollectorError is a structured error for collection failures.
// It wraps the underlying error with the collector name for debugging.
type CollectorError struct {
	// Collector is the name of the collector that failed.
	Collector string
	// Err is the underlying error.
	Err error
}

// Error returns a formatted error string with the collector name.
func (e *CollectorError) Error() string {
	return fmt.Sprintf("collector %s: %v", e.Collector, e.Err)
}

// Unwrap returns the underlying error for error chain compatibility.
func (e *CollectorError) Unwrap() error {
	return e.Err
}

// MultiCollector composes multiple collectors and merges their results.
// It implements the Collector interface for consistent usage.
//
// Merge semantics:
//   - First non-nil value for each field wins
//   - Errors from individual collectors are aggregated via errors.Join()
//   - Returns merged result even if some collectors fail (partial posture)
type MultiCollector struct {
	collectors []Collector
}

// NewMultiCollector creates a new MultiCollector with the given collectors.
// Nil collectors are filtered out for convenience.
func NewMultiCollector(collectors ...Collector) *MultiCollector {
	filtered := make([]Collector, 0, len(collectors))
	for _, c := range collectors {
		if c != nil {
			filtered = append(filtered, c)
		}
	}
	return &MultiCollector{collectors: filtered}
}

// Name returns "multi" as the collector name.
func (m *MultiCollector) Name() string {
	return "multi"
}

// Collect gathers posture from all collectors and merges the results.
// First non-nil value for each field wins. Returns merged result even if some collectors fail.
func (m *MultiCollector) Collect(ctx context.Context) (*DevicePosture, error) {
	if len(m.collectors) == 0 {
		// No collectors configured, return minimal posture
		return &DevicePosture{
			DeviceID:    NewDeviceID(),
			Status:      StatusUnknown,
			CollectedAt: time.Now().UTC(),
		}, nil
	}

	var (
		merged *DevicePosture
		errs   []error
	)

	for _, c := range m.collectors {
		posture, err := c.Collect(ctx)
		if err != nil {
			errs = append(errs, &CollectorError{
				Collector: c.Name(),
				Err:       err,
			})
		}

		if posture != nil {
			merged = mergePosture(merged, posture)
		}
	}

	// If nothing collected, return minimal posture
	if merged == nil {
		merged = &DevicePosture{
			DeviceID:    NewDeviceID(),
			Status:      StatusUnknown,
			CollectedAt: time.Now().UTC(),
		}
	}

	return merged, errors.Join(errs...)
}

// mergePosture merges two DevicePosture structs, first non-nil wins for each field.
// If base is nil, returns other. If other is nil, returns base.
func mergePosture(base, other *DevicePosture) *DevicePosture {
	if base == nil {
		return other
	}
	if other == nil {
		return base
	}

	// DeviceID: first non-empty wins
	if base.DeviceID == "" && other.DeviceID != "" {
		base.DeviceID = other.DeviceID
	}

	// Status: first non-unknown wins
	if base.Status == StatusUnknown && other.Status != StatusUnknown {
		base.Status = other.Status
	}

	// DiskEncrypted: first non-nil wins
	if base.DiskEncrypted == nil && other.DiskEncrypted != nil {
		base.DiskEncrypted = other.DiskEncrypted
	}

	// FirewallEnabled: first non-nil wins
	if base.FirewallEnabled == nil && other.FirewallEnabled != nil {
		base.FirewallEnabled = other.FirewallEnabled
	}

	// OSVersion: first non-empty wins
	if base.OSVersion == "" && other.OSVersion != "" {
		base.OSVersion = other.OSVersion
	}

	// OSType: first non-empty wins
	if base.OSType == "" && other.OSType != "" {
		base.OSType = other.OSType
	}

	// MDMEnrolled: first non-nil wins
	if base.MDMEnrolled == nil && other.MDMEnrolled != nil {
		base.MDMEnrolled = other.MDMEnrolled
	}

	// MDMCompliant: first non-nil wins
	if base.MDMCompliant == nil && other.MDMCompliant != nil {
		base.MDMCompliant = other.MDMCompliant
	}

	// CollectedAt: first non-zero wins
	if base.CollectedAt.IsZero() && !other.CollectedAt.IsZero() {
		base.CollectedAt = other.CollectedAt
	}

	// CollectorVersion: first non-empty wins
	if base.CollectorVersion == "" && other.CollectorVersion != "" {
		base.CollectorVersion = other.CollectorVersion
	}

	return base
}

// NoopCollector is a no-op collector that returns empty posture with StatusUnknown.
// Useful for testing or when device posture collection is disabled.
type NoopCollector struct{}

// Name returns "noop" as the collector name.
func (n *NoopCollector) Name() string {
	return "noop"
}

// Collect returns a minimal DevicePosture with StatusUnknown.
// It always succeeds and generates a new DeviceID.
func (n *NoopCollector) Collect(_ context.Context) (*DevicePosture, error) {
	return &DevicePosture{
		DeviceID:    NewDeviceID(),
		Status:      StatusUnknown,
		CollectedAt: time.Now().UTC(),
	}, nil
}

// CollectorConfig holds configuration for collector initialization.
type CollectorConfig struct {
	// EnableLocal enables local posture collection (disk encryption, firewall, OS).
	EnableLocal bool `json:"enable_local"`

	// DeviceID allows providing a persistent device ID instead of generating new.
	// If empty, NewDeviceID() is called.
	DeviceID string `json:"device_id,omitempty"`

	// CollectorVersion is the version string for posture reports.
	CollectorVersion string `json:"collector_version,omitempty"`
}
