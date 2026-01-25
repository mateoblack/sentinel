package mdm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// mockProvider is a test helper for simulating MDM provider behavior.
type mockProvider struct {
	name string
	info *MDMDeviceInfo
	err  error
}

func (m *mockProvider) LookupDevice(_ context.Context, _ string) (*MDMDeviceInfo, error) {
	return m.info, m.err
}

func (m *mockProvider) Name() string {
	return m.name
}

// TestMDMDeviceInfo_Validation tests validation of MDMDeviceInfo.
func TestMDMDeviceInfo_Validation(t *testing.T) {
	t.Run("valid device info passes", func(t *testing.T) {
		info := &MDMDeviceInfo{
			DeviceID:    "device-123",
			Enrolled:    true,
			Compliant:   true,
			LastCheckIn: time.Now().UTC(),
			MDMProvider: "jamf",
		}

		if err := info.Validate(); err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("missing DeviceID fails", func(t *testing.T) {
		info := &MDMDeviceInfo{
			DeviceID:    "", // Missing
			Enrolled:    true,
			LastCheckIn: time.Now().UTC(),
			MDMProvider: "jamf",
		}

		err := info.Validate()
		if err == nil {
			t.Error("Validate() error = nil, want error for missing device_id")
		}
		if !strings.Contains(err.Error(), "device_id") {
			t.Errorf("error %q should mention 'device_id'", err)
		}
	})

	t.Run("missing MDMProvider fails", func(t *testing.T) {
		info := &MDMDeviceInfo{
			DeviceID:    "device-123",
			Enrolled:    true,
			LastCheckIn: time.Now().UTC(),
			MDMProvider: "", // Missing
		}

		err := info.Validate()
		if err == nil {
			t.Error("Validate() error = nil, want error for missing mdm_provider")
		}
		if !strings.Contains(err.Error(), "mdm_provider") {
			t.Errorf("error %q should mention 'mdm_provider'", err)
		}
	})

	t.Run("missing LastCheckIn fails", func(t *testing.T) {
		info := &MDMDeviceInfo{
			DeviceID:    "device-123",
			Enrolled:    true,
			LastCheckIn: time.Time{}, // Zero time
			MDMProvider: "jamf",
		}

		err := info.Validate()
		if err == nil {
			t.Error("Validate() error = nil, want error for missing last_check_in")
		}
		if !strings.Contains(err.Error(), "last_check_in") {
			t.Errorf("error %q should mention 'last_check_in'", err)
		}
	})
}

// TestMDMConfig_Validation tests validation of MDMConfig.
func TestMDMConfig_Validation(t *testing.T) {
	t.Run("valid config passes", func(t *testing.T) {
		cfg := &MDMConfig{
			ProviderType: "jamf",
			BaseURL:      "https://company.jamfcloud.com",
			APIToken:     "secret-token",
		}

		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("missing ProviderType fails", func(t *testing.T) {
		cfg := &MDMConfig{
			ProviderType: "", // Missing
			BaseURL:      "https://company.jamfcloud.com",
			APIToken:     "secret-token",
		}

		err := cfg.Validate()
		if err == nil {
			t.Error("Validate() error = nil, want error for missing provider_type")
		}
		if !strings.Contains(err.Error(), "provider_type") {
			t.Errorf("error %q should mention 'provider_type'", err)
		}
	})

	t.Run("missing BaseURL fails", func(t *testing.T) {
		cfg := &MDMConfig{
			ProviderType: "jamf",
			BaseURL:      "", // Missing
			APIToken:     "secret-token",
		}

		err := cfg.Validate()
		if err == nil {
			t.Error("Validate() error = nil, want error for missing base_url")
		}
		if !strings.Contains(err.Error(), "base_url") {
			t.Errorf("error %q should mention 'base_url'", err)
		}
	})

	t.Run("GetTimeout returns default when not set", func(t *testing.T) {
		cfg := &MDMConfig{
			ProviderType: "jamf",
			BaseURL:      "https://company.jamfcloud.com",
			Timeout:      0, // Not set
		}

		if got := cfg.GetTimeout(); got != DefaultTimeout {
			t.Errorf("GetTimeout() = %v, want %v", got, DefaultTimeout)
		}
	})

	t.Run("GetTimeout returns configured value", func(t *testing.T) {
		cfg := &MDMConfig{
			ProviderType: "jamf",
			BaseURL:      "https://company.jamfcloud.com",
			Timeout:      30 * time.Second,
		}

		if got := cfg.GetTimeout(); got != 30*time.Second {
			t.Errorf("GetTimeout() = %v, want 30s", got)
		}
	})
}

// TestMDMError tests MDMError formatting and error chain compatibility.
func TestMDMError(t *testing.T) {
	t.Run("Error formats correctly with device ID", func(t *testing.T) {
		err := &MDMError{
			Provider: "jamf",
			DeviceID: "device-123",
			Err:      errors.New("connection refused"),
		}

		expected := "mdm jamf: device device-123: connection refused"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %q, want %q", got, expected)
		}
	})

	t.Run("Error formats correctly without device ID", func(t *testing.T) {
		err := &MDMError{
			Provider: "intune",
			DeviceID: "",
			Err:      errors.New("authentication failed"),
		}

		expected := "mdm intune: authentication failed"
		if got := err.Error(); got != expected {
			t.Errorf("Error() = %q, want %q", got, expected)
		}
	})

	t.Run("Unwrap returns underlying error", func(t *testing.T) {
		underlying := errors.New("timeout")
		err := &MDMError{
			Provider: "kandji",
			Err:      underlying,
		}

		if got := err.Unwrap(); got != underlying {
			t.Errorf("Unwrap() = %v, want %v", got, underlying)
		}
	})

	t.Run("errors.Is works with sentinel errors", func(t *testing.T) {
		err := &MDMError{
			Provider: "jamf",
			DeviceID: "device-123",
			Err:      ErrDeviceNotFound,
		}

		if !errors.Is(err, ErrDeviceNotFound) {
			t.Error("errors.Is() should find ErrDeviceNotFound in chain")
		}

		if errors.Is(err, ErrMDMUnavailable) {
			t.Error("errors.Is() should not find ErrMDMUnavailable in chain")
		}

		if errors.Is(err, ErrMDMAuthFailed) {
			t.Error("errors.Is() should not find ErrMDMAuthFailed in chain")
		}
	})

	t.Run("errors.As works for MDMError", func(t *testing.T) {
		mdmErr := &MDMError{
			Provider: "intune",
			DeviceID: "device-456",
			Err:      errors.New("API error"),
		}

		// Wrap in another error
		outer := errors.Join(mdmErr, errors.New("additional context"))

		var extractedErr *MDMError
		if !errors.As(outer, &extractedErr) {
			t.Error("errors.As() should find MDMError in chain")
		}

		if extractedErr.Provider != "intune" {
			t.Errorf("Provider = %q, want %q", extractedErr.Provider, "intune")
		}

		if extractedErr.DeviceID != "device-456" {
			t.Errorf("DeviceID = %q, want %q", extractedErr.DeviceID, "device-456")
		}
	})
}

// TestMultiProvider tests MultiProvider composition behavior.
func TestMultiProvider(t *testing.T) {
	t.Run("empty provider list returns ErrDeviceNotFound", func(t *testing.T) {
		mp := NewMultiProvider()
		_, err := mp.LookupDevice(context.Background(), "device-123")

		if !errors.Is(err, ErrDeviceNotFound) {
			t.Errorf("error = %v, want ErrDeviceNotFound", err)
		}
	})

	t.Run("first successful provider wins", func(t *testing.T) {
		first := &mockProvider{
			name: "first",
			info: &MDMDeviceInfo{
				DeviceID:    "device-123",
				Enrolled:    true,
				Compliant:   true,
				LastCheckIn: time.Now().UTC(),
				MDMProvider: "first",
			},
		}

		second := &mockProvider{
			name: "second",
			info: &MDMDeviceInfo{
				DeviceID:    "device-123",
				Enrolled:    true,
				Compliant:   false, // Different value
				LastCheckIn: time.Now().UTC(),
				MDMProvider: "second",
			},
		}

		mp := NewMultiProvider(first, second)
		info, err := mp.LookupDevice(context.Background(), "device-123")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// First provider's result should be returned
		if info.MDMProvider != "first" {
			t.Errorf("MDMProvider = %q, want %q", info.MDMProvider, "first")
		}

		if !info.Compliant {
			t.Error("Compliant should be true (from first provider)")
		}
	})

	t.Run("all failures aggregates errors", func(t *testing.T) {
		err1 := errors.New("first provider error")
		err2 := errors.New("second provider error")

		first := &mockProvider{
			name: "failing-1",
			err:  err1,
		}

		second := &mockProvider{
			name: "failing-2",
			err:  err2,
		}

		mp := NewMultiProvider(first, second)
		_, err := mp.LookupDevice(context.Background(), "device-123")

		if err == nil {
			t.Fatal("expected aggregated error, got nil")
		}

		// Both errors should be in the chain
		errStr := err.Error()
		if !strings.Contains(errStr, "failing-1") {
			t.Errorf("error %q should contain 'failing-1'", errStr)
		}
		if !strings.Contains(errStr, "failing-2") {
			t.Errorf("error %q should contain 'failing-2'", errStr)
		}
	})

	t.Run("nil providers filtered out", func(t *testing.T) {
		valid := &mockProvider{
			name: "valid",
			info: &MDMDeviceInfo{
				DeviceID:    "device-123",
				Enrolled:    true,
				Compliant:   true,
				LastCheckIn: time.Now().UTC(),
				MDMProvider: "valid",
			},
		}

		mp := NewMultiProvider(nil, valid, nil)
		info, err := mp.LookupDevice(context.Background(), "device-123")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if info.MDMProvider != "valid" {
			t.Errorf("MDMProvider = %q, want %q", info.MDMProvider, "valid")
		}
	})

	t.Run("skips failed provider and returns next success", func(t *testing.T) {
		failing := &mockProvider{
			name: "failing",
			err:  ErrMDMUnavailable,
		}

		working := &mockProvider{
			name: "working",
			info: &MDMDeviceInfo{
				DeviceID:    "device-123",
				Enrolled:    true,
				Compliant:   true,
				LastCheckIn: time.Now().UTC(),
				MDMProvider: "working",
			},
		}

		mp := NewMultiProvider(failing, working)
		info, err := mp.LookupDevice(context.Background(), "device-123")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if info.MDMProvider != "working" {
			t.Errorf("MDMProvider = %q, want %q", info.MDMProvider, "working")
		}
	})

	t.Run("Name returns multi", func(t *testing.T) {
		mp := NewMultiProvider()
		if got := mp.Name(); got != "multi" {
			t.Errorf("Name() = %q, want %q", got, "multi")
		}
	})
}

// TestNoopProvider tests NoopProvider behavior.
func TestNoopProvider(t *testing.T) {
	t.Run("Name returns noop", func(t *testing.T) {
		p := &NoopProvider{}
		if got := p.Name(); got != "noop" {
			t.Errorf("Name() = %q, want %q", got, "noop")
		}
	})

	t.Run("LookupDevice returns ErrDeviceNotFound", func(t *testing.T) {
		p := &NoopProvider{}
		info, err := p.LookupDevice(context.Background(), "device-123")

		if info != nil {
			t.Errorf("expected nil info, got %+v", info)
		}

		if !errors.Is(err, ErrDeviceNotFound) {
			t.Errorf("error = %v, want ErrDeviceNotFound", err)
		}
	})
}

// TestDeviceIDMapper tests device ID mapping.
func TestDeviceIDMapper(t *testing.T) {
	t.Run("MapDeviceID passthrough for MVP", func(t *testing.T) {
		mapper := NewDeviceIDMapper()
		mdmID, err := mapper.MapDeviceID("sentinel-device-123")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// MVP: direct passthrough
		if mdmID != "sentinel-device-123" {
			t.Errorf("MapDeviceID() = %q, want %q", mdmID, "sentinel-device-123")
		}
	})

	t.Run("MapDeviceID empty string fails", func(t *testing.T) {
		mapper := NewDeviceIDMapper()
		_, err := mapper.MapDeviceID("")

		if err == nil {
			t.Error("expected error for empty sentinel ID")
		}
	})
}

// TestSentinelErrors tests that sentinel errors are properly defined.
func TestSentinelErrors(t *testing.T) {
	t.Run("ErrDeviceNotFound is defined", func(t *testing.T) {
		if ErrDeviceNotFound == nil {
			t.Fatal("ErrDeviceNotFound should not be nil")
		}

		expected := "device not found in MDM"
		if got := ErrDeviceNotFound.Error(); got != expected {
			t.Errorf("ErrDeviceNotFound.Error() = %q, want %q", got, expected)
		}
	})

	t.Run("ErrMDMUnavailable is defined", func(t *testing.T) {
		if ErrMDMUnavailable == nil {
			t.Fatal("ErrMDMUnavailable should not be nil")
		}

		expected := "MDM service unavailable"
		if got := ErrMDMUnavailable.Error(); got != expected {
			t.Errorf("ErrMDMUnavailable.Error() = %q, want %q", got, expected)
		}
	})

	t.Run("ErrMDMAuthFailed is defined", func(t *testing.T) {
		if ErrMDMAuthFailed == nil {
			t.Fatal("ErrMDMAuthFailed should not be nil")
		}

		expected := "MDM authentication failed"
		if got := ErrMDMAuthFailed.Error(); got != expected {
			t.Errorf("ErrMDMAuthFailed.Error() = %q, want %q", got, expected)
		}
	})

	t.Run("sentinel errors are distinct", func(t *testing.T) {
		if errors.Is(ErrDeviceNotFound, ErrMDMUnavailable) {
			t.Error("ErrDeviceNotFound and ErrMDMUnavailable should be distinct")
		}
		if errors.Is(ErrDeviceNotFound, ErrMDMAuthFailed) {
			t.Error("ErrDeviceNotFound and ErrMDMAuthFailed should be distinct")
		}
		if errors.Is(ErrMDMUnavailable, ErrMDMAuthFailed) {
			t.Error("ErrMDMUnavailable and ErrMDMAuthFailed should be distinct")
		}
	})
}
