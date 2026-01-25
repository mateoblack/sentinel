package device

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// mockCollector is a test helper for simulating collector behavior.
type mockCollector struct {
	name    string
	posture *DevicePosture
	err     error
}

func (m *mockCollector) Collect(_ context.Context) (*DevicePosture, error) {
	return m.posture, m.err
}

func (m *mockCollector) Name() string {
	return m.name
}

func TestNoopCollector(t *testing.T) {
	t.Run("returns DevicePosture with StatusUnknown", func(t *testing.T) {
		c := &NoopCollector{}
		posture, err := c.Collect(context.Background())

		if err != nil {
			t.Fatalf("NoopCollector.Collect() error = %v, want nil", err)
		}

		if posture == nil {
			t.Fatal("NoopCollector.Collect() returned nil posture")
		}

		if posture.Status != StatusUnknown {
			t.Errorf("NoopCollector.Collect().Status = %q, want %q", posture.Status, StatusUnknown)
		}
	})

	t.Run("generates valid 32-char hex DeviceID", func(t *testing.T) {
		c := &NoopCollector{}
		posture, _ := c.Collect(context.Background())

		if len(posture.DeviceID) != DeviceIDLength {
			t.Errorf("DeviceID length = %d, want %d", len(posture.DeviceID), DeviceIDLength)
		}

		if !ValidateDeviceID(posture.DeviceID) {
			t.Errorf("DeviceID %q is not valid", posture.DeviceID)
		}
	})

	t.Run("sets CollectedAt timestamp", func(t *testing.T) {
		c := &NoopCollector{}
		before := time.Now().UTC()
		posture, _ := c.Collect(context.Background())
		after := time.Now().UTC()

		if posture.CollectedAt.IsZero() {
			t.Error("CollectedAt is zero, expected non-zero timestamp")
		}

		if posture.CollectedAt.Before(before) {
			t.Errorf("CollectedAt %v is before test start %v", posture.CollectedAt, before)
		}

		if posture.CollectedAt.After(after) {
			t.Errorf("CollectedAt %v is after test end %v", posture.CollectedAt, after)
		}
	})

	t.Run("Name returns noop", func(t *testing.T) {
		c := &NoopCollector{}
		if got := c.Name(); got != "noop" {
			t.Errorf("NoopCollector.Name() = %q, want %q", got, "noop")
		}
	})

	t.Run("generates unique IDs on each call", func(t *testing.T) {
		c := &NoopCollector{}
		posture1, _ := c.Collect(context.Background())
		posture2, _ := c.Collect(context.Background())

		if posture1.DeviceID == posture2.DeviceID {
			t.Errorf("NoopCollector generated same DeviceID twice: %q", posture1.DeviceID)
		}
	})
}

func TestMultiCollector_SingleCollector(t *testing.T) {
	t.Run("single collector passes through result", func(t *testing.T) {
		boolTrue := true
		expectedPosture := &DevicePosture{
			DeviceID:      "a1b2c3d4e5f67890a1b2c3d4e5f67890",
			Status:        StatusCompliant,
			DiskEncrypted: &boolTrue,
			CollectedAt:   time.Now().UTC(),
		}

		mock := &mockCollector{
			name:    "test-collector",
			posture: expectedPosture,
			err:     nil,
		}

		mc := NewMultiCollector(mock)
		posture, err := mc.Collect(context.Background())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if posture.DeviceID != expectedPosture.DeviceID {
			t.Errorf("DeviceID = %q, want %q", posture.DeviceID, expectedPosture.DeviceID)
		}

		if posture.Status != expectedPosture.Status {
			t.Errorf("Status = %q, want %q", posture.Status, expectedPosture.Status)
		}

		if posture.DiskEncrypted == nil || *posture.DiskEncrypted != *expectedPosture.DiskEncrypted {
			t.Errorf("DiskEncrypted = %v, want %v", posture.DiskEncrypted, expectedPosture.DiskEncrypted)
		}
	})

	t.Run("single collector error returns error with result", func(t *testing.T) {
		expectedErr := errors.New("collection failed")
		expectedPosture := &DevicePosture{
			DeviceID:    "a1b2c3d4e5f67890a1b2c3d4e5f67890",
			Status:      StatusUnknown,
			CollectedAt: time.Now().UTC(),
		}

		mock := &mockCollector{
			name:    "failing-collector",
			posture: expectedPosture,
			err:     expectedErr,
		}

		mc := NewMultiCollector(mock)
		posture, err := mc.Collect(context.Background())

		// Should return both result and error
		if posture == nil {
			t.Fatal("expected posture even with error")
		}

		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// Error should be wrapped in CollectorError
		var collectorErr *CollectorError
		if !errors.As(err, &collectorErr) {
			t.Errorf("expected CollectorError, got %T", err)
		}

		if collectorErr.Collector != "failing-collector" {
			t.Errorf("Collector name = %q, want %q", collectorErr.Collector, "failing-collector")
		}
	})
}

func TestMultiCollector_MergeOrder(t *testing.T) {
	t.Run("first non-nil wins for pointer bools", func(t *testing.T) {
		boolTrue := true
		boolFalse := false

		// First collector has DiskEncrypted = true
		first := &mockCollector{
			name: "first",
			posture: &DevicePosture{
				DeviceID:      "11111111111111111111111111111111",
				Status:        StatusCompliant,
				DiskEncrypted: &boolTrue,
				CollectedAt:   time.Now().UTC(),
			},
		}

		// Second collector has DiskEncrypted = false
		second := &mockCollector{
			name: "second",
			posture: &DevicePosture{
				DeviceID:      "22222222222222222222222222222222",
				Status:        StatusNonCompliant,
				DiskEncrypted: &boolFalse,
				CollectedAt:   time.Now().UTC(),
			},
		}

		mc := NewMultiCollector(first, second)
		posture, err := mc.Collect(context.Background())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// First wins for DeviceID
		if posture.DeviceID != "11111111111111111111111111111111" {
			t.Errorf("DeviceID = %q, want first collector's value", posture.DeviceID)
		}

		// First wins for DiskEncrypted
		if posture.DiskEncrypted == nil || *posture.DiskEncrypted != true {
			t.Errorf("DiskEncrypted = %v, want true (from first collector)", posture.DiskEncrypted)
		}
	})

	t.Run("nil does not override non-nil", func(t *testing.T) {
		boolTrue := true

		// First collector has FirewallEnabled = nil
		first := &mockCollector{
			name: "first",
			posture: &DevicePosture{
				DeviceID:        "11111111111111111111111111111111",
				Status:          StatusUnknown,
				FirewallEnabled: nil,
				CollectedAt:     time.Now().UTC(),
			},
		}

		// Second collector has FirewallEnabled = true
		second := &mockCollector{
			name: "second",
			posture: &DevicePosture{
				DeviceID:        "22222222222222222222222222222222",
				Status:          StatusCompliant,
				FirewallEnabled: &boolTrue,
				CollectedAt:     time.Now().UTC(),
			},
		}

		mc := NewMultiCollector(first, second)
		posture, err := mc.Collect(context.Background())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// First nil, second non-nil → second wins
		if posture.FirewallEnabled == nil || *posture.FirewallEnabled != true {
			t.Errorf("FirewallEnabled = %v, want true (from second collector)", posture.FirewallEnabled)
		}

		// First wins for DeviceID since first had non-empty value
		if posture.DeviceID != "11111111111111111111111111111111" {
			t.Errorf("DeviceID = %q, want first collector's value", posture.DeviceID)
		}
	})

	t.Run("first non-unknown status wins", func(t *testing.T) {
		// First collector has StatusUnknown
		first := &mockCollector{
			name: "first",
			posture: &DevicePosture{
				DeviceID:    "11111111111111111111111111111111",
				Status:      StatusUnknown,
				CollectedAt: time.Now().UTC(),
			},
		}

		// Second collector has StatusCompliant
		second := &mockCollector{
			name: "second",
			posture: &DevicePosture{
				DeviceID:    "22222222222222222222222222222222",
				Status:      StatusCompliant,
				CollectedAt: time.Now().UTC(),
			},
		}

		mc := NewMultiCollector(first, second)
		posture, err := mc.Collect(context.Background())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// StatusUnknown is overridden by StatusCompliant
		if posture.Status != StatusCompliant {
			t.Errorf("Status = %q, want %q", posture.Status, StatusCompliant)
		}
	})

	t.Run("first non-empty string wins", func(t *testing.T) {
		// First collector has empty OSVersion
		first := &mockCollector{
			name: "first",
			posture: &DevicePosture{
				DeviceID:    "11111111111111111111111111111111",
				Status:      StatusCompliant,
				OSVersion:   "",
				OSType:      "darwin",
				CollectedAt: time.Now().UTC(),
			},
		}

		// Second collector has OSVersion
		second := &mockCollector{
			name: "second",
			posture: &DevicePosture{
				DeviceID:    "22222222222222222222222222222222",
				Status:      StatusCompliant,
				OSVersion:   "14.2.1",
				OSType:      "linux",
				CollectedAt: time.Now().UTC(),
			},
		}

		mc := NewMultiCollector(first, second)
		posture, err := mc.Collect(context.Background())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Empty string from first is overridden
		if posture.OSVersion != "14.2.1" {
			t.Errorf("OSVersion = %q, want %q (from second collector)", posture.OSVersion, "14.2.1")
		}

		// Non-empty from first wins
		if posture.OSType != "darwin" {
			t.Errorf("OSType = %q, want %q (from first collector)", posture.OSType, "darwin")
		}
	})
}

func TestMultiCollector_PartialFailure(t *testing.T) {
	t.Run("handles partial failure with mixed results", func(t *testing.T) {
		boolTrue := true
		expectedErr := errors.New("service unavailable")

		// First collector succeeds with partial data
		first := &mockCollector{
			name: "working",
			posture: &DevicePosture{
				DeviceID:      "11111111111111111111111111111111",
				Status:        StatusCompliant,
				DiskEncrypted: &boolTrue,
				CollectedAt:   time.Now().UTC(),
			},
		}

		// Second collector fails with error
		second := &mockCollector{
			name: "failing",
			posture: nil,
			err:  expectedErr,
		}

		mc := NewMultiCollector(first, second)
		posture, err := mc.Collect(context.Background())

		// Should have both partial result and error
		if posture == nil {
			t.Fatal("expected posture from working collector")
		}

		if posture.DeviceID != "11111111111111111111111111111111" {
			t.Errorf("DeviceID = %q, want working collector's value", posture.DeviceID)
		}

		if posture.DiskEncrypted == nil || *posture.DiskEncrypted != true {
			t.Error("expected DiskEncrypted from working collector")
		}

		// Should have error from failing collector
		if err == nil {
			t.Fatal("expected error from failing collector")
		}

		// Verify errors.Is works through the chain
		var collectorErr *CollectorError
		if !errors.As(err, &collectorErr) {
			t.Errorf("expected CollectorError in chain, got %T", err)
		}

		if !errors.Is(collectorErr.Err, expectedErr) {
			t.Errorf("expected underlying error %v, got %v", expectedErr, collectorErr.Err)
		}
	})

	t.Run("returns result even when first collector fails", func(t *testing.T) {
		boolTrue := true
		expectedErr := errors.New("first failed")

		// First collector fails
		first := &mockCollector{
			name: "failing-first",
			posture: nil,
			err:  expectedErr,
		}

		// Second collector succeeds
		second := &mockCollector{
			name: "working-second",
			posture: &DevicePosture{
				DeviceID:        "22222222222222222222222222222222",
				Status:          StatusCompliant,
				FirewallEnabled: &boolTrue,
				CollectedAt:     time.Now().UTC(),
			},
		}

		mc := NewMultiCollector(first, second)
		posture, err := mc.Collect(context.Background())

		// Should have result from second collector
		if posture == nil {
			t.Fatal("expected posture from second collector")
		}

		if posture.DeviceID != "22222222222222222222222222222222" {
			t.Errorf("DeviceID = %q, want second collector's value", posture.DeviceID)
		}

		// Should have error from first collector
		if err == nil {
			t.Fatal("expected error from first collector")
		}
	})
}

func TestMultiCollector_AllFail(t *testing.T) {
	t.Run("all collectors fail returns minimal posture and joined errors", func(t *testing.T) {
		err1 := errors.New("error from first")
		err2 := errors.New("error from second")

		first := &mockCollector{
			name: "failing-1",
			posture: nil,
			err:  err1,
		}

		second := &mockCollector{
			name: "failing-2",
			posture: nil,
			err:  err2,
		}

		mc := NewMultiCollector(first, second)
		posture, err := mc.Collect(context.Background())

		// Should return minimal posture (generated ID, unknown status)
		if posture == nil {
			t.Fatal("expected minimal posture even when all fail")
		}

		if posture.Status != StatusUnknown {
			t.Errorf("Status = %q, want %q", posture.Status, StatusUnknown)
		}

		if !ValidateDeviceID(posture.DeviceID) {
			t.Errorf("DeviceID %q is not valid", posture.DeviceID)
		}

		if posture.CollectedAt.IsZero() {
			t.Error("CollectedAt should be set")
		}

		// Should have joined errors
		if err == nil {
			t.Fatal("expected joined errors")
		}

		// Verify both errors are in the chain
		errStr := err.Error()
		if !containsString(errStr, "failing-1") {
			t.Errorf("error %q should contain collector name 'failing-1'", errStr)
		}
		if !containsString(errStr, "failing-2") {
			t.Errorf("error %q should contain collector name 'failing-2'", errStr)
		}
	})
}

func TestMultiCollector_NoCollectors(t *testing.T) {
	t.Run("empty collectors returns minimal posture", func(t *testing.T) {
		mc := NewMultiCollector()
		posture, err := mc.Collect(context.Background())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if posture == nil {
			t.Fatal("expected minimal posture")
		}

		if posture.Status != StatusUnknown {
			t.Errorf("Status = %q, want %q", posture.Status, StatusUnknown)
		}

		if !ValidateDeviceID(posture.DeviceID) {
			t.Errorf("DeviceID %q is not valid", posture.DeviceID)
		}
	})

	t.Run("filters nil collectors", func(t *testing.T) {
		boolTrue := true
		valid := &mockCollector{
			name: "valid",
			posture: &DevicePosture{
				DeviceID:      "11111111111111111111111111111111",
				Status:        StatusCompliant,
				DiskEncrypted: &boolTrue,
				CollectedAt:   time.Now().UTC(),
			},
		}

		mc := NewMultiCollector(nil, valid, nil)
		posture, err := mc.Collect(context.Background())

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if posture.DeviceID != "11111111111111111111111111111111" {
			t.Errorf("DeviceID = %q, want valid collector's value", posture.DeviceID)
		}
	})

	t.Run("Name returns multi", func(t *testing.T) {
		mc := NewMultiCollector()
		if got := mc.Name(); got != "multi" {
			t.Errorf("MultiCollector.Name() = %q, want %q", got, "multi")
		}
	})
}

func TestCollectorError(t *testing.T) {
	t.Run("Error returns formatted string with collector name", func(t *testing.T) {
		underlying := errors.New("connection refused")
		err := &CollectorError{
			Collector: "jamf-mdm",
			Err:       underlying,
		}

		expected := "collector jamf-mdm: connection refused"
		if got := err.Error(); got != expected {
			t.Errorf("CollectorError.Error() = %q, want %q", got, expected)
		}
	})

	t.Run("Unwrap returns underlying error", func(t *testing.T) {
		underlying := errors.New("timeout")
		err := &CollectorError{
			Collector: "local",
			Err:       underlying,
		}

		unwrapped := err.Unwrap()
		if unwrapped != underlying {
			t.Errorf("Unwrap() = %v, want %v", unwrapped, underlying)
		}
	})

	t.Run("errors.Is works through the chain", func(t *testing.T) {
		err := &CollectorError{
			Collector: "test",
			Err:       ErrCollectionFailed,
		}

		if !errors.Is(err, ErrCollectionFailed) {
			t.Error("errors.Is() should find ErrCollectionFailed in chain")
		}

		if errors.Is(err, ErrCollectionTimeout) {
			t.Error("errors.Is() should not find ErrCollectionTimeout in chain")
		}
	})

	t.Run("errors.As works for CollectorError", func(t *testing.T) {
		wrapped := &CollectorError{
			Collector: "mdm",
			Err:       errors.New("API error"),
		}

		// Wrap in another error
		outer := errors.Join(wrapped, errors.New("additional context"))

		var collectorErr *CollectorError
		if !errors.As(outer, &collectorErr) {
			t.Error("errors.As() should find CollectorError in chain")
		}

		if collectorErr.Collector != "mdm" {
			t.Errorf("Collector = %q, want %q", collectorErr.Collector, "mdm")
		}
	})
}

func TestCollectorConfig(t *testing.T) {
	t.Run("empty DeviceID means generate new", func(t *testing.T) {
		cfg := CollectorConfig{
			EnableLocal: true,
			DeviceID:    "", // Empty means generate new
		}

		// When DeviceID is empty, consumer should call NewDeviceID()
		if cfg.DeviceID != "" {
			t.Errorf("empty config should have empty DeviceID, got %q", cfg.DeviceID)
		}
	})

	t.Run("provided DeviceID uses as-is", func(t *testing.T) {
		cfg := CollectorConfig{
			EnableLocal: true,
			DeviceID:    "a1b2c3d4e5f67890a1b2c3d4e5f67890",
		}

		if cfg.DeviceID != "a1b2c3d4e5f67890a1b2c3d4e5f67890" {
			t.Errorf("DeviceID = %q, want provided value", cfg.DeviceID)
		}
	})

	t.Run("invalid DeviceID still accepted (validation at use time)", func(t *testing.T) {
		// CollectorConfig doesn't validate DeviceID - that happens when creating DevicePosture
		cfg := CollectorConfig{
			EnableLocal: true,
			DeviceID:    "invalid-not-hex",
		}

		// Config accepts it, validation happens elsewhere
		if cfg.DeviceID != "invalid-not-hex" {
			t.Errorf("DeviceID = %q, want provided value", cfg.DeviceID)
		}
	})

	t.Run("CollectorVersion field", func(t *testing.T) {
		cfg := CollectorConfig{
			EnableLocal:      true,
			CollectorVersion: "1.15.0",
		}

		if cfg.CollectorVersion != "1.15.0" {
			t.Errorf("CollectorVersion = %q, want %q", cfg.CollectorVersion, "1.15.0")
		}
	})
}

func TestSentinelErrors(t *testing.T) {
	t.Run("ErrCollectionFailed is defined", func(t *testing.T) {
		if ErrCollectionFailed == nil {
			t.Fatal("ErrCollectionFailed should not be nil")
		}

		expected := "device posture collection failed"
		if got := ErrCollectionFailed.Error(); got != expected {
			t.Errorf("ErrCollectionFailed.Error() = %q, want %q", got, expected)
		}
	})

	t.Run("ErrCollectionTimeout is defined", func(t *testing.T) {
		if ErrCollectionTimeout == nil {
			t.Fatal("ErrCollectionTimeout should not be nil")
		}

		expected := "device posture collection timed out"
		if got := ErrCollectionTimeout.Error(); got != expected {
			t.Errorf("ErrCollectionTimeout.Error() = %q, want %q", got, expected)
		}
	})

	t.Run("errors are distinct", func(t *testing.T) {
		if errors.Is(ErrCollectionFailed, ErrCollectionTimeout) {
			t.Error("ErrCollectionFailed and ErrCollectionTimeout should be distinct")
		}
	})
}

// containsString checks if substr is contained in s.
func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}
