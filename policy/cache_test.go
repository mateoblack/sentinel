package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/policy"
)

// mockLoader is a test double for PolicyLoader that tracks call counts.
type mockLoader struct {
	policy    *policy.Policy
	err       error
	callCount int
}

func (m *mockLoader) Load(ctx context.Context, name string) (*policy.Policy, error) {
	m.callCount++
	return m.policy, m.err
}

func TestCachedLoader_CacheHit(t *testing.T) {
	mock := &mockLoader{
		policy: &policy.Policy{Version: "1.0"},
	}
	cached := policy.NewCachedLoader(mock, time.Minute)
	ctx := context.Background()

	// First call should hit the underlying loader
	p1, err := cached.Load(ctx, "test-param")
	if err != nil {
		t.Fatalf("first Load: unexpected error: %v", err)
	}
	if mock.callCount != 1 {
		t.Errorf("after first Load: callCount = %d, want 1", mock.callCount)
	}

	// Second call should hit cache
	p2, err := cached.Load(ctx, "test-param")
	if err != nil {
		t.Fatalf("second Load: unexpected error: %v", err)
	}
	if mock.callCount != 1 {
		t.Errorf("after second Load: callCount = %d, want 1 (cache hit)", mock.callCount)
	}

	// Both should return same policy pointer
	if p1 != p2 {
		t.Error("cache hit should return same policy pointer")
	}
}

func TestCachedLoader_CacheExpiry(t *testing.T) {
	mock := &mockLoader{
		policy: &policy.Policy{Version: "1.0"},
	}
	// Very short TTL for testing expiry
	cached := policy.NewCachedLoader(mock, time.Millisecond)
	ctx := context.Background()

	// First call
	_, err := cached.Load(ctx, "test-param")
	if err != nil {
		t.Fatalf("first Load: unexpected error: %v", err)
	}
	if mock.callCount != 1 {
		t.Errorf("after first Load: callCount = %d, want 1", mock.callCount)
	}

	// Wait for cache to expire
	time.Sleep(5 * time.Millisecond)

	// Second call should miss cache due to expiry
	_, err = cached.Load(ctx, "test-param")
	if err != nil {
		t.Fatalf("second Load: unexpected error: %v", err)
	}
	if mock.callCount != 2 {
		t.Errorf("after second Load (expired): callCount = %d, want 2", mock.callCount)
	}
}

func TestCachedLoader_ErrorNotCached(t *testing.T) {
	testErr := errors.New("test error")
	mock := &mockLoader{
		err: testErr,
	}
	cached := policy.NewCachedLoader(mock, time.Minute)
	ctx := context.Background()

	// First call should return error
	_, err := cached.Load(ctx, "test-param")
	if !errors.Is(err, testErr) {
		t.Errorf("first Load: got error %v, want %v", err, testErr)
	}
	if mock.callCount != 1 {
		t.Errorf("after first Load: callCount = %d, want 1", mock.callCount)
	}

	// Second call should also hit loader (errors not cached)
	_, err = cached.Load(ctx, "test-param")
	if !errors.Is(err, testErr) {
		t.Errorf("second Load: got error %v, want %v", err, testErr)
	}
	if mock.callCount != 2 {
		t.Errorf("after second Load: callCount = %d, want 2 (error not cached)", mock.callCount)
	}
}

func TestCachedLoader_DifferentParameters(t *testing.T) {
	mock := &mockLoader{
		policy: &policy.Policy{Version: "1.0"},
	}
	cached := policy.NewCachedLoader(mock, time.Minute)
	ctx := context.Background()

	// Load first parameter
	_, err := cached.Load(ctx, "param1")
	if err != nil {
		t.Fatalf("Load param1: unexpected error: %v", err)
	}
	if mock.callCount != 1 {
		t.Errorf("after param1: callCount = %d, want 1", mock.callCount)
	}

	// Load different parameter - should not hit cache for param1
	_, err = cached.Load(ctx, "param2")
	if err != nil {
		t.Fatalf("Load param2: unexpected error: %v", err)
	}
	if mock.callCount != 2 {
		t.Errorf("after param2: callCount = %d, want 2 (different cache key)", mock.callCount)
	}

	// Load param1 again - should hit cache
	_, err = cached.Load(ctx, "param1")
	if err != nil {
		t.Fatalf("Load param1 again: unexpected error: %v", err)
	}
	if mock.callCount != 2 {
		t.Errorf("after param1 again: callCount = %d, want 2 (cache hit)", mock.callCount)
	}
}
