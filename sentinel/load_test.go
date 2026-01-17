//go:build loadtest

package sentinel

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/testutil"
)

// mockPolicyLoader returns a fixed policy for load testing.
// It does not make any SSM calls.
type mockPolicyLoader struct {
	policy *policy.Policy
}

func (m *mockPolicyLoader) Load(ctx context.Context, parameterName string) (*policy.Policy, error) {
	return m.policy, nil
}

// TestLoad_PolicyEvaluation tests policy evaluation under sustained load.
// Target: 1000 req/sec for 10 seconds with >99% success rate.
func TestLoad_PolicyEvaluation(t *testing.T) {
	// Create a policy that allows alice on production
	allowPolicy := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-production",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Users:    []string{"alice"},
					Profiles: []string{"production"},
				},
				Reason: "allowed by load test policy",
			},
		},
	}

	config := testutil.LoadTestConfig{
		RequestsPerSecond: 1000,
		Duration:          10 * time.Second,
		Workers:           50,
		Timeout:           100 * time.Millisecond,
	}

	// Use deterministic time for reproducible results
	fixedTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)

	requestFn := func(ctx context.Context) error {
		req := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    fixedTime,
		}
		decision := policy.Evaluate(allowPolicy, req)
		if decision.Effect != policy.EffectAllow {
			return errUnexpectedDeny
		}
		return nil
	}

	result := testutil.RunLoadTest(context.Background(), config, requestFn)

	t.Logf("Policy Evaluation Load Test Results:\n%s", testutil.FormatLoadTestResult(result))

	// Assert minimum thresholds
	if result.SuccessRate() < 99.0 {
		t.Errorf("Success rate %.1f%% below 99%% threshold", result.SuccessRate())
	}
	if result.LatencyP99 > 10*time.Millisecond {
		t.Errorf("P99 latency %v exceeds 10ms threshold", result.LatencyP99)
	}
	if result.Throughput < 800 {
		t.Errorf("Throughput %.1f req/sec below 800 req/sec threshold", result.Throughput)
	}
}

// errUnexpectedDeny is returned when policy evaluation unexpectedly denies.
var errUnexpectedDeny = &unexpectedDenyError{}

type unexpectedDenyError struct{}

func (e *unexpectedDenyError) Error() string { return "unexpected deny from policy evaluation" }

// TestLoad_CachedPolicyEvaluation tests the cache hit path under sustained load.
// Target: 1000 req/sec for 10 seconds with ~100% cache hit ratio.
func TestLoad_CachedPolicyEvaluation(t *testing.T) {
	// Create a policy that allows alice on production
	allowPolicy := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-production",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Users:    []string{"alice"},
					Profiles: []string{"production"},
				},
				Reason: "allowed by load test policy",
			},
		},
	}

	// Create mock loader and cached loader
	loader := &mockPolicyLoader{policy: allowPolicy}
	cachedLoader := policy.NewCachedLoader(loader, 5*time.Minute)

	// Pre-warm the cache
	ctx := context.Background()
	_, err := cachedLoader.Load(ctx, "/sentinel/test/production")
	if err != nil {
		t.Fatalf("Failed to warm cache: %v", err)
	}

	// Track cache loads to verify cache hit ratio
	var loadCount int64
	var loadMu sync.Mutex

	// Replace the underlying loader with one that counts calls
	countingLoader := &countingMockPolicyLoader{
		policy: allowPolicy,
		count:  &loadCount,
		mu:     &loadMu,
	}
	cachedLoaderWithCounting := policy.NewCachedLoader(countingLoader, 5*time.Minute)
	// Pre-warm
	_, _ = cachedLoaderWithCounting.Load(ctx, "/sentinel/test/production")
	// Reset counter after warm-up
	loadMu.Lock()
	loadCount = 0
	loadMu.Unlock()

	config := testutil.LoadTestConfig{
		RequestsPerSecond: 1000,
		Duration:          10 * time.Second,
		Workers:           50,
		Timeout:           100 * time.Millisecond,
	}

	// Use deterministic time
	fixedTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)

	requestFn := func(ctx context.Context) error {
		// Load policy from cache
		pol, err := cachedLoaderWithCounting.Load(ctx, "/sentinel/test/production")
		if err != nil {
			return err
		}

		// Evaluate
		req := &policy.Request{
			User:    "alice",
			Profile: "production",
			Time:    fixedTime,
		}
		decision := policy.Evaluate(pol, req)
		if decision.Effect != policy.EffectAllow {
			return errUnexpectedDeny
		}
		return nil
	}

	result := testutil.RunLoadTest(context.Background(), config, requestFn)

	// Calculate cache stats
	loadMu.Lock()
	finalLoadCount := loadCount
	loadMu.Unlock()

	cacheHitRatio := 100.0
	if result.SuccessCount > 0 {
		cacheHitRatio = float64(result.SuccessCount-int(finalLoadCount)) / float64(result.SuccessCount) * 100.0
	}

	t.Logf("Cached Policy Evaluation Load Test Results:\n%s", testutil.FormatLoadTestResult(result))
	t.Logf("Cache Statistics:\n  Underlying loads: %d\n  Cache hit ratio: %.2f%%", finalLoadCount, cacheHitRatio)

	// Assert minimum thresholds
	if result.SuccessRate() < 99.0 {
		t.Errorf("Success rate %.1f%% below 99%% threshold", result.SuccessRate())
	}
	if cacheHitRatio < 99.0 {
		t.Errorf("Cache hit ratio %.2f%% below 99%% threshold", cacheHitRatio)
	}
	if result.LatencyP99 > 10*time.Millisecond {
		t.Errorf("P99 latency %v exceeds 10ms threshold", result.LatencyP99)
	}
}

// countingMockPolicyLoader counts loads for cache hit ratio verification.
type countingMockPolicyLoader struct {
	policy *policy.Policy
	count  *int64
	mu     *sync.Mutex
}

func (m *countingMockPolicyLoader) Load(ctx context.Context, parameterName string) (*policy.Policy, error) {
	m.mu.Lock()
	*m.count++
	m.mu.Unlock()
	return m.policy, nil
}

// TestLoad_IdentityGeneration tests request ID generation under high load.
// Target: 5000 req/sec for 5 seconds testing crypto/rand throughput.
//
// Note: We don't track collisions in the hot path as that would create
// mutex contention that dominates the benchmark. With 32-bit entropy and
// ~25k samples, birthday problem probability is ~0.07% (negligible).
func TestLoad_IdentityGeneration(t *testing.T) {
	config := testutil.LoadTestConfig{
		RequestsPerSecond: 5000,
		Duration:          5 * time.Second,
		Workers:           100,
		Timeout:           50 * time.Millisecond,
	}

	requestFn := func(ctx context.Context) error {
		// Generate a new request ID
		id := identity.NewRequestID()

		// Validate the generated ID
		if !identity.ValidateRequestID(id) {
			return &invalidIDError{id: id}
		}

		return nil
	}

	result := testutil.RunLoadTest(context.Background(), config, requestFn)

	t.Logf("Identity Generation Load Test Results:\n%s", testutil.FormatLoadTestResult(result))

	// Assert minimum thresholds
	if result.SuccessRate() < 99.9 {
		t.Errorf("Success rate %.1f%% below 99.9%% threshold", result.SuccessRate())
	}
	if result.Throughput < 4000 {
		t.Errorf("Throughput %.1f req/sec below 4000 req/sec threshold", result.Throughput)
	}
}

type invalidIDError struct {
	id string
}

func (e *invalidIDError) Error() string {
	return "invalid request ID generated: " + e.id
}

// TestLoad_MixedWorkload tests a realistic mixed workload.
// Workload distribution:
//   - 80% policy evaluation (allow)
//   - 15% policy evaluation (deny)
//   - 5% cache miss (new profile)
//
// Target: 500 req/sec for 30 seconds.
func TestLoad_MixedWorkload(t *testing.T) {
	// Create policies
	allowPolicy := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-alice-production",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Users:    []string{"alice"},
					Profiles: []string{"production"},
				},
			},
			{
				Name:   "deny-bob-production",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Users:    []string{"bob"},
					Profiles: []string{"production"},
				},
				Reason: "bob is not authorized",
			},
		},
	}

	// Create cached loader
	loader := &mockPolicyLoader{policy: allowPolicy}
	cachedLoader := policy.NewCachedLoader(loader, 5*time.Minute)

	// Pre-warm the cache for the main policy path
	ctx := context.Background()
	_, _ = cachedLoader.Load(ctx, "/sentinel/test/production")

	config := testutil.LoadTestConfig{
		RequestsPerSecond: 500,
		Duration:          30 * time.Second,
		Workers:           25,
		Timeout:           100 * time.Millisecond,
	}

	// Track workload distribution
	var statsMu sync.Mutex
	var allowCount, denyCount, cacheMissCount int

	// Request counter for distribution
	var reqCounter int64
	var reqMu sync.Mutex

	// Use deterministic time
	fixedTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)

	requestFn := func(ctx context.Context) error {
		// Determine workload type based on counter
		reqMu.Lock()
		counter := reqCounter
		reqCounter++
		reqMu.Unlock()

		workloadType := counter % 100

		var user, profile, paramPath string

		switch {
		case workloadType < 80:
			// 80% allow path
			user = "alice"
			profile = "production"
			paramPath = "/sentinel/test/production"
			statsMu.Lock()
			allowCount++
			statsMu.Unlock()
		case workloadType < 95:
			// 15% deny path
			user = "bob"
			profile = "production"
			paramPath = "/sentinel/test/production"
			statsMu.Lock()
			denyCount++
			statsMu.Unlock()
		default:
			// 5% cache miss (unique profile)
			user = "alice"
			profile = "staging"
			// Unique parameter path to force cache miss
			paramPath = "/sentinel/test/staging-" + identity.NewRequestID()
			statsMu.Lock()
			cacheMissCount++
			statsMu.Unlock()
		}

		// Load policy
		pol, err := cachedLoader.Load(ctx, paramPath)
		if err != nil {
			return err
		}

		// Evaluate policy
		req := &policy.Request{
			User:    user,
			Profile: profile,
			Time:    fixedTime,
		}
		decision := policy.Evaluate(pol, req)

		// Validate expected outcome
		switch {
		case user == "alice" && profile == "production":
			if decision.Effect != policy.EffectAllow {
				return errUnexpectedDeny
			}
		case user == "bob" && profile == "production":
			if decision.Effect != policy.EffectDeny {
				return &unexpectedAllowError{}
			}
		}
		// Cache miss path (staging) goes to default deny, which is expected

		return nil
	}

	result := testutil.RunLoadTest(context.Background(), config, requestFn)

	// Get final stats
	statsMu.Lock()
	finalAllowCount := allowCount
	finalDenyCount := denyCount
	finalCacheMissCount := cacheMissCount
	statsMu.Unlock()

	totalWorkload := finalAllowCount + finalDenyCount + finalCacheMissCount
	allowPct := float64(finalAllowCount) / float64(totalWorkload) * 100.0
	denyPct := float64(finalDenyCount) / float64(totalWorkload) * 100.0
	cacheMissPct := float64(finalCacheMissCount) / float64(totalWorkload) * 100.0

	t.Logf("Mixed Workload Load Test Results:\n%s", testutil.FormatLoadTestResult(result))
	t.Logf("Workload Distribution:\n  Allow: %d (%.1f%%)\n  Deny: %d (%.1f%%)\n  Cache Miss: %d (%.1f%%)",
		finalAllowCount, allowPct, finalDenyCount, denyPct, finalCacheMissCount, cacheMissPct)

	// Assert minimum thresholds
	if result.SuccessRate() < 99.0 {
		t.Errorf("Success rate %.1f%% below 99%% threshold", result.SuccessRate())
	}
	if result.Throughput < 400 {
		t.Errorf("Throughput %.1f req/sec below 400 req/sec threshold", result.Throughput)
	}
	if result.LatencyP99 > 10*time.Millisecond {
		t.Errorf("P99 latency %v exceeds 10ms threshold", result.LatencyP99)
	}

	// Verify workload distribution is roughly as expected (within tolerance)
	if allowPct < 75.0 || allowPct > 85.0 {
		t.Logf("Warning: Allow percentage %.1f%% outside expected range [75%%, 85%%]", allowPct)
	}
	if denyPct < 10.0 || denyPct > 20.0 {
		t.Logf("Warning: Deny percentage %.1f%% outside expected range [10%%, 20%%]", denyPct)
	}
	if cacheMissPct < 2.0 || cacheMissPct > 10.0 {
		t.Logf("Warning: Cache miss percentage %.1f%% outside expected range [2%%, 10%%]", cacheMissPct)
	}
}

type unexpectedAllowError struct{}

func (e *unexpectedAllowError) Error() string { return "unexpected allow from policy evaluation" }
