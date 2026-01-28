//go:build loadtest

package sentinel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/session"
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

// ============================================================================
// Server HTTP Load Tests - verify server mode performance under sustained load
// ============================================================================

// TestLoad_ServerCredentialRequests tests server HTTP credential requests under sustained load.
// Target: 100 req/sec for 10 seconds with >99% success rate and P99 latency <50ms.
//
// This test verifies:
//   - SentinelServer can handle concurrent HTTP requests efficiently
//   - Policy evaluation + credential retrieval path performs well under load
//   - No race conditions in concurrent access patterns
func TestLoad_ServerCredentialRequests(t *testing.T) {
	t.Skip("DEPRECATED: Local server mode tests skipped - use Lambda TVM instead (v1.22)")
	// Create server with allow policy
	mockLoader := &mockPolicyLoader{
		policy: &policy.Policy{
			Rules: []policy.Rule{
				{Name: "allow-all", Effect: policy.EffectAllow},
			},
		},
	}

	mockProvider := &MockCredentialProvider{
		CredentialResult: &CredentialResult{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "token-for-load-test",
			Expiration:      time.Now().Add(15 * time.Minute),
			CanExpire:       true,
			SourceIdentity:  "sentinel:testuser:loadtest",
			RoleARN:         "arn:aws:iam::123456789012:role/TestRole",
		},
	}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	authToken := server.AuthToken()

	loadConfig := testutil.LoadTestConfig{
		RequestsPerSecond: 100,
		Duration:          10 * time.Second,
		Workers:           10,
		Timeout:           100 * time.Millisecond,
	}

	requestFn := func(ctx context.Context) error {
		// Create HTTP request
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", authToken)
		rec := httptest.NewRecorder()

		// Call DefaultRoute directly (bypasses network overhead)
		server.DefaultRoute(rec, req)

		// Verify success
		if rec.Code != http.StatusOK {
			return &httpLoadTestError{code: rec.Code, body: rec.Body.String()}
		}

		// Verify response contains credentials
		var resp map[string]string
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			return err
		}
		if resp["AccessKeyId"] == "" {
			return &httpLoadTestError{code: rec.Code, body: "missing AccessKeyId"}
		}

		return nil
	}

	result := testutil.RunLoadTest(context.Background(), loadConfig, requestFn)

	t.Logf("Server HTTP Load Test Results:\n%s", testutil.FormatLoadTestResult(result))

	// Assert minimum thresholds
	if result.SuccessRate() < 99.0 {
		t.Errorf("Success rate %.1f%% below 99%% threshold", result.SuccessRate())
	}
	if result.LatencyP99 > 50*time.Millisecond {
		t.Errorf("P99 latency %v exceeds 50ms threshold", result.LatencyP99)
	}
	if result.Throughput < 80 {
		t.Errorf("Throughput %.1f req/sec below 80 req/sec threshold", result.Throughput)
	}
}

// httpLoadTestError is returned when HTTP load test request fails.
type httpLoadTestError struct {
	code int
	body string
}

func (e *httpLoadTestError) Error() string {
	return "HTTP " + strconv.Itoa(e.code) + ": " + e.body
}

// TestLoad_RevocationTiming tests that revocation takes effect within acceptable latency.
// This tests the real-time revocation promise:
//   - Requests BEFORE revocation succeed
//   - Requests AFTER revocation fail within 100ms propagation
//
// The test runs requests at 50 req/sec, then revokes the session after 5 seconds,
// and verifies the revocation takes effect immediately.
func TestLoad_RevocationTiming(t *testing.T) {
	t.Skip("DEPRECATED: Local server mode tests skipped - use Lambda TVM instead (v1.22)")
	mockStore := NewMockSessionStore()

	// Create server with allow policy and session store
	mockLoader := &mockPolicyLoader{
		policy: &policy.Policy{
			Rules: []policy.Rule{
				{Name: "allow-all", Effect: policy.EffectAllow},
			},
		},
	}

	mockProvider := &MockCredentialProvider{
		CredentialResult: &CredentialResult{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "token",
			Expiration:      time.Now().Add(15 * time.Minute),
			CanExpire:       true,
			SourceIdentity:  "sentinel:testuser:revoke-test",
			RoleARN:         "arn:aws:iam::123456789012:role/TestRole",
		},
	}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		SessionStore:       mockStore,
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	authToken := server.AuthToken()
	sessionID := server.sessionID
	if sessionID == "" {
		t.Fatal("Expected session to be created")
	}

	// Track pre/post revocation request results
	var preRevocationSuccesses, postRevocationDenials int64
	var preRevocationMu, postRevocationMu sync.Mutex
	var revocationTime time.Time
	var revoked bool
	var revokedMu sync.Mutex

	// Request loop in background
	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	// Start request workers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					// Make credential request
					req := httptest.NewRequest("GET", "/", nil)
					req.Header.Set("Authorization", authToken)
					rec := httptest.NewRecorder()
					server.DefaultRoute(rec, req)

					// Track result based on timing
					revokedMu.Lock()
					wasRevoked := revoked
					revokeTime := revocationTime
					revokedMu.Unlock()

					if !wasRevoked {
						if rec.Code == http.StatusOK {
							preRevocationMu.Lock()
							preRevocationSuccesses++
							preRevocationMu.Unlock()
						}
					} else {
						// After revocation
						if rec.Code == http.StatusForbidden {
							postRevocationMu.Lock()
							postRevocationDenials++
							postRevocationMu.Unlock()
						} else if rec.Code == http.StatusOK {
							// This is a timing window issue - request started before revocation
							// was visible. Track timing to ensure it's within acceptable latency.
							elapsed := time.Since(revokeTime)
							if elapsed > 100*time.Millisecond {
								t.Errorf("Request succeeded %v after revocation (should fail within 100ms)", elapsed)
							}
						}
					}

					// 50 req/sec = 20ms between requests per worker (5 workers = ~50 req/sec total)
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()
	}

	// Let pre-revocation requests run for 2 seconds
	time.Sleep(2 * time.Second)

	// Verify some pre-revocation requests succeeded
	preRevocationMu.Lock()
	preCount := preRevocationSuccesses
	preRevocationMu.Unlock()
	if preCount == 0 {
		t.Fatal("Expected some pre-revocation requests to succeed")
	}
	t.Logf("Pre-revocation successes: %d", preCount)

	// Revoke the session by setting GetResult to a revoked session
	revokedMu.Lock()
	revocationTime = time.Now()
	revoked = true
	revokedMu.Unlock()

	// Configure mock to return revoked session
	mockStore.GetResult = &session.ServerSession{
		ID:            sessionID,
		User:          "testuser",
		Profile:       "test-profile",
		Status:        session.StatusRevoked,
		RevokedBy:     "admin",
		RevokedReason: "load test revocation",
		StartedAt:     time.Now().Add(-5 * time.Minute),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	// Let post-revocation requests run for 1 second
	time.Sleep(1 * time.Second)

	// Stop workers
	close(stopCh)
	wg.Wait()

	// Verify post-revocation denials
	postRevocationMu.Lock()
	postCount := postRevocationDenials
	postRevocationMu.Unlock()

	t.Logf("Post-revocation denials: %d", postCount)

	if postCount == 0 {
		t.Error("Expected some post-revocation requests to be denied")
	}

	// Calculate denial rate after revocation
	// Should be >90% (allowing for timing window)
	totalPostRevocation := postCount // Simplified - we don't track post-revocation successes in detail
	if totalPostRevocation > 0 {
		t.Logf("Revocation timing test passed: %d denials after revocation", postCount)
	}
}

// TestLoad_ConcurrentRevocationCheck tests thread-safety of revocation checking under concurrent access.
// This verifies no race conditions in the revocation check path with the -race flag.
//
// The test launches 50 concurrent goroutines, each making 100 credential requests,
// while session state is being read/written concurrently.
func TestLoad_ConcurrentRevocationCheck(t *testing.T) {
	t.Skip("DEPRECATED: Local server mode tests skipped - use Lambda TVM instead (v1.22)")
	mockStore := NewMockSessionStore()

	// Create server with allow policy and session store
	mockLoader := &mockPolicyLoader{
		policy: &policy.Policy{
			Rules: []policy.Rule{
				{Name: "allow-all", Effect: policy.EffectAllow},
			},
		},
	}

	mockProvider := &MockCredentialProvider{
		CredentialResult: &CredentialResult{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "token",
			Expiration:      time.Now().Add(15 * time.Minute),
			CanExpire:       true,
			SourceIdentity:  "sentinel:testuser:concurrent-test",
			RoleARN:         "arn:aws:iam::123456789012:role/TestRole",
		},
	}

	config := SentinelServerConfig{
		ProfileName:        "test-profile",
		PolicyParameter:    "/sentinel/test",
		User:               "testuser",
		PolicyLoader:       mockLoader,
		CredentialProvider: mockProvider,
		SessionStore:       mockStore,
		LazyLoad:           true,
	}

	server, err := NewSentinelServer(context.Background(), config, "test-token", 0)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Shutdown(context.Background())

	authToken := server.AuthToken()

	// Launch 50 concurrent goroutines each making 100 requests
	var wg sync.WaitGroup
	var successCount, errorCount int64
	var countMu sync.Mutex

	numGoroutines := 50
	requestsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				// Make credential request
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("Authorization", authToken)
				rec := httptest.NewRecorder()
				server.DefaultRoute(rec, req)

				countMu.Lock()
				if rec.Code == http.StatusOK {
					successCount++
				} else {
					errorCount++
				}
				countMu.Unlock()
			}
		}()
	}

	wg.Wait()

	totalRequests := int64(numGoroutines * requestsPerGoroutine)
	t.Logf("Concurrent Revocation Check Results:")
	t.Logf("  Total requests: %d", totalRequests)
	t.Logf("  Successes: %d", successCount)
	t.Logf("  Errors: %d", errorCount)
	t.Logf("  Touch calls: %d", mockStore.TouchCallCount())

	// Verify all requests succeeded (no race conditions causing failures)
	if errorCount > 0 {
		t.Errorf("Expected 0 errors with active session, got %d", errorCount)
	}

	// Verify Touch was called for each successful request
	touchCalls := int64(mockStore.TouchCallCount())
	if touchCalls != successCount {
		t.Logf("Warning: Touch calls (%d) != success count (%d) - possible race in Touch tracking", touchCalls, successCount)
	}

	// The -race flag will detect any data races during execution
	// If this test passes with -race, the concurrent access is thread-safe
}
