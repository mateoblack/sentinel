// Security regression tests for rate limiting to prevent abuse.
// These tests verify security boundaries beyond functional correctness:
// - Concurrent access respects limits (race condition prevention)
// - Memory exhaustion prevention with cleanup
// - Fail-open behavior is consistent
// - Configuration validation rejects invalid values
// - Window boundary handling is secure
// - DynamoDB atomic operations (distributed rate limiting)
// - Key isolation between users (DynamoDB)

package ratelimit

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ============================================================================
// Concurrent Request Security Tests
// ============================================================================

// TestSecurity_ConcurrentRequestsRespectLimits verifies that concurrent requests
// respect rate limits. This is security-critical: 100 concurrent requests with
// limit of 10 should only allow exactly 10, preventing race condition exploits.
func TestSecurity_ConcurrentRequestsRespectLimits(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// Run 100 concurrent requests - should allow exactly 10
	const totalRequests = 100
	const expectedAllowed = 10

	var wg sync.WaitGroup
	var allowedCount int64

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _, err := limiter.Allow(ctx, "concurrent-test-key")
			if err != nil {
				t.Errorf("concurrent Allow returned error: %v", err)
				return
			}
			if allowed {
				atomic.AddInt64(&allowedCount, 1)
			}
		}()
	}

	wg.Wait()

	// SECURITY: Exactly 10 should have been allowed - no more, no less
	if allowedCount != expectedAllowed {
		t.Errorf("SECURITY VIOLATION: expected exactly %d allowed requests, got %d (race condition may exist)",
			expectedAllowed, allowedCount)
	}
}

// TestSecurity_ConcurrentDifferentKeys verifies that concurrent requests to
// different keys are independently rate limited.
func TestSecurity_ConcurrentDifferentKeys(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 5,
		Window:            time.Minute,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// 10 different keys, 20 requests each = 200 total
	// Each key should allow 5 requests = 50 total allowed
	const numKeys = 10
	const requestsPerKey = 20
	const expectedAllowedPerKey = 5

	var wg sync.WaitGroup
	allowedPerKey := make([]int64, numKeys)

	for keyIdx := 0; keyIdx < numKeys; keyIdx++ {
		for reqIdx := 0; reqIdx < requestsPerKey; reqIdx++ {
			wg.Add(1)
			go func(key int) {
				defer wg.Done()
				keyStr := string(rune('A' + key)) // Keys: A, B, C, ...
				allowed, _, err := limiter.Allow(ctx, keyStr)
				if err != nil {
					t.Errorf("concurrent Allow returned error: %v", err)
					return
				}
				if allowed {
					atomic.AddInt64(&allowedPerKey[key], 1)
				}
			}(keyIdx)
		}
	}

	wg.Wait()

	// SECURITY: Each key should have exactly expectedAllowedPerKey allowed
	for i, allowed := range allowedPerKey {
		if allowed != int64(expectedAllowedPerKey) {
			t.Errorf("SECURITY VIOLATION: key %c expected exactly %d allowed, got %d (keys not isolated)",
				rune('A'+i), expectedAllowedPerKey, allowed)
		}
	}
}

// ============================================================================
// Memory Exhaustion Prevention Tests
// ============================================================================

// TestSecurity_MemoryBoundedWithManyKeys verifies that rate limiter with many
// unique keys doesn't exhaust memory. Cleanup goroutine should remove expired entries.
func TestSecurity_MemoryBoundedWithManyKeys(t *testing.T) {
	ctx := context.Background()

	// Short window and cleanup interval for testing
	cfg := Config{
		RequestsPerWindow: 1,
		Window:            50 * time.Millisecond,
	}

	limiter, err := NewMemoryRateLimiterWithCleanup(cfg, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// Record initial memory
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	// Add 10000 unique keys
	const numKeys = 10000
	for i := 0; i < numKeys; i++ {
		key := string(rune(i))
		limiter.Allow(ctx, key)
	}

	// Verify keys exist
	stats := limiter.Stats()
	if stats.TotalKeys < numKeys/2 {
		t.Errorf("Expected at least %d keys, got %d", numKeys/2, stats.TotalKeys)
	}

	// Wait for window to expire + multiple cleanup cycles
	time.Sleep(200 * time.Millisecond)

	// Verify cleanup removed expired entries
	stats = limiter.Stats()
	if stats.TotalKeys > numKeys/10 {
		t.Errorf("SECURITY CONCERN: cleanup not working - expected most keys cleaned up, still have %d", stats.TotalKeys)
	}

	// Memory should not have grown significantly (allowing for test overhead)
	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	// Allow reasonable memory growth but not unbounded
	memGrowthMB := float64(mAfter.Alloc-mBefore.Alloc) / 1024 / 1024
	if memGrowthMB > 50 {
		t.Errorf("SECURITY CONCERN: excessive memory growth %.2f MB after cleanup (possible memory leak)", memGrowthMB)
	}
}

// TestSecurity_CleanupRemovesExpiredEntries verifies cleanup goroutine behavior.
func TestSecurity_CleanupRemovesExpiredEntries(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 10,
		Window:            30 * time.Millisecond,
	}

	// Create with short cleanup interval for testing
	limiter, err := NewMemoryRateLimiterWithCleanup(cfg, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// Add entries for multiple keys
	keys := []string{"key1", "key2", "key3"}
	for _, key := range keys {
		for i := 0; i < 5; i++ {
			limiter.Allow(ctx, key)
		}
	}

	// Verify keys exist
	stats := limiter.Stats()
	if stats.TotalKeys != len(keys) {
		t.Errorf("Expected %d keys, got %d", len(keys), stats.TotalKeys)
	}
	if stats.TotalRequests != len(keys)*5 {
		t.Errorf("Expected %d requests, got %d", len(keys)*5, stats.TotalRequests)
	}

	// Wait for window to expire + cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Verify all keys were cleaned up
	stats = limiter.Stats()
	if stats.TotalKeys != 0 {
		t.Errorf("SECURITY CONCERN: expected 0 keys after cleanup, got %d", stats.TotalKeys)
	}
	if stats.TotalRequests != 0 {
		t.Errorf("SECURITY CONCERN: expected 0 requests after cleanup, got %d", stats.TotalRequests)
	}
}

// ============================================================================
// Fail-Open Behavior Tests
// ============================================================================

// MockFailingRateLimiter simulates internal errors for fail-open testing.
// Note: MemoryRateLimiter doesn't currently return errors from Allow(),
// but this tests the interface contract and future implementations.
type MockFailingRateLimiter struct {
	ShouldFail bool
	FailError  error
}

func (m *MockFailingRateLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	if m.ShouldFail {
		return false, 0, m.FailError
	}
	return true, 0, nil
}

// TestSecurity_FailOpenBehaviorInterface verifies the fail-open contract:
// When Allow() returns an error, callers should allow the request.
// This is a design decision documented in the interface.
func TestSecurity_FailOpenBehaviorInterface(t *testing.T) {
	// This test documents the expected fail-open behavior:
	// When a rate limiter error occurs, the request should be allowed
	// to maintain availability over strict limiting.

	mock := &MockFailingRateLimiter{
		ShouldFail: true,
		FailError:  context.DeadlineExceeded, // Simulating timeout
	}

	ctx := context.Background()
	allowed, _, err := mock.Allow(ctx, "test-key")

	// When error occurs, caller should check error first
	if err == nil {
		t.Fatal("Expected error from failing rate limiter")
	}

	// The interface returns allowed=false with error
	// Caller is responsible for fail-open: if err != nil, allow request
	if allowed {
		t.Error("Interface should return allowed=false with error; caller decides fail-open policy")
	}

	// Document expected caller behavior:
	// if err != nil {
	//     log.Printf("WARNING: Rate limit check failed: %v", err)
	//     // Fail open - allow the request
	// } else if !allowed {
	//     return 429 Too Many Requests
	// }
}

// ============================================================================
// Configuration Validation Tests
// ============================================================================

// TestSecurity_RejectsZeroRequestsPerWindow verifies that zero or negative
// RequestsPerWindow is rejected. This prevents misconfiguration that could
// either block all requests or allow unlimited requests.
func TestSecurity_RejectsZeroRequestsPerWindow(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "zero requests",
			config: Config{
				RequestsPerWindow: 0,
				Window:            time.Minute,
			},
			wantErr: true,
		},
		{
			name: "negative requests",
			config: Config{
				RequestsPerWindow: -1,
				Window:            time.Minute,
			},
			wantErr: true,
		},
		{
			name: "valid requests",
			config: Config{
				RequestsPerWindow: 1,
				Window:            time.Minute,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter, err := NewMemoryRateLimiter(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMemoryRateLimiter() error = %v, wantErr %v", err, tt.wantErr)
			}
			if limiter != nil {
				limiter.Close()
			}
		})
	}
}

// TestSecurity_RejectsZeroWindow verifies that zero or negative Window is rejected.
func TestSecurity_RejectsZeroWindow(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "zero window",
			config: Config{
				RequestsPerWindow: 10,
				Window:            0,
			},
			wantErr: true,
		},
		{
			name: "negative window",
			config: Config{
				RequestsPerWindow: 10,
				Window:            -time.Second,
			},
			wantErr: true,
		},
		{
			name: "valid window",
			config: Config{
				RequestsPerWindow: 10,
				Window:            time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter, err := NewMemoryRateLimiter(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMemoryRateLimiter() error = %v, wantErr %v", err, tt.wantErr)
			}
			if limiter != nil {
				limiter.Close()
			}
		})
	}
}

// TestSecurity_RejectsNegativeBurstSize verifies that negative BurstSize is rejected.
func TestSecurity_RejectsNegativeBurstSize(t *testing.T) {
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
		BurstSize:         -1,
	}

	_, err := NewMemoryRateLimiter(cfg)
	if err == nil {
		t.Error("SECURITY VIOLATION: expected error for negative BurstSize")
	}
}

// ============================================================================
// Window Boundary Security Tests
// ============================================================================

// TestSecurity_WindowBoundaryNoDoubleCount verifies requests at window boundary
// don't allow double-counting exploit. Sliding window should not leak extra requests.
func TestSecurity_WindowBoundaryNoDoubleCount(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 5,
		Window:            100 * time.Millisecond,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	key := "boundary-test"

	// Use 4 of 5 requests
	for i := 0; i < 4; i++ {
		allowed, _, _ := limiter.Allow(ctx, key)
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// Wait for half the window
	time.Sleep(50 * time.Millisecond)

	// Use the 5th request
	allowed, _, _ := limiter.Allow(ctx, key)
	if !allowed {
		t.Error("5th request should be allowed")
	}

	// 6th request should be denied (window hasn't fully passed)
	allowed, _, _ = limiter.Allow(ctx, key)
	if allowed {
		t.Error("SECURITY VIOLATION: 6th request should be denied at window boundary")
	}

	// Wait for first requests to expire
	time.Sleep(60 * time.Millisecond)

	// Now some requests should be allowed (first 4 have expired)
	allowedCount := 0
	for i := 0; i < 5; i++ {
		allowed, _, _ := limiter.Allow(ctx, key)
		if allowed {
			allowedCount++
		}
	}

	// Should allow 3-4 requests (first 4 expired, 5th still in window)
	if allowedCount < 3 {
		t.Errorf("Expected at least 3 requests allowed after partial window expiry, got %d", allowedCount)
	}
}

// TestSecurity_SlidingWindowConsistent verifies sliding window is consistent
// across rapid requests.
func TestSecurity_SlidingWindowConsistent(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Second,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	key := "sliding-test"

	// Make 10 requests rapidly
	for i := 0; i < 10; i++ {
		allowed, _, _ := limiter.Allow(ctx, key)
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// All subsequent requests should be denied until window expires
	deniedCount := 0
	for i := 0; i < 20; i++ {
		allowed, _, _ := limiter.Allow(ctx, key)
		if !allowed {
			deniedCount++
		}
	}

	if deniedCount != 20 {
		t.Errorf("SECURITY VIOLATION: expected 20 denied requests after limit, got %d", deniedCount)
	}
}

// ============================================================================
// Key Normalization Tests
// ============================================================================

// TestSecurity_KeysAreCaseSensitive verifies that keys are case-sensitive.
// "User1" and "user1" should be different rate limit buckets.
func TestSecurity_KeysAreCaseSensitive(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 1,
		Window:            time.Minute,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// First request for "User1"
	allowed1, _, _ := limiter.Allow(ctx, "User1")
	if !allowed1 {
		t.Error("First request for 'User1' should be allowed")
	}

	// Second request for "User1" should be denied
	allowed2, _, _ := limiter.Allow(ctx, "User1")
	if allowed2 {
		t.Error("Second request for 'User1' should be denied")
	}

	// First request for "user1" (different case) should be allowed
	// This tests that keys are NOT normalized to lowercase
	allowed3, _, _ := limiter.Allow(ctx, "user1")
	if !allowed3 {
		t.Error("First request for 'user1' (different case) should be allowed as separate key")
	}

	// Verify both keys exist
	stats := limiter.Stats()
	if stats.TotalKeys != 2 {
		t.Errorf("Expected 2 keys (case-sensitive), got %d", stats.TotalKeys)
	}
}

// TestSecurity_EmptyKeyWorks verifies empty string key is handled correctly.
func TestSecurity_EmptyKeyWorks(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 2,
		Window:            time.Minute,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	// Empty key should work
	allowed1, _, err := limiter.Allow(ctx, "")
	if err != nil {
		t.Errorf("Allow with empty key returned error: %v", err)
	}
	if !allowed1 {
		t.Error("First request with empty key should be allowed")
	}

	allowed2, _, _ := limiter.Allow(ctx, "")
	if !allowed2 {
		t.Error("Second request with empty key should be allowed")
	}

	allowed3, _, _ := limiter.Allow(ctx, "")
	if allowed3 {
		t.Error("Third request with empty key should be denied")
	}
}

// ============================================================================
// Boundary Condition Tests
// ============================================================================

// TestSecurity_ExactlyAtLimit verifies behavior when count equals limit.
func TestSecurity_ExactlyAtLimit(t *testing.T) {
	ctx := context.Background()

	cfg := Config{
		RequestsPerWindow: 5,
		Window:            time.Minute,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	key := "boundary"

	// Use exactly 5 requests
	for i := 0; i < 5; i++ {
		allowed, _, _ := limiter.Allow(ctx, key)
		if !allowed {
			t.Errorf("Request %d of 5 should be allowed", i+1)
		}
	}

	// 6th request should be denied (not >5, but ==5 used)
	allowed, retryAfter, _ := limiter.Allow(ctx, key)
	if allowed {
		t.Error("SECURITY VIOLATION: request after limit should be denied")
	}
	if retryAfter <= 0 {
		t.Error("retryAfter should be positive when denied")
	}
}

// TestSecurity_RetryAfterAccurate verifies Retry-After is reasonable.
func TestSecurity_RetryAfterAccurate(t *testing.T) {
	ctx := context.Background()

	window := 200 * time.Millisecond
	cfg := Config{
		RequestsPerWindow: 1,
		Window:            window,
	}

	limiter, err := NewMemoryRateLimiter(cfg)
	if err != nil {
		t.Fatalf("NewMemoryRateLimiter failed: %v", err)
	}
	defer limiter.Close()

	key := "retry-test"

	// Use the single allowed request
	limiter.Allow(ctx, key)

	// Get retry-after for denied request
	_, retryAfter, _ := limiter.Allow(ctx, key)

	// Retry-after should be between 0 and window duration
	if retryAfter < 0 {
		t.Errorf("SECURITY CONCERN: negative retryAfter: %v", retryAfter)
	}
	if retryAfter > window {
		t.Errorf("retryAfter %v exceeds window %v", retryAfter, window)
	}
}

// ============================================================================
// DynamoDB Security Regression Tests (Distributed Rate Limiting)
// ============================================================================

// securityCaptureMockDynamoDB captures which DynamoDB operations are called
// to verify atomic operations are used (UpdateItem), not read-modify-write (GetItem+PutItem).
type securityCaptureMockDynamoDB struct {
	updateItemCalled int
	getItemCalled    int
	putItemCalled    int
	lastUpdateExpr   string
	lastCondExpr     string
}

func (m *securityCaptureMockDynamoDB) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	m.updateItemCalled++
	if params.UpdateExpression != nil {
		m.lastUpdateExpr = *params.UpdateExpression
	}
	if params.ConditionExpression != nil {
		m.lastCondExpr = *params.ConditionExpression
	}
	return &dynamodb.UpdateItemOutput{
		Attributes: map[string]types.AttributeValue{
			"Count": &types.AttributeValueMemberN{Value: "1"},
		},
	}, nil
}

// TestSecurityRegression_DynamoDBAtomicIncrement verifies that DynamoDBRateLimiter
// uses atomic UpdateItem with ADD operation, not read-modify-write pattern.
// THREAT: Race condition in distributed increment could allow rate limit bypass.
// PREVENTION: Use DynamoDB atomic ADD operation via UpdateItem, not GetItem/PutItem.
func TestSecurityRegression_DynamoDBAtomicIncrement(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	mock := &securityCaptureMockDynamoDB{}
	limiter, err := NewDynamoDBRateLimiter(mock, "test-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	_, _, err = limiter.Allow(ctx, "test-key")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}

	// SECURITY: Must use UpdateItem for atomic increment
	if mock.updateItemCalled == 0 {
		t.Error("SECURITY VIOLATION: Must use UpdateItem for atomic increment")
	}

	// SECURITY: Must NOT use GetItem/PutItem pattern (has race conditions)
	if mock.getItemCalled > 0 {
		t.Error("SECURITY VIOLATION: Must NOT use GetItem (race condition risk)")
	}
	if mock.putItemCalled > 0 {
		t.Error("SECURITY VIOLATION: Must NOT use PutItem without condition (race condition risk)")
	}

	// SECURITY: Update expression must use atomic if_not_exists pattern
	if !strings.Contains(mock.lastUpdateExpr, "if_not_exists") {
		t.Errorf("SECURITY VIOLATION: UpdateExpression must use if_not_exists for atomic increment, got: %s",
			mock.lastUpdateExpr)
	}

	// SECURITY: Must have condition expression to prevent stale window overwrites
	if mock.lastCondExpr == "" {
		t.Error("SECURITY VIOLATION: Must have ConditionExpression to prevent race conditions")
	}
}

// securityErrorMockDynamoDB returns errors for testing fail-open behavior.
type securityErrorMockDynamoDB struct {
	err error
}

func (m *securityErrorMockDynamoDB) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	return nil, m.err
}

// TestSecurityRegression_DynamoDBFailOpen verifies that DynamoDB errors result
// in fail-open behavior (allow the request) rather than blocking all requests.
// THREAT: DynamoDB outage could block all credential requests (DoS).
// PREVENTION: Fail-open on DynamoDB errors (availability over strict rate limiting).
func TestSecurityRegression_DynamoDBFailOpen(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	mock := &securityErrorMockDynamoDB{err: errors.New("DynamoDB unavailable")}
	limiter, err := NewDynamoDBRateLimiter(mock, "test-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	allowed, _, rlErr := limiter.Allow(ctx, "test-key")

	// SECURITY: Must fail-open (return allowed=true) on DynamoDB errors
	if !allowed {
		t.Error("SECURITY VIOLATION: DynamoDB errors must fail-open, not block requests")
	}

	// SECURITY: Must return error for logging (observability)
	if rlErr == nil {
		t.Error("SECURITY: Error should be returned for logging (but allowed=true)")
	}
}

// securityCountingMockDynamoDB tracks counts per key for isolation testing.
type securityCountingMockDynamoDB struct {
	counts map[string]int
	mu     sync.Mutex
}

func (m *securityCountingMockDynamoDB) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.counts == nil {
		m.counts = make(map[string]int)
	}

	// Extract key from PK
	pk := ""
	if pkAttr, ok := params.Key["PK"].(*types.AttributeValueMemberS); ok {
		pk = pkAttr.Value
	}

	m.counts[pk]++

	return &dynamodb.UpdateItemOutput{
		Attributes: map[string]types.AttributeValue{
			"Count": &types.AttributeValueMemberN{Value: strconv.Itoa(m.counts[pk])},
		},
	}, nil
}

// TestSecurityRegression_KeyIsolation verifies that different IAM ARNs have
// completely separate rate limit buckets in DynamoDB.
// THREAT: Shared rate limit buckets could cause DoS across different users.
// PREVENTION: Rate limit key includes full IAM ARN for complete isolation.
func TestSecurityRegression_KeyIsolation(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 2, // Low limit to trigger rate limiting
		Window:            time.Minute,
	}

	mock := &securityCountingMockDynamoDB{}
	limiter, err := NewDynamoDBRateLimiter(mock, "test-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	// User Alice makes 2 requests (at limit)
	aliceARN := "arn:aws:iam::123456789012:user/alice"
	for i := 0; i < 2; i++ {
		allowed, _, _ := limiter.Allow(ctx, aliceARN)
		if !allowed {
			t.Errorf("Alice request %d should be allowed", i+1)
		}
	}

	// Alice's 3rd request should be denied
	allowed, _, _ := limiter.Allow(ctx, aliceARN)
	if allowed {
		t.Error("Alice's 3rd request should be denied (at limit)")
	}

	// User Bob should have independent rate limit (his requests should succeed)
	bobARN := "arn:aws:iam::123456789012:user/bob"
	for i := 0; i < 2; i++ {
		allowed, _, _ := limiter.Allow(ctx, bobARN)
		if !allowed {
			t.Errorf("SECURITY VIOLATION: Bob request %d should be allowed (keys not isolated from Alice)", i+1)
		}
	}

	// Verify keys are stored separately in DynamoDB
	expectedAliceKey := "RL#" + aliceARN
	expectedBobKey := "RL#" + bobARN

	if mock.counts[expectedAliceKey] == 0 {
		t.Error("SECURITY VIOLATION: Alice's key not found in DynamoDB - keys not isolated")
	}
	if mock.counts[expectedBobKey] == 0 {
		t.Error("SECURITY VIOLATION: Bob's key not found in DynamoDB - keys not isolated")
	}
	if mock.counts[expectedAliceKey] == mock.counts[expectedBobKey] {
		// They should have different counts (3 for Alice due to denied request, 2 for Bob)
		// But more importantly, they should be stored under different keys
		t.Logf("INFO: Both users have same count (%d), but stored under separate keys",
			mock.counts[expectedAliceKey])
	}
}

// TestSecurityRegression_DynamoDBConditionPreventsOverwrite verifies that
// the condition expression prevents race conditions during window rollover.
// THREAT: Without condition, concurrent requests during window change could
// lose increments (count=1 overwrites count=5 from another instance).
// PREVENTION: Use condition expression to detect stale window and retry.
func TestSecurityRegression_DynamoDBConditionPreventsOverwrite(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	mock := &securityCaptureMockDynamoDB{}
	limiter, err := NewDynamoDBRateLimiter(mock, "test-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	_, _, err = limiter.Allow(ctx, "test-key")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}

	// SECURITY: Condition expression must check window to prevent overwrites
	if !strings.Contains(mock.lastCondExpr, "attribute_not_exists") &&
		!strings.Contains(mock.lastCondExpr, "#ws") {
		t.Errorf("SECURITY VIOLATION: ConditionExpression must check WindowStart to prevent overwrites, got: %s",
			mock.lastCondExpr)
	}
}
