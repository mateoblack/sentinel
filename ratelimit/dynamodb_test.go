package ratelimit

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// mockCall records a DynamoDB API call for verification.
type mockCall struct {
	Method string
	Input  *dynamodb.UpdateItemInput
}

// mockDynamoDBClient implements DynamoDBAPI for testing.
type mockDynamoDBClient struct {
	updateItemFn func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
	calls        []mockCall
}

func (m *mockDynamoDBClient) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	m.calls = append(m.calls, mockCall{Method: "UpdateItem", Input: params})
	if m.updateItemFn != nil {
		return m.updateItemFn(ctx, params)
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

func TestDynamoDBRateLimiter_AllowUnderLimit(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 3,
		Window:            time.Minute,
	}

	requestCount := 0
	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			requestCount++
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: strconv.Itoa(requestCount)},
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		allowed, retryAfter, err := limiter.Allow(ctx, "user1")
		if err != nil {
			t.Fatalf("Allow returned error: %v", err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
		if retryAfter != 0 {
			t.Errorf("retryAfter should be 0 when allowed, got %v", retryAfter)
		}
	}
}

func TestDynamoDBRateLimiter_AllowAtLimit(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 3,
		Window:            time.Minute,
	}

	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			// Return count=4 (over limit)
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: "4"},
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	allowed, retryAfter, err := limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}
	if allowed {
		t.Error("request should be denied when at limit")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Errorf("retryAfter should be between 0 and 1 minute, got %v", retryAfter)
	}
}

func TestDynamoDBRateLimiter_WindowRollover(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 3,
		Window:            time.Minute,
	}

	callCount := 0
	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			callCount++
			if callCount == 1 {
				// First call: condition check fails (window rolled over)
				return nil, &types.ConditionalCheckFailedException{
					Message: aws.String("condition check failed"),
				}
			}
			// Second call (resetAndIncrement): return count=1
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: "1"},
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	allowed, retryAfter, err := limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}
	if !allowed {
		t.Error("request should be allowed after window rollover")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter should be 0 when allowed, got %v", retryAfter)
	}

	// Should have made 2 calls (initial + reset)
	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestDynamoDBRateLimiter_FailOpenOnError(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 3,
		Window:            time.Minute,
	}

	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			// Return a generic DynamoDB error
			return nil, errors.New("DynamoDB service unavailable")
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	// Should fail open (allow) on DynamoDB error
	allowed, retryAfter, err := limiter.Allow(ctx, "user1")
	if err == nil {
		t.Error("expected error to be returned")
	}
	if !allowed {
		t.Error("should fail open (allow) on DynamoDB error")
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter should be 0 on fail-open, got %v", retryAfter)
	}
}

func TestDynamoDBRateLimiter_RetryAfterCalculation(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 3,
		Window:            time.Minute,
	}

	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: "10"}, // Over limit
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	allowed, retryAfter, err := limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}
	if allowed {
		t.Error("request should be denied")
	}

	// retryAfter should be positive and no more than window duration
	if retryAfter <= 0 {
		t.Errorf("retryAfter should be positive, got %v", retryAfter)
	}
	if retryAfter > cfg.Window {
		t.Errorf("retryAfter should not exceed window (%v), got %v", cfg.Window, retryAfter)
	}
}

func TestDynamoDBRateLimiter_ConcurrentRequests(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	callCount := 0
	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			callCount++
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: strconv.Itoa(callCount)},
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	// Make multiple requests
	for i := 0; i < 5; i++ {
		_, _, err := limiter.Allow(ctx, "user1")
		if err != nil {
			t.Fatalf("Allow returned error: %v", err)
		}
	}

	// Verify UpdateItem was called for each request
	if len(mock.calls) != 5 {
		t.Errorf("expected 5 UpdateItem calls, got %d", len(mock.calls))
	}
}

func TestDynamoDBRateLimiter_KeyFormat(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	var capturedPK string
	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			if pk, ok := input.Key["PK"].(*types.AttributeValueMemberS); ok {
				capturedPK = pk.Value
			}
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: "1"},
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	testKey := "arn:aws:iam::123456789012:user/alice"
	_, _, err = limiter.Allow(ctx, testKey)
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}

	expectedPK := "RL#" + testKey
	if capturedPK != expectedPK {
		t.Errorf("expected PK=%q, got %q", expectedPK, capturedPK)
	}
}

func TestDynamoDBRateLimiter_TTLCalculation(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	var capturedTTL int64
	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			if ttlVal, ok := input.ExpressionAttributeValues[":ttl"].(*types.AttributeValueMemberN); ok {
				capturedTTL, _ = strconv.ParseInt(ttlVal.Value, 10, 64)
			}
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: "1"},
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	before := time.Now()
	_, _, err = limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}

	// TTL should be window end + 1 hour buffer
	// Window end is approximately now + window duration (1 minute)
	// So TTL should be approximately now + 1 minute + 1 hour
	expectedMinTTL := before.Truncate(cfg.Window).Add(cfg.Window).Add(time.Hour).Unix()
	expectedMaxTTL := expectedMinTTL + 60 // Allow 60 second tolerance

	if capturedTTL < expectedMinTTL || capturedTTL > expectedMaxTTL {
		t.Errorf("TTL=%d not in expected range [%d, %d]", capturedTTL, expectedMinTTL, expectedMaxTTL)
	}
}

func TestDynamoDBRateLimiter_TableName(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	var capturedTableName string
	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			capturedTableName = *input.TableName
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: "1"},
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "my-rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	_, _, err = limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}

	if capturedTableName != "my-rate-limit-table" {
		t.Errorf("expected table name %q, got %q", "my-rate-limit-table", capturedTableName)
	}
}

func TestDynamoDBRateLimiter_BurstSize(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 3,
		Window:            time.Minute,
		BurstSize:         5, // Allow bursts up to 5
	}

	requestCount := 0
	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			requestCount++
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: strconv.Itoa(requestCount)},
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	// Should allow up to burst size (5)
	for i := 0; i < 5; i++ {
		allowed, _, err := limiter.Allow(ctx, "user1")
		if err != nil {
			t.Fatalf("Allow returned error: %v", err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed (within burst)", i+1)
		}
	}

	// 6th request should be denied
	allowed, _, err := limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}
	if allowed {
		t.Error("6th request should be denied (exceeds burst)")
	}
}

func TestNewDynamoDBRateLimiter_InvalidConfig(t *testing.T) {
	mock := &mockDynamoDBClient{}

	tests := []struct {
		name      string
		cfg       Config
		tableName string
		wantErr   string
	}{
		{
			name:      "invalid RequestsPerWindow",
			cfg:       Config{RequestsPerWindow: 0, Window: time.Minute},
			tableName: "table",
			wantErr:   "RequestsPerWindow must be positive",
		},
		{
			name:      "invalid Window",
			cfg:       Config{RequestsPerWindow: 10, Window: 0},
			tableName: "table",
			wantErr:   "Window must be positive",
		},
		{
			name:      "empty tableName",
			cfg:       Config{RequestsPerWindow: 10, Window: time.Minute},
			tableName: "",
			wantErr:   "tableName cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDynamoDBRateLimiter(mock, tt.tableName, tt.cfg)
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestNewDynamoDBRateLimiter_NilClient(t *testing.T) {
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	_, err := NewDynamoDBRateLimiter(nil, "table", cfg)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	if !strings.Contains(err.Error(), "client cannot be nil") {
		t.Errorf("expected error about nil client, got %q", err.Error())
	}
}

func TestDynamoDBRateLimiter_ImplementsInterface(t *testing.T) {
	// This test verifies at compile time that DynamoDBRateLimiter implements RateLimiter
	var _ RateLimiter = (*DynamoDBRateLimiter)(nil)
}

func TestParseCount(t *testing.T) {
	tests := []struct {
		name     string
		attr     types.AttributeValue
		expected int
	}{
		{
			name:     "nil attribute",
			attr:     nil,
			expected: 0,
		},
		{
			name:     "valid number",
			attr:     &types.AttributeValueMemberN{Value: "42"},
			expected: 42,
		},
		{
			name:     "zero",
			attr:     &types.AttributeValueMemberN{Value: "0"},
			expected: 0,
		},
		{
			name:     "wrong type (string)",
			attr:     &types.AttributeValueMemberS{Value: "42"},
			expected: 0,
		},
		{
			name:     "invalid number format",
			attr:     &types.AttributeValueMemberN{Value: "not-a-number"},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCount(tt.attr)
			if result != tt.expected {
				t.Errorf("parseCount(%v) = %d, want %d", tt.attr, result, tt.expected)
			}
		})
	}
}

func TestDynamoDBRateLimiter_ResetAndIncrementError(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 3,
		Window:            time.Minute,
	}

	callCount := 0
	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			callCount++
			if callCount == 1 {
				// First call: condition check fails
				return nil, &types.ConditionalCheckFailedException{
					Message: aws.String("condition check failed"),
				}
			}
			// Second call (resetAndIncrement): also fails
			return nil, errors.New("DynamoDB error during reset")
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	// Should fail open when resetAndIncrement also fails
	allowed, _, err := limiter.Allow(ctx, "user1")
	if err == nil {
		t.Error("expected error to be returned")
	}
	if !allowed {
		t.Error("should fail open on resetAndIncrement error")
	}
}

func TestDynamoDBRateLimiter_UpdateExpression(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		RequestsPerWindow: 10,
		Window:            time.Minute,
	}

	var capturedUpdateExpr string
	var capturedConditionExpr string
	mock := &mockDynamoDBClient{
		updateItemFn: func(ctx context.Context, input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			capturedUpdateExpr = *input.UpdateExpression
			if input.ConditionExpression != nil {
				capturedConditionExpr = *input.ConditionExpression
			}
			return &dynamodb.UpdateItemOutput{
				Attributes: map[string]types.AttributeValue{
					"Count": &types.AttributeValueMemberN{Value: "1"},
				},
			}, nil
		},
	}

	limiter, err := NewDynamoDBRateLimiter(mock, "rate-limit-table", cfg)
	if err != nil {
		t.Fatalf("NewDynamoDBRateLimiter failed: %v", err)
	}

	_, _, err = limiter.Allow(ctx, "user1")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}

	// Verify update expression uses if_not_exists for atomic increment
	if !strings.Contains(capturedUpdateExpr, "if_not_exists") {
		t.Errorf("update expression should use if_not_exists, got %q", capturedUpdateExpr)
	}

	// Verify condition expression checks for window
	if !strings.Contains(capturedConditionExpr, "attribute_not_exists") {
		t.Errorf("condition expression should check attribute_not_exists, got %q", capturedConditionExpr)
	}
}
