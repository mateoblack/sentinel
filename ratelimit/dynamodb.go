package ratelimit

import (
	"context"
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DynamoDBAPI defines the DynamoDB operations needed for rate limiting.
// This interface enables testing with mock implementations.
type DynamoDBAPI interface {
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// DynamoDBRateLimiter implements RateLimiter using DynamoDB for distributed rate limiting.
// Uses atomic UpdateItem with ADD to increment counters safely across Lambda instances.
//
// Table schema (single-table design):
//   - PK: "RL#" + key (e.g., "RL#arn:aws:iam::123456789012:user/alice")
//   - WindowStart: ISO8601 timestamp of current window start
//   - Count: Number of requests in current window
//   - TTL: Unix timestamp for DynamoDB TTL (window end + buffer)
type DynamoDBRateLimiter struct {
	client    DynamoDBAPI
	tableName string
	config    Config
}

// NewDynamoDBRateLimiter creates a new DynamoDB-backed rate limiter.
// The tableName must reference a DynamoDB table with a String partition key named "PK".
func NewDynamoDBRateLimiter(client DynamoDBAPI, tableName string, cfg Config) (*DynamoDBRateLimiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("DynamoDB client cannot be nil")
	}
	if tableName == "" {
		return nil, errors.New("tableName cannot be empty")
	}

	return &DynamoDBRateLimiter{
		client:    client,
		tableName: tableName,
		config:    cfg,
	}, nil
}

// Allow checks if a request should be allowed for the given key.
// Uses atomic DynamoDB UpdateItem to increment counters safely.
// Implements fail-open policy: DynamoDB errors return allowed=true with error logged.
func (r *DynamoDBRateLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	now := time.Now()
	windowStart := now.Truncate(r.config.Window)
	windowStartStr := windowStart.Format(time.RFC3339)
	// TTL = window end + 1 hour buffer for cleanup
	ttl := windowStart.Add(r.config.Window).Add(time.Hour).Unix()

	pk := "RL#" + key

	// Use UpdateItem with condition for atomic increment or window reset.
	// The condition checks if WindowStart matches current window - if so, increment Count.
	// If condition fails (window changed), we retry with window reset.
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
		},
		UpdateExpression: aws.String("SET #count = if_not_exists(#count, :zero) + :one, #ws = if_not_exists(#ws, :ws), #ttl = :ttl"),
		ConditionExpression: aws.String("attribute_not_exists(#ws) OR #ws = :ws"),
		ExpressionAttributeNames: map[string]string{
			"#count": "Count",
			"#ws":    "WindowStart",
			"#ttl":   "TTL",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":zero": &types.AttributeValueMemberN{Value: "0"},
			":one":  &types.AttributeValueMemberN{Value: "1"},
			":ws":   &types.AttributeValueMemberS{Value: windowStartStr},
			":ttl":  &types.AttributeValueMemberN{Value: strconv.FormatInt(ttl, 10)},
		},
		ReturnValues: types.ReturnValueAllNew,
	}

	output, err := r.client.UpdateItem(ctx, input)
	if err != nil {
		// Check for condition check failure - means window rolled over
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			// Window changed - retry with new window (reset count to 1)
			return r.resetAndIncrement(ctx, key, now)
		}
		// Other DynamoDB error - fail open with warning
		log.Printf("ratelimit: DynamoDB error (failing open): %v", err)
		return true, 0, err
	}

	// Parse count from response
	count := parseCount(output.Attributes["Count"])

	limit := r.config.EffectiveBurstSize()
	if count > limit {
		retryAfter := windowStart.Add(r.config.Window).Sub(now)
		return false, retryAfter, nil
	}

	return true, 0, nil
}

// resetAndIncrement handles window rollover by unconditionally setting Count=1 with new WindowStart.
// Called when the condition check fails because the window has changed.
func (r *DynamoDBRateLimiter) resetAndIncrement(ctx context.Context, key string, now time.Time) (bool, time.Duration, error) {
	windowStart := now.Truncate(r.config.Window)
	windowStartStr := windowStart.Format(time.RFC3339)
	ttl := windowStart.Add(r.config.Window).Add(time.Hour).Unix()

	pk := "RL#" + key

	// Unconditionally reset the window and set Count=1
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
		},
		UpdateExpression: aws.String("SET #count = :one, #ws = :ws, #ttl = :ttl"),
		ExpressionAttributeNames: map[string]string{
			"#count": "Count",
			"#ws":    "WindowStart",
			"#ttl":   "TTL",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one": &types.AttributeValueMemberN{Value: "1"},
			":ws":  &types.AttributeValueMemberS{Value: windowStartStr},
			":ttl": &types.AttributeValueMemberN{Value: strconv.FormatInt(ttl, 10)},
		},
		ReturnValues: types.ReturnValueAllNew,
	}

	output, err := r.client.UpdateItem(ctx, input)
	if err != nil {
		// DynamoDB error - fail open with warning
		log.Printf("ratelimit: DynamoDB error on reset (failing open): %v", err)
		return true, 0, err
	}

	// Parse count from response
	count := parseCount(output.Attributes["Count"])

	limit := r.config.EffectiveBurstSize()
	if count > limit {
		retryAfter := windowStart.Add(r.config.Window).Sub(now)
		return false, retryAfter, nil
	}

	return true, 0, nil
}

// parseCount extracts the count value from a DynamoDB attribute.
// Returns 0 if the attribute is nil or cannot be parsed.
func parseCount(attr types.AttributeValue) int {
	if attr == nil {
		return 0
	}
	n, ok := attr.(*types.AttributeValueMemberN)
	if !ok {
		return 0
	}
	count, err := strconv.Atoi(n.Value)
	if err != nil {
		return 0
	}
	return count
}

// Ensure DynamoDBRateLimiter implements RateLimiter interface.
var _ RateLimiter = (*DynamoDBRateLimiter)(nil)
