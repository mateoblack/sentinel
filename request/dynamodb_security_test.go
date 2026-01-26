package request

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// TestSecurityRegression_CreateDuplicatePrevented verifies that conditional writes
// prevent duplicate request creation attacks.
func TestSecurityRegression_CreateDuplicatePrevented(t *testing.T) {
	// Mock returns ConditionalCheckFailedException to simulate existing item
	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			// Verify condition expression is present
			if params.ConditionExpression == nil || *params.ConditionExpression != "attribute_not_exists(id)" {
				t.Error("SECURITY VIOLATION: Create() missing uniqueness condition")
			}
			return nil, &types.ConditionalCheckFailedException{Message: aws.String("exists")}
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	req := testRequest()

	err := store.Create(context.Background(), req)
	if !errors.Is(err, ErrRequestExists) {
		t.Errorf("SECURITY VIOLATION: Create duplicate should return ErrRequestExists, got: %v", err)
	}
}

// TestSecurityRegression_ConcurrentModificationDetected verifies optimistic locking
// prevents concurrent modification attacks.
func TestSecurityRegression_ConcurrentModificationDetected(t *testing.T) {
	now := time.Now().UTC()
	currentItem := &dynamoItem{
		ID:        "test-id",
		Requester: "alice",
		Profile:   "prod",
		Status:    string(StatusPending),
		CreatedAt: now.Format(time.RFC3339Nano),
		UpdatedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	av, _ := attributevalue.MarshalMap(currentItem)

	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			// Verify condition expression includes updated_at check
			if params.ConditionExpression == nil || !strings.Contains(*params.ConditionExpression, "updated_at") {
				t.Error("SECURITY VIOLATION: Update() missing optimistic locking condition")
			}
			return nil, &types.ConditionalCheckFailedException{Message: aws.String("modified")}
		},
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			// Return item exists (so it's concurrent modification, not not-found)
			return &dynamodb.GetItemOutput{Item: av}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	req := testRequest()
	req.ID = "test-id"
	req.Status = StatusApproved // Valid transition from pending
	req.UpdatedAt = now.Add(-time.Minute) // Stale timestamp

	err := store.Update(context.Background(), req)
	if !errors.Is(err, ErrConcurrentModification) {
		t.Errorf("SECURITY VIOLATION: Concurrent modification should be detected, got: %v", err)
	}
}

// TestSecurityRegression_InvalidStateTransitionPrevented verifies that invalid
// state transitions are rejected (e.g., approved -> pending).
func TestSecurityRegression_InvalidStateTransitionPrevented(t *testing.T) {
	testCases := []struct {
		name       string
		fromStatus RequestStatus
		toStatus   RequestStatus
		shouldFail bool
	}{
		// Valid transitions
		{"pending_to_approved", StatusPending, StatusApproved, false},
		{"pending_to_denied", StatusPending, StatusDenied, false},
		{"pending_to_expired", StatusPending, StatusExpired, false},
		{"pending_to_cancelled", StatusPending, StatusCancelled, false},
		// Idempotent (same status)
		{"pending_to_pending", StatusPending, StatusPending, false},
		{"approved_to_approved", StatusApproved, StatusApproved, false},
		// Invalid transitions (attack scenarios)
		{"approved_to_pending", StatusApproved, StatusPending, true},
		{"denied_to_approved", StatusDenied, StatusApproved, true},
		{"expired_to_approved", StatusExpired, StatusApproved, true},
		{"cancelled_to_pending", StatusCancelled, StatusPending, true},
		{"approved_to_denied", StatusApproved, StatusDenied, true},
		{"denied_to_pending", StatusDenied, StatusPending, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			currentItem := &dynamoItem{
				ID:        "test-id",
				Requester: "alice",
				Profile:   "prod",
				Status:    string(tc.fromStatus),
				CreatedAt: now.Format(time.RFC3339Nano),
				UpdatedAt: now.Format(time.RFC3339Nano),
				ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
			}
			av, _ := attributevalue.MarshalMap(currentItem)

			mock := &mockDynamoDBClient{
				getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
					return &dynamodb.GetItemOutput{Item: av}, nil
				},
				putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
					return &dynamodb.PutItemOutput{}, nil
				},
			}

			store := newDynamoDBStoreWithClient(mock, "test-table")
			req := &Request{
				ID:            "test-id",
				Requester:     "alice",
				Profile:       "prod",
				Justification: "test justification",
				Duration:      time.Hour,
				Status:        tc.toStatus,
				CreatedAt:     now,
				UpdatedAt:     now,
				ExpiresAt:     now.Add(time.Hour),
			}

			err := store.Update(context.Background(), req)

			if tc.shouldFail {
				if !errors.Is(err, ErrInvalidStateTransition) {
					t.Errorf("SECURITY VIOLATION: %s should be prevented, got: %v", tc.name, err)
				}
			} else {
				if errors.Is(err, ErrInvalidStateTransition) {
					t.Errorf("Valid transition %s incorrectly rejected: %v", tc.name, err)
				}
			}
		})
	}
}

// TestSecurityRegression_OptimisticLockingUsesOriginalTimestamp verifies that
// Update() properly saves the original UpdatedAt for the condition check.
func TestSecurityRegression_OptimisticLockingUsesOriginalTimestamp(t *testing.T) {
	originalTime := time.Now().UTC().Add(-time.Hour) // Original timestamp from "previous read"
	var capturedConditionValue string

	currentItem := &dynamoItem{
		ID:        "test-id",
		Requester: "alice",
		Profile:   "prod",
		Status:    string(StatusPending),
		CreatedAt: originalTime.Format(time.RFC3339Nano),
		UpdatedAt: originalTime.Format(time.RFC3339Nano),
		ExpiresAt: originalTime.Add(2 * time.Hour).Format(time.RFC3339Nano),
	}
	av, _ := attributevalue.MarshalMap(currentItem)

	mock := &mockDynamoDBClient{
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: av}, nil
		},
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			if params.ConditionExpression == nil || !strings.Contains(*params.ConditionExpression, "updated_at") {
				t.Error("SECURITY VIOLATION: Update() missing optimistic locking condition")
			}
			if val, ok := params.ExpressionAttributeValues[":old_updated_at"]; ok {
				if s, ok := val.(*types.AttributeValueMemberS); ok {
					capturedConditionValue = s.Value
				}
			}
			return &dynamodb.PutItemOutput{}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	req := testRequest()
	req.ID = "test-id"
	req.UpdatedAt = originalTime // Simulate request read with this timestamp

	_ = store.Update(context.Background(), req)

	// The condition should use the ORIGINAL timestamp, not a new one
	expectedCondition := originalTime.Format(time.RFC3339Nano)
	if capturedConditionValue != expectedCondition {
		t.Errorf("SECURITY VIOLATION: Condition used %q instead of original %q - optimistic locking broken",
			capturedConditionValue, expectedCondition)
	}

	// The request's UpdatedAt should have been updated to a NEW value (not the original)
	if req.UpdatedAt.Equal(originalTime) {
		t.Error("SECURITY VIOLATION: Request UpdatedAt was not updated - writes would conflict")
	}
}

// TestSecurityRegression_CreateConditionExpressionPresent verifies Create() always
// includes the attribute_not_exists condition.
func TestSecurityRegression_CreateConditionExpressionPresent(t *testing.T) {
	var conditionChecked bool
	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			if params.ConditionExpression == nil {
				t.Error("SECURITY VIOLATION: Create() has no ConditionExpression")
				return &dynamodb.PutItemOutput{}, nil
			}
			if *params.ConditionExpression != "attribute_not_exists(id)" {
				t.Errorf("SECURITY VIOLATION: Create() has wrong condition: %s", *params.ConditionExpression)
			}
			conditionChecked = true
			return &dynamodb.PutItemOutput{}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	req := testRequest()

	_ = store.Create(context.Background(), req)

	if !conditionChecked {
		t.Error("SECURITY VIOLATION: PutItem was not called with condition check")
	}
}

// TestSecurityRegression_UpdateConditionExpressionPresent verifies Update() always
// includes the optimistic locking condition.
func TestSecurityRegression_UpdateConditionExpressionPresent(t *testing.T) {
	now := time.Now().UTC()
	currentItem := &dynamoItem{
		ID:        "test-id",
		Requester: "alice",
		Profile:   "prod",
		Status:    string(StatusPending),
		CreatedAt: now.Format(time.RFC3339Nano),
		UpdatedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	av, _ := attributevalue.MarshalMap(currentItem)

	var conditionChecked bool
	mock := &mockDynamoDBClient{
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: av}, nil
		},
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			if params.ConditionExpression == nil {
				t.Error("SECURITY VIOLATION: Update() has no ConditionExpression")
				return &dynamodb.PutItemOutput{}, nil
			}
			expectedCondition := "attribute_exists(id) AND updated_at = :old_updated_at"
			if *params.ConditionExpression != expectedCondition {
				t.Errorf("SECURITY VIOLATION: Update() has wrong condition: got %q, want %q",
					*params.ConditionExpression, expectedCondition)
			}
			conditionChecked = true
			return &dynamodb.PutItemOutput{}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	req := testRequest()
	req.ID = "test-id"
	req.UpdatedAt = now

	_ = store.Update(context.Background(), req)

	if !conditionChecked {
		t.Error("SECURITY VIOLATION: PutItem was not called with condition check")
	}
}
