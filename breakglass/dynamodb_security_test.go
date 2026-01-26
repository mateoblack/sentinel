package breakglass

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

// TestSecurityRegression_CreateDuplicatePrevented verifies conditional writes
// prevent duplicate break-glass event creation.
func TestSecurityRegression_CreateDuplicatePrevented(t *testing.T) {
	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			if params.ConditionExpression == nil || *params.ConditionExpression != "attribute_not_exists(id)" {
				t.Error("SECURITY VIOLATION: Create() missing uniqueness condition")
			}
			return nil, &types.ConditionalCheckFailedException{Message: aws.String("exists")}
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	event := testEvent()

	err := store.Create(context.Background(), event)
	if !errors.Is(err, ErrEventExists) {
		t.Errorf("SECURITY VIOLATION: Create duplicate should return ErrEventExists, got: %v", err)
	}
}

// TestSecurityRegression_ConcurrentModificationDetected verifies optimistic locking.
func TestSecurityRegression_ConcurrentModificationDetected(t *testing.T) {
	now := time.Now().UTC()
	currentItem := &dynamoItem{
		ID:         "test-id",
		Invoker:    "alice",
		Profile:    "prod",
		ReasonCode: string(ReasonIncident),
		Status:     string(StatusActive),
		CreatedAt:  now.Format(time.RFC3339Nano),
		UpdatedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt:  now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	av, _ := attributevalue.MarshalMap(currentItem)

	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			if params.ConditionExpression == nil || !strings.Contains(*params.ConditionExpression, "updated_at") {
				t.Error("SECURITY VIOLATION: Update() missing optimistic locking condition")
			}
			return nil, &types.ConditionalCheckFailedException{Message: aws.String("modified")}
		},
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: av}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	event := testEvent()
	event.ID = "test-id"
	event.Status = StatusClosed // Valid transition from active
	event.UpdatedAt = now.Add(-time.Minute) // Stale timestamp

	err := store.Update(context.Background(), event)
	if !errors.Is(err, ErrConcurrentModification) {
		t.Errorf("SECURITY VIOLATION: Concurrent modification should be detected, got: %v", err)
	}
}

// TestSecurityRegression_InvalidStateTransitionPrevented verifies break-glass
// reactivation attacks are prevented.
func TestSecurityRegression_InvalidStateTransitionPrevented(t *testing.T) {
	testCases := []struct {
		name       string
		fromStatus BreakGlassStatus
		toStatus   BreakGlassStatus
		shouldFail bool
	}{
		// Valid transitions
		{"active_to_closed", StatusActive, StatusClosed, false},
		{"active_to_expired", StatusActive, StatusExpired, false},
		// Idempotent (same status)
		{"active_to_active", StatusActive, StatusActive, false},
		{"closed_to_closed", StatusClosed, StatusClosed, false},
		{"expired_to_expired", StatusExpired, StatusExpired, false},
		// Invalid transitions (reactivation attacks)
		{"closed_to_active", StatusClosed, StatusActive, true},
		{"expired_to_active", StatusExpired, StatusActive, true},
		{"closed_to_expired", StatusClosed, StatusExpired, true},
		{"expired_to_closed", StatusExpired, StatusClosed, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			currentItem := &dynamoItem{
				ID:         "test-id",
				Invoker:    "alice",
				Profile:    "prod",
				ReasonCode: string(ReasonIncident),
				Status:     string(tc.fromStatus),
				CreatedAt:  now.Format(time.RFC3339Nano),
				UpdatedAt:  now.Format(time.RFC3339Nano),
				ExpiresAt:  now.Add(time.Hour).Format(time.RFC3339Nano),
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
			event := &BreakGlassEvent{
				ID:            "test-id",
				Invoker:       "alice",
				Profile:       "prod",
				ReasonCode:    ReasonIncident,
				Justification: "test justification for break-glass",
				Duration:      time.Hour,
				Status:        tc.toStatus,
				CreatedAt:     now,
				UpdatedAt:     now,
				ExpiresAt:     now.Add(time.Hour),
			}

			err := store.Update(context.Background(), event)

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
		ID:         "test-id",
		Invoker:    "alice",
		Profile:    "prod",
		ReasonCode: string(ReasonIncident),
		Status:     string(StatusActive),
		CreatedAt:  originalTime.Format(time.RFC3339Nano),
		UpdatedAt:  originalTime.Format(time.RFC3339Nano),
		ExpiresAt:  originalTime.Add(2 * time.Hour).Format(time.RFC3339Nano),
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
	event := testEvent()
	event.ID = "test-id"
	event.UpdatedAt = originalTime // Simulate event read with this timestamp

	_ = store.Update(context.Background(), event)

	// The condition should use the ORIGINAL timestamp, not a new one
	expectedCondition := originalTime.Format(time.RFC3339Nano)
	if capturedConditionValue != expectedCondition {
		t.Errorf("SECURITY VIOLATION: Condition used %q instead of original %q - optimistic locking broken",
			capturedConditionValue, expectedCondition)
	}

	// The event's UpdatedAt should have been updated to a NEW value (not the original)
	if event.UpdatedAt.Equal(originalTime) {
		t.Error("SECURITY VIOLATION: Event UpdatedAt was not updated - writes would conflict")
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
	event := testEvent()

	_ = store.Create(context.Background(), event)

	if !conditionChecked {
		t.Error("SECURITY VIOLATION: PutItem was not called with condition check")
	}
}

// TestSecurityRegression_UpdateConditionExpressionPresent verifies Update() always
// includes the optimistic locking condition.
func TestSecurityRegression_UpdateConditionExpressionPresent(t *testing.T) {
	now := time.Now().UTC()
	currentItem := &dynamoItem{
		ID:         "test-id",
		Invoker:    "alice",
		Profile:    "prod",
		ReasonCode: string(ReasonIncident),
		Status:     string(StatusActive),
		CreatedAt:  now.Format(time.RFC3339Nano),
		UpdatedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt:  now.Add(time.Hour).Format(time.RFC3339Nano),
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
	event := testEvent()
	event.ID = "test-id"
	event.UpdatedAt = now

	_ = store.Update(context.Background(), event)

	if !conditionChecked {
		t.Error("SECURITY VIOLATION: PutItem was not called with condition check")
	}
}

// TestSecurityRegression_ReactivationAttackPrevented specifically tests that
// closed/expired break-glass events cannot be reactivated to gain unauthorized access.
func TestSecurityRegression_ReactivationAttackPrevented(t *testing.T) {
	// This is a high-severity attack: if an attacker can reactivate a closed
	// break-glass event, they can regain emergency access without going through
	// the proper break-glass invocation flow.

	terminalStatuses := []BreakGlassStatus{StatusClosed, StatusExpired}

	for _, fromStatus := range terminalStatuses {
		t.Run("reactivate_from_"+string(fromStatus), func(t *testing.T) {
			now := time.Now().UTC()
			currentItem := &dynamoItem{
				ID:         "test-id",
				Invoker:    "alice",
				Profile:    "prod",
				ReasonCode: string(ReasonIncident),
				Status:     string(fromStatus),
				CreatedAt:  now.Format(time.RFC3339Nano),
				UpdatedAt:  now.Format(time.RFC3339Nano),
				ExpiresAt:  now.Add(time.Hour).Format(time.RFC3339Nano),
			}
			av, _ := attributevalue.MarshalMap(currentItem)

			mock := &mockDynamoDBClient{
				getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
					return &dynamodb.GetItemOutput{Item: av}, nil
				},
				putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
					// This should never be called for an invalid transition
					t.Error("SECURITY VIOLATION: PutItem was called for reactivation attempt")
					return &dynamodb.PutItemOutput{}, nil
				},
			}

			store := newDynamoDBStoreWithClient(mock, "test-table")
			event := &BreakGlassEvent{
				ID:            "test-id",
				Invoker:       "alice",
				Profile:       "prod",
				ReasonCode:    ReasonIncident,
				Justification: "trying to reactivate",
				Duration:      time.Hour,
				Status:        StatusActive, // Attempting to reactivate
				CreatedAt:     now,
				UpdatedAt:     now,
				ExpiresAt:     now.Add(time.Hour),
			}

			err := store.Update(context.Background(), event)
			if !errors.Is(err, ErrInvalidStateTransition) {
				t.Errorf("SECURITY VIOLATION: Reactivation from %s should fail with ErrInvalidStateTransition, got: %v",
					fromStatus, err)
			}
		})
	}
}
