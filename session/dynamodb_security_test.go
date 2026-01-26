package session

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

// mockDynamoDBClient implements dynamoDBAPI for testing.
type mockDynamoDBClient struct {
	putItemFunc    func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	getItemFunc    func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	deleteItemFunc func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	updateItemFunc func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	queryFunc      func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	scanFunc       func(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

func (m *mockDynamoDBClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if m.putItemFunc != nil {
		return m.putItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.PutItemOutput{}, nil
}

func (m *mockDynamoDBClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if m.getItemFunc != nil {
		return m.getItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.GetItemOutput{}, nil
}

func (m *mockDynamoDBClient) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	if m.deleteItemFunc != nil {
		return m.deleteItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.DeleteItemOutput{}, nil
}

func (m *mockDynamoDBClient) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if m.updateItemFunc != nil {
		return m.updateItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

func (m *mockDynamoDBClient) Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, params, optFns...)
	}
	return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
}

func (m *mockDynamoDBClient) Scan(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	if m.scanFunc != nil {
		return m.scanFunc(ctx, params, optFns...)
	}
	return &dynamodb.ScanOutput{Items: []map[string]types.AttributeValue{}}, nil
}

// testSession returns a valid ServerSession for testing.
func testSession() *ServerSession {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	return &ServerSession{
		ID:               "a1b2c3d4e5f67890",
		User:             "alice",
		Profile:          "production",
		ServerInstanceID: "server123",
		Status:           StatusActive,
		StartedAt:        now,
		LastAccessAt:     now,
		ExpiresAt:        now.Add(15 * time.Minute),
		RequestCount:     0,
		SourceIdentity:   "alice@example.com",
		DeviceID:         "device123",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// TestSecurityRegression_CreateDuplicatePrevented verifies conditional writes
// prevent duplicate session creation attacks.
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
	session := testSession()

	err := store.Create(context.Background(), session)
	if !errors.Is(err, ErrSessionExists) {
		t.Errorf("SECURITY VIOLATION: Create duplicate should return ErrSessionExists, got: %v", err)
	}
}

// TestSecurityRegression_ConcurrentModificationDetected verifies optimistic locking.
func TestSecurityRegression_ConcurrentModificationDetected(t *testing.T) {
	now := time.Now().UTC()
	currentItem := &dynamoItem{
		ID:               "test-id",
		User:             "alice",
		Profile:          "prod",
		ServerInstanceID: "server123",
		Status:           string(StatusActive),
		StartedAt:        now.Format(time.RFC3339Nano),
		LastAccessAt:     now.Format(time.RFC3339Nano),
		ExpiresAt:        now.Add(15 * time.Minute).Format(time.RFC3339Nano),
		CreatedAt:        now.Format(time.RFC3339Nano),
		UpdatedAt:        now.Format(time.RFC3339Nano),
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
	session := testSession()
	session.ID = "test-id"
	session.UpdatedAt = now.Add(-time.Minute) // Stale timestamp

	err := store.Update(context.Background(), session)
	if !errors.Is(err, ErrConcurrentModification) {
		t.Errorf("SECURITY VIOLATION: Concurrent modification should be detected, got: %v", err)
	}
}

// TestSecurityRegression_OptimisticLockingUsesOriginalTimestamp verifies that
// Update() properly saves the original UpdatedAt for the condition check.
// This specifically tests the fix from Plan 01.
func TestSecurityRegression_OptimisticLockingUsesOriginalTimestamp(t *testing.T) {
	originalTime := time.Now().UTC().Add(-time.Hour) // Original timestamp from "previous read"
	var capturedConditionValue string

	currentItem := &dynamoItem{
		ID:               "test-id",
		User:             "alice",
		Profile:          "prod",
		ServerInstanceID: "server123",
		Status:           string(StatusActive),
		StartedAt:        originalTime.Format(time.RFC3339Nano),
		LastAccessAt:     originalTime.Format(time.RFC3339Nano),
		ExpiresAt:        originalTime.Add(2 * time.Hour).Format(time.RFC3339Nano),
		CreatedAt:        originalTime.Format(time.RFC3339Nano),
		UpdatedAt:        originalTime.Format(time.RFC3339Nano),
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
	session := testSession()
	session.ID = "test-id"
	session.UpdatedAt = originalTime // Simulate session read with this timestamp

	_ = store.Update(context.Background(), session)

	// The condition should use the ORIGINAL timestamp, not a new one
	expectedCondition := originalTime.Format(time.RFC3339Nano)
	if capturedConditionValue != expectedCondition {
		t.Errorf("SECURITY VIOLATION: Condition used %q instead of original %q - optimistic locking broken",
			capturedConditionValue, expectedCondition)
	}

	// The session's UpdatedAt should have been updated to a NEW value (not the original)
	if session.UpdatedAt.Equal(originalTime) {
		t.Error("SECURITY VIOLATION: Session UpdatedAt was not updated - writes would conflict")
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
	session := testSession()

	_ = store.Create(context.Background(), session)

	if !conditionChecked {
		t.Error("SECURITY VIOLATION: PutItem was not called with condition check")
	}
}

// TestSecurityRegression_UpdateConditionExpressionPresent verifies Update() always
// includes the optimistic locking condition.
func TestSecurityRegression_UpdateConditionExpressionPresent(t *testing.T) {
	now := time.Now().UTC()
	currentItem := &dynamoItem{
		ID:               "test-id",
		User:             "alice",
		Profile:          "prod",
		ServerInstanceID: "server123",
		Status:           string(StatusActive),
		StartedAt:        now.Format(time.RFC3339Nano),
		LastAccessAt:     now.Format(time.RFC3339Nano),
		ExpiresAt:        now.Add(15 * time.Minute).Format(time.RFC3339Nano),
		CreatedAt:        now.Format(time.RFC3339Nano),
		UpdatedAt:        now.Format(time.RFC3339Nano),
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
	session := testSession()
	session.ID = "test-id"
	session.UpdatedAt = now

	_ = store.Update(context.Background(), session)

	if !conditionChecked {
		t.Error("SECURITY VIOLATION: PutItem was not called with condition check")
	}
}

// TestSecurityRegression_TouchConditionExpressionPresent verifies Touch() always
// includes the attribute_exists condition.
func TestSecurityRegression_TouchConditionExpressionPresent(t *testing.T) {
	var conditionChecked bool
	mock := &mockDynamoDBClient{
		updateItemFunc: func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
			if params.ConditionExpression == nil {
				t.Error("SECURITY VIOLATION: Touch() has no ConditionExpression")
				return &dynamodb.UpdateItemOutput{}, nil
			}
			if *params.ConditionExpression != "attribute_exists(id)" {
				t.Errorf("SECURITY VIOLATION: Touch() has wrong condition: %s", *params.ConditionExpression)
			}
			conditionChecked = true
			return &dynamodb.UpdateItemOutput{}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	_ = store.Touch(context.Background(), "test-id")

	if !conditionChecked {
		t.Error("SECURITY VIOLATION: UpdateItem was not called with condition check")
	}
}

// TestSecurityRegression_TouchNotFoundReturnsError verifies Touch() returns
// ErrSessionNotFound when session doesn't exist.
func TestSecurityRegression_TouchNotFoundReturnsError(t *testing.T) {
	mock := &mockDynamoDBClient{
		updateItemFunc: func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
			return nil, &types.ConditionalCheckFailedException{Message: aws.String("not found")}
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	err := store.Touch(context.Background(), "nonexistent-id")

	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("SECURITY VIOLATION: Touch() should return ErrSessionNotFound, got: %v", err)
	}
}

// TestSecurityRegression_SessionStatusValidation verifies that only valid
// session statuses are accepted.
func TestSecurityRegression_SessionStatusValidation(t *testing.T) {
	testCases := []struct {
		status  SessionStatus
		isValid bool
	}{
		{StatusActive, true},
		{StatusRevoked, true},
		{StatusExpired, true},
		{"", false},
		{"Active", false},          // Case-sensitive
		{"ACTIVE", false},          // Case-sensitive
		{"pending", false},         // Not a valid session status
		{"approved", false},        // Not a valid session status
		{"active ", false},         // Trailing space
		{" active", false},         // Leading space
		{"active\x00", false},      // Null byte
		{"'; DROP TABLE;--", false}, // SQL injection
	}

	for _, tc := range testCases {
		t.Run(string(tc.status), func(t *testing.T) {
			if tc.status.IsValid() != tc.isValid {
				if tc.isValid {
					t.Errorf("SECURITY VIOLATION: Status %q should be valid", tc.status)
				} else {
					t.Errorf("SECURITY VIOLATION: Status %q should be invalid", tc.status)
				}
			}
		})
	}
}

// TestSecurityRegression_SessionTerminalStatus verifies terminal status detection.
func TestSecurityRegression_SessionTerminalStatus(t *testing.T) {
	testCases := []struct {
		status     SessionStatus
		isTerminal bool
	}{
		{StatusActive, false},
		{StatusRevoked, true},
		{StatusExpired, true},
	}

	for _, tc := range testCases {
		t.Run(string(tc.status), func(t *testing.T) {
			if tc.status.IsTerminal() != tc.isTerminal {
				if tc.isTerminal {
					t.Errorf("SECURITY VIOLATION: Status %q should be terminal", tc.status)
				} else {
					t.Errorf("SECURITY VIOLATION: Status %q should not be terminal", tc.status)
				}
			}
		})
	}
}

// TestSecurityRegression_FindActiveByServerInstanceFilterActive verifies that
// FindActiveByServerInstance only returns active sessions.
func TestSecurityRegression_FindActiveByServerInstanceFilterActive(t *testing.T) {
	var capturedFilterExpression string
	var capturedExpressionValues map[string]types.AttributeValue

	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			if params.FilterExpression != nil {
				capturedFilterExpression = *params.FilterExpression
			}
			capturedExpressionValues = params.ExpressionAttributeValues
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	_, _ = store.FindActiveByServerInstance(context.Background(), "server123")

	// Verify filter expression filters for active status
	if !strings.Contains(capturedFilterExpression, "status") {
		t.Error("SECURITY VIOLATION: FindActiveByServerInstance() should filter by status")
	}

	// Verify status value is "active"
	if statusAttr, ok := capturedExpressionValues[":status"]; ok {
		if s, ok := statusAttr.(*types.AttributeValueMemberS); ok {
			if s.Value != string(StatusActive) {
				t.Errorf("SECURITY VIOLATION: FindActiveByServerInstance() filters for %q instead of %q",
					s.Value, StatusActive)
			}
		}
	}
}

// TestSecurityRegression_SessionIDValidation verifies that session ID format
// is properly validated.
func TestSecurityRegression_SessionIDValidation(t *testing.T) {
	testCases := []struct {
		id      string
		isValid bool
	}{
		{"a1b2c3d4e5f67890", true},  // Valid 16 hex lowercase
		{"0000000000000000", true},  // Valid all zeros
		{"aaaaaaaaaaaaaaaa", true},  // Valid all a's
		{"A1B2C3D4E5F67890", false}, // Uppercase (invalid)
		{"a1b2c3d4e5f6789", false},  // Too short (15 chars)
		{"a1b2c3d4e5f678901", false}, // Too long (17 chars)
		{"a1b2c3d4e5f6789g", false}, // Invalid character g
		{"", false},                 // Empty
		{"a1b2c3d4-5f67890", false}, // Contains dash
		{"a1b2c3d4 5f67890", false}, // Contains space
	}

	for _, tc := range testCases {
		t.Run(tc.id, func(t *testing.T) {
			if ValidateSessionID(tc.id) != tc.isValid {
				if tc.isValid {
					t.Errorf("SECURITY VIOLATION: Session ID %q should be valid", tc.id)
				} else {
					t.Errorf("SECURITY VIOLATION: Session ID %q should be invalid", tc.id)
				}
			}
		})
	}
}
