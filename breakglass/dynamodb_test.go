package breakglass

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// mockDynamoDBClient implements dynamoDBAPI for testing.
type mockDynamoDBClient struct {
	putItemFunc    func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	getItemFunc    func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	deleteItemFunc func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	queryFunc      func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
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

func (m *mockDynamoDBClient) Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, params, optFns...)
	}
	return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
}

// testEvent returns a valid BreakGlassEvent for testing.
func testEvent() *BreakGlassEvent {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	return &BreakGlassEvent{
		ID:            "abcdef1234567890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    ReasonIncident,
		Justification: "Production incident - database connection failures affecting customer orders",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
		ClosedBy:      "",
		ClosedReason:  "",
		RequestID:     "",
	}
}

func TestDynamoDBStore_Create_Success(t *testing.T) {
	var capturedInput *dynamodb.PutItemInput
	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			capturedInput = params
			return &dynamodb.PutItemOutput{}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	event := testEvent()

	err := store.Create(context.Background(), event)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify table name
	if *capturedInput.TableName != "test-table" {
		t.Errorf("TableName = %q, want %q", *capturedInput.TableName, "test-table")
	}

	// Verify condition expression for uniqueness
	if capturedInput.ConditionExpression == nil || *capturedInput.ConditionExpression != "attribute_not_exists(id)" {
		t.Errorf("ConditionExpression = %v, want %q", capturedInput.ConditionExpression, "attribute_not_exists(id)")
	}

	// Verify item contains expected ID
	if idAttr, ok := capturedInput.Item["id"].(*types.AttributeValueMemberS); !ok || idAttr.Value != event.ID {
		t.Errorf("Item[id] = %v, want %q", capturedInput.Item["id"], event.ID)
	}
}

func TestDynamoDBStore_Create_AlreadyExists(t *testing.T) {
	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			return nil, &types.ConditionalCheckFailedException{
				Message: stringPtr("The conditional request failed"),
			}
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	event := testEvent()

	err := store.Create(context.Background(), event)
	if err == nil {
		t.Fatal("Create() should return error for existing ID")
	}

	if !errors.Is(err, ErrEventExists) {
		t.Errorf("Create() error = %v, want error wrapping ErrEventExists", err)
	}
}

func TestDynamoDBStore_Get_Success(t *testing.T) {
	event := testEvent()
	item := eventToItem(event)
	av, _ := attributevalue.MarshalMap(item)

	mock := &mockDynamoDBClient{
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: av}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	got, err := store.Get(context.Background(), event.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Verify retrieved event matches
	if got.ID != event.ID {
		t.Errorf("Get().ID = %q, want %q", got.ID, event.ID)
	}
	if got.Invoker != event.Invoker {
		t.Errorf("Get().Invoker = %q, want %q", got.Invoker, event.Invoker)
	}
	if got.Profile != event.Profile {
		t.Errorf("Get().Profile = %q, want %q", got.Profile, event.Profile)
	}
	if got.Status != event.Status {
		t.Errorf("Get().Status = %q, want %q", got.Status, event.Status)
	}
	if got.ReasonCode != event.ReasonCode {
		t.Errorf("Get().ReasonCode = %q, want %q", got.ReasonCode, event.ReasonCode)
	}
}

func TestDynamoDBStore_Get_NotFound(t *testing.T) {
	mock := &mockDynamoDBClient{
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: nil}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	_, err := store.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("Get() should return error for non-existent ID")
	}

	if !errors.Is(err, ErrEventNotFound) {
		t.Errorf("Get() error = %v, want error wrapping ErrEventNotFound", err)
	}
}

func TestDynamoDBStore_Update_Success(t *testing.T) {
	event := testEvent()
	item := eventToItem(event)
	av, _ := attributevalue.MarshalMap(item)

	var capturedInput *dynamodb.PutItemInput
	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			capturedInput = params
			return &dynamodb.PutItemOutput{}, nil
		},
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: av}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	err := store.Update(context.Background(), event)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify optimistic locking condition
	if capturedInput.ConditionExpression == nil {
		t.Fatal("ConditionExpression should be set for optimistic locking")
	}
	if *capturedInput.ConditionExpression != "attribute_exists(id) AND updated_at = :old_updated_at" {
		t.Errorf("ConditionExpression = %q, want optimistic locking condition", *capturedInput.ConditionExpression)
	}
}

func TestDynamoDBStore_Update_NotFound(t *testing.T) {
	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			return nil, &types.ConditionalCheckFailedException{
				Message: stringPtr("The conditional request failed"),
			}
		},
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			// Item doesn't exist
			return &dynamodb.GetItemOutput{Item: nil}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	event := testEvent()

	err := store.Update(context.Background(), event)
	if err == nil {
		t.Fatal("Update() should return error for non-existent ID")
	}

	if !errors.Is(err, ErrEventNotFound) {
		t.Errorf("Update() error = %v, want error wrapping ErrEventNotFound", err)
	}
}

func TestDynamoDBStore_Update_ConcurrentModification(t *testing.T) {
	event := testEvent()
	// Create a different version of the item that exists in the store
	existingItem := eventToItem(event)
	av, _ := attributevalue.MarshalMap(existingItem)

	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			// Condition fails because updated_at doesn't match
			return nil, &types.ConditionalCheckFailedException{
				Message: stringPtr("The conditional request failed"),
			}
		},
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			// Item exists (so it's not a not-found error)
			return &dynamodb.GetItemOutput{Item: av}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	// Modify the event's updated_at to simulate reading old data
	event.UpdatedAt = event.UpdatedAt.Add(-time.Hour)

	err := store.Update(context.Background(), event)
	if err == nil {
		t.Fatal("Update() should return error for concurrent modification")
	}

	if !errors.Is(err, ErrConcurrentModification) {
		t.Errorf("Update() error = %v, want error wrapping ErrConcurrentModification", err)
	}
}

func TestDynamoDBStore_Delete_Success(t *testing.T) {
	var capturedInput *dynamodb.DeleteItemInput
	mock := &mockDynamoDBClient{
		deleteItemFunc: func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
			capturedInput = params
			return &dynamodb.DeleteItemOutput{}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	err := store.Delete(context.Background(), "abcdef1234567890")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify key is set correctly
	if idAttr, ok := capturedInput.Key["id"].(*types.AttributeValueMemberS); !ok || idAttr.Value != "abcdef1234567890" {
		t.Errorf("Key[id] = %v, want %q", capturedInput.Key["id"], "abcdef1234567890")
	}

	// Delete is idempotent - no condition expression
	if capturedInput.ConditionExpression != nil {
		t.Errorf("Delete should not have ConditionExpression for idempotency")
	}
}

func TestDynamoDBStore_Delete_Idempotent(t *testing.T) {
	// Delete of non-existent item should not error (idempotent)
	mock := &mockDynamoDBClient{
		deleteItemFunc: func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
			// DynamoDB returns success even if item doesn't exist
			return &dynamodb.DeleteItemOutput{}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	err := store.Delete(context.Background(), "nonexistent")
	if err != nil {
		t.Errorf("Delete() of non-existent item should not error: %v", err)
	}
}

func TestDynamoDBStore_Marshaling(t *testing.T) {
	// Create an event with all fields populated
	now := time.Now().UTC().Truncate(time.Nanosecond)
	original := &BreakGlassEvent{
		ID:            "deadbeef12345678",
		Invoker:       "bob",
		Profile:       "staging",
		ReasonCode:    ReasonSecurity,
		Justification: "Security incident - suspicious activity detected, need to investigate logs",
		Duration:      2*time.Hour + 30*time.Minute,
		Status:        StatusClosed,
		CreatedAt:     now,
		UpdatedAt:     now.Add(time.Hour),
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
		ClosedBy:      "charlie",
		ClosedReason:  "Incident resolved",
		RequestID:     "req-123456",
	}

	// Convert to item and back
	item := eventToItem(original)
	roundtripped, err := itemToEvent(item)
	if err != nil {
		t.Fatalf("itemToEvent() error = %v", err)
	}

	// Verify all fields match
	if roundtripped.ID != original.ID {
		t.Errorf("ID = %q, want %q", roundtripped.ID, original.ID)
	}
	if roundtripped.Invoker != original.Invoker {
		t.Errorf("Invoker = %q, want %q", roundtripped.Invoker, original.Invoker)
	}
	if roundtripped.Profile != original.Profile {
		t.Errorf("Profile = %q, want %q", roundtripped.Profile, original.Profile)
	}
	if roundtripped.ReasonCode != original.ReasonCode {
		t.Errorf("ReasonCode = %q, want %q", roundtripped.ReasonCode, original.ReasonCode)
	}
	if roundtripped.Justification != original.Justification {
		t.Errorf("Justification = %q, want %q", roundtripped.Justification, original.Justification)
	}
	if roundtripped.Duration != original.Duration {
		t.Errorf("Duration = %v, want %v", roundtripped.Duration, original.Duration)
	}
	if roundtripped.Status != original.Status {
		t.Errorf("Status = %q, want %q", roundtripped.Status, original.Status)
	}
	if !roundtripped.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", roundtripped.CreatedAt, original.CreatedAt)
	}
	if !roundtripped.UpdatedAt.Equal(original.UpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", roundtripped.UpdatedAt, original.UpdatedAt)
	}
	if !roundtripped.ExpiresAt.Equal(original.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", roundtripped.ExpiresAt, original.ExpiresAt)
	}
	if roundtripped.ClosedBy != original.ClosedBy {
		t.Errorf("ClosedBy = %q, want %q", roundtripped.ClosedBy, original.ClosedBy)
	}
	if roundtripped.ClosedReason != original.ClosedReason {
		t.Errorf("ClosedReason = %q, want %q", roundtripped.ClosedReason, original.ClosedReason)
	}
	if roundtripped.RequestID != original.RequestID {
		t.Errorf("RequestID = %q, want %q", roundtripped.RequestID, original.RequestID)
	}

	// Verify TTL is set correctly
	if item.TTL != original.ExpiresAt.Unix() {
		t.Errorf("TTL = %d, want %d (Unix timestamp of ExpiresAt)", item.TTL, original.ExpiresAt.Unix())
	}
}

func TestDynamoDBStore_Marshaling_EmptyOptionalFields(t *testing.T) {
	// Test with empty optional fields
	now := time.Now().UTC().Truncate(time.Nanosecond)
	original := &BreakGlassEvent{
		ID:            "abcdef1234567890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    ReasonIncident,
		Justification: "Production incident - service degradation",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
		ClosedBy:      "", // empty
		ClosedReason:  "", // empty
		RequestID:     "", // empty
	}

	item := eventToItem(original)
	roundtripped, err := itemToEvent(item)
	if err != nil {
		t.Fatalf("itemToEvent() error = %v", err)
	}

	if roundtripped.ClosedBy != "" {
		t.Errorf("ClosedBy = %q, want empty", roundtripped.ClosedBy)
	}
	if roundtripped.ClosedReason != "" {
		t.Errorf("ClosedReason = %q, want empty", roundtripped.ClosedReason)
	}
	if roundtripped.RequestID != "" {
		t.Errorf("RequestID = %q, want empty", roundtripped.RequestID)
	}
}

func TestDynamoDBStore_Create_DynamoDBError(t *testing.T) {
	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			return nil, errors.New("network error")
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	err := store.Create(context.Background(), testEvent())
	if err == nil {
		t.Fatal("Create() should return error on DynamoDB failure")
	}

	// Should NOT be ErrEventExists
	if errors.Is(err, ErrEventExists) {
		t.Error("Create() error should not be ErrEventExists for network error")
	}
}

func TestDynamoDBStore_Get_DynamoDBError(t *testing.T) {
	mock := &mockDynamoDBClient{
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return nil, errors.New("network error")
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	_, err := store.Get(context.Background(), "anyid")
	if err == nil {
		t.Fatal("Get() should return error on DynamoDB failure")
	}

	// Should NOT be ErrEventNotFound
	if errors.Is(err, ErrEventNotFound) {
		t.Error("Get() error should not be ErrEventNotFound for network error")
	}
}

func stringPtr(s string) *string {
	return &s
}

// TestDynamoDBStore_ListByInvoker_Success tests returning events for a user, newest first.
func TestDynamoDBStore_ListByInvoker_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	event1 := &BreakGlassEvent{
		ID:            "event001",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    ReasonIncident,
		Justification: "First incident - database issues",
		Duration:      time.Hour,
		Status:        StatusClosed,
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
	}
	event2 := &BreakGlassEvent{
		ID:            "event002",
		Invoker:       "alice",
		Profile:       "staging",
		ReasonCode:    ReasonMaintenance,
		Justification: "Second incident - emergency maintenance",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
	}

	item1, _ := attributevalue.MarshalMap(eventToItem(event1))
	item2, _ := attributevalue.MarshalMap(eventToItem(event2))

	var capturedInput *dynamodb.QueryInput
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			capturedInput = params
			// Return newest first (event2 before event1)
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{item2, item1}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	results, err := store.ListByInvoker(context.Background(), "alice", 10)
	if err != nil {
		t.Fatalf("ListByInvoker() error = %v", err)
	}

	// Verify query parameters
	if *capturedInput.IndexName != GSIInvoker {
		t.Errorf("IndexName = %q, want %q", *capturedInput.IndexName, GSIInvoker)
	}
	if *capturedInput.ScanIndexForward != false {
		t.Error("ScanIndexForward should be false for descending order")
	}
	if *capturedInput.Limit != 10 {
		t.Errorf("Limit = %d, want %d", *capturedInput.Limit, 10)
	}

	// Verify results
	if len(results) != 2 {
		t.Fatalf("ListByInvoker() returned %d results, want 2", len(results))
	}
	if results[0].ID != "event002" {
		t.Errorf("First result ID = %q, want %q (newest first)", results[0].ID, "event002")
	}
	if results[1].ID != "event001" {
		t.Errorf("Second result ID = %q, want %q", results[1].ID, "event001")
	}
}

// TestDynamoDBStore_ListByInvoker_Empty tests returning empty slice for unknown user.
func TestDynamoDBStore_ListByInvoker_Empty(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	results, err := store.ListByInvoker(context.Background(), "unknown-user", 10)
	if err != nil {
		t.Fatalf("ListByInvoker() error = %v", err)
	}

	if len(results) != 0 {
		t.Errorf("ListByInvoker() returned %d results, want 0 for unknown user", len(results))
	}
}

// TestDynamoDBStore_ListByStatus_Active tests returning active events for security review.
func TestDynamoDBStore_ListByStatus_Active(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	event := &BreakGlassEvent{
		ID:            "active001",
		Invoker:       "bob",
		Profile:       "production",
		ReasonCode:    ReasonSecurity,
		Justification: "Active security incident investigation",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
	}

	item, _ := attributevalue.MarshalMap(eventToItem(event))

	var capturedInput *dynamodb.QueryInput
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			capturedInput = params
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{item}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	results, err := store.ListByStatus(context.Background(), StatusActive, 50)
	if err != nil {
		t.Fatalf("ListByStatus() error = %v", err)
	}

	// Verify query parameters
	if *capturedInput.IndexName != GSIStatus {
		t.Errorf("IndexName = %q, want %q", *capturedInput.IndexName, GSIStatus)
	}
	// Verify the status value in expression attributes
	if v, ok := capturedInput.ExpressionAttributeValues[":v"].(*types.AttributeValueMemberS); !ok || v.Value != "active" {
		t.Errorf("ExpressionAttributeValues[:v] = %v, want %q", capturedInput.ExpressionAttributeValues[":v"], "active")
	}

	// Verify results
	if len(results) != 1 {
		t.Fatalf("ListByStatus() returned %d results, want 1", len(results))
	}
	if results[0].Status != StatusActive {
		t.Errorf("Result status = %q, want %q", results[0].Status, StatusActive)
	}
}

// TestDynamoDBStore_ListByStatus_Empty tests returning empty slice when no matching status.
func TestDynamoDBStore_ListByStatus_Empty(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	results, err := store.ListByStatus(context.Background(), StatusExpired, 10)
	if err != nil {
		t.Fatalf("ListByStatus() error = %v", err)
	}

	if len(results) != 0 {
		t.Errorf("ListByStatus() returned %d results, want 0 for status with no matches", len(results))
	}
}

// TestDynamoDBStore_ListByProfile_Success tests returning events for a profile.
func TestDynamoDBStore_ListByProfile_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	event := &BreakGlassEvent{
		ID:            "profile001",
		Invoker:       "charlie",
		Profile:       "production",
		ReasonCode:    ReasonRecovery,
		Justification: "Disaster recovery procedure underway",
		Duration:      time.Hour,
		Status:        StatusClosed,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
	}

	item, _ := attributevalue.MarshalMap(eventToItem(event))

	var capturedInput *dynamodb.QueryInput
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			capturedInput = params
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{item}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	results, err := store.ListByProfile(context.Background(), "production", 25)
	if err != nil {
		t.Fatalf("ListByProfile() error = %v", err)
	}

	// Verify query parameters
	if *capturedInput.IndexName != GSIProfile {
		t.Errorf("IndexName = %q, want %q", *capturedInput.IndexName, GSIProfile)
	}

	// Verify results
	if len(results) != 1 {
		t.Fatalf("ListByProfile() returned %d results, want 1", len(results))
	}
	if results[0].Profile != "production" {
		t.Errorf("Result profile = %q, want %q", results[0].Profile, "production")
	}
}

// TestDynamoDBStore_ListByProfile_Empty tests returning empty slice for unused profile.
func TestDynamoDBStore_ListByProfile_Empty(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	results, err := store.ListByProfile(context.Background(), "unused-profile", 10)
	if err != nil {
		t.Fatalf("ListByProfile() error = %v", err)
	}

	if len(results) != 0 {
		t.Errorf("ListByProfile() returned %d results, want 0 for unused profile", len(results))
	}
}

// TestDynamoDBStore_FindActiveByInvokerAndProfile_Found tests finding an active event.
func TestDynamoDBStore_FindActiveByInvokerAndProfile_Found(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	event := &BreakGlassEvent{
		ID:            "active001",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    ReasonIncident,
		Justification: "Active incident investigation in progress",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
	}

	item, _ := attributevalue.MarshalMap(eventToItem(event))

	var capturedInput *dynamodb.QueryInput
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			capturedInput = params
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{item}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	result, err := store.FindActiveByInvokerAndProfile(context.Background(), "alice", "production")
	if err != nil {
		t.Fatalf("FindActiveByInvokerAndProfile() error = %v", err)
	}

	// Verify query parameters
	if *capturedInput.IndexName != GSIInvoker {
		t.Errorf("IndexName = %q, want %q", *capturedInput.IndexName, GSIInvoker)
	}
	if capturedInput.FilterExpression == nil {
		t.Fatal("FilterExpression should be set")
	}
	if *capturedInput.FilterExpression != "profile = :profile AND #status = :status" {
		t.Errorf("FilterExpression = %q, want filter for profile and status", *capturedInput.FilterExpression)
	}

	// Verify result
	if result == nil {
		t.Fatal("FindActiveByInvokerAndProfile() returned nil, want event")
	}
	if result.ID != "active001" {
		t.Errorf("Result ID = %q, want %q", result.ID, "active001")
	}
	if result.Status != StatusActive {
		t.Errorf("Result Status = %q, want %q", result.Status, StatusActive)
	}
}

// TestDynamoDBStore_FindActiveByInvokerAndProfile_NotFound tests when no active event exists.
func TestDynamoDBStore_FindActiveByInvokerAndProfile_NotFound(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			// No matching events
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	result, err := store.FindActiveByInvokerAndProfile(context.Background(), "alice", "staging")
	if err != nil {
		t.Fatalf("FindActiveByInvokerAndProfile() error = %v", err)
	}

	if result != nil {
		t.Errorf("FindActiveByInvokerAndProfile() returned %v, want nil for no active event", result)
	}
}

// TestDynamoDBStore_FindActiveByInvokerAndProfile_DynamoDBError tests error handling.
func TestDynamoDBStore_FindActiveByInvokerAndProfile_DynamoDBError(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return nil, errors.New("network error")
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	_, err := store.FindActiveByInvokerAndProfile(context.Background(), "alice", "production")
	if err == nil {
		t.Fatal("FindActiveByInvokerAndProfile() should return error on DynamoDB failure")
	}
}

// TestDynamoDBStore_QueryLimit tests limit parameter handling.
func TestDynamoDBStore_QueryLimit(t *testing.T) {
	tests := []struct {
		name          string
		inputLimit    int
		expectedLimit int32
	}{
		{"zero uses default", 0, int32(DefaultQueryLimit)},
		{"positive uses value", 50, 50},
		{"exceeds max gets capped", 2000, int32(MaxQueryLimit)},
		{"negative uses default", -5, int32(DefaultQueryLimit)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedLimit int32
			mock := &mockDynamoDBClient{
				queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
					capturedLimit = *params.Limit
					return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
				},
			}

			store := newDynamoDBStoreWithClient(mock, "test-table")

			_, err := store.ListByInvoker(context.Background(), "user", tt.inputLimit)
			if err != nil {
				t.Fatalf("ListByInvoker() error = %v", err)
			}

			if capturedLimit != tt.expectedLimit {
				t.Errorf("Limit = %d, want %d", capturedLimit, tt.expectedLimit)
			}
		})
	}
}

// TestDynamoDBStore_Query_DynamoDBError tests error handling for query operations.
func TestDynamoDBStore_Query_DynamoDBError(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return nil, errors.New("network error")
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	_, err := store.ListByInvoker(context.Background(), "user", 10)
	if err == nil {
		t.Fatal("ListByInvoker() should return error on DynamoDB failure")
	}
}

// TestDynamoDBStore_CountByInvokerSince_Success tests counting events for a user within a time window.
func TestDynamoDBStore_CountByInvokerSince_Success(t *testing.T) {
	var capturedInput *dynamodb.QueryInput
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			capturedInput = params
			return &dynamodb.QueryOutput{Count: 3}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	since := time.Now().Add(-24 * time.Hour)

	count, err := store.CountByInvokerSince(context.Background(), "alice", since)
	if err != nil {
		t.Fatalf("CountByInvokerSince() error = %v", err)
	}

	// Verify query parameters
	if *capturedInput.IndexName != GSIInvoker {
		t.Errorf("IndexName = %q, want %q", *capturedInput.IndexName, GSIInvoker)
	}
	if capturedInput.Select != types.SelectCount {
		t.Errorf("Select = %v, want %v for efficient counting", capturedInput.Select, types.SelectCount)
	}
	if capturedInput.FilterExpression == nil || *capturedInput.FilterExpression != "created_at >= :since" {
		t.Errorf("FilterExpression = %v, want filter for created_at >= :since", capturedInput.FilterExpression)
	}

	// Verify result
	if count != 3 {
		t.Errorf("CountByInvokerSince() = %d, want 3", count)
	}
}

// TestDynamoDBStore_CountByInvokerSince_Empty tests returning zero for no matching events.
func TestDynamoDBStore_CountByInvokerSince_Empty(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Count: 0}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	since := time.Now().Add(-time.Hour)

	count, err := store.CountByInvokerSince(context.Background(), "unknown-user", since)
	if err != nil {
		t.Fatalf("CountByInvokerSince() error = %v", err)
	}

	if count != 0 {
		t.Errorf("CountByInvokerSince() = %d, want 0 for no matches", count)
	}
}

// TestDynamoDBStore_CountByInvokerSince_Error tests error handling.
func TestDynamoDBStore_CountByInvokerSince_Error(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return nil, errors.New("network error")
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	_, err := store.CountByInvokerSince(context.Background(), "alice", time.Now())
	if err == nil {
		t.Fatal("CountByInvokerSince() should return error on DynamoDB failure")
	}
}

// TestDynamoDBStore_CountByProfileSince_Success tests counting events for a profile within a time window.
func TestDynamoDBStore_CountByProfileSince_Success(t *testing.T) {
	var capturedInput *dynamodb.QueryInput
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			capturedInput = params
			return &dynamodb.QueryOutput{Count: 5}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	since := time.Now().Add(-24 * time.Hour)

	count, err := store.CountByProfileSince(context.Background(), "production", since)
	if err != nil {
		t.Fatalf("CountByProfileSince() error = %v", err)
	}

	// Verify query parameters
	if *capturedInput.IndexName != GSIProfile {
		t.Errorf("IndexName = %q, want %q", *capturedInput.IndexName, GSIProfile)
	}
	if capturedInput.Select != types.SelectCount {
		t.Errorf("Select = %v, want %v for efficient counting", capturedInput.Select, types.SelectCount)
	}

	// Verify result
	if count != 5 {
		t.Errorf("CountByProfileSince() = %d, want 5", count)
	}
}

// TestDynamoDBStore_CountByProfileSince_Empty tests returning zero for no matching events.
func TestDynamoDBStore_CountByProfileSince_Empty(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Count: 0}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")
	since := time.Now().Add(-time.Hour)

	count, err := store.CountByProfileSince(context.Background(), "unused-profile", since)
	if err != nil {
		t.Fatalf("CountByProfileSince() error = %v", err)
	}

	if count != 0 {
		t.Errorf("CountByProfileSince() = %d, want 0 for no matches", count)
	}
}

// TestDynamoDBStore_CountByProfileSince_Error tests error handling.
func TestDynamoDBStore_CountByProfileSince_Error(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return nil, errors.New("network error")
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	_, err := store.CountByProfileSince(context.Background(), "production", time.Now())
	if err == nil {
		t.Fatal("CountByProfileSince() should return error on DynamoDB failure")
	}
}

// TestDynamoDBStore_GetLastByInvokerAndProfile_Found tests returning the most recent event.
func TestDynamoDBStore_GetLastByInvokerAndProfile_Found(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	event := &BreakGlassEvent{
		ID:            "newest001",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    ReasonIncident,
		Justification: "Most recent break-glass event for cooldown check",
		Duration:      time.Hour,
		Status:        StatusClosed,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
	}

	item, _ := attributevalue.MarshalMap(eventToItem(event))

	var capturedInput *dynamodb.QueryInput
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			capturedInput = params
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{item}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	result, err := store.GetLastByInvokerAndProfile(context.Background(), "alice", "production")
	if err != nil {
		t.Fatalf("GetLastByInvokerAndProfile() error = %v", err)
	}

	// Verify query parameters
	if *capturedInput.IndexName != GSIInvoker {
		t.Errorf("IndexName = %q, want %q", *capturedInput.IndexName, GSIInvoker)
	}
	if *capturedInput.ScanIndexForward != false {
		t.Error("ScanIndexForward should be false for newest first")
	}
	if *capturedInput.Limit != 1 {
		t.Errorf("Limit = %d, want 1 for getting last event only", *capturedInput.Limit)
	}
	if capturedInput.FilterExpression == nil || *capturedInput.FilterExpression != "profile = :profile" {
		t.Errorf("FilterExpression = %v, want filter for profile", capturedInput.FilterExpression)
	}

	// Verify result
	if result == nil {
		t.Fatal("GetLastByInvokerAndProfile() returned nil, want event")
	}
	if result.ID != "newest001" {
		t.Errorf("Result ID = %q, want %q", result.ID, "newest001")
	}
}

// TestDynamoDBStore_GetLastByInvokerAndProfile_NotFound tests returning nil when no events exist.
func TestDynamoDBStore_GetLastByInvokerAndProfile_NotFound(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	result, err := store.GetLastByInvokerAndProfile(context.Background(), "alice", "staging")
	if err != nil {
		t.Fatalf("GetLastByInvokerAndProfile() error = %v", err)
	}

	if result != nil {
		t.Errorf("GetLastByInvokerAndProfile() = %v, want nil for no events", result)
	}
}

// TestDynamoDBStore_GetLastByInvokerAndProfile_Error tests error handling.
func TestDynamoDBStore_GetLastByInvokerAndProfile_Error(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return nil, errors.New("network error")
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	_, err := store.GetLastByInvokerAndProfile(context.Background(), "alice", "production")
	if err == nil {
		t.Fatal("GetLastByInvokerAndProfile() should return error on DynamoDB failure")
	}
}
