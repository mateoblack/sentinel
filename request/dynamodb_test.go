package request

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

// testRequest returns a valid Request for testing.
func testRequest() *Request {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	return &Request{
		ID:              "abcdef1234567890",
		Requester:       "alice",
		Profile:         "production",
		Justification:   "Need access for deployment review",
		Duration:        time.Hour,
		Status:          StatusPending,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       now.Add(DefaultRequestTTL),
		Approver:        "",
		ApproverComment: "",
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
	req := testRequest()

	err := store.Create(context.Background(), req)
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
	if idAttr, ok := capturedInput.Item["id"].(*types.AttributeValueMemberS); !ok || idAttr.Value != req.ID {
		t.Errorf("Item[id] = %v, want %q", capturedInput.Item["id"], req.ID)
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
	req := testRequest()

	err := store.Create(context.Background(), req)
	if err == nil {
		t.Fatal("Create() should return error for existing ID")
	}

	if !errors.Is(err, ErrRequestExists) {
		t.Errorf("Create() error = %v, want error wrapping ErrRequestExists", err)
	}
}

func TestDynamoDBStore_Get_Success(t *testing.T) {
	req := testRequest()
	item := requestToItem(req)
	av, _ := attributevalue.MarshalMap(item)

	mock := &mockDynamoDBClient{
		getItemFunc: func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: av}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	got, err := store.Get(context.Background(), req.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Verify retrieved request matches
	if got.ID != req.ID {
		t.Errorf("Get().ID = %q, want %q", got.ID, req.ID)
	}
	if got.Requester != req.Requester {
		t.Errorf("Get().Requester = %q, want %q", got.Requester, req.Requester)
	}
	if got.Profile != req.Profile {
		t.Errorf("Get().Profile = %q, want %q", got.Profile, req.Profile)
	}
	if got.Status != req.Status {
		t.Errorf("Get().Status = %q, want %q", got.Status, req.Status)
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

	if !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("Get() error = %v, want error wrapping ErrRequestNotFound", err)
	}
}

func TestDynamoDBStore_Update_Success(t *testing.T) {
	req := testRequest()
	item := requestToItem(req)
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

	err := store.Update(context.Background(), req)
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
	req := testRequest()

	err := store.Update(context.Background(), req)
	if err == nil {
		t.Fatal("Update() should return error for non-existent ID")
	}

	if !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("Update() error = %v, want error wrapping ErrRequestNotFound", err)
	}
}

func TestDynamoDBStore_Update_ConcurrentModification(t *testing.T) {
	req := testRequest()
	// Create a different version of the item that exists in the store
	existingItem := requestToItem(req)
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

	// Modify the request's updated_at to simulate reading old data
	req.UpdatedAt = req.UpdatedAt.Add(-time.Hour)

	err := store.Update(context.Background(), req)
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
	// Create a request with all fields populated
	now := time.Now().UTC().Truncate(time.Nanosecond)
	original := &Request{
		ID:              "deadbeef12345678",
		Requester:       "bob",
		Profile:         "staging",
		Justification:   "Testing marshaling roundtrip",
		Duration:        2*time.Hour + 30*time.Minute,
		Status:          StatusApproved,
		CreatedAt:       now,
		UpdatedAt:       now.Add(time.Hour),
		ExpiresAt:       now.Add(DefaultRequestTTL),
		Approver:        "charlie",
		ApproverComment: "Approved for testing",
	}

	// Convert to item and back
	item := requestToItem(original)
	roundtripped, err := itemToRequest(item)
	if err != nil {
		t.Fatalf("itemToRequest() error = %v", err)
	}

	// Verify all fields match
	if roundtripped.ID != original.ID {
		t.Errorf("ID = %q, want %q", roundtripped.ID, original.ID)
	}
	if roundtripped.Requester != original.Requester {
		t.Errorf("Requester = %q, want %q", roundtripped.Requester, original.Requester)
	}
	if roundtripped.Profile != original.Profile {
		t.Errorf("Profile = %q, want %q", roundtripped.Profile, original.Profile)
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
	if roundtripped.Approver != original.Approver {
		t.Errorf("Approver = %q, want %q", roundtripped.Approver, original.Approver)
	}
	if roundtripped.ApproverComment != original.ApproverComment {
		t.Errorf("ApproverComment = %q, want %q", roundtripped.ApproverComment, original.ApproverComment)
	}

	// Verify TTL is set correctly
	if item.TTL != original.ExpiresAt.Unix() {
		t.Errorf("TTL = %d, want %d (Unix timestamp of ExpiresAt)", item.TTL, original.ExpiresAt.Unix())
	}
}

func TestDynamoDBStore_Marshaling_EmptyOptionalFields(t *testing.T) {
	// Test with empty optional fields
	now := time.Now().UTC().Truncate(time.Nanosecond)
	original := &Request{
		ID:              "abcdef1234567890",
		Requester:       "alice",
		Profile:         "production",
		Justification:   "Testing with empty optional fields",
		Duration:        time.Hour,
		Status:          StatusPending,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       now.Add(DefaultRequestTTL),
		Approver:        "", // empty
		ApproverComment: "", // empty
	}

	item := requestToItem(original)
	roundtripped, err := itemToRequest(item)
	if err != nil {
		t.Fatalf("itemToRequest() error = %v", err)
	}

	if roundtripped.Approver != "" {
		t.Errorf("Approver = %q, want empty", roundtripped.Approver)
	}
	if roundtripped.ApproverComment != "" {
		t.Errorf("ApproverComment = %q, want empty", roundtripped.ApproverComment)
	}
}

func TestDynamoDBStore_Create_DynamoDBError(t *testing.T) {
	mock := &mockDynamoDBClient{
		putItemFunc: func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			return nil, errors.New("network error")
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	err := store.Create(context.Background(), testRequest())
	if err == nil {
		t.Fatal("Create() should return error on DynamoDB failure")
	}

	// Should NOT be ErrRequestExists
	if errors.Is(err, ErrRequestExists) {
		t.Error("Create() error should not be ErrRequestExists for network error")
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

	// Should NOT be ErrRequestNotFound
	if errors.Is(err, ErrRequestNotFound) {
		t.Error("Get() error should not be ErrRequestNotFound for network error")
	}
}

func stringPtr(s string) *string {
	return &s
}
