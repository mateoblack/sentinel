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

// TestDynamoDBStore_ListByRequester_Success tests returning requests for a user, newest first.
func TestDynamoDBStore_ListByRequester_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	req1 := &Request{
		ID:            "req001",
		Requester:     "alice",
		Profile:       "production",
		Justification: "First request",
		Duration:      time.Hour,
		Status:        StatusPending,
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
		ExpiresAt:     now.Add(DefaultRequestTTL),
	}
	req2 := &Request{
		ID:            "req002",
		Requester:     "alice",
		Profile:       "staging",
		Justification: "Second request",
		Duration:      time.Hour,
		Status:        StatusApproved,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultRequestTTL),
	}

	item1, _ := attributevalue.MarshalMap(requestToItem(req1))
	item2, _ := attributevalue.MarshalMap(requestToItem(req2))

	var capturedInput *dynamodb.QueryInput
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			capturedInput = params
			// Return newest first (req2 before req1)
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{item2, item1}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	results, err := store.ListByRequester(context.Background(), "alice", 10)
	if err != nil {
		t.Fatalf("ListByRequester() error = %v", err)
	}

	// Verify query parameters
	if *capturedInput.IndexName != GSIRequester {
		t.Errorf("IndexName = %q, want %q", *capturedInput.IndexName, GSIRequester)
	}
	if *capturedInput.KeyConditionExpression != "requester = :v" {
		t.Errorf("KeyConditionExpression = %q, want %q", *capturedInput.KeyConditionExpression, "requester = :v")
	}
	if *capturedInput.ScanIndexForward != false {
		t.Error("ScanIndexForward should be false for descending order")
	}
	if *capturedInput.Limit != 10 {
		t.Errorf("Limit = %d, want %d", *capturedInput.Limit, 10)
	}

	// Verify results
	if len(results) != 2 {
		t.Fatalf("ListByRequester() returned %d results, want 2", len(results))
	}
	if results[0].ID != "req002" {
		t.Errorf("First result ID = %q, want %q (newest first)", results[0].ID, "req002")
	}
	if results[1].ID != "req001" {
		t.Errorf("Second result ID = %q, want %q", results[1].ID, "req001")
	}
}

// TestDynamoDBStore_ListByRequester_Empty tests returning empty slice for unknown user.
func TestDynamoDBStore_ListByRequester_Empty(t *testing.T) {
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	results, err := store.ListByRequester(context.Background(), "unknown-user", 10)
	if err != nil {
		t.Fatalf("ListByRequester() error = %v", err)
	}

	if len(results) != 0 {
		t.Errorf("ListByRequester() returned %d results, want 0 for unknown user", len(results))
	}
}

// TestDynamoDBStore_ListByStatus_Pending tests returning pending requests for approver view.
func TestDynamoDBStore_ListByStatus_Pending(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	req := &Request{
		ID:            "pending001",
		Requester:     "bob",
		Profile:       "production",
		Justification: "Pending request",
		Duration:      time.Hour,
		Status:        StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultRequestTTL),
	}

	item, _ := attributevalue.MarshalMap(requestToItem(req))

	var capturedInput *dynamodb.QueryInput
	mock := &mockDynamoDBClient{
		queryFunc: func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
			capturedInput = params
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{item}}, nil
		},
	}

	store := newDynamoDBStoreWithClient(mock, "test-table")

	results, err := store.ListByStatus(context.Background(), StatusPending, 50)
	if err != nil {
		t.Fatalf("ListByStatus() error = %v", err)
	}

	// Verify query parameters
	if *capturedInput.IndexName != GSIStatus {
		t.Errorf("IndexName = %q, want %q", *capturedInput.IndexName, GSIStatus)
	}
	if *capturedInput.KeyConditionExpression != "status = :v" {
		t.Errorf("KeyConditionExpression = %q, want %q", *capturedInput.KeyConditionExpression, "status = :v")
	}
	// Verify the status value in expression attributes
	if v, ok := capturedInput.ExpressionAttributeValues[":v"].(*types.AttributeValueMemberS); !ok || v.Value != "pending" {
		t.Errorf("ExpressionAttributeValues[:v] = %v, want %q", capturedInput.ExpressionAttributeValues[":v"], "pending")
	}

	// Verify results
	if len(results) != 1 {
		t.Fatalf("ListByStatus() returned %d results, want 1", len(results))
	}
	if results[0].Status != StatusPending {
		t.Errorf("Result status = %q, want %q", results[0].Status, StatusPending)
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

// TestDynamoDBStore_ListByProfile_Success tests returning requests for a profile.
func TestDynamoDBStore_ListByProfile_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Nanosecond)
	req := &Request{
		ID:            "profile001",
		Requester:     "charlie",
		Profile:       "production",
		Justification: "Profile access request",
		Duration:      time.Hour,
		Status:        StatusApproved,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultRequestTTL),
	}

	item, _ := attributevalue.MarshalMap(requestToItem(req))

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
	if *capturedInput.KeyConditionExpression != "profile = :v" {
		t.Errorf("KeyConditionExpression = %q, want %q", *capturedInput.KeyConditionExpression, "profile = :v")
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

			_, err := store.ListByRequester(context.Background(), "user", tt.inputLimit)
			if err != nil {
				t.Fatalf("ListByRequester() error = %v", err)
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

	_, err := store.ListByRequester(context.Background(), "user", 10)
	if err == nil {
		t.Fatal("ListByRequester() should return error on DynamoDB failure")
	}
}
