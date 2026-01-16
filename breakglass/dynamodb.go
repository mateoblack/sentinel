package breakglass

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// GSI name constants for DynamoDB Global Secondary Indexes.
// These indexes are created externally via Terraform/CloudFormation.
const (
	// GSIInvoker indexes events by invoker with created_at sort key.
	GSIInvoker = "gsi-invoker"
	// GSIStatus indexes events by status with created_at sort key.
	GSIStatus = "gsi-status"
	// GSIProfile indexes events by profile with created_at sort key.
	GSIProfile = "gsi-profile"
)

// dynamoDBAPI defines the DynamoDB operations used by DynamoDBStore.
// This interface enables testing with mock implementations.
type dynamoDBAPI interface {
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
}

// DynamoDBStore implements Store using AWS DynamoDB.
// It provides CRUD operations for break-glass events with optimistic locking.
//
// Table schema assumptions (created externally via Terraform/CloudFormation):
//   - Partition key: id (String)
//   - TTL attribute: ttl (Number, Unix timestamp)
//   - GSI: gsi-invoker (invoker, created_at)
//   - GSI: gsi-status (status, created_at)
//   - GSI: gsi-profile (profile, created_at)
//   - All BreakGlassEvent fields stored as attributes
type DynamoDBStore struct {
	client    dynamoDBAPI
	tableName string
}

// NewDynamoDBStore creates a new DynamoDBStore using the provided AWS configuration.
// The tableName specifies the DynamoDB table for storing break-glass events.
func NewDynamoDBStore(cfg aws.Config, tableName string) *DynamoDBStore {
	return &DynamoDBStore{
		client:    dynamodb.NewFromConfig(cfg),
		tableName: tableName,
	}
}

// newDynamoDBStoreWithClient creates a DynamoDBStore with a custom client.
// This is primarily used for testing with mock clients.
func newDynamoDBStoreWithClient(client dynamoDBAPI, tableName string) *DynamoDBStore {
	return &DynamoDBStore{
		client:    client,
		tableName: tableName,
	}
}

// dynamoItem represents the DynamoDB item structure for a BreakGlassEvent.
// It uses explicit field mapping for proper serialization of Go types.
type dynamoItem struct {
	ID            string `dynamodbav:"id"`
	Invoker       string `dynamodbav:"invoker"`
	Profile       string `dynamodbav:"profile"`
	ReasonCode    string `dynamodbav:"reason_code"`
	Justification string `dynamodbav:"justification"`
	Duration      int64  `dynamodbav:"duration"`     // nanoseconds
	Status        string `dynamodbav:"status"`       // BreakGlassStatus as string
	CreatedAt     string `dynamodbav:"created_at"`   // RFC3339Nano
	UpdatedAt     string `dynamodbav:"updated_at"`   // RFC3339Nano
	ExpiresAt     string `dynamodbav:"expires_at"`   // RFC3339Nano
	TTL           int64  `dynamodbav:"ttl"`          // Unix timestamp for DynamoDB TTL
	ClosedBy      string `dynamodbav:"closed_by"`    // may be empty
	ClosedReason  string `dynamodbav:"closed_reason"` // may be empty
	RequestID     string `dynamodbav:"request_id"`   // may be empty
}

// eventToItem converts a BreakGlassEvent to a DynamoDB item structure.
func eventToItem(event *BreakGlassEvent) *dynamoItem {
	return &dynamoItem{
		ID:            event.ID,
		Invoker:       event.Invoker,
		Profile:       event.Profile,
		ReasonCode:    string(event.ReasonCode),
		Justification: event.Justification,
		Duration:      int64(event.Duration),
		Status:        string(event.Status),
		CreatedAt:     event.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:     event.UpdatedAt.Format(time.RFC3339Nano),
		ExpiresAt:     event.ExpiresAt.Format(time.RFC3339Nano),
		TTL:           event.ExpiresAt.Unix(),
		ClosedBy:      event.ClosedBy,
		ClosedReason:  event.ClosedReason,
		RequestID:     event.RequestID,
	}
}

// itemToEvent converts a DynamoDB item structure back to a BreakGlassEvent.
func itemToEvent(item *dynamoItem) (*BreakGlassEvent, error) {
	createdAt, err := time.Parse(time.RFC3339Nano, item.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, item.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, item.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}

	return &BreakGlassEvent{
		ID:            item.ID,
		Invoker:       item.Invoker,
		Profile:       item.Profile,
		ReasonCode:    ReasonCode(item.ReasonCode),
		Justification: item.Justification,
		Duration:      time.Duration(item.Duration),
		Status:        BreakGlassStatus(item.Status),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		ExpiresAt:     expiresAt,
		ClosedBy:      item.ClosedBy,
		ClosedReason:  item.ClosedReason,
		RequestID:     item.RequestID,
	}, nil
}

// Create stores a new break-glass event. Returns ErrEventExists if ID already exists.
func (s *DynamoDBStore) Create(ctx context.Context, event *BreakGlassEvent) error {
	item := eventToItem(event)
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(id)"),
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return fmt.Errorf("%s: %w", event.ID, ErrEventExists)
		}
		return fmt.Errorf("dynamodb PutItem: %w", err)
	}

	return nil
}

// Get retrieves a break-glass event by ID. Returns ErrEventNotFound if not exists.
func (s *DynamoDBStore) Get(ctx context.Context, id string) (*BreakGlassEvent, error) {
	output, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb GetItem: %w", err)
	}

	if output.Item == nil {
		return nil, fmt.Errorf("%s: %w", id, ErrEventNotFound)
	}

	var item dynamoItem
	if err := attributevalue.UnmarshalMap(output.Item, &item); err != nil {
		return nil, fmt.Errorf("unmarshal event: %w", err)
	}

	return itemToEvent(&item)
}

// Update modifies an existing event using optimistic locking.
// Returns ErrEventNotFound if event doesn't exist.
// Returns ErrConcurrentModification if event was modified since last read.
func (s *DynamoDBStore) Update(ctx context.Context, event *BreakGlassEvent) error {
	item := eventToItem(event)
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	// Build condition: item must exist AND updated_at must match
	// This implements optimistic locking - if someone else updated the item,
	// the condition will fail.
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_exists(id) AND updated_at = :old_updated_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":old_updated_at": &types.AttributeValueMemberS{Value: event.UpdatedAt.Format(time.RFC3339Nano)},
		},
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			// Could be either not found or concurrent modification
			// Check if item exists to differentiate
			exists, checkErr := s.exists(ctx, event.ID)
			if checkErr != nil {
				return fmt.Errorf("dynamodb PutItem condition failed, check exists: %w", checkErr)
			}
			if !exists {
				return fmt.Errorf("%s: %w", event.ID, ErrEventNotFound)
			}
			return fmt.Errorf("%s: %w", event.ID, ErrConcurrentModification)
		}
		return fmt.Errorf("dynamodb PutItem: %w", err)
	}

	return nil
}

// Delete removes a break-glass event by ID. No-op if not exists (idempotent).
func (s *DynamoDBStore) Delete(ctx context.Context, id string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return fmt.Errorf("dynamodb DeleteItem: %w", err)
	}

	return nil
}

// exists checks if an event with the given ID exists in the store.
func (s *DynamoDBStore) exists(ctx context.Context, id string) (bool, error) {
	output, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
		ProjectionExpression: aws.String("id"),
	})
	if err != nil {
		return false, fmt.Errorf("dynamodb GetItem: %w", err)
	}

	return output.Item != nil, nil
}

// ListByInvoker returns all events from a specific user, ordered by created_at desc.
// Returns empty slice if no events found.
func (s *DynamoDBStore) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*BreakGlassEvent, error) {
	return s.queryByIndex(ctx, GSIInvoker, "invoker", invoker, limit)
}

// ListByStatus returns all events with a specific status, ordered by created_at desc.
// Commonly used to list active break-glass events for security review.
func (s *DynamoDBStore) ListByStatus(ctx context.Context, status BreakGlassStatus, limit int) ([]*BreakGlassEvent, error) {
	return s.queryByIndex(ctx, GSIStatus, "status", string(status), limit)
}

// ListByProfile returns all events for a specific AWS profile, ordered by created_at desc.
// Useful for viewing break-glass history for a profile.
func (s *DynamoDBStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*BreakGlassEvent, error) {
	return s.queryByIndex(ctx, GSIProfile, "profile", profile, limit)
}

// FindActiveByInvokerAndProfile checks if the user already has active break-glass access
// for a profile. Returns the active event if found, nil if no active event exists.
// This is critical to prevent stacking of break-glass access.
func (s *DynamoDBStore) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	// Query by invoker GSI with filter for profile and active status
	output, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String(GSIInvoker),
		KeyConditionExpression: aws.String("invoker = :invoker"),
		FilterExpression:       aws.String("profile = :profile AND #status = :status"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status", // status is a reserved word
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":invoker": &types.AttributeValueMemberS{Value: invoker},
			":profile": &types.AttributeValueMemberS{Value: profile},
			":status":  &types.AttributeValueMemberS{Value: string(StatusActive)},
		},
		ScanIndexForward: aws.Bool(false), // Newest first
		Limit:            aws.Int32(1),    // We only need one
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb Query: %w", err)
	}

	if len(output.Items) == 0 {
		return nil, nil // No active event found
	}

	var item dynamoItem
	if err := attributevalue.UnmarshalMap(output.Items[0], &item); err != nil {
		return nil, fmt.Errorf("unmarshal event: %w", err)
	}

	return itemToEvent(&item)
}

// queryByIndex executes a query against a GSI with the given partition key.
// Results are ordered by created_at descending (newest first).
func (s *DynamoDBStore) queryByIndex(ctx context.Context, indexName, keyAttr, keyValue string, limit int) ([]*BreakGlassEvent, error) {
	// Apply limit defaults and cap
	effectiveLimit := limit
	if effectiveLimit <= 0 {
		effectiveLimit = DefaultQueryLimit
	}
	if effectiveLimit > MaxQueryLimit {
		effectiveLimit = MaxQueryLimit
	}

	// Use expression attribute names for reserved words
	keyCondition := fmt.Sprintf("#pk = :v")
	exprAttrNames := map[string]string{
		"#pk": keyAttr,
	}

	output, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(s.tableName),
		IndexName:                 aws.String(indexName),
		KeyConditionExpression:    aws.String(keyCondition),
		ExpressionAttributeNames:  exprAttrNames,
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":v": &types.AttributeValueMemberS{Value: keyValue},
		},
		ScanIndexForward: aws.Bool(false), // Descending order (newest first)
		Limit:            aws.Int32(int32(effectiveLimit)),
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb Query %s: %w", indexName, err)
	}

	// Convert items to events
	events := make([]*BreakGlassEvent, 0, len(output.Items))
	for _, av := range output.Items {
		var item dynamoItem
		if err := attributevalue.UnmarshalMap(av, &item); err != nil {
			return nil, fmt.Errorf("unmarshal event: %w", err)
		}
		event, err := itemToEvent(&item)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	return events, nil
}

// CountByInvokerSince counts events from a specific user since the given time.
// Uses Select: COUNT for efficiency, minimizing data transfer.
func (s *DynamoDBStore) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	return s.countByIndexSince(ctx, GSIInvoker, "invoker", invoker, since)
}

// CountByProfileSince counts events for a specific profile since the given time.
// Uses Select: COUNT for efficiency, minimizing data transfer.
func (s *DynamoDBStore) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	return s.countByIndexSince(ctx, GSIProfile, "profile", profile, since)
}

// GetLastByInvokerAndProfile returns the most recent event for a user+profile combination.
// Returns nil, nil if no events found. Used for cooldown checking.
func (s *DynamoDBStore) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*BreakGlassEvent, error) {
	output, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String(GSIInvoker),
		KeyConditionExpression: aws.String("invoker = :invoker"),
		FilterExpression:       aws.String("profile = :profile"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":invoker": &types.AttributeValueMemberS{Value: invoker},
			":profile": &types.AttributeValueMemberS{Value: profile},
		},
		ScanIndexForward: aws.Bool(false), // Newest first
		Limit:            aws.Int32(1),    // Only need the most recent
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb Query: %w", err)
	}

	if len(output.Items) == 0 {
		return nil, nil // No events found
	}

	var item dynamoItem
	if err := attributevalue.UnmarshalMap(output.Items[0], &item); err != nil {
		return nil, fmt.Errorf("unmarshal event: %w", err)
	}

	return itemToEvent(&item)
}

// countByIndexSince counts events matching the given index key since a specific time.
// Uses Select: COUNT for efficiency - only returns count, not full items.
func (s *DynamoDBStore) countByIndexSince(ctx context.Context, indexName, keyAttr, keyValue string, since time.Time) (int, error) {
	// Format time as RFC3339Nano for string comparison in DynamoDB
	sinceStr := since.Format(time.RFC3339Nano)

	output, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String(indexName),
		KeyConditionExpression: aws.String("#pk = :v"),
		FilterExpression:       aws.String("created_at >= :since"),
		ExpressionAttributeNames: map[string]string{
			"#pk": keyAttr,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":v":     &types.AttributeValueMemberS{Value: keyValue},
			":since": &types.AttributeValueMemberS{Value: sinceStr},
		},
		Select: types.SelectCount, // Only return count, not items
	})
	if err != nil {
		return 0, fmt.Errorf("dynamodb Query %s: %w", indexName, err)
	}

	return int(output.Count), nil
}
