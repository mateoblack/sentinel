package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	sentinelerrors "github.com/byteness/aws-vault/v7/errors"
)

// GSI name constants for DynamoDB Global Secondary Indexes.
// These indexes are created externally via Terraform/CloudFormation.
const (
	// GSIUser indexes sessions by user with created_at sort key.
	GSIUser = "gsi-user"
	// GSIStatus indexes sessions by status with created_at sort key.
	GSIStatus = "gsi-status"
	// GSIProfile indexes sessions by profile with created_at sort key.
	GSIProfile = "gsi-profile"
	// GSIServerInstance indexes sessions by server_instance_id with status.
	GSIServerInstance = "gsi-server-instance"
	// GSIDeviceID indexes sessions by device_id with created_at sort key.
	GSIDeviceID = "gsi-device-id"
)

// dynamoDBAPI defines the DynamoDB operations used by DynamoDBStore.
// This interface enables testing with mock implementations.
type dynamoDBAPI interface {
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	Scan(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

// DynamoDBStore implements Store using AWS DynamoDB.
// It provides CRUD operations for server sessions with optimistic locking.
//
// Table schema assumptions (created externally via Terraform/CloudFormation):
//   - Partition key: id (String)
//   - TTL attribute: ttl (Number, Unix timestamp)
//   - GSI: gsi-user (user, created_at)
//   - GSI: gsi-status (status, created_at)
//   - GSI: gsi-profile (profile, created_at)
//   - GSI: gsi-server-instance (server_instance_id, status)
//   - All ServerSession fields stored as attributes
type DynamoDBStore struct {
	client    dynamoDBAPI
	tableName string
}

// NewDynamoDBStore creates a new DynamoDBStore using the provided AWS configuration.
// The tableName specifies the DynamoDB table for storing server sessions.
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

// dynamoItem represents the DynamoDB item structure for a ServerSession.
// It uses explicit field mapping for proper serialization of Go types.
type dynamoItem struct {
	ID               string `dynamodbav:"id"`
	User             string `dynamodbav:"user"`
	Profile          string `dynamodbav:"profile"`
	ServerInstanceID string `dynamodbav:"server_instance_id"`
	Status           string `dynamodbav:"status"`
	StartedAt        string `dynamodbav:"started_at"`     // RFC3339Nano
	LastAccessAt     string `dynamodbav:"last_access_at"` // RFC3339Nano
	ExpiresAt        string `dynamodbav:"expires_at"`     // RFC3339Nano
	RequestCount     int64  `dynamodbav:"request_count"`
	SourceIdentity   string `dynamodbav:"source_identity"`
	DeviceID         string `dynamodbav:"device_id"`
	CreatedAt        string `dynamodbav:"created_at"` // RFC3339Nano
	UpdatedAt        string `dynamodbav:"updated_at"` // RFC3339Nano
	TTL              int64  `dynamodbav:"ttl"`        // Unix timestamp for DynamoDB TTL
	RevokedBy        string `dynamodbav:"revoked_by"`
	RevokedReason    string `dynamodbav:"revoked_reason"`
}

// toItem converts a ServerSession to a DynamoDB item structure.
func toItem(session *ServerSession) *dynamoItem {
	return &dynamoItem{
		ID:               session.ID,
		User:             session.User,
		Profile:          session.Profile,
		ServerInstanceID: session.ServerInstanceID,
		Status:           string(session.Status),
		StartedAt:        session.StartedAt.Format(time.RFC3339Nano),
		LastAccessAt:     session.LastAccessAt.Format(time.RFC3339Nano),
		ExpiresAt:        session.ExpiresAt.Format(time.RFC3339Nano),
		RequestCount:     session.RequestCount,
		SourceIdentity:   session.SourceIdentity,
		DeviceID:         session.DeviceID,
		CreatedAt:        session.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:        session.UpdatedAt.Format(time.RFC3339Nano),
		TTL:              session.ExpiresAt.Unix(),
		RevokedBy:        session.RevokedBy,
		RevokedReason:    session.RevokedReason,
	}
}

// fromItem converts a DynamoDB item structure back to a ServerSession.
func fromItem(item *dynamoItem) (*ServerSession, error) {
	startedAt, err := time.Parse(time.RFC3339Nano, item.StartedAt)
	if err != nil {
		return nil, fmt.Errorf("parse started_at: %w", err)
	}
	lastAccessAt, err := time.Parse(time.RFC3339Nano, item.LastAccessAt)
	if err != nil {
		return nil, fmt.Errorf("parse last_access_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, item.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, item.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, item.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at: %w", err)
	}

	return &ServerSession{
		ID:               item.ID,
		User:             item.User,
		Profile:          item.Profile,
		ServerInstanceID: item.ServerInstanceID,
		Status:           SessionStatus(item.Status),
		StartedAt:        startedAt,
		LastAccessAt:     lastAccessAt,
		ExpiresAt:        expiresAt,
		RequestCount:     item.RequestCount,
		SourceIdentity:   item.SourceIdentity,
		DeviceID:         item.DeviceID,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
		RevokedBy:        item.RevokedBy,
		RevokedReason:    item.RevokedReason,
	}, nil
}

// enforceLimit applies default and maximum limits to query limit values.
func enforceLimit(limit int) int {
	if limit <= 0 {
		return DefaultQueryLimit
	}
	if limit > MaxQueryLimit {
		return MaxQueryLimit
	}
	return limit
}

// Create stores a new server session. Returns ErrSessionExists if ID already exists.
func (s *DynamoDBStore) Create(ctx context.Context, session *ServerSession) error {
	item := toItem(session)
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(id)"),
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return fmt.Errorf("%s: %w", session.ID, ErrSessionExists)
		}
		return sentinelerrors.WrapDynamoDBError(err, s.tableName, "PutItem")
	}

	return nil
}

// Get retrieves a server session by ID. Returns ErrSessionNotFound if not exists.
func (s *DynamoDBStore) Get(ctx context.Context, id string) (*ServerSession, error) {
	output, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return nil, sentinelerrors.WrapDynamoDBError(err, s.tableName, "GetItem")
	}

	if output.Item == nil {
		return nil, fmt.Errorf("%s: %w", id, ErrSessionNotFound)
	}

	var item dynamoItem
	if err := attributevalue.UnmarshalMap(output.Item, &item); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return fromItem(&item)
}

// Update modifies an existing session using optimistic locking.
// Returns ErrSessionNotFound if session doesn't exist.
// Returns ErrConcurrentModification if session was modified since last read.
// Note: Update() sets UpdatedAt internally - callers should NOT set it before calling.
func (s *DynamoDBStore) Update(ctx context.Context, session *ServerSession) error {
	// Save original UpdatedAt for optimistic lock condition check
	originalUpdatedAt := session.UpdatedAt

	// Set new UpdatedAt for the write (this also updates the caller's session in-place)
	session.UpdatedAt = time.Now()

	item := toItem(session)
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	// Build condition: item must exist AND updated_at must match ORIGINAL value
	// This implements optimistic locking - if someone else updated the item,
	// the condition will fail.
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_exists(id) AND updated_at = :old_updated_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":old_updated_at": &types.AttributeValueMemberS{Value: originalUpdatedAt.Format(time.RFC3339Nano)},
		},
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			// Could be either not found or concurrent modification
			// Check if item exists to differentiate
			exists, checkErr := s.exists(ctx, session.ID)
			if checkErr != nil {
				return fmt.Errorf("dynamodb PutItem condition failed, check exists: %w", checkErr)
			}
			if !exists {
				return fmt.Errorf("%s: %w", session.ID, ErrSessionNotFound)
			}
			return fmt.Errorf("%s: %w", session.ID, ErrConcurrentModification)
		}
		return sentinelerrors.WrapDynamoDBError(err, s.tableName, "PutItem")
	}

	return nil
}

// Delete removes a server session by ID. No-op if not exists (idempotent).
func (s *DynamoDBStore) Delete(ctx context.Context, id string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return sentinelerrors.WrapDynamoDBError(err, s.tableName, "DeleteItem")
	}

	return nil
}

// exists checks if a session with the given ID exists in the store.
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

// ListByUser returns all sessions from a specific user, ordered by created_at desc.
// Returns empty slice if no sessions found.
func (s *DynamoDBStore) ListByUser(ctx context.Context, user string, limit int) ([]*ServerSession, error) {
	return s.queryByIndex(ctx, GSIUser, "user", user, limit)
}

// ListByStatus returns all sessions with a specific status, ordered by created_at desc.
// Commonly used to list active sessions for monitoring.
func (s *DynamoDBStore) ListByStatus(ctx context.Context, status SessionStatus, limit int) ([]*ServerSession, error) {
	return s.queryByIndex(ctx, GSIStatus, "status", string(status), limit)
}

// ListByProfile returns all sessions for a specific AWS profile, ordered by created_at desc.
// Useful for viewing session history for a profile.
func (s *DynamoDBStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*ServerSession, error) {
	return s.queryByIndex(ctx, GSIProfile, "profile", profile, limit)
}

// FindActiveByServerInstance finds the active session for a specific server instance.
// Returns nil, nil if no active session exists for that server instance.
func (s *DynamoDBStore) FindActiveByServerInstance(ctx context.Context, serverInstanceID string) (*ServerSession, error) {
	// Query by server instance GSI with filter for active status
	output, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String(GSIServerInstance),
		KeyConditionExpression: aws.String("server_instance_id = :server_instance_id"),
		FilterExpression:       aws.String("#status = :status"),
		ExpressionAttributeNames: map[string]string{
			"#status": "status", // status is a reserved word
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":server_instance_id": &types.AttributeValueMemberS{Value: serverInstanceID},
			":status":             &types.AttributeValueMemberS{Value: string(StatusActive)},
		},
		ScanIndexForward: aws.Bool(false), // Newest first
		Limit:            aws.Int32(1),    // We only need one
	})
	if err != nil {
		return nil, sentinelerrors.WrapDynamoDBError(err, s.tableName, "Query:FindActive")
	}

	if len(output.Items) == 0 {
		return nil, nil // No active session found
	}

	var item dynamoItem
	if err := attributevalue.UnmarshalMap(output.Items[0], &item); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return fromItem(&item)
}

// Touch updates LastAccessAt and increments RequestCount atomically.
// This is optimized for the hot path - uses UpdateItem with atomic operations.
func (s *DynamoDBStore) Touch(ctx context.Context, id string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
		UpdateExpression: aws.String("SET last_access_at = :now, request_count = request_count + :inc, updated_at = :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now": &types.AttributeValueMemberS{Value: now},
			":inc": &types.AttributeValueMemberN{Value: "1"},
		},
		ConditionExpression: aws.String("attribute_exists(id)"),
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return fmt.Errorf("%s: %w", id, ErrSessionNotFound)
		}
		return sentinelerrors.WrapDynamoDBError(err, s.tableName, "UpdateItem:Touch")
	}

	return nil
}

// ListByTimeRange retrieves sessions created within a time range.
// Uses a scan with filter since we don't have a GSI on created_at.
// For audit queries, this is acceptable as they are infrequent.
func (s *DynamoDBStore) ListByTimeRange(ctx context.Context, startTime, endTime time.Time, limit int) ([]*ServerSession, error) {
	effectiveLimit := enforceLimit(limit)

	var sessions []*ServerSession
	var lastEvaluatedKey map[string]types.AttributeValue

	for len(sessions) < effectiveLimit {
		input := &dynamodb.ScanInput{
			TableName:        aws.String(s.tableName),
			FilterExpression: aws.String("created_at BETWEEN :start AND :end"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":start": &types.AttributeValueMemberS{Value: startTime.Format(time.RFC3339Nano)},
				":end":   &types.AttributeValueMemberS{Value: endTime.Format(time.RFC3339Nano)},
			},
			ExclusiveStartKey: lastEvaluatedKey,
		}

		output, err := s.client.Scan(ctx, input)
		if err != nil {
			return nil, sentinelerrors.WrapDynamoDBError(err, s.tableName, "Scan:TimeRange")
		}

		for _, item := range output.Items {
			var di dynamoItem
			if err := attributevalue.UnmarshalMap(item, &di); err != nil {
				continue // Skip invalid items
			}
			sess, err := fromItem(&di)
			if err != nil {
				continue // Skip items that fail parsing
			}
			sessions = append(sessions, sess)
			if len(sessions) >= effectiveLimit {
				break
			}
		}

		// Check if there are more pages
		lastEvaluatedKey = output.LastEvaluatedKey
		if lastEvaluatedKey == nil {
			break // No more pages
		}
	}

	// Sort by created_at descending (newest first)
	sortSessionsByCreatedAtDesc(sessions)

	return sessions, nil
}

// sortSessionsByCreatedAtDesc sorts sessions by created_at in descending order.
func sortSessionsByCreatedAtDesc(sessions []*ServerSession) {
	for i := 0; i < len(sessions)-1; i++ {
		for j := i + 1; j < len(sessions); j++ {
			if sessions[j].CreatedAt.After(sessions[i].CreatedAt) {
				sessions[i], sessions[j] = sessions[j], sessions[i]
			}
		}
	}
}

// GetBySourceIdentity retrieves a session by its source identity.
// Returns nil, nil if no session with the source identity is found.
// This uses a scan with filter since source_identity is not indexed.
// For audit queries, this is acceptable as they are infrequent.
func (s *DynamoDBStore) GetBySourceIdentity(ctx context.Context, sourceIdentity string) (*ServerSession, error) {
	input := &dynamodb.ScanInput{
		TableName:        aws.String(s.tableName),
		FilterExpression: aws.String("source_identity = :sid"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":sid": &types.AttributeValueMemberS{Value: sourceIdentity},
		},
		Limit: aws.Int32(1),
	}

	output, err := s.client.Scan(ctx, input)
	if err != nil {
		return nil, sentinelerrors.WrapDynamoDBError(err, s.tableName, "Scan:SourceIdentity")
	}

	if len(output.Items) == 0 {
		return nil, nil // Not found, return nil without error
	}

	var item dynamoItem
	if err := attributevalue.UnmarshalMap(output.Items[0], &item); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return fromItem(&item)
}

// ListByDeviceID returns all sessions from a specific device, ordered by created_at desc.
// Returns empty slice if no sessions found for the device.
func (s *DynamoDBStore) ListByDeviceID(ctx context.Context, deviceID string, limit int) ([]*ServerSession, error) {
	return s.queryByIndex(ctx, GSIDeviceID, "device_id", deviceID, limit)
}

// queryByIndex executes a query against a GSI with the given partition key.
// Results are ordered by created_at descending (newest first).
func (s *DynamoDBStore) queryByIndex(ctx context.Context, indexName, keyAttr, keyValue string, limit int) ([]*ServerSession, error) {
	effectiveLimit := enforceLimit(limit)

	// Use expression attribute names for reserved words
	keyCondition := "#pk = :v"
	exprAttrNames := map[string]string{
		"#pk": keyAttr,
	}

	output, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:                aws.String(s.tableName),
		IndexName:                aws.String(indexName),
		KeyConditionExpression:   aws.String(keyCondition),
		ExpressionAttributeNames: exprAttrNames,
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":v": &types.AttributeValueMemberS{Value: keyValue},
		},
		ScanIndexForward: aws.Bool(false), // Descending order (newest first)
		Limit:            aws.Int32(int32(effectiveLimit)),
	})
	if err != nil {
		return nil, sentinelerrors.WrapDynamoDBError(err, s.tableName, fmt.Sprintf("Query:%s", indexName))
	}

	// Convert items to sessions
	sessions := make([]*ServerSession, 0, len(output.Items))
	for _, av := range output.Items {
		var item dynamoItem
		if err := attributevalue.UnmarshalMap(av, &item); err != nil {
			return nil, fmt.Errorf("unmarshal session: %w", err)
		}
		session, err := fromItem(&item)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}
