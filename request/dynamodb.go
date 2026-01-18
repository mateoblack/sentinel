package request

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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
	// GSIRequester indexes requests by requester with created_at sort key.
	GSIRequester = "gsi-requester"
	// GSIStatus indexes requests by status with created_at sort key.
	GSIStatus = "gsi-status"
	// GSIProfile indexes requests by profile with created_at sort key.
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
// It provides CRUD operations for approval requests with optimistic locking.
//
// Table schema assumptions (created externally via Terraform/CloudFormation):
//   - Partition key: id (String)
//   - TTL attribute: ttl (Number, Unix timestamp)
//   - All Request fields stored as attributes
type DynamoDBStore struct {
	client    dynamoDBAPI
	tableName string
}

// NewDynamoDBStore creates a new DynamoDBStore using the provided AWS configuration.
// The tableName specifies the DynamoDB table for storing requests.
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

// dynamoItem represents the DynamoDB item structure for a Request.
// It uses explicit field mapping for proper serialization of Go types.
type dynamoItem struct {
	ID              string `dynamodbav:"id"`
	Requester       string `dynamodbav:"requester"`
	Profile         string `dynamodbav:"profile"`
	Justification   string `dynamodbav:"justification"`
	Duration        int64  `dynamodbav:"duration"`         // nanoseconds
	Status          string `dynamodbav:"status"`           // RequestStatus as string
	CreatedAt       string `dynamodbav:"created_at"`       // RFC3339
	UpdatedAt       string `dynamodbav:"updated_at"`       // RFC3339
	ExpiresAt       string `dynamodbav:"expires_at"`       // RFC3339
	TTL             int64  `dynamodbav:"ttl"`              // Unix timestamp for DynamoDB TTL
	Approver        string `dynamodbav:"approver"`         // may be empty
	ApproverComment string `dynamodbav:"approver_comment"` // may be empty
}

// requestToItem converts a Request to a DynamoDB item structure.
func requestToItem(req *Request) *dynamoItem {
	return &dynamoItem{
		ID:              req.ID,
		Requester:       req.Requester,
		Profile:         req.Profile,
		Justification:   req.Justification,
		Duration:        int64(req.Duration),
		Status:          string(req.Status),
		CreatedAt:       req.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:       req.UpdatedAt.Format(time.RFC3339Nano),
		ExpiresAt:       req.ExpiresAt.Format(time.RFC3339Nano),
		TTL:             req.ExpiresAt.Unix(),
		Approver:        req.Approver,
		ApproverComment: req.ApproverComment,
	}
}

// itemToRequest converts a DynamoDB item structure back to a Request.
func itemToRequest(item *dynamoItem) (*Request, error) {
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

	return &Request{
		ID:              item.ID,
		Requester:       item.Requester,
		Profile:         item.Profile,
		Justification:   item.Justification,
		Duration:        time.Duration(item.Duration),
		Status:          RequestStatus(item.Status),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		ExpiresAt:       expiresAt,
		Approver:        item.Approver,
		ApproverComment: item.ApproverComment,
	}, nil
}

// Create stores a new request. Returns ErrRequestExists if ID already exists.
func (s *DynamoDBStore) Create(ctx context.Context, req *Request) error {
	item := requestToItem(req)
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(id)"),
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return fmt.Errorf("%s: %w", req.ID, ErrRequestExists)
		}
		return sentinelerrors.WrapDynamoDBError(err, s.tableName, "PutItem")
	}

	return nil
}

// Get retrieves a request by ID. Returns ErrRequestNotFound if not exists.
func (s *DynamoDBStore) Get(ctx context.Context, id string) (*Request, error) {
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
		return nil, fmt.Errorf("%s: %w", id, ErrRequestNotFound)
	}

	var item dynamoItem
	if err := attributevalue.UnmarshalMap(output.Item, &item); err != nil {
		return nil, fmt.Errorf("unmarshal request: %w", err)
	}

	return itemToRequest(&item)
}

// Update modifies an existing request using optimistic locking.
// Returns ErrRequestNotFound if request doesn't exist.
// Returns ErrConcurrentModification if request was modified since last read.
func (s *DynamoDBStore) Update(ctx context.Context, req *Request) error {
	item := requestToItem(req)
	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	// Build condition: item must exist AND updated_at must match
	// This implements optimistic locking - if someone else updated the item,
	// the condition will fail.
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_exists(id) AND updated_at = :old_updated_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":old_updated_at": &types.AttributeValueMemberS{Value: req.UpdatedAt.Format(time.RFC3339Nano)},
		},
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			// Could be either not found or concurrent modification
			// Check if item exists to differentiate
			exists, checkErr := s.exists(ctx, req.ID)
			if checkErr != nil {
				return fmt.Errorf("dynamodb PutItem condition failed, check exists: %w", checkErr)
			}
			if !exists {
				return fmt.Errorf("%s: %w", req.ID, ErrRequestNotFound)
			}
			return fmt.Errorf("%s: %w", req.ID, ErrConcurrentModification)
		}
		return sentinelerrors.WrapDynamoDBError(err, s.tableName, "PutItem")
	}

	return nil
}

// Delete removes a request by ID. No-op if not exists (idempotent).
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

// exists checks if a request with the given ID exists in the store.
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

// parseDynamoDBTime parses a time string that may be in RFC3339Nano format
// or as a Unix timestamp (for backward compatibility).
func parseDynamoDBTime(s string) (time.Time, error) {
	// Try RFC3339Nano first
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	// Try RFC3339 (without nanos)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// Try Unix timestamp
	if unix, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(unix, 0), nil
	}
	return time.Time{}, fmt.Errorf("cannot parse time: %q", s)
}

// ListByRequester returns all requests from a specific user, ordered by created_at desc.
// Returns empty slice if no requests found.
func (s *DynamoDBStore) ListByRequester(ctx context.Context, requester string, limit int) ([]*Request, error) {
	return s.queryByIndex(ctx, GSIRequester, "requester", requester, limit)
}

// ListByStatus returns all requests with a specific status, ordered by created_at desc.
// Commonly used to list pending requests for approvers.
func (s *DynamoDBStore) ListByStatus(ctx context.Context, status RequestStatus, limit int) ([]*Request, error) {
	return s.queryByIndex(ctx, GSIStatus, "status", string(status), limit)
}

// ListByProfile returns all requests for a specific AWS profile, ordered by created_at desc.
// Useful for viewing request history for a profile.
func (s *DynamoDBStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*Request, error) {
	return s.queryByIndex(ctx, GSIProfile, "profile", profile, limit)
}

// queryByIndex executes a query against a GSI with the given partition key.
// Results are ordered by created_at descending (newest first).
func (s *DynamoDBStore) queryByIndex(ctx context.Context, indexName, keyAttr, keyValue string, limit int) ([]*Request, error) {
	// Apply limit defaults and cap
	effectiveLimit := limit
	if effectiveLimit <= 0 {
		effectiveLimit = DefaultQueryLimit
	}
	if effectiveLimit > MaxQueryLimit {
		effectiveLimit = MaxQueryLimit
	}

	output, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String(indexName),
		KeyConditionExpression: aws.String(fmt.Sprintf("%s = :v", keyAttr)),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":v": &types.AttributeValueMemberS{Value: keyValue},
		},
		ScanIndexForward: aws.Bool(false), // Descending order (newest first)
		Limit:            aws.Int32(int32(effectiveLimit)),
	})
	if err != nil {
		return nil, sentinelerrors.WrapDynamoDBError(err, s.tableName, fmt.Sprintf("Query:%s", indexName))
	}

	// Convert items to requests
	requests := make([]*Request, 0, len(output.Items))
	for _, av := range output.Items {
		var item dynamoItem
		if err := attributevalue.UnmarshalMap(av, &item); err != nil {
			return nil, fmt.Errorf("unmarshal request: %w", err)
		}
		req, err := itemToRequest(&item)
		if err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}

	return requests, nil
}
