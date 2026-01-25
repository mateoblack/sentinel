package infrastructure

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	sentinelerrors "github.com/byteness/aws-vault/v7/errors"
)

// ProvisionStatus represents the result status of a provision operation.
type ProvisionStatus string

const (
	// StatusCreated indicates the table was created successfully.
	StatusCreated ProvisionStatus = "CREATED"
	// StatusExists indicates the table already exists and is active.
	StatusExists ProvisionStatus = "EXISTS"
	// StatusFailed indicates the provision operation failed.
	StatusFailed ProvisionStatus = "FAILED"
)

// Backoff configuration for waiting on table status.
const (
	// initialBackoff is the starting backoff duration.
	initialBackoff = 1 * time.Second
	// maxBackoff is the maximum backoff duration.
	maxBackoff = 30 * time.Second
	// waitTimeout is the total timeout for waiting on table status.
	waitTimeout = 5 * time.Minute
)

// dynamoDBProvisionerAPI defines the DynamoDB operations used by TableProvisioner.
// This interface enables testing with mock implementations.
type dynamoDBProvisionerAPI interface {
	CreateTable(ctx context.Context, params *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error)
	DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	UpdateTimeToLive(ctx context.Context, params *dynamodb.UpdateTimeToLiveInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTimeToLiveOutput, error)
}

// TableProvisioner handles DynamoDB table creation and management.
// It provides idempotent table creation with GSI support and TTL configuration.
type TableProvisioner struct {
	client dynamoDBProvisionerAPI
	region string
}

// NewTableProvisioner creates a new TableProvisioner using the provided AWS configuration.
func NewTableProvisioner(cfg aws.Config, region string) *TableProvisioner {
	return &TableProvisioner{
		client: dynamodb.NewFromConfig(cfg),
		region: region,
	}
}

// newTableProvisionerWithClient creates a TableProvisioner with a custom client.
// This is primarily used for testing with mock clients.
func newTableProvisionerWithClient(client dynamoDBProvisionerAPI, region string) *TableProvisioner {
	return &TableProvisioner{
		client: client,
		region: region,
	}
}

// ProvisionResult contains the result of a table provisioning operation.
type ProvisionResult struct {
	// TableName is the name of the table.
	TableName string `json:"table_name"`
	// Status indicates the operation result.
	Status ProvisionStatus `json:"status"`
	// ARN is the table ARN (set when created or exists).
	ARN string `json:"arn,omitempty"`
	// Error is the error if status is FAILED.
	Error error `json:"error,omitempty"`
}

// ProvisionPlan describes what would be created for a table.
type ProvisionPlan struct {
	// TableName is the name of the table.
	TableName string `json:"table_name"`
	// WouldCreate is true if the table would be created.
	WouldCreate bool `json:"would_create"`
	// GSIs lists the GSI names that would be created.
	GSIs []string `json:"gsis,omitempty"`
	// TTLAttribute is the TTL attribute that would be configured.
	TTLAttribute string `json:"ttl_attribute,omitempty"`
	// BillingMode is the billing mode that would be set.
	BillingMode string `json:"billing_mode,omitempty"`
	// EncryptionType is the encryption type that would be set.
	EncryptionType string `json:"encryption_type,omitempty"`
}

// Create provisions a DynamoDB table from the given schema.
// It is idempotent: if the table already exists and is ACTIVE, it returns StatusExists.
// If the table exists but is not ACTIVE, it waits for the table to become ACTIVE.
// TTL is configured after the table becomes ACTIVE.
func (p *TableProvisioner) Create(ctx context.Context, schema TableSchema) (*ProvisionResult, error) {
	if err := schema.Validate(); err != nil {
		return nil, fmt.Errorf("invalid schema: %w", err)
	}

	// Check if table exists
	status, arn, err := p.getTableStatus(ctx, schema.TableName)
	if err != nil {
		return nil, err
	}

	switch status {
	case "ACTIVE":
		// Table exists and is active
		return &ProvisionResult{
			TableName: schema.TableName,
			Status:    StatusExists,
			ARN:       arn,
		}, nil

	case "CREATING", "UPDATING":
		// Table exists but not ready, wait for it
		arn, err := p.waitForActive(ctx, schema.TableName)
		if err != nil {
			return &ProvisionResult{
				TableName: schema.TableName,
				Status:    StatusFailed,
				Error:     err,
			}, nil
		}
		return &ProvisionResult{
			TableName: schema.TableName,
			Status:    StatusExists,
			ARN:       arn,
		}, nil

	case "NOT_FOUND":
		// Table doesn't exist, create it
		input := schemaToCreateTableInput(schema)
		output, err := p.client.CreateTable(ctx, input)
		if err != nil {
			// Check if it's a resource in use error (concurrent creation)
			var riu *types.ResourceInUseException
			if errors.As(err, &riu) {
				// Another process created it, wait for it to be active
				arn, waitErr := p.waitForActive(ctx, schema.TableName)
				if waitErr != nil {
					return &ProvisionResult{
						TableName: schema.TableName,
						Status:    StatusFailed,
						Error:     waitErr,
					}, nil
				}
				return &ProvisionResult{
					TableName: schema.TableName,
					Status:    StatusExists,
					ARN:       arn,
				}, nil
			}
			wrappedErr := sentinelerrors.WrapDynamoDBError(err, schema.TableName, "CreateTable")
			return &ProvisionResult{
				TableName: schema.TableName,
				Status:    StatusFailed,
				Error:     wrappedErr,
			}, nil
		}

		// Wait for table to become active
		arn, err = p.waitForActive(ctx, schema.TableName)
		if err != nil {
			return &ProvisionResult{
				TableName: schema.TableName,
				Status:    StatusFailed,
				Error:     err,
			}, nil
		}

		// If ARN not set from wait, get from create output
		if arn == "" && output.TableDescription != nil {
			arn = aws.ToString(output.TableDescription.TableArn)
		}

		// Configure TTL if specified
		if schema.TTLAttribute != "" {
			if err := p.configureTTL(ctx, schema.TableName, schema.TTLAttribute); err != nil {
				return &ProvisionResult{
					TableName: schema.TableName,
					Status:    StatusFailed,
					ARN:       arn,
					Error:     fmt.Errorf("table created but TTL configuration failed: %w", err),
				}, nil
			}
		}

		return &ProvisionResult{
			TableName: schema.TableName,
			Status:    StatusCreated,
			ARN:       arn,
		}, nil

	default:
		// Unexpected status (DELETING, etc.)
		return &ProvisionResult{
			TableName: schema.TableName,
			Status:    StatusFailed,
			Error:     fmt.Errorf("table exists with unexpected status: %s", status),
		}, nil
	}
}

// Plan returns what would be created for the given schema without making changes.
// Plan shows what WOULD be created without checking table status.
// This allows users to see the schema before they have DynamoDB permissions.
// The plan always shows WouldCreate=true since we cannot check without permissions.
func (p *TableProvisioner) Plan(ctx context.Context, schema TableSchema) (*ProvisionPlan, error) {
	if err := schema.Validate(); err != nil {
		return nil, fmt.Errorf("invalid schema: %w", err)
	}

	// Plan shows what WOULD be created without checking table status.
	// This allows users to see the schema before they have DynamoDB permissions.
	// We always assume the table would be created since we can't check without permissions.
	plan := &ProvisionPlan{
		TableName:    schema.TableName,
		WouldCreate:  true, // Cannot check without permissions, show full schema
		GSIs:         schema.GSINames(),
		TTLAttribute: schema.TTLAttribute,
	}

	if schema.BillingMode != "" {
		plan.BillingMode = string(schema.BillingMode)
	} else {
		plan.BillingMode = string(BillingModePayPerRequest) // Default
	}

	// Set encryption type if configured
	if schema.Encryption != nil {
		plan.EncryptionType = string(schema.Encryption.Type)
	}

	return plan, nil
}

// TableStatus returns the current status of a table.
// Returns "NOT_FOUND" if the table doesn't exist.
func (p *TableProvisioner) TableStatus(ctx context.Context, tableName string) (string, error) {
	status, _, err := p.getTableStatus(ctx, tableName)
	return status, err
}

// getTableStatus checks if a table exists and returns its status and ARN.
// Returns ("NOT_FOUND", "", nil) if the table doesn't exist.
func (p *TableProvisioner) getTableStatus(ctx context.Context, tableName string) (string, string, error) {
	output, err := p.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		var rnf *types.ResourceNotFoundException
		if errors.As(err, &rnf) {
			return "NOT_FOUND", "", nil
		}
		wrappedErr := sentinelerrors.WrapDynamoDBError(err, tableName, "DescribeTable")
		return "", "", wrappedErr
	}

	if output.Table == nil {
		return "NOT_FOUND", "", nil
	}

	status := string(output.Table.TableStatus)
	arn := aws.ToString(output.Table.TableArn)
	return status, arn, nil
}

// waitForActive polls until the table reaches ACTIVE status or timeout.
func (p *TableProvisioner) waitForActive(ctx context.Context, tableName string) (string, error) {
	backoff := initialBackoff
	deadline := time.Now().Add(waitTimeout)

	for {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timeout waiting for table %s to become ACTIVE", tableName)
		}

		status, arn, err := p.getTableStatus(ctx, tableName)
		if err != nil {
			return "", err
		}

		if status == "ACTIVE" {
			return arn, nil
		}

		if status == "NOT_FOUND" || status == "DELETING" {
			return "", fmt.Errorf("table %s is %s", tableName, status)
		}

		// Wait before next poll with exponential backoff
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}

		// Increase backoff, capped at max
		backoff = backoff * 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// configureTTL enables TTL on the specified attribute.
func (p *TableProvisioner) configureTTL(ctx context.Context, tableName, ttlAttribute string) error {
	_, err := p.client.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(tableName),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			Enabled:       aws.Bool(true),
			AttributeName: aws.String(ttlAttribute),
		},
	})
	if err != nil {
		return sentinelerrors.WrapDynamoDBError(err, tableName, "UpdateTimeToLive")
	}
	return nil
}

// schemaToCreateTableInput converts a TableSchema to a DynamoDB CreateTableInput.
func schemaToCreateTableInput(schema TableSchema) *dynamodb.CreateTableInput {
	// Collect all unique attribute definitions
	attrDefs := make(map[string]types.AttributeDefinition)

	// Add table keys
	attrDefs[schema.PartitionKey.Name] = types.AttributeDefinition{
		AttributeName: aws.String(schema.PartitionKey.Name),
		AttributeType: types.ScalarAttributeType(schema.PartitionKey.Type),
	}

	if schema.SortKey != nil {
		attrDefs[schema.SortKey.Name] = types.AttributeDefinition{
			AttributeName: aws.String(schema.SortKey.Name),
			AttributeType: types.ScalarAttributeType(schema.SortKey.Type),
		}
	}

	// Add GSI keys
	for _, gsi := range schema.GlobalSecondaryIndexes {
		attrDefs[gsi.PartitionKey.Name] = types.AttributeDefinition{
			AttributeName: aws.String(gsi.PartitionKey.Name),
			AttributeType: types.ScalarAttributeType(gsi.PartitionKey.Type),
		}
		if gsi.SortKey != nil {
			attrDefs[gsi.SortKey.Name] = types.AttributeDefinition{
				AttributeName: aws.String(gsi.SortKey.Name),
				AttributeType: types.ScalarAttributeType(gsi.SortKey.Type),
			}
		}
	}

	// Convert to slice
	attrDefSlice := make([]types.AttributeDefinition, 0, len(attrDefs))
	for _, ad := range attrDefs {
		attrDefSlice = append(attrDefSlice, ad)
	}

	// Build key schema for table
	keySchema := []types.KeySchemaElement{
		{
			AttributeName: aws.String(schema.PartitionKey.Name),
			KeyType:       types.KeyTypeHash,
		},
	}
	if schema.SortKey != nil {
		keySchema = append(keySchema, types.KeySchemaElement{
			AttributeName: aws.String(schema.SortKey.Name),
			KeyType:       types.KeyTypeRange,
		})
	}

	// Build GSIs
	var gsis []types.GlobalSecondaryIndex
	for _, gsi := range schema.GlobalSecondaryIndexes {
		gsiKeySchema := []types.KeySchemaElement{
			{
				AttributeName: aws.String(gsi.PartitionKey.Name),
				KeyType:       types.KeyTypeHash,
			},
		}
		if gsi.SortKey != nil {
			gsiKeySchema = append(gsiKeySchema, types.KeySchemaElement{
				AttributeName: aws.String(gsi.SortKey.Name),
				KeyType:       types.KeyTypeRange,
			})
		}

		// Default to ALL projection if not specified
		projectionType := types.ProjectionTypeAll
		if gsi.Projection != "" {
			projectionType = types.ProjectionType(gsi.Projection)
		}

		gsis = append(gsis, types.GlobalSecondaryIndex{
			IndexName: aws.String(gsi.IndexName),
			KeySchema: gsiKeySchema,
			Projection: &types.Projection{
				ProjectionType: projectionType,
			},
		})
	}

	// Determine billing mode
	billingMode := types.BillingModePayPerRequest
	if schema.BillingMode != "" {
		billingMode = types.BillingMode(schema.BillingMode)
	}

	input := &dynamodb.CreateTableInput{
		TableName:            aws.String(schema.TableName),
		AttributeDefinitions: attrDefSlice,
		KeySchema:            keySchema,
		BillingMode:          billingMode,
	}

	if len(gsis) > 0 {
		input.GlobalSecondaryIndexes = gsis
	}

	// Add SSESpecification if encryption is configured
	if schema.Encryption != nil {
		switch schema.Encryption.Type {
		case EncryptionDefault:
			// DEFAULT uses AWS owned encryption (AES256)
			// DynamoDB default - no SSESpecification needed, but we can explicitly set it
			// Omit SSESpecification for DEFAULT to maintain backward compatibility
		case EncryptionKMS:
			// KMS uses AWS managed KMS key
			input.SSESpecification = &types.SSESpecification{
				Enabled: aws.Bool(true),
				SSEType: types.SSETypeKms,
			}
		case EncryptionCustomerKey:
			// Customer-provided CMK
			input.SSESpecification = &types.SSESpecification{
				Enabled:        aws.Bool(true),
				SSEType:        types.SSETypeKms,
				KMSMasterKeyId: aws.String(schema.Encryption.KMSKeyARN),
			}
		}
	}

	return input
}
