package deploy

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DefaultSentinelTablePrefix is the default prefix for Sentinel DynamoDB tables.
const DefaultSentinelTablePrefix = "sentinel-"

// dynamodbHardenAPI extends audit operations with hardening capabilities.
type dynamodbHardenAPI interface {
	// Audit operations (existing from dynamodbAuditAPI)
	DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	DescribeContinuousBackups(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error)

	// Discovery operations
	ListTables(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)

	// Hardening operations
	UpdateTable(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error)
	UpdateContinuousBackups(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error)
}

// DynamoDBHardener enables deletion protection and PITR on DynamoDB tables.
type DynamoDBHardener struct {
	client dynamodbHardenAPI
}

// TableProtectionStatus represents the current protection state of a table.
type TableProtectionStatus struct {
	TableName          string `json:"table_name"`
	DeletionProtection bool   `json:"deletion_protection"`
	PITREnabled        bool   `json:"pitr_enabled"`
	TableARN           string `json:"table_arn"`
}

// HardenResult contains the result of a hardening operation.
type HardenResult struct {
	TableName                 string `json:"table_name"`
	DeletionProtectionChanged bool   `json:"deletion_protection_changed"`
	PITRChanged               bool   `json:"pitr_changed"`
	Error                     error  `json:"error,omitempty"`
}

// NewDynamoDBHardener creates a new DynamoDBHardener using the provided AWS configuration.
func NewDynamoDBHardener(cfg aws.Config) *DynamoDBHardener {
	return &DynamoDBHardener{
		client: dynamodb.NewFromConfig(cfg),
	}
}

// NewDynamoDBHardenerWithClient creates a DynamoDBHardener with a custom client for testing.
func NewDynamoDBHardenerWithClient(client dynamodbHardenAPI) *DynamoDBHardener {
	return &DynamoDBHardener{
		client: client,
	}
}

// DiscoverSentinelTables finds all DynamoDB tables matching the Sentinel prefix pattern.
// Default prefix is "sentinel-" but can be customized.
func (h *DynamoDBHardener) DiscoverSentinelTables(ctx context.Context, prefix string) ([]string, error) {
	if prefix == "" {
		prefix = DefaultSentinelTablePrefix
	}

	var tables []string
	var lastEvaluatedTableName *string

	for {
		input := &dynamodb.ListTablesInput{
			ExclusiveStartTableName: lastEvaluatedTableName,
		}

		output, err := h.client.ListTables(ctx, input)
		if err != nil {
			return nil, err
		}

		for _, tableName := range output.TableNames {
			if strings.HasPrefix(tableName, prefix) {
				tables = append(tables, tableName)
			}
		}

		if output.LastEvaluatedTableName == nil {
			break
		}
		lastEvaluatedTableName = output.LastEvaluatedTableName
	}

	return tables, nil
}

// GetTableStatus returns the current protection status for a table.
func (h *DynamoDBHardener) GetTableStatus(ctx context.Context, tableName string) (*TableProtectionStatus, error) {
	status := &TableProtectionStatus{
		TableName: tableName,
	}

	// Get table description for deletion protection
	tableOutput, err := h.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return nil, err
	}

	if tableOutput.Table != nil {
		status.DeletionProtection = tableOutput.Table.DeletionProtectionEnabled
		if tableOutput.Table.TableArn != nil {
			status.TableARN = *tableOutput.Table.TableArn
		}
	}

	// Get PITR status
	backupsOutput, err := h.client.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		// If we can't get PITR status, we still have deletion protection info
		// Return what we have rather than failing completely
		if isAccessDenied(err) {
			return status, nil
		}
		return nil, err
	}

	if backupsOutput.ContinuousBackupsDescription != nil &&
		backupsOutput.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
		pitrStatus := backupsOutput.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus
		status.PITREnabled = pitrStatus == dbtypes.PointInTimeRecoveryStatusEnabled
	}

	return status, nil
}

// HardenTable enables deletion protection and PITR on a table.
// It is idempotent: if protections are already enabled, it reports no changes.
func (h *DynamoDBHardener) HardenTable(ctx context.Context, tableName string, enableDeletionProtection, enablePITR bool) (*HardenResult, error) {
	result := &HardenResult{
		TableName: tableName,
	}

	// Get current status
	status, err := h.GetTableStatus(ctx, tableName)
	if err != nil {
		result.Error = err
		return result, err
	}

	// Enable deletion protection if requested and not already enabled
	if enableDeletionProtection && !status.DeletionProtection {
		_, err := h.client.UpdateTable(ctx, &dynamodb.UpdateTableInput{
			TableName:                 aws.String(tableName),
			DeletionProtectionEnabled: aws.Bool(true),
		})
		if err != nil {
			result.Error = err
			return result, err
		}
		result.DeletionProtectionChanged = true
	}

	// Enable PITR if requested and not already enabled
	if enablePITR && !status.PITREnabled {
		_, err := h.client.UpdateContinuousBackups(ctx, &dynamodb.UpdateContinuousBackupsInput{
			TableName: aws.String(tableName),
			PointInTimeRecoverySpecification: &dbtypes.PointInTimeRecoverySpecification{
				PointInTimeRecoveryEnabled: aws.Bool(true),
			},
		})
		if err != nil {
			result.Error = err
			return result, err
		}
		result.PITRChanged = true
	}

	return result, nil
}

// HardenTables applies hardening to multiple tables.
// Returns results for each table including any errors.
// Unlike HardenTable, this continues on individual table failures and collects all results.
func (h *DynamoDBHardener) HardenTables(ctx context.Context, tableNames []string, enableDeletionProtection, enablePITR bool) ([]*HardenResult, error) {
	var results []*HardenResult

	for _, tableName := range tableNames {
		result, err := h.HardenTable(ctx, tableName, enableDeletionProtection, enablePITR)
		if err != nil {
			// Store error in result but continue with other tables
			result.Error = err
		}
		results = append(results, result)
	}

	return results, nil
}
