package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ============================================================================
// Mock Client for DynamoDB Hardening
// ============================================================================

// mockDynamoDBHardenClient implements dynamodbHardenAPI for testing.
type mockDynamoDBHardenClient struct {
	DescribeTableFunc             func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	DescribeContinuousBackupsFunc func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error)
	ListTablesFunc                func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	UpdateTableFunc               func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error)
	UpdateContinuousBackupsFunc   func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error)
}

func (m *mockDynamoDBHardenClient) DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if m.DescribeTableFunc != nil {
		return m.DescribeTableFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribeTable not implemented")
}

func (m *mockDynamoDBHardenClient) DescribeContinuousBackups(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	if m.DescribeContinuousBackupsFunc != nil {
		return m.DescribeContinuousBackupsFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribeContinuousBackups not implemented")
}

func (m *mockDynamoDBHardenClient) ListTables(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	if m.ListTablesFunc != nil {
		return m.ListTablesFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListTables not implemented")
}

func (m *mockDynamoDBHardenClient) UpdateTable(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
	if m.UpdateTableFunc != nil {
		return m.UpdateTableFunc(ctx, params, optFns...)
	}
	return nil, errors.New("UpdateTable not implemented")
}

func (m *mockDynamoDBHardenClient) UpdateContinuousBackups(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
	if m.UpdateContinuousBackupsFunc != nil {
		return m.UpdateContinuousBackupsFunc(ctx, params, optFns...)
	}
	return nil, errors.New("UpdateContinuousBackups not implemented")
}

// ============================================================================
// DiscoverSentinelTables Tests
// ============================================================================

func TestDynamoDBHardener_DiscoverSentinelTables_DefaultPrefix(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{
					"sentinel-requests",
					"sentinel-breakglass",
					"sentinel-sessions",
					"other-table",
					"my-app-data",
				},
			}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	tables, err := hardener.DiscoverSentinelTables(ctx, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tables) != 3 {
		t.Fatalf("expected 3 tables, got %d: %v", len(tables), tables)
	}

	// Verify all tables have sentinel- prefix
	for _, table := range tables {
		if table != "sentinel-requests" && table != "sentinel-breakglass" && table != "sentinel-sessions" {
			t.Errorf("unexpected table: %s", table)
		}
	}
}

func TestDynamoDBHardener_DiscoverSentinelTables_CustomPrefix(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{
					"myorg-sentinel-requests",
					"myorg-sentinel-sessions",
					"sentinel-requests",
					"other-table",
				},
			}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	tables, err := hardener.DiscoverSentinelTables(ctx, "myorg-sentinel-")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tables) != 2 {
		t.Fatalf("expected 2 tables, got %d: %v", len(tables), tables)
	}
}

func TestDynamoDBHardener_DiscoverSentinelTables_Pagination(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	client := &mockDynamoDBHardenClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			callCount++
			if callCount == 1 {
				return &dynamodb.ListTablesOutput{
					TableNames:             []string{"sentinel-requests", "other-table"},
					LastEvaluatedTableName: aws.String("other-table"),
				}, nil
			}
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"sentinel-sessions", "sentinel-breakglass"},
			}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	tables, err := hardener.DiscoverSentinelTables(ctx, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 API calls for pagination, got %d", callCount)
	}

	if len(tables) != 3 {
		t.Fatalf("expected 3 tables across pages, got %d: %v", len(tables), tables)
	}
}

func TestDynamoDBHardener_DiscoverSentinelTables_NoMatches(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"other-table", "my-app-data"},
			}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	tables, err := hardener.DiscoverSentinelTables(ctx, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tables) != 0 {
		t.Errorf("expected 0 tables, got %d: %v", len(tables), tables)
	}
}

// ============================================================================
// GetTableStatus Tests
// ============================================================================

func TestDynamoDBHardener_GetTableStatus_BothEnabled(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 aws.String("sentinel-requests"),
					TableArn:                  aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/sentinel-requests"),
					DeletionProtectionEnabled: aws.Bool(true),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusEnabled,
					},
				},
			}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	status, err := hardener.GetTableStatus(ctx, "sentinel-requests")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !status.DeletionProtection {
		t.Error("expected DeletionProtection=true")
	}
	if !status.PITREnabled {
		t.Error("expected PITREnabled=true")
	}
	if status.TableARN != "arn:aws:dynamodb:us-east-1:123456789012:table/sentinel-requests" {
		t.Errorf("unexpected TableARN: %s", status.TableARN)
	}
}

func TestDynamoDBHardener_GetTableStatus_BothDisabled(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 aws.String("sentinel-sessions"),
					TableArn:                  aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/sentinel-sessions"),
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	status, err := hardener.GetTableStatus(ctx, "sentinel-sessions")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.DeletionProtection {
		t.Error("expected DeletionProtection=false")
	}
	if status.PITREnabled {
		t.Error("expected PITREnabled=false")
	}
}

func TestDynamoDBHardener_GetTableStatus_MixedState(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 aws.String("sentinel-breakglass"),
					TableArn:                  aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/sentinel-breakglass"),
					DeletionProtectionEnabled: aws.Bool(true),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	status, err := hardener.GetTableStatus(ctx, "sentinel-breakglass")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !status.DeletionProtection {
		t.Error("expected DeletionProtection=true")
	}
	if status.PITREnabled {
		t.Error("expected PITREnabled=false")
	}
}

// ============================================================================
// HardenTable Tests
// ============================================================================

func TestDynamoDBHardener_HardenTable_BothProtections(t *testing.T) {
	ctx := context.Background()

	updateTableCalled := false
	updateBackupsCalled := false

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 aws.String("sentinel-requests"),
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			updateTableCalled = true
			if !*params.DeletionProtectionEnabled {
				t.Error("expected DeletionProtectionEnabled=true")
			}
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			updateBackupsCalled = true
			if !*params.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled {
				t.Error("expected PointInTimeRecoveryEnabled=true")
			}
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	result, err := hardener.HardenTable(ctx, "sentinel-requests", true, true)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !updateTableCalled {
		t.Error("expected UpdateTable to be called")
	}
	if !updateBackupsCalled {
		t.Error("expected UpdateContinuousBackups to be called")
	}
	if !result.DeletionProtectionChanged {
		t.Error("expected DeletionProtectionChanged=true")
	}
	if !result.PITRChanged {
		t.Error("expected PITRChanged=true")
	}
}

func TestDynamoDBHardener_HardenTable_AlreadyEnabled(t *testing.T) {
	ctx := context.Background()

	updateTableCalled := false
	updateBackupsCalled := false

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 aws.String("sentinel-requests"),
					DeletionProtectionEnabled: aws.Bool(true),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusEnabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			updateTableCalled = true
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			updateBackupsCalled = true
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	result, err := hardener.HardenTable(ctx, "sentinel-requests", true, true)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not call update APIs when already enabled
	if updateTableCalled {
		t.Error("expected UpdateTable NOT to be called when already enabled")
	}
	if updateBackupsCalled {
		t.Error("expected UpdateContinuousBackups NOT to be called when already enabled")
	}
	if result.DeletionProtectionChanged {
		t.Error("expected DeletionProtectionChanged=false when already enabled")
	}
	if result.PITRChanged {
		t.Error("expected PITRChanged=false when already enabled")
	}
}

func TestDynamoDBHardener_HardenTable_PartialEnable(t *testing.T) {
	ctx := context.Background()

	updateTableCalled := false
	updateBackupsCalled := false

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 aws.String("sentinel-breakglass"),
					DeletionProtectionEnabled: aws.Bool(true), // Already enabled
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled, // Needs enabling
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			updateTableCalled = true
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			updateBackupsCalled = true
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	result, err := hardener.HardenTable(ctx, "sentinel-breakglass", true, true)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only call PITR update since deletion protection is already enabled
	if updateTableCalled {
		t.Error("expected UpdateTable NOT to be called when deletion protection already enabled")
	}
	if !updateBackupsCalled {
		t.Error("expected UpdateContinuousBackups to be called for PITR")
	}
	if result.DeletionProtectionChanged {
		t.Error("expected DeletionProtectionChanged=false")
	}
	if !result.PITRChanged {
		t.Error("expected PITRChanged=true")
	}
}

func TestDynamoDBHardener_HardenTable_OnlyDeletionProtection(t *testing.T) {
	ctx := context.Background()

	updateTableCalled := false
	updateBackupsCalled := false

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 aws.String("sentinel-requests"),
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			updateTableCalled = true
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			updateBackupsCalled = true
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	// Only enable deletion protection, skip PITR
	result, err := hardener.HardenTable(ctx, "sentinel-requests", true, false)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !updateTableCalled {
		t.Error("expected UpdateTable to be called")
	}
	if updateBackupsCalled {
		t.Error("expected UpdateContinuousBackups NOT to be called when enablePITR=false")
	}
	if !result.DeletionProtectionChanged {
		t.Error("expected DeletionProtectionChanged=true")
	}
	if result.PITRChanged {
		t.Error("expected PITRChanged=false")
	}
}

// ============================================================================
// HardenTables Tests
// ============================================================================

func TestDynamoDBHardener_HardenTables_BatchOperation(t *testing.T) {
	ctx := context.Background()

	tableStatuses := map[string]bool{
		"sentinel-requests":   false, // Needs hardening
		"sentinel-sessions":   false, // Needs hardening
		"sentinel-breakglass": true,  // Already hardened
	}
	hardenedTables := make(map[string]bool)

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			tableName := *params.TableName
			isEnabled := tableStatuses[tableName]
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: &isEnabled,
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			tableName := *params.TableName
			status := dbtypes.PointInTimeRecoveryStatusDisabled
			if tableStatuses[tableName] {
				status = dbtypes.PointInTimeRecoveryStatusEnabled
			}
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: status,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			hardenedTables[*params.TableName] = true
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	results, err := hardener.HardenTables(ctx, []string{"sentinel-requests", "sentinel-sessions", "sentinel-breakglass"}, true, true)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Check that only the tables that needed hardening were updated
	if !hardenedTables["sentinel-requests"] {
		t.Error("expected sentinel-requests to be hardened")
	}
	if !hardenedTables["sentinel-sessions"] {
		t.Error("expected sentinel-sessions to be hardened")
	}
	if hardenedTables["sentinel-breakglass"] {
		t.Error("expected sentinel-breakglass NOT to be hardened (already protected)")
	}
}

func TestDynamoDBHardener_HardenTables_PartialFailure(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			if *params.TableName == "sentinel-bad-table" {
				return nil, errors.New("AccessDeniedException: User not authorized")
			}
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	results, err := hardener.HardenTables(ctx, []string{"sentinel-requests", "sentinel-bad-table", "sentinel-sessions"}, true, true)

	// HardenTables should not return error even on partial failure
	if err != nil {
		t.Fatalf("unexpected error from HardenTables: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Check that the first table succeeded
	if results[0].Error != nil {
		t.Errorf("expected sentinel-requests to succeed, got error: %v", results[0].Error)
	}
	if !results[0].DeletionProtectionChanged {
		t.Error("expected sentinel-requests DeletionProtectionChanged=true")
	}

	// Check that the second table failed
	if results[1].Error == nil {
		t.Error("expected sentinel-bad-table to have error")
	}

	// Check that the third table succeeded
	if results[2].Error != nil {
		t.Errorf("expected sentinel-sessions to succeed, got error: %v", results[2].Error)
	}
	if !results[2].DeletionProtectionChanged {
		t.Error("expected sentinel-sessions DeletionProtectionChanged=true")
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestDynamoDBHardener_DiscoverSentinelTables_AccessDenied(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return nil, errors.New("AccessDeniedException: User not authorized to perform dynamodb:ListTables")
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	_, err := hardener.DiscoverSentinelTables(ctx, "")

	if err == nil {
		t.Fatal("expected error for access denied")
	}
}

func TestDynamoDBHardener_HardenTable_UpdateTableError(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			return nil, errors.New("ValidationException: Table is in a state that does not allow update")
		},
	}

	hardener := NewDynamoDBHardenerWithClient(client)
	result, err := hardener.HardenTable(ctx, "sentinel-requests", true, true)

	if err == nil {
		t.Fatal("expected error for update table failure")
	}

	if result.Error == nil {
		t.Error("expected result.Error to be set")
	}
}
