package infrastructure

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// mockDynamoDBProvisionerClient implements dynamoDBProvisionerAPI for testing.
type mockDynamoDBProvisionerClient struct {
	mu                   sync.Mutex
	createTableFunc      func(ctx context.Context, params *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error)
	describeTableFunc    func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	updateTimeToLiveFunc func(ctx context.Context, params *dynamodb.UpdateTimeToLiveInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTimeToLiveOutput, error)
	createTableCalls     []string
	describeTableCalls   []string
	ttlCalls             []string
}

func (m *mockDynamoDBProvisionerClient) CreateTable(ctx context.Context, params *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error) {
	m.mu.Lock()
	m.createTableCalls = append(m.createTableCalls, aws.ToString(params.TableName))
	m.mu.Unlock()
	if m.createTableFunc != nil {
		return m.createTableFunc(ctx, params, optFns...)
	}
	return &dynamodb.CreateTableOutput{
		TableDescription: &types.TableDescription{
			TableName:   params.TableName,
			TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/" + aws.ToString(params.TableName)),
			TableStatus: types.TableStatusCreating,
		},
	}, nil
}

func (m *mockDynamoDBProvisionerClient) DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	m.mu.Lock()
	m.describeTableCalls = append(m.describeTableCalls, aws.ToString(params.TableName))
	m.mu.Unlock()
	if m.describeTableFunc != nil {
		return m.describeTableFunc(ctx, params, optFns...)
	}
	return nil, &types.ResourceNotFoundException{}
}

func (m *mockDynamoDBProvisionerClient) UpdateTimeToLive(ctx context.Context, params *dynamodb.UpdateTimeToLiveInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTimeToLiveOutput, error) {
	m.mu.Lock()
	m.ttlCalls = append(m.ttlCalls, aws.ToString(params.TableName))
	m.mu.Unlock()
	if m.updateTimeToLiveFunc != nil {
		return m.updateTimeToLiveFunc(ctx, params, optFns...)
	}
	return &dynamodb.UpdateTimeToLiveOutput{}, nil
}

// validSchema returns a valid TableSchema for testing.
func validSchema() TableSchema {
	return TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		BillingMode:  BillingModePayPerRequest,
	}
}

// validSchemaWithTTL returns a valid TableSchema with TTL for testing.
func validSchemaWithTTL() TableSchema {
	return TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		TTLAttribute: "ttl",
		BillingMode:  BillingModePayPerRequest,
	}
}

// ============================================================================
// Create() Tests
// ============================================================================

func TestTableProvisioner_Create_TableNotExists_Success(t *testing.T) {
	describeCallCount := 0
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			describeCallCount++
			// First call: table not found
			if describeCallCount == 1 {
				return nil, &types.ResourceNotFoundException{}
			}
			// Subsequent calls: table is active
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/test-table"),
					TableStatus: types.TableStatusActive,
				},
			}, nil
		},
		createTableFunc: func(ctx context.Context, params *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error) {
			return &dynamodb.CreateTableOutput{
				TableDescription: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/test-table"),
					TableStatus: types.TableStatusCreating,
				},
			}, nil
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	result, err := provisioner.Create(context.Background(), validSchema())

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Status != StatusCreated {
		t.Errorf("expected status CREATED, got %v", result.Status)
	}
	if result.TableName != "test-table" {
		t.Errorf("expected table name test-table, got %s", result.TableName)
	}
	if result.ARN == "" {
		t.Error("expected non-empty ARN")
	}
	if len(mock.createTableCalls) != 1 {
		t.Errorf("expected 1 CreateTable call, got %d", len(mock.createTableCalls))
	}
}

func TestTableProvisioner_Create_TableNotExists_WithTTL(t *testing.T) {
	describeCallCount := 0
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			describeCallCount++
			if describeCallCount == 1 {
				return nil, &types.ResourceNotFoundException{}
			}
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/test-table"),
					TableStatus: types.TableStatusActive,
				},
			}, nil
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	result, err := provisioner.Create(context.Background(), validSchemaWithTTL())

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Status != StatusCreated {
		t.Errorf("expected status CREATED, got %v", result.Status)
	}
	// Verify TTL was configured
	if len(mock.ttlCalls) != 1 {
		t.Errorf("expected 1 UpdateTimeToLive call, got %d", len(mock.ttlCalls))
	}
}

func TestTableProvisioner_Create_TableExists_Active(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/test-table"),
					TableStatus: types.TableStatusActive,
				},
			}, nil
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	result, err := provisioner.Create(context.Background(), validSchema())

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Status != StatusExists {
		t.Errorf("expected status EXISTS, got %v", result.Status)
	}
	if result.ARN == "" {
		t.Error("expected non-empty ARN")
	}
	// Should NOT call CreateTable
	if len(mock.createTableCalls) != 0 {
		t.Errorf("expected 0 CreateTable calls, got %d", len(mock.createTableCalls))
	}
}

func TestTableProvisioner_Create_TableExists_Creating(t *testing.T) {
	describeCallCount := 0
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			describeCallCount++
			// First call: CREATING, then ACTIVE
			status := types.TableStatusCreating
			if describeCallCount > 1 {
				status = types.TableStatusActive
			}
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/test-table"),
					TableStatus: status,
				},
			}, nil
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	result, err := provisioner.Create(context.Background(), validSchema())

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Status != StatusExists {
		t.Errorf("expected status EXISTS, got %v", result.Status)
	}
	// Should NOT call CreateTable (table already being created)
	if len(mock.createTableCalls) != 0 {
		t.Errorf("expected 0 CreateTable calls, got %d", len(mock.createTableCalls))
	}
	// Should have polled DescribeTable multiple times
	if describeCallCount < 2 {
		t.Errorf("expected at least 2 DescribeTable calls for polling, got %d", describeCallCount)
	}
}

func TestTableProvisioner_Create_AccessDenied(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, &types.ResourceNotFoundException{}
		},
		createTableFunc: func(ctx context.Context, params *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error) {
			return nil, errors.New("AccessDeniedException: User is not authorized")
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	result, err := provisioner.Create(context.Background(), validSchema())

	if err != nil {
		t.Fatalf("Create() should not return error, got %v", err)
	}
	if result.Status != StatusFailed {
		t.Errorf("expected status FAILED, got %v", result.Status)
	}
	if result.Error == nil {
		t.Error("expected non-nil error in result")
	}
}

func TestTableProvisioner_Create_ConcurrentCreation(t *testing.T) {
	// Simulate ResourceInUseException when another process creates the table
	describeCallCount := 0
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			describeCallCount++
			if describeCallCount == 1 {
				// First check: not found
				return nil, &types.ResourceNotFoundException{}
			}
			// After create attempt: table is active (created by other process)
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/test-table"),
					TableStatus: types.TableStatusActive,
				},
			}, nil
		},
		createTableFunc: func(ctx context.Context, params *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error) {
			// Another process created the table
			return nil, &types.ResourceInUseException{Message: aws.String("Table already exists")}
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	result, err := provisioner.Create(context.Background(), validSchema())

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	// Should succeed with EXISTS status (table was created by another process)
	if result.Status != StatusExists {
		t.Errorf("expected status EXISTS, got %v", result.Status)
	}
}

func TestTableProvisioner_Create_WaitTimeout(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			// Always return CREATING to simulate timeout
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/test-table"),
					TableStatus: types.TableStatusCreating,
				},
			}, nil
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")

	// Use a context with timeout to simulate wait timeout faster
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result, err := provisioner.Create(ctx, validSchema())

	if err != nil {
		t.Fatalf("Create() should not return error, got %v", err)
	}
	if result.Status != StatusFailed {
		t.Errorf("expected status FAILED, got %v", result.Status)
	}
	if result.Error == nil {
		t.Error("expected non-nil error in result")
	}
}

func TestTableProvisioner_Create_TTLConfigFails(t *testing.T) {
	describeCallCount := 0
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			describeCallCount++
			if describeCallCount == 1 {
				return nil, &types.ResourceNotFoundException{}
			}
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/test-table"),
					TableStatus: types.TableStatusActive,
				},
			}, nil
		},
		updateTimeToLiveFunc: func(ctx context.Context, params *dynamodb.UpdateTimeToLiveInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTimeToLiveOutput, error) {
			return nil, errors.New("ValidationException: TTL is already enabled")
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	result, err := provisioner.Create(context.Background(), validSchemaWithTTL())

	if err != nil {
		t.Fatalf("Create() should not return error, got %v", err)
	}
	if result.Status != StatusFailed {
		t.Errorf("expected status FAILED (TTL config failed), got %v", result.Status)
	}
	if result.Error == nil {
		t.Error("expected non-nil error in result")
	}
	if !strings.Contains(result.Error.Error(), "TTL") {
		t.Errorf("expected error to mention TTL, got: %v", result.Error)
	}
	// ARN should still be set since table was created
	if result.ARN == "" {
		t.Error("expected ARN to be set even though TTL failed")
	}
}

func TestTableProvisioner_Create_InvalidSchema(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{}
	provisioner := newTableProvisionerWithClient(mock, "us-east-1")

	// Invalid schema (no table name)
	invalidSchema := TableSchema{
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
	}

	_, err := provisioner.Create(context.Background(), invalidSchema)

	if err == nil {
		t.Error("expected error for invalid schema")
	}
	if !strings.Contains(err.Error(), "invalid schema") {
		t.Errorf("expected 'invalid schema' in error, got: %v", err)
	}
}

func TestTableProvisioner_Create_TableDeleting(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/test-table"),
					TableStatus: types.TableStatusDeleting,
				},
			}, nil
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	result, err := provisioner.Create(context.Background(), validSchema())

	if err != nil {
		t.Fatalf("Create() should not return error, got %v", err)
	}
	if result.Status != StatusFailed {
		t.Errorf("expected status FAILED for DELETING table, got %v", result.Status)
	}
	if !strings.Contains(result.Error.Error(), "unexpected status") {
		t.Errorf("expected 'unexpected status' in error, got: %v", result.Error)
	}
}

// ============================================================================
// Plan() Tests
// ============================================================================

func TestTableProvisioner_Plan_ShowsSchema(t *testing.T) {
	// Plan() now shows what WOULD be created without checking table status.
	// This allows users to see the schema before they have DynamoDB permissions.
	mock := &mockDynamoDBProvisionerClient{}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	plan, err := provisioner.Plan(context.Background(), validSchemaWithTTL())

	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	// Plan always shows WouldCreate=true since we can't check without permissions
	if !plan.WouldCreate {
		t.Error("expected WouldCreate=true")
	}
	if plan.TableName != "test-table" {
		t.Errorf("expected table name test-table, got %s", plan.TableName)
	}
	if plan.TTLAttribute != "ttl" {
		t.Errorf("expected TTL attribute 'ttl', got %s", plan.TTLAttribute)
	}
	if plan.BillingMode != "PAY_PER_REQUEST" {
		t.Errorf("expected billing mode PAY_PER_REQUEST, got %s", plan.BillingMode)
	}
	// Verify DescribeTable was NOT called (Plan() doesn't check table status)
	if len(mock.describeTableCalls) != 0 {
		t.Errorf("expected 0 DescribeTable calls, got %d", len(mock.describeTableCalls))
	}
}

func TestTableProvisioner_Plan_AlwaysShowsFullSchema(t *testing.T) {
	// Plan() no longer queries DynamoDB - it shows the full schema that WOULD be created.
	// This is by design: users can see what will be created before they have permissions.
	mock := &mockDynamoDBProvisionerClient{}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	plan, err := provisioner.Plan(context.Background(), validSchema())

	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	// Plan always shows WouldCreate=true (cannot check without permissions)
	if !plan.WouldCreate {
		t.Error("expected WouldCreate=true (Plan always assumes create)")
	}
	// Verify DescribeTable was NOT called
	if len(mock.describeTableCalls) != 0 {
		t.Errorf("expected 0 DescribeTable calls, got %d", len(mock.describeTableCalls))
	}
}

func TestTableProvisioner_Plan_WithGSIs(t *testing.T) {
	// Plan() shows GSI configuration without querying DynamoDB
	mock := &mockDynamoDBProvisionerClient{}

	schema := ApprovalTableSchema("sentinel-requests")
	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	plan, err := provisioner.Plan(context.Background(), schema)

	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if !plan.WouldCreate {
		t.Error("expected WouldCreate=true")
	}
	if len(plan.GSIs) != 3 {
		t.Errorf("expected 3 GSIs, got %d", len(plan.GSIs))
	}
	// Verify DescribeTable was NOT called
	if len(mock.describeTableCalls) != 0 {
		t.Errorf("expected 0 DescribeTable calls, got %d", len(mock.describeTableCalls))
	}
}

func TestTableProvisioner_Plan_NoPermissionsRequired(t *testing.T) {
	// Plan() should work even without DynamoDB permissions.
	// This allows users to see the schema before requesting access.
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			// This should NOT be called since Plan() doesn't query DynamoDB
			return nil, errors.New("AccessDeniedException: Not authorized")
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	plan, err := provisioner.Plan(context.Background(), validSchema())

	// Plan should succeed without calling DynamoDB
	if err != nil {
		t.Errorf("Plan() should not require permissions, got error: %v", err)
	}
	if plan == nil {
		t.Fatal("expected non-nil plan")
	}
	if !plan.WouldCreate {
		t.Error("expected WouldCreate=true")
	}
	// Verify DescribeTable was NOT called
	if len(mock.describeTableCalls) != 0 {
		t.Errorf("expected 0 DescribeTable calls (Plan should not query DynamoDB), got %d", len(mock.describeTableCalls))
	}
}

func TestTableProvisioner_Plan_InvalidSchema(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{}
	provisioner := newTableProvisionerWithClient(mock, "us-east-1")

	invalidSchema := TableSchema{
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
	}

	_, err := provisioner.Plan(context.Background(), invalidSchema)

	if err == nil {
		t.Error("expected error for invalid schema")
	}
}

// ============================================================================
// TableStatus() Tests
// ============================================================================

func TestTableProvisioner_TableStatus_Exists(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableStatus: types.TableStatusActive,
				},
			}, nil
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	status, err := provisioner.TableStatus(context.Background(), "test-table")

	if err != nil {
		t.Fatalf("TableStatus() error = %v", err)
	}
	if status != "ACTIVE" {
		t.Errorf("expected status ACTIVE, got %s", status)
	}
}

func TestTableProvisioner_TableStatus_NotFound(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, &types.ResourceNotFoundException{}
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	status, err := provisioner.TableStatus(context.Background(), "test-table")

	if err != nil {
		t.Fatalf("TableStatus() error = %v", err)
	}
	if status != "NOT_FOUND" {
		t.Errorf("expected status NOT_FOUND, got %s", status)
	}
}

func TestTableProvisioner_TableStatus_APIError(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, errors.New("InternalServerError")
		},
	}

	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	_, err := provisioner.TableStatus(context.Background(), "test-table")

	if err == nil {
		t.Error("expected error for API failure")
	}
}

// ============================================================================
// schemaToCreateTableInput() Tests
// ============================================================================

func TestSchemaToCreateTableInput_PartitionKeyOnly(t *testing.T) {
	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		BillingMode:  BillingModePayPerRequest,
	}

	input := schemaToCreateTableInput(schema)

	if aws.ToString(input.TableName) != "test-table" {
		t.Errorf("expected table name test-table, got %s", aws.ToString(input.TableName))
	}
	if len(input.KeySchema) != 1 {
		t.Errorf("expected 1 key schema element, got %d", len(input.KeySchema))
	}
	if aws.ToString(input.KeySchema[0].AttributeName) != "id" {
		t.Errorf("expected key name 'id', got %s", aws.ToString(input.KeySchema[0].AttributeName))
	}
	if input.KeySchema[0].KeyType != types.KeyTypeHash {
		t.Errorf("expected key type HASH, got %v", input.KeySchema[0].KeyType)
	}
	if input.BillingMode != types.BillingModePayPerRequest {
		t.Errorf("expected PAY_PER_REQUEST, got %v", input.BillingMode)
	}
}

func TestSchemaToCreateTableInput_WithSortKey(t *testing.T) {
	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
		SortKey:      &KeyAttribute{Name: "sk", Type: KeyTypeNumber},
		BillingMode:  BillingModeProvisioned,
	}

	input := schemaToCreateTableInput(schema)

	if len(input.KeySchema) != 2 {
		t.Errorf("expected 2 key schema elements, got %d", len(input.KeySchema))
	}
	// Find the range key
	var hasRangeKey bool
	for _, ks := range input.KeySchema {
		if ks.KeyType == types.KeyTypeRange {
			hasRangeKey = true
			if aws.ToString(ks.AttributeName) != "sk" {
				t.Errorf("expected range key 'sk', got %s", aws.ToString(ks.AttributeName))
			}
		}
	}
	if !hasRangeKey {
		t.Error("expected range key in key schema")
	}
}

func TestSchemaToCreateTableInput_WithGSIs(t *testing.T) {
	schema := ApprovalTableSchema("sentinel-requests")
	input := schemaToCreateTableInput(schema)

	if len(input.GlobalSecondaryIndexes) != 3 {
		t.Errorf("expected 3 GSIs, got %d", len(input.GlobalSecondaryIndexes))
	}

	// Verify each GSI has correct structure
	for _, gsi := range input.GlobalSecondaryIndexes {
		if aws.ToString(gsi.IndexName) == "" {
			t.Error("expected non-empty index name")
		}
		if len(gsi.KeySchema) < 1 {
			t.Error("expected at least 1 key in GSI key schema")
		}
		if gsi.Projection == nil || gsi.Projection.ProjectionType != types.ProjectionTypeAll {
			t.Errorf("expected projection type ALL, got %v", gsi.Projection)
		}
	}
}

func TestSchemaToCreateTableInput_UniqueAttributeDefinitions(t *testing.T) {
	// Schema with GSIs that share attributes (e.g., created_at used in multiple GSIs)
	schema := ApprovalTableSchema("test-table")
	input := schemaToCreateTableInput(schema)

	// Count unique attribute names
	attrNames := make(map[string]bool)
	for _, attr := range input.AttributeDefinitions {
		name := aws.ToString(attr.AttributeName)
		if attrNames[name] {
			t.Errorf("duplicate attribute definition for %s", name)
		}
		attrNames[name] = true
	}

	// Should have: id, requester, status, profile, created_at = 5 unique
	if len(attrNames) != 5 {
		t.Errorf("expected 5 unique attribute definitions, got %d: %v", len(attrNames), attrNames)
	}
}

func TestSchemaToCreateTableInput_DefaultBillingMode(t *testing.T) {
	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		// No BillingMode specified
	}

	input := schemaToCreateTableInput(schema)

	if input.BillingMode != types.BillingModePayPerRequest {
		t.Errorf("expected default PAY_PER_REQUEST, got %v", input.BillingMode)
	}
}

func TestSchemaToCreateTableInput_DefaultProjection(t *testing.T) {
	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		GlobalSecondaryIndexes: []GSISchema{
			{
				IndexName:    "gsi-test",
				PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
				// No Projection specified
			},
		},
	}

	input := schemaToCreateTableInput(schema)

	if len(input.GlobalSecondaryIndexes) != 1 {
		t.Fatalf("expected 1 GSI, got %d", len(input.GlobalSecondaryIndexes))
	}
	if input.GlobalSecondaryIndexes[0].Projection.ProjectionType != types.ProjectionTypeAll {
		t.Errorf("expected default projection ALL, got %v", input.GlobalSecondaryIndexes[0].Projection.ProjectionType)
	}
}

// ============================================================================
// ProvisionStatus Tests
// ============================================================================

func TestProvisionStatus_Constants(t *testing.T) {
	// Verify constants are correct strings
	if StatusCreated != "CREATED" {
		t.Errorf("StatusCreated = %q, want CREATED", StatusCreated)
	}
	if StatusExists != "EXISTS" {
		t.Errorf("StatusExists = %q, want EXISTS", StatusExists)
	}
	if StatusFailed != "FAILED" {
		t.Errorf("StatusFailed = %q, want FAILED", StatusFailed)
	}
}

// ============================================================================
// Constructor Tests
// ============================================================================

func TestNewTableProvisionerWithClient(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{}
	provisioner := newTableProvisionerWithClient(mock, "us-west-2")

	if provisioner.client != mock {
		t.Error("expected mock client to be set")
	}
	if provisioner.region != "us-west-2" {
		t.Errorf("expected region us-west-2, got %s", provisioner.region)
	}
}

// ============================================================================
// Integration-style Tests (using ApprovalTableSchema)
// ============================================================================

func TestTableProvisioner_Create_ApprovalTableSchema(t *testing.T) {
	describeCallCount := 0
	mock := &mockDynamoDBProvisionerClient{
		describeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			describeCallCount++
			if describeCallCount == 1 {
				return nil, &types.ResourceNotFoundException{}
			}
			return &dynamodb.DescribeTableOutput{
				Table: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/sentinel-requests"),
					TableStatus: types.TableStatusActive,
				},
			}, nil
		},
		createTableFunc: func(ctx context.Context, params *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error) {
			// Verify the CreateTable input has correct structure
			if len(params.GlobalSecondaryIndexes) != 3 {
				t.Errorf("expected 3 GSIs in CreateTable, got %d", len(params.GlobalSecondaryIndexes))
			}
			if params.BillingMode != types.BillingModePayPerRequest {
				t.Errorf("expected PAY_PER_REQUEST billing, got %v", params.BillingMode)
			}
			return &dynamodb.CreateTableOutput{
				TableDescription: &types.TableDescription{
					TableName:   params.TableName,
					TableArn:    aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/sentinel-requests"),
					TableStatus: types.TableStatusCreating,
				},
			}, nil
		},
		updateTimeToLiveFunc: func(ctx context.Context, params *dynamodb.UpdateTimeToLiveInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTimeToLiveOutput, error) {
			// Verify TTL attribute
			if aws.ToString(params.TimeToLiveSpecification.AttributeName) != "ttl" {
				t.Errorf("expected TTL attribute 'ttl', got %s", aws.ToString(params.TimeToLiveSpecification.AttributeName))
			}
			return &dynamodb.UpdateTimeToLiveOutput{}, nil
		},
	}

	schema := ApprovalTableSchema("sentinel-requests")
	provisioner := newTableProvisionerWithClient(mock, "us-east-1")
	result, err := provisioner.Create(context.Background(), schema)

	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Status != StatusCreated {
		t.Errorf("expected status CREATED, got %v", result.Status)
	}
	if result.TableName != "sentinel-requests" {
		t.Errorf("expected table name sentinel-requests, got %s", result.TableName)
	}
}

// ============================================================================
// SSESpecification (Encryption) Tests
// ============================================================================

func TestSchemaToCreateTableInput_NoEncryption(t *testing.T) {
	// When Encryption is nil, no SSESpecification should be set (backward compatible)
	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		Encryption:   nil,
	}

	input := schemaToCreateTableInput(schema)

	if input.SSESpecification != nil {
		t.Errorf("expected nil SSESpecification for nil Encryption, got %v", input.SSESpecification)
	}
}

func TestSchemaToCreateTableInput_EncryptionDefault(t *testing.T) {
	// DEFAULT encryption type should not set SSESpecification (AWS owned encryption is default)
	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		Encryption:   &EncryptionConfig{Type: EncryptionDefault},
	}

	input := schemaToCreateTableInput(schema)

	if input.SSESpecification != nil {
		t.Errorf("expected nil SSESpecification for EncryptionDefault, got %v", input.SSESpecification)
	}
}

func TestSchemaToCreateTableInput_EncryptionKMS(t *testing.T) {
	// KMS encryption type should set SSESpecification with SSEType=KMS
	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		Encryption:   &EncryptionConfig{Type: EncryptionKMS},
	}

	input := schemaToCreateTableInput(schema)

	if input.SSESpecification == nil {
		t.Fatal("expected non-nil SSESpecification for EncryptionKMS")
	}
	if !aws.ToBool(input.SSESpecification.Enabled) {
		t.Error("expected SSESpecification.Enabled = true")
	}
	if input.SSESpecification.SSEType != types.SSETypeKms {
		t.Errorf("expected SSEType KMS, got %v", input.SSESpecification.SSEType)
	}
	if input.SSESpecification.KMSMasterKeyId != nil {
		t.Errorf("expected nil KMSMasterKeyId for KMS (AWS managed), got %s", aws.ToString(input.SSESpecification.KMSMasterKeyId))
	}
}

func TestSchemaToCreateTableInput_EncryptionCustomerKey(t *testing.T) {
	// Customer key encryption should set SSESpecification with KMSMasterKeyId
	kmsARN := "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		Encryption: &EncryptionConfig{
			Type:      EncryptionCustomerKey,
			KMSKeyARN: kmsARN,
		},
	}

	input := schemaToCreateTableInput(schema)

	if input.SSESpecification == nil {
		t.Fatal("expected non-nil SSESpecification for EncryptionCustomerKey")
	}
	if !aws.ToBool(input.SSESpecification.Enabled) {
		t.Error("expected SSESpecification.Enabled = true")
	}
	if input.SSESpecification.SSEType != types.SSETypeKms {
		t.Errorf("expected SSEType KMS, got %v", input.SSESpecification.SSEType)
	}
	if aws.ToString(input.SSESpecification.KMSMasterKeyId) != kmsARN {
		t.Errorf("expected KMSMasterKeyId = %q, got %q", kmsARN, aws.ToString(input.SSESpecification.KMSMasterKeyId))
	}
}

func TestTableProvisioner_Plan_WithEncryption(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{}
	provisioner := newTableProvisionerWithClient(mock, "us-east-1")

	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		Encryption:   DefaultEncryptionKMS(),
	}

	plan, err := provisioner.Plan(context.Background(), schema)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if plan.EncryptionType != string(EncryptionKMS) {
		t.Errorf("expected EncryptionType = %q, got %q", EncryptionKMS, plan.EncryptionType)
	}
}

func TestTableProvisioner_Plan_WithoutEncryption(t *testing.T) {
	mock := &mockDynamoDBProvisionerClient{}
	provisioner := newTableProvisionerWithClient(mock, "us-east-1")

	schema := TableSchema{
		TableName:    "test-table",
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		Encryption:   nil,
	}

	plan, err := provisioner.Plan(context.Background(), schema)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if plan.EncryptionType != "" {
		t.Errorf("expected empty EncryptionType for nil Encryption, got %q", plan.EncryptionType)
	}
}
