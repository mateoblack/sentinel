package testutil

import (
	"context"
	"errors"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ============================================================================
// MockSSMClient - SSM Parameter Store operations
// ============================================================================

// MockSSMClient implements SSM client operations for testing.
// Supports GetParameter, GetParametersByPath, and PutParameter operations.
type MockSSMClient struct {
	mu sync.Mutex

	// Configurable behavior functions
	GetParameterFunc        func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParametersByPathFunc func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
	PutParameterFunc        func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)

	// Call tracking
	GetParameterCalls        []*ssm.GetParameterInput
	GetParametersByPathCalls []*ssm.GetParametersByPathInput
	PutParameterCalls        []*ssm.PutParameterInput
}

// GetParameter implements SSM GetParameter operation.
func (m *MockSSMClient) GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	m.mu.Lock()
	m.GetParameterCalls = append(m.GetParameterCalls, params)
	m.mu.Unlock()

	if m.GetParameterFunc != nil {
		return m.GetParameterFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetParameter not implemented")
}

// GetParametersByPath implements SSM GetParametersByPath operation.
func (m *MockSSMClient) GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	m.mu.Lock()
	m.GetParametersByPathCalls = append(m.GetParametersByPathCalls, params)
	m.mu.Unlock()

	if m.GetParametersByPathFunc != nil {
		return m.GetParametersByPathFunc(ctx, params, optFns...)
	}
	return &ssm.GetParametersByPathOutput{}, nil
}

// PutParameter implements SSM PutParameter operation.
func (m *MockSSMClient) PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	m.mu.Lock()
	m.PutParameterCalls = append(m.PutParameterCalls, params)
	m.mu.Unlock()

	if m.PutParameterFunc != nil {
		return m.PutParameterFunc(ctx, params, optFns...)
	}
	return &ssm.PutParameterOutput{Version: 1}, nil
}

// Reset clears all call tracking data.
func (m *MockSSMClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetParameterCalls = nil
	m.GetParametersByPathCalls = nil
	m.PutParameterCalls = nil
}

// ============================================================================
// MockDynamoDBClient - DynamoDB operations
// ============================================================================

// MockDynamoDBClient implements DynamoDB client operations for testing.
// Supports PutItem, GetItem, DeleteItem, Query, and UpdateItem operations.
type MockDynamoDBClient struct {
	mu sync.Mutex

	// Configurable behavior functions
	PutItemFunc    func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItemFunc    func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	DeleteItemFunc func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	QueryFunc      func(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	UpdateItemFunc func(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)

	// Call tracking
	PutItemCalls    []*dynamodb.PutItemInput
	GetItemCalls    []*dynamodb.GetItemInput
	DeleteItemCalls []*dynamodb.DeleteItemInput
	QueryCalls      []*dynamodb.QueryInput
	UpdateItemCalls []*dynamodb.UpdateItemInput
}

// PutItem implements DynamoDB PutItem operation.
func (m *MockDynamoDBClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	m.mu.Lock()
	m.PutItemCalls = append(m.PutItemCalls, params)
	m.mu.Unlock()

	if m.PutItemFunc != nil {
		return m.PutItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.PutItemOutput{}, nil
}

// GetItem implements DynamoDB GetItem operation.
func (m *MockDynamoDBClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	m.mu.Lock()
	m.GetItemCalls = append(m.GetItemCalls, params)
	m.mu.Unlock()

	if m.GetItemFunc != nil {
		return m.GetItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.GetItemOutput{}, nil
}

// DeleteItem implements DynamoDB DeleteItem operation.
func (m *MockDynamoDBClient) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	m.mu.Lock()
	m.DeleteItemCalls = append(m.DeleteItemCalls, params)
	m.mu.Unlock()

	if m.DeleteItemFunc != nil {
		return m.DeleteItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.DeleteItemOutput{}, nil
}

// Query implements DynamoDB Query operation.
func (m *MockDynamoDBClient) Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	m.mu.Lock()
	m.QueryCalls = append(m.QueryCalls, params)
	m.mu.Unlock()

	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, params, optFns...)
	}
	return &dynamodb.QueryOutput{}, nil
}

// UpdateItem implements DynamoDB UpdateItem operation.
func (m *MockDynamoDBClient) UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	m.mu.Lock()
	m.UpdateItemCalls = append(m.UpdateItemCalls, params)
	m.mu.Unlock()

	if m.UpdateItemFunc != nil {
		return m.UpdateItemFunc(ctx, params, optFns...)
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

// Reset clears all call tracking data.
func (m *MockDynamoDBClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PutItemCalls = nil
	m.GetItemCalls = nil
	m.DeleteItemCalls = nil
	m.QueryCalls = nil
	m.UpdateItemCalls = nil
}

// ============================================================================
// MockSNSClient - SNS notifications
// ============================================================================

// MockSNSClient implements SNS client operations for testing.
// Tracks published messages for assertions.
type MockSNSClient struct {
	mu sync.Mutex

	// Configurable behavior functions
	PublishFunc func(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error)

	// Call tracking
	PublishCalls []*sns.PublishInput

	// Auto-increment message ID counter
	messageIDCounter int
}

// Publish implements SNS Publish operation.
func (m *MockSNSClient) Publish(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error) {
	m.mu.Lock()
	m.PublishCalls = append(m.PublishCalls, params)
	m.messageIDCounter++
	msgID := m.messageIDCounter
	m.mu.Unlock()

	if m.PublishFunc != nil {
		return m.PublishFunc(ctx, params, optFns...)
	}
	return &sns.PublishOutput{
		MessageId: aws.String(stringf("mock-message-%d", msgID)),
	}, nil
}

// Reset clears all call tracking data and resets counters.
func (m *MockSNSClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PublishCalls = nil
	m.messageIDCounter = 0
}

// PublishCallCount returns the number of Publish calls made.
func (m *MockSNSClient) PublishCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.PublishCalls)
}

// LastPublishedMessage returns the last published message input, or nil if none.
func (m *MockSNSClient) LastPublishedMessage() *sns.PublishInput {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.PublishCalls) == 0 {
		return nil
	}
	return m.PublishCalls[len(m.PublishCalls)-1]
}

// ============================================================================
// MockSTSClient - STS operations
// ============================================================================

// MockSTSClient implements STS client operations for testing.
// Supports AssumeRole and GetCallerIdentity operations.
type MockSTSClient struct {
	mu sync.Mutex

	// Configurable behavior functions
	AssumeRoleFunc        func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)

	// Call tracking
	AssumeRoleCalls        []*sts.AssumeRoleInput
	GetCallerIdentityCalls []*sts.GetCallerIdentityInput
}

// AssumeRole implements STS AssumeRole operation.
func (m *MockSTSClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	m.mu.Lock()
	m.AssumeRoleCalls = append(m.AssumeRoleCalls, params)
	m.mu.Unlock()

	if m.AssumeRoleFunc != nil {
		return m.AssumeRoleFunc(ctx, params, optFns...)
	}
	return nil, errors.New("AssumeRole not implemented")
}

// GetCallerIdentity implements STS GetCallerIdentity operation.
func (m *MockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	m.mu.Lock()
	m.GetCallerIdentityCalls = append(m.GetCallerIdentityCalls, params)
	m.mu.Unlock()

	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"),
		Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/MockRole/session"),
		UserId:  aws.String("AIDAMOCKUSERID"),
	}, nil
}

// Reset clears all call tracking data.
func (m *MockSTSClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AssumeRoleCalls = nil
	m.GetCallerIdentityCalls = nil
}

// ============================================================================
// MockIAMClient - IAM operations
// ============================================================================

// MockIAMClient implements IAM client operations for testing.
// Supports GetRole and ListRoles operations.
type MockIAMClient struct {
	mu sync.Mutex

	// Configurable behavior functions
	GetRoleFunc   func(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	ListRolesFunc func(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)

	// Call tracking
	GetRoleCalls   []*iam.GetRoleInput
	ListRolesCalls []*iam.ListRolesInput
}

// GetRole implements IAM GetRole operation.
func (m *MockIAMClient) GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	m.mu.Lock()
	m.GetRoleCalls = append(m.GetRoleCalls, params)
	m.mu.Unlock()

	if m.GetRoleFunc != nil {
		return m.GetRoleFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetRole not implemented")
}

// ListRoles implements IAM ListRoles operation.
func (m *MockIAMClient) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	m.mu.Lock()
	m.ListRolesCalls = append(m.ListRolesCalls, params)
	m.mu.Unlock()

	if m.ListRolesFunc != nil {
		return m.ListRolesFunc(ctx, params, optFns...)
	}
	return &iam.ListRolesOutput{}, nil
}

// Reset clears all call tracking data.
func (m *MockIAMClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetRoleCalls = nil
	m.ListRolesCalls = nil
}

// ============================================================================
// MockCloudTrailClient - CloudTrail queries
// ============================================================================

// MockCloudTrailClient implements CloudTrail client operations for testing.
// Supports LookupEvents operation.
type MockCloudTrailClient struct {
	mu sync.Mutex

	// Configurable behavior functions
	LookupEventsFunc func(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)

	// Call tracking
	LookupEventsCalls []*cloudtrail.LookupEventsInput
}

// LookupEvents implements CloudTrail LookupEvents operation.
func (m *MockCloudTrailClient) LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	m.mu.Lock()
	m.LookupEventsCalls = append(m.LookupEventsCalls, params)
	m.mu.Unlock()

	if m.LookupEventsFunc != nil {
		return m.LookupEventsFunc(ctx, params, optFns...)
	}
	return &cloudtrail.LookupEventsOutput{}, nil
}

// Reset clears all call tracking data.
func (m *MockCloudTrailClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LookupEventsCalls = nil
}

// ============================================================================
// MockKMSClient - KMS operations
// ============================================================================

// MockKMSClient implements KMS client operations for testing.
// Supports Sign and Verify operations for policy signing.
type MockKMSClient struct {
	mu sync.Mutex

	// Configurable behavior functions
	SignFunc   func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	VerifyFunc func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)

	// Call tracking
	SignCalls   []*kms.SignInput
	VerifyCalls []*kms.VerifyInput
}

// Sign implements KMS Sign operation.
func (m *MockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	m.mu.Lock()
	m.SignCalls = append(m.SignCalls, params)
	m.mu.Unlock()

	if m.SignFunc != nil {
		return m.SignFunc(ctx, params, optFns...)
	}
	return nil, errors.New("Sign not implemented")
}

// Verify implements KMS Verify operation.
func (m *MockKMSClient) Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	m.mu.Lock()
	m.VerifyCalls = append(m.VerifyCalls, params)
	m.mu.Unlock()

	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("Verify not implemented")
}

// Reset clears all call tracking data.
func (m *MockKMSClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SignCalls = nil
	m.VerifyCalls = nil
}

// ============================================================================
// Helper functions
// ============================================================================

// stringf is a simple helper to format strings (avoiding fmt import in mock file).
func stringf(format string, args ...interface{}) string {
	// Simple replacement for common case: %d
	if len(args) == 1 {
		if v, ok := args[0].(int); ok {
			return format[:len(format)-2] + itoa(v)
		}
	}
	return format
}

// itoa converts an int to string without using strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
