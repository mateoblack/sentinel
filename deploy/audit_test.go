package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ============================================================================
// Mock Clients
// ============================================================================

// mockDynamoDBAuditClient implements dynamodbAuditAPI for testing.
type mockDynamoDBAuditClient struct {
	DescribeTableFunc             func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	DescribeContinuousBackupsFunc func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error)
}

func (m *mockDynamoDBAuditClient) DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if m.DescribeTableFunc != nil {
		return m.DescribeTableFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribeTable not implemented")
}

func (m *mockDynamoDBAuditClient) DescribeContinuousBackups(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	if m.DescribeContinuousBackupsFunc != nil {
		return m.DescribeContinuousBackupsFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribeContinuousBackups not implemented")
}

// mockSSMAuditClient implements ssmAuditAPI for testing.
type mockSSMAuditClient struct {
	GetParameterFunc        func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParametersByPathFunc func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
}

func (m *mockSSMAuditClient) GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if m.GetParameterFunc != nil {
		return m.GetParameterFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetParameter not implemented")
}

func (m *mockSSMAuditClient) GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	if m.GetParametersByPathFunc != nil {
		return m.GetParametersByPathFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetParametersByPath not implemented")
}

// mockKMSAuditClient implements kmsAuditAPI for testing.
type mockKMSAuditClient struct {
	DescribeKeyFunc func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

func (m *mockKMSAuditClient) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if m.DescribeKeyFunc != nil {
		return m.DescribeKeyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribeKey not implemented")
}

// mockCloudWatchAuditClient implements cloudwatchAuditAPI for testing.
type mockCloudWatchAuditClient struct {
	DescribeAlarmsFunc func(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

func (m *mockCloudWatchAuditClient) DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	if m.DescribeAlarmsFunc != nil {
		return m.DescribeAlarmsFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribeAlarms not implemented")
}

// ============================================================================
// DynamoDB Audit Tests
// ============================================================================

func TestAuditDynamoDBTables_DeletionProtectionEnabled(t *testing.T) {
	ctx := context.Background()

	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: true,
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &ddbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &ddbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: ddbtypes.PointInTimeRecoveryStatusEnabled,
					},
				},
			}, nil
		},
	}

	auditor := NewAuditorWithClients(ddbClient, nil, nil, nil)
	findings := auditor.AuditDynamoDBTables(ctx, []string{"sentinel-requests"})

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for protected table, got %d", len(findings))
		for _, f := range findings {
			t.Logf("Finding: %s - %s", f.CheckID, f.Message)
		}
	}
}

func TestAuditDynamoDBTables_DeletionProtectionDisabled(t *testing.T) {
	ctx := context.Background()

	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: false, // Not protected
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &ddbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &ddbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: ddbtypes.PointInTimeRecoveryStatusEnabled,
					},
				},
			}, nil
		},
	}

	auditor := NewAuditorWithClients(ddbClient, nil, nil, nil)
	findings := auditor.AuditDynamoDBTables(ctx, []string{"sentinel-requests"})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unprotected table, got %d", len(findings))
	}

	finding := findings[0]
	if finding.CheckID != "DEPLOY-02" {
		t.Errorf("expected CheckID DEPLOY-02, got %s", finding.CheckID)
	}
	if finding.RiskLevel != RiskLevelHigh {
		t.Errorf("expected HIGH risk level, got %s", finding.RiskLevel)
	}
	if finding.Category != "DynamoDB" {
		t.Errorf("expected category DynamoDB, got %s", finding.Category)
	}
}

func TestAuditDynamoDBTables_PITRDisabled(t *testing.T) {
	ctx := context.Background()

	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: true,
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &ddbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &ddbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: ddbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
	}

	auditor := NewAuditorWithClients(ddbClient, nil, nil, nil)
	findings := auditor.AuditDynamoDBTables(ctx, []string{"sentinel-requests"})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for PITR disabled, got %d", len(findings))
	}

	finding := findings[0]
	if finding.CheckID != "DEPLOY-02b" {
		t.Errorf("expected CheckID DEPLOY-02b, got %s", finding.CheckID)
	}
	if finding.RiskLevel != RiskLevelMedium {
		t.Errorf("expected MEDIUM risk level, got %s", finding.RiskLevel)
	}
}

func TestAuditDynamoDBTables_AccessDenied(t *testing.T) {
	ctx := context.Background()

	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return nil, errors.New("AccessDeniedException: User not authorized")
		},
	}

	auditor := NewAuditorWithClients(ddbClient, nil, nil, nil)
	findings := auditor.AuditDynamoDBTables(ctx, []string{"sentinel-requests"})

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for access denied, got %d", len(findings))
	}

	finding := findings[0]
	if finding.RiskLevel != RiskLevelUnknown {
		t.Errorf("expected UNKNOWN risk level for access denied, got %s", finding.RiskLevel)
	}
}

func TestAuditDynamoDBTables_MultipleIssues(t *testing.T) {
	ctx := context.Background()

	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: false, // Issue 1
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &ddbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &ddbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: ddbtypes.PointInTimeRecoveryStatusDisabled, // Issue 2
					},
				},
			}, nil
		},
	}

	auditor := NewAuditorWithClients(ddbClient, nil, nil, nil)
	findings := auditor.AuditDynamoDBTables(ctx, []string{"sentinel-requests"})

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for table with both issues, got %d", len(findings))
	}

	// Verify we have both types of findings
	var hasDeploy02, hasDeploy02b bool
	for _, f := range findings {
		if f.CheckID == "DEPLOY-02" {
			hasDeploy02 = true
		}
		if f.CheckID == "DEPLOY-02b" {
			hasDeploy02b = true
		}
	}
	if !hasDeploy02 || !hasDeploy02b {
		t.Error("expected both DEPLOY-02 and DEPLOY-02b findings")
	}
}

// ============================================================================
// SSM Parameter Audit Tests
// ============================================================================

func TestAuditSSMParameters_WellVersioned(t *testing.T) {
	ctx := context.Background()

	ssmClient := &mockSSMAuditClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []ssmtypes.Parameter{
					{
						Name:    aws.String("/sentinel/policies/production"),
						Version: 5, // Multiple versions - good
					},
				},
			}, nil
		},
	}

	auditor := NewAuditorWithClients(nil, ssmClient, nil, nil)
	findings := auditor.AuditSSMParameters(ctx, "/sentinel/policies")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for well-versioned parameter, got %d", len(findings))
	}
}

func TestAuditSSMParameters_SingleVersion(t *testing.T) {
	ctx := context.Background()

	ssmClient := &mockSSMAuditClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []ssmtypes.Parameter{
					{
						Name:    aws.String("/sentinel/policies/staging"),
						Version: 1, // Only version 1 - may not be using versioned workflow
					},
				},
			}, nil
		},
	}

	auditor := NewAuditorWithClients(nil, ssmClient, nil, nil)
	findings := auditor.AuditSSMParameters(ctx, "/sentinel/policies")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for single-version parameter, got %d", len(findings))
	}

	finding := findings[0]
	if finding.CheckID != "DEPLOY-03" {
		t.Errorf("expected CheckID DEPLOY-03, got %s", finding.CheckID)
	}
	if finding.RiskLevel != RiskLevelLow {
		t.Errorf("expected LOW risk level, got %s", finding.RiskLevel)
	}
}

func TestAuditSSMParameters_AccessDenied(t *testing.T) {
	ctx := context.Background()

	ssmClient := &mockSSMAuditClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return nil, errors.New("AccessDeniedException: User not authorized")
		},
	}

	auditor := NewAuditorWithClients(nil, ssmClient, nil, nil)
	findings := auditor.AuditSSMParameters(ctx, "/sentinel/policies")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for access denied, got %d", len(findings))
	}

	finding := findings[0]
	if finding.RiskLevel != RiskLevelUnknown {
		t.Errorf("expected UNKNOWN risk level, got %s", finding.RiskLevel)
	}
}

// ============================================================================
// KMS Key Audit Tests
// ============================================================================

func TestAuditKMSKey_Enabled(t *testing.T) {
	ctx := context.Background()

	kmsClient := &mockKMSAuditClient{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId:    params.KeyId,
					Enabled:  true,
					KeyState: kmstypes.KeyStateEnabled,
				},
			}, nil
		},
	}

	auditor := NewAuditorWithClients(nil, nil, kmsClient, nil)
	findings := auditor.AuditKMSKey(ctx, "alias/sentinel-signing-key")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for enabled key, got %d", len(findings))
	}
}

func TestAuditKMSKey_Disabled(t *testing.T) {
	ctx := context.Background()

	kmsClient := &mockKMSAuditClient{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId:    params.KeyId,
					Enabled:  false, // Disabled
					KeyState: kmstypes.KeyStateDisabled,
				},
			}, nil
		},
	}

	auditor := NewAuditorWithClients(nil, nil, kmsClient, nil)
	findings := auditor.AuditKMSKey(ctx, "alias/sentinel-signing-key")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for disabled key, got %d", len(findings))
	}

	finding := findings[0]
	if finding.CheckID != "DEPLOY-04" {
		t.Errorf("expected CheckID DEPLOY-04, got %s", finding.CheckID)
	}
	if finding.RiskLevel != RiskLevelHigh {
		t.Errorf("expected HIGH risk level, got %s", finding.RiskLevel)
	}
}

func TestAuditKMSKey_PendingDeletion(t *testing.T) {
	ctx := context.Background()

	kmsClient := &mockKMSAuditClient{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					KeyId:    params.KeyId,
					Enabled:  true,
					KeyState: kmstypes.KeyStatePendingDeletion, // Pending deletion
				},
			}, nil
		},
	}

	auditor := NewAuditorWithClients(nil, nil, kmsClient, nil)
	findings := auditor.AuditKMSKey(ctx, "alias/sentinel-signing-key")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for key pending deletion, got %d", len(findings))
	}

	finding := findings[0]
	if finding.CheckID != "DEPLOY-04" {
		t.Errorf("expected CheckID DEPLOY-04, got %s", finding.CheckID)
	}
	if finding.RiskLevel != RiskLevelHigh {
		t.Errorf("expected HIGH risk level, got %s", finding.RiskLevel)
	}
}

func TestAuditKMSKey_AccessDenied(t *testing.T) {
	ctx := context.Background()

	kmsClient := &mockKMSAuditClient{
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return nil, errors.New("AccessDeniedException: User not authorized")
		},
	}

	auditor := NewAuditorWithClients(nil, nil, kmsClient, nil)
	findings := auditor.AuditKMSKey(ctx, "alias/sentinel-signing-key")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for access denied, got %d", len(findings))
	}

	finding := findings[0]
	if finding.RiskLevel != RiskLevelUnknown {
		t.Errorf("expected UNKNOWN risk level, got %s", finding.RiskLevel)
	}
}

func TestAuditKMSKey_EmptyKeyID(t *testing.T) {
	ctx := context.Background()

	auditor := NewAuditorWithClients(nil, nil, nil, nil)
	findings := auditor.AuditKMSKey(ctx, "") // Empty key ID

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty key ID, got %d", len(findings))
	}
}

// ============================================================================
// Result Aggregation Tests
// ============================================================================

func TestNewAuditResult(t *testing.T) {
	findings := []DeploymentFinding{
		{CheckID: "DEPLOY-02", RiskLevel: RiskLevelHigh},
		{CheckID: "DEPLOY-02b", RiskLevel: RiskLevelMedium},
		{CheckID: "DEPLOY-03", RiskLevel: RiskLevelLow},
		{CheckID: "DEPLOY-01", RiskLevel: RiskLevelUnknown},
	}

	result := NewAuditResult(findings, 5)

	if result.CheckedResources != 5 {
		t.Errorf("expected 5 checked resources, got %d", result.CheckedResources)
	}

	if result.RiskSummary[RiskLevelHigh] != 1 {
		t.Errorf("expected 1 HIGH finding, got %d", result.RiskSummary[RiskLevelHigh])
	}

	if result.RiskSummary[RiskLevelMedium] != 1 {
		t.Errorf("expected 1 MEDIUM finding, got %d", result.RiskSummary[RiskLevelMedium])
	}

	if result.RiskSummary[RiskLevelLow] != 1 {
		t.Errorf("expected 1 LOW finding, got %d", result.RiskSummary[RiskLevelLow])
	}

	if !result.HasCriticalIssues {
		t.Error("expected HasCriticalIssues to be true with HIGH finding")
	}
}

func TestNewAuditResult_NoCriticalIssues(t *testing.T) {
	findings := []DeploymentFinding{
		{CheckID: "DEPLOY-02b", RiskLevel: RiskLevelMedium},
		{CheckID: "DEPLOY-03", RiskLevel: RiskLevelLow},
	}

	result := NewAuditResult(findings, 3)

	if result.HasCriticalIssues {
		t.Error("expected HasCriticalIssues to be false without HIGH findings")
	}
}

func TestNewAuditResult_EmptyFindings(t *testing.T) {
	result := NewAuditResult([]DeploymentFinding{}, 3)

	if result.HasCriticalIssues {
		t.Error("expected HasCriticalIssues to be false with no findings")
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}
