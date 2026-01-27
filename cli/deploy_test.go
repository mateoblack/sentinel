package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/byteness/aws-vault/v7/deploy"
)

// ============================================================================
// Mock Clients for CLI Tests
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

// mockOrganizationsAuditClient implements organizationsAuditAPI for testing.
type mockOrganizationsAuditClient struct {
	ListPoliciesFunc         func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicyFunc       func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicyFunc func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
}

func (m *mockOrganizationsAuditClient) ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if m.ListPoliciesFunc != nil {
		return m.ListPoliciesFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListPolicies not implemented")
}

func (m *mockOrganizationsAuditClient) DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if m.DescribePolicyFunc != nil {
		return m.DescribePolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribePolicy not implemented")
}

func (m *mockOrganizationsAuditClient) ListTargetsForPolicy(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	if m.ListTargetsForPolicyFunc != nil {
		return m.ListTargetsForPolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListTargetsForPolicy not implemented")
}

// ============================================================================
// CLI Tests
// ============================================================================

func TestDeployValidateCommand_HealthyDeployment(t *testing.T) {
	ctx := context.Background()

	// Create mock clients for healthy infrastructure
	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(true),
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

	ssmClient := &mockSSMAuditClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []ssmtypes.Parameter{
					{Name: aws.String("/sentinel/policies/production"), Version: 5},
				},
			}, nil
		},
	}

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

	auditor := deploy.NewAuditorWithClients(ddbClient, ssmClient, kmsClient, nil)

	// Create temp files for stdout/stderr
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DeployValidateCommandInput{
		PolicyRoot:   "/sentinel/policies",
		Tables:       []string{"sentinel-requests"},
		SigningKeyID: "alias/sentinel-signing-key",
		CheckSCP:     false, // Skip SCP check for this test
		Auditor:      auditor,
		Stdout:       stdout,
		Stderr:       stderr,
	}

	exitCode := DeployValidateCommand(ctx, input)

	if exitCode != 0 {
		stdout.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stdout)
		t.Logf("Output: %s", buf.String())
		t.Errorf("expected exit code 0 for healthy deployment, got %d", exitCode)
	}
}

func TestDeployValidateCommand_DynamoDBIssues(t *testing.T) {
	ctx := context.Background()

	// Create mock clients with DynamoDB issues
	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false), // Issue!
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

	ssmClient := &mockSSMAuditClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{Parameters: []ssmtypes.Parameter{}}, nil
		},
	}

	auditor := deploy.NewAuditorWithClients(ddbClient, ssmClient, nil, nil)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DeployValidateCommandInput{
		PolicyRoot: "/sentinel/policies",
		Tables:     []string{"sentinel-requests"},
		CheckSCP:   false,
		Auditor:    auditor,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := DeployValidateCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for HIGH finding, got %d", exitCode)
	}

	// Verify output contains the finding
	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "DEPLOY-02") {
		t.Error("expected output to contain DEPLOY-02 finding")
	}
	if !strings.Contains(output, "HIGH") {
		t.Error("expected output to contain HIGH risk level")
	}
}

func TestDeployValidateCommand_JSONOutput(t *testing.T) {
	ctx := context.Background()

	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(true),
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

	ssmClient := &mockSSMAuditClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{Parameters: []ssmtypes.Parameter{}}, nil
		},
	}

	auditor := deploy.NewAuditorWithClients(ddbClient, ssmClient, nil, nil)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DeployValidateCommandInput{
		PolicyRoot: "/sentinel/policies",
		Tables:     []string{"sentinel-requests"},
		CheckSCP:   false,
		JSONOutput: true,
		Auditor:    auditor,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := DeployValidateCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Verify it's valid JSON structure
	if !strings.Contains(output, "\"policy_root\"") {
		t.Error("expected JSON output to contain policy_root field")
	}
	if !strings.Contains(output, "\"risk_summary\"") {
		t.Error("expected JSON output to contain risk_summary field")
	}
}

func TestDeployValidateCommand_MinRiskFilter(t *testing.T) {
	ctx := context.Background()

	// Create mock with LOW finding only
	ssmClient := &mockSSMAuditClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []ssmtypes.Parameter{
					{Name: aws.String("/sentinel/policies/staging"), Version: 1}, // LOW finding
				},
			}, nil
		},
	}

	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(true),
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

	auditor := deploy.NewAuditorWithClients(ddbClient, ssmClient, nil, nil)

	// Test with min-risk=high (should filter out LOW findings)
	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DeployValidateCommandInput{
		PolicyRoot: "/sentinel/policies",
		Tables:     []string{"sentinel-requests"},
		CheckSCP:   false,
		MinRisk:    "high",
		Auditor:    auditor,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := DeployValidateCommand(ctx, input)

	// Exit code 0 because no HIGH or MEDIUM findings
	if exitCode != 0 {
		t.Errorf("expected exit code 0 with min-risk=high filter, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// LOW finding should not appear in output with high filter
	if strings.Contains(output, "DEPLOY-03") {
		t.Error("LOW finding DEPLOY-03 should be filtered out with min-risk=high")
	}
}

func TestDeployValidateCommand_InvalidMinRisk(t *testing.T) {
	ctx := context.Background()

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DeployValidateCommandInput{
		PolicyRoot: "/sentinel/policies",
		Tables:     []string{"sentinel-requests"},
		CheckSCP:   false,
		MinRisk:    "invalid",
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := DeployValidateCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid min-risk, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	output := buf.String()

	if !strings.Contains(output, "invalid --min-risk") {
		t.Error("expected error message about invalid min-risk")
	}
}

func TestDeployValidateCommand_SCPMissing(t *testing.T) {
	ctx := context.Background()

	ddbClient := &mockDynamoDBAuditClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(true),
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

	ssmClient := &mockSSMAuditClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{Parameters: []ssmtypes.Parameter{}}, nil
		},
	}

	// No Sentinel SCP
	orgClient := &mockOrganizationsAuditClient{
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{Id: aws.String("p-xyz"), Name: aws.String("EC2Restrictions")},
				},
			}, nil
		},
		DescribePolicyFunc: func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
			return &organizations.DescribePolicyOutput{
				Policy: &orgtypes.Policy{
					Content: aws.String(`{"Statement": [{"Effect": "Deny", "Action": "ec2:*"}]}`),
				},
			}, nil
		},
	}

	auditor := deploy.NewAuditorWithClients(ddbClient, ssmClient, nil, nil)
	scpAuditor := deploy.NewSCPAuditorWithClient(orgClient)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DeployValidateCommandInput{
		PolicyRoot: "/sentinel/policies",
		Tables:     []string{"sentinel-requests"},
		CheckSCP:   true,
		Auditor:    auditor,
		SCPAuditor: scpAuditor,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := DeployValidateCommand(ctx, input)

	// Exit code 1 because missing SCP is HIGH finding
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing SCP, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "DEPLOY-01") {
		t.Error("expected output to contain DEPLOY-01 SCP finding")
	}
	if !strings.Contains(output, "SCP Enforcement") {
		t.Error("expected output to contain SCP Enforcement section")
	}
}

func TestDeployValidateCommand_ExitCodes(t *testing.T) {
	tests := []struct {
		name         string
		highCount    int
		mediumCount  int
		expectedCode int
	}{
		{"no_findings", 0, 0, 0},
		{"high_only", 1, 0, 1},
		{"medium_only", 0, 1, 2},
		{"high_and_medium", 1, 1, 1}, // HIGH takes precedence
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &deploy.DeploymentAuditResult{
				RiskSummary: map[deploy.RiskLevel]int{
					deploy.RiskLevelHigh:   tt.highCount,
					deploy.RiskLevelMedium: tt.mediumCount,
					deploy.RiskLevelLow:    0,
				},
			}

			exitCode := calculateDeployExitCode(result)
			if exitCode != tt.expectedCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedCode, exitCode)
			}
		})
	}
}
