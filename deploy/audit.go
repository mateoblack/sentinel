package deploy

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// RiskLevel indicates the severity of a deployment finding.
type RiskLevel string

const (
	// RiskLevelHigh indicates a critical security issue requiring immediate attention.
	RiskLevelHigh RiskLevel = "HIGH"
	// RiskLevelMedium indicates a significant security concern that should be addressed.
	RiskLevelMedium RiskLevel = "MEDIUM"
	// RiskLevelLow indicates a minor issue or best practice recommendation.
	RiskLevelLow RiskLevel = "LOW"
	// RiskLevelUnknown indicates the check could not be performed (e.g., access denied).
	RiskLevelUnknown RiskLevel = "UNKNOWN"
)

// DeploymentFinding represents a single security issue found during deployment audit.
type DeploymentFinding struct {
	// CheckID is the identifier for the audit check (e.g., DEPLOY-01, DEPLOY-02).
	CheckID string `json:"check_id"`
	// Category is the type of resource being checked (SCP, DynamoDB, SSM, KMS).
	Category string `json:"category"`
	// RiskLevel indicates the severity of this finding.
	RiskLevel RiskLevel `json:"risk_level"`
	// Resource is the identifier of the affected resource.
	Resource string `json:"resource"`
	// Message describes the issue found.
	Message string `json:"message"`
	// Remediation provides a specific command to fix the issue.
	Remediation string `json:"remediation"`
}

// DeploymentAuditResult aggregates all findings from auditing deployment infrastructure.
type DeploymentAuditResult struct {
	// Findings contains all audit issues found.
	Findings []DeploymentFinding `json:"findings"`
	// CheckedResources is the total count of resources audited.
	CheckedResources int `json:"checked_resources"`
	// RiskSummary counts findings by risk level.
	RiskSummary map[RiskLevel]int `json:"risk_summary"`
	// HasCriticalIssues is true if any HIGH findings exist.
	HasCriticalIssues bool `json:"has_critical_issues"`
}

// ============================================================================
// Auditable Resource Interfaces
// ============================================================================

// dynamodbAuditAPI defines DynamoDB operations used for security audits.
type dynamodbAuditAPI interface {
	DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	DescribeContinuousBackups(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error)
}

// ssmAuditAPI defines SSM operations used for security audits.
type ssmAuditAPI interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
}

// kmsAuditAPI defines KMS operations used for security audits.
type kmsAuditAPI interface {
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// cloudwatchAuditAPI defines CloudWatch operations used for security audits.
type cloudwatchAuditAPI interface {
	DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

// ============================================================================
// Auditor
// ============================================================================

// Auditor performs security audits on Sentinel deployment infrastructure.
type Auditor struct {
	dynamodb   dynamodbAuditAPI
	ssm        ssmAuditAPI
	kms        kmsAuditAPI
	cloudwatch cloudwatchAuditAPI
}

// NewAuditor creates a new Auditor using the provided AWS configuration.
func NewAuditor(cfg aws.Config) *Auditor {
	return &Auditor{
		dynamodb:   dynamodb.NewFromConfig(cfg),
		ssm:        ssm.NewFromConfig(cfg),
		kms:        kms.NewFromConfig(cfg),
		cloudwatch: cloudwatch.NewFromConfig(cfg),
	}
}

// NewAuditorWithClients creates an Auditor with custom clients for testing.
func NewAuditorWithClients(ddb dynamodbAuditAPI, ssmClient ssmAuditAPI, kmsClient kmsAuditAPI, cwClient cloudwatchAuditAPI) *Auditor {
	return &Auditor{
		dynamodb:   ddb,
		ssm:        ssmClient,
		kms:        kmsClient,
		cloudwatch: cwClient,
	}
}

// AuditDynamoDBTables checks DynamoDB tables for security configurations.
// Checks deletion protection (DEPLOY-02) and point-in-time recovery (DEPLOY-02b).
func (a *Auditor) AuditDynamoDBTables(ctx context.Context, tableNames []string) []DeploymentFinding {
	var findings []DeploymentFinding

	for _, tableName := range tableNames {
		// Check table properties including deletion protection
		tableOutput, err := a.dynamodb.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: aws.String(tableName),
		})
		if err != nil {
			// Handle access denied gracefully
			if isAccessDenied(err) {
				findings = append(findings, DeploymentFinding{
					CheckID:     "DEPLOY-02",
					Category:    "DynamoDB",
					RiskLevel:   RiskLevelUnknown,
					Resource:    tableName,
					Message:     "Unable to check table configuration (access denied)",
					Remediation: "Ensure IAM permissions include dynamodb:DescribeTable",
				})
				continue
			}
			// Table not found or other error - skip
			continue
		}

		// DEPLOY-02: Check deletion protection
		if tableOutput.Table != nil && !tableOutput.Table.DeletionProtectionEnabled {
			findings = append(findings, DeploymentFinding{
				CheckID:     "DEPLOY-02",
				Category:    "DynamoDB",
				RiskLevel:   RiskLevelHigh,
				Resource:    tableName,
				Message:     "Deletion protection disabled - table can be accidentally deleted",
				Remediation: "aws dynamodb update-table --table-name " + tableName + " --deletion-protection-enabled",
			})
		}

		// Check PITR status
		backupsOutput, err := a.dynamodb.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
			TableName: aws.String(tableName),
		})
		if err != nil {
			if isAccessDenied(err) {
				findings = append(findings, DeploymentFinding{
					CheckID:     "DEPLOY-02b",
					Category:    "DynamoDB",
					RiskLevel:   RiskLevelUnknown,
					Resource:    tableName,
					Message:     "Unable to check PITR status (access denied)",
					Remediation: "Ensure IAM permissions include dynamodb:DescribeContinuousBackups",
				})
				continue
			}
			continue
		}

		// DEPLOY-02b: Check point-in-time recovery
		if backupsOutput.ContinuousBackupsDescription != nil &&
			backupsOutput.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
			pitrStatus := backupsOutput.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus
			if pitrStatus != "ENABLED" {
				findings = append(findings, DeploymentFinding{
					CheckID:     "DEPLOY-02b",
					Category:    "DynamoDB",
					RiskLevel:   RiskLevelMedium,
					Resource:    tableName,
					Message:     "Point-in-time recovery disabled - cannot recover from data corruption",
					Remediation: "aws dynamodb update-continuous-backups --table-name " + tableName + " --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
				})
			}
		}
	}

	return findings
}

// AuditSSMParameters checks SSM parameters under the policy root for proper configuration.
// DEPLOY-03: Checks if parameters have multiple versions (indicating proper versioning workflow).
func (a *Auditor) AuditSSMParameters(ctx context.Context, policyRoot string) []DeploymentFinding {
	var findings []DeploymentFinding

	// Ensure policyRoot has trailing slash for path queries
	if !strings.HasSuffix(policyRoot, "/") {
		policyRoot = policyRoot + "/"
	}
	// Remove trailing slash for query (AWS GetParametersByPath expects path without trailing /)
	queryPath := strings.TrimSuffix(policyRoot, "/")

	output, err := a.ssm.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
		Path:      aws.String(queryPath),
		Recursive: aws.Bool(true),
	})
	if err != nil {
		if isAccessDenied(err) {
			findings = append(findings, DeploymentFinding{
				CheckID:     "DEPLOY-03",
				Category:    "SSM",
				RiskLevel:   RiskLevelUnknown,
				Resource:    policyRoot,
				Message:     "Unable to list SSM parameters (access denied)",
				Remediation: "Ensure IAM permissions include ssm:GetParametersByPath",
			})
		}
		return findings
	}

	// Check each parameter for versioning
	for _, param := range output.Parameters {
		paramName := aws.ToString(param.Name)
		// SSM versioning is automatic, but version 1 indicates parameter was just created
		// and hasn't been updated through proper workflow
		if param.Version <= 1 {
			findings = append(findings, DeploymentFinding{
				CheckID:     "DEPLOY-03",
				Category:    "SSM",
				RiskLevel:   RiskLevelLow,
				Resource:    paramName,
				Message:     "Parameter has only version 1 - consider using versioned updates for audit trail",
				Remediation: "Use 'sentinel init publish' to update policies with version history",
			})
		}
	}

	return findings
}

// AuditKMSKey checks the KMS signing key status.
// DEPLOY-04: Verifies key is enabled and not pending deletion.
func (a *Auditor) AuditKMSKey(ctx context.Context, keyID string) []DeploymentFinding {
	var findings []DeploymentFinding

	if keyID == "" {
		return findings
	}

	output, err := a.kms.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		if isAccessDenied(err) {
			findings = append(findings, DeploymentFinding{
				CheckID:     "DEPLOY-04",
				Category:    "KMS",
				RiskLevel:   RiskLevelUnknown,
				Resource:    keyID,
				Message:     "Unable to check KMS key status (access denied)",
				Remediation: "Ensure IAM permissions include kms:DescribeKey",
			})
		}
		return findings
	}

	if output.KeyMetadata != nil {
		keyMeta := output.KeyMetadata

		// Check if key is disabled
		if !keyMeta.Enabled {
			findings = append(findings, DeploymentFinding{
				CheckID:     "DEPLOY-04",
				Category:    "KMS",
				RiskLevel:   RiskLevelHigh,
				Resource:    keyID,
				Message:     "KMS signing key is disabled - policy signing will fail",
				Remediation: "aws kms enable-key --key-id " + keyID,
			})
		}

		// Check if key is pending deletion
		if keyMeta.KeyState == kmstypes.KeyStatePendingDeletion {
			findings = append(findings, DeploymentFinding{
				CheckID:     "DEPLOY-04",
				Category:    "KMS",
				RiskLevel:   RiskLevelHigh,
				Resource:    keyID,
				Message:     "KMS signing key is pending deletion - policy signing will fail",
				Remediation: "aws kms cancel-key-deletion --key-id " + keyID,
			})
		}
	}

	return findings
}

// ============================================================================
// Helper functions
// ============================================================================

// isAccessDenied checks if an error indicates access was denied.
func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "AccessDenied") ||
		strings.Contains(errMsg, "AccessDeniedException") ||
		strings.Contains(errMsg, "not authorized") ||
		strings.Contains(errMsg, "UnrecognizedClientException")
}

// NewAuditResult creates a new DeploymentAuditResult from findings.
func NewAuditResult(findings []DeploymentFinding, checkedResources int) *DeploymentAuditResult {
	result := &DeploymentAuditResult{
		Findings:          findings,
		CheckedResources:  checkedResources,
		RiskSummary:       map[RiskLevel]int{RiskLevelHigh: 0, RiskLevelMedium: 0, RiskLevelLow: 0, RiskLevelUnknown: 0},
		HasCriticalIssues: false,
	}

	for _, f := range findings {
		result.RiskSummary[f.RiskLevel]++
		if f.RiskLevel == RiskLevelHigh {
			result.HasCriticalIssues = true
		}
	}

	return result
}
