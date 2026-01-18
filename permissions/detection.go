package permissions

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// DetectionResult contains the features detected in the current environment.
type DetectionResult struct {
	// Features lists the detected features.
	Features []Feature
	// FeatureDetails provides the reason for detection (e.g., "table exists", "env var set").
	FeatureDetails map[Feature]string
	// Errors contains non-fatal detection errors.
	Errors []DetectionError
}

// DetectionError represents a non-fatal error during detection.
type DetectionError struct {
	Feature Feature
	Message string
}

// ssmDetectorAPI defines the SSM operations used by Detector.
// This interface enables testing with mock implementations.
type ssmDetectorAPI interface {
	GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
}

// dynamoDetectorAPI defines the DynamoDB operations used by Detector.
// This interface enables testing with mock implementations.
type dynamoDetectorAPI interface {
	DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// DetectorInterface defines the interface for feature detection.
// This enables testing with mock detectors in the CLI.
type DetectorInterface interface {
	Detect(ctx context.Context) (*DetectionResult, error)
}

// Detector checks AWS resources to determine which Sentinel features are configured.
type Detector struct {
	ssmClient    ssmDetectorAPI
	dynamoClient dynamoDetectorAPI
}

// NewDetector creates a Detector using the provided AWS configuration.
func NewDetector(cfg aws.Config) *Detector {
	return &Detector{
		ssmClient:    ssm.NewFromConfig(cfg),
		dynamoClient: dynamodb.NewFromConfig(cfg),
	}
}

// newDetectorWithClients creates a Detector with custom clients (for testing).
func newDetectorWithClients(ssmClient ssmDetectorAPI, dynamoClient dynamoDetectorAPI) *Detector {
	return &Detector{
		ssmClient:    ssmClient,
		dynamoClient: dynamoClient,
	}
}

// Detect probes AWS resources to determine which features are configured.
// It returns all detected features, even if some checks fail.
// Errors are collected but don't stop detection of other features.
func (d *Detector) Detect(ctx context.Context) (*DetectionResult, error) {
	result := &DetectionResult{
		Features:       []Feature{},
		FeatureDetails: make(map[Feature]string),
		Errors:         []DetectionError{},
	}

	// credential_issue is always detected (base feature required for all Sentinel use)
	result.Features = append(result.Features, FeatureCredentialIssue)
	result.FeatureDetails[FeatureCredentialIssue] = "base feature (always required)"

	// audit_verify is always detected (CloudTrail available in all accounts)
	result.Features = append(result.Features, FeatureAuditVerify)
	result.FeatureDetails[FeatureAuditVerify] = "CloudTrail available in all AWS accounts"

	// enforce_analyze is always detected (IAM available in all accounts)
	result.Features = append(result.Features, FeatureEnforceAnalyze)
	result.FeatureDetails[FeatureEnforceAnalyze] = "IAM available in all AWS accounts"

	// Check SSM for policy_load and bootstrap_plan
	policyExists, err := d.checkSSMPolicyExists(ctx)
	if err != nil {
		result.Errors = append(result.Errors, DetectionError{
			Feature: FeaturePolicyLoad,
			Message: err.Error(),
		})
	} else if policyExists {
		result.Features = append(result.Features, FeaturePolicyLoad)
		result.FeatureDetails[FeaturePolicyLoad] = "SSM parameter /sentinel/policies/* exists"

		// bootstrap_plan uses same SSM read permissions
		result.Features = append(result.Features, FeatureBootstrapPlan)
		result.FeatureDetails[FeatureBootstrapPlan] = "SSM parameter /sentinel/policies/* exists"
	}

	// Check DynamoDB for approval_workflow (sentinel-requests table)
	requestsExists, err := d.checkDynamoTableExists(ctx, "sentinel-requests")
	if err != nil {
		result.Errors = append(result.Errors, DetectionError{
			Feature: FeatureApprovalWorkflow,
			Message: err.Error(),
		})
	} else if requestsExists {
		result.Features = append(result.Features, FeatureApprovalWorkflow)
		result.FeatureDetails[FeatureApprovalWorkflow] = "DynamoDB table sentinel-requests exists"
	}

	// Check DynamoDB for breakglass (sentinel-breakglass table)
	breakglassExists, err := d.checkDynamoTableExists(ctx, "sentinel-breakglass")
	if err != nil {
		result.Errors = append(result.Errors, DetectionError{
			Feature: FeatureBreakGlass,
			Message: err.Error(),
		})
	} else if breakglassExists {
		result.Features = append(result.Features, FeatureBreakGlass)
		result.FeatureDetails[FeatureBreakGlass] = "DynamoDB table sentinel-breakglass exists"
	}

	// Note: notify_sns, notify_webhook, and bootstrap_apply are intentionally not auto-detected
	// - notify_sns: Optional, detected via config not resources
	// - notify_webhook: No AWS permissions needed
	// - bootstrap_apply: Optional write operation

	return result, nil
}

// checkSSMPolicyExists checks if any /sentinel/policies/* parameter exists.
func (d *Detector) checkSSMPolicyExists(ctx context.Context) (bool, error) {
	output, err := d.ssmClient.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
		Path:      aws.String("/sentinel/policies"),
		Recursive: aws.Bool(true),
		MaxResults: aws.Int32(1), // We only need to know if at least one exists
	})
	if err != nil {
		// Check if it's a "path not found" type error - treat as no parameters
		var notFound *types.ParameterNotFound
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, err
	}

	return len(output.Parameters) > 0, nil
}

// checkDynamoTableExists checks if a DynamoDB table exists by name.
func (d *Detector) checkDynamoTableExists(ctx context.Context, tableName string) (bool, error) {
	_, err := d.dynamoClient.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		// Check if it's a "table not found" error
		var notFoundErr *ddbtypes.ResourceNotFoundException
		if errors.As(err, &notFoundErr) {
			return false, nil
		}
		// For other errors, we need to check the error message
		// AWS SDK v2 uses typed errors but not all are exported
		if isResourceNotFoundError(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// isResourceNotFoundError checks if the error indicates a resource was not found.
// This handles cases where the specific error type isn't available.
func isResourceNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Check error message for common "not found" indicators
	errMsg := err.Error()
	return strings.Contains(errMsg, "ResourceNotFoundException") ||
		strings.Contains(errMsg, "not found") ||
		strings.Contains(errMsg, "does not exist")
}
