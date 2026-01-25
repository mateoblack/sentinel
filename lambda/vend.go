// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/byteness/aws-vault/v7/identity"
)

// Credential vending specific errors.
var (
	// ErrMissingCaller indicates the Caller field is nil.
	ErrMissingCaller = errors.New("Caller is required")

	// ErrMissingRoleARN indicates the RoleARN field is empty.
	ErrMissingRoleARN = errors.New("RoleARN is required")

	// ErrInvalidARN indicates the ARN format is invalid.
	ErrInvalidARN = errors.New("invalid ARN format")

	// ErrEmptyUsername indicates the username could not be extracted from ARN.
	ErrEmptyUsername = errors.New("could not extract username from ARN")
)

// Default values for credential vending.
const (
	// DefaultVendDuration is the default session duration (1 hour).
	DefaultVendDuration = time.Hour
)

// STSClient defines the interface for STS operations used by credential vending.
// This enables testing by allowing mock implementations.
type STSClient interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// VendInput contains the parameters for credential vending.
type VendInput struct {
	// Caller is the IAM identity of the API Gateway caller.
	// Required.
	Caller *CallerIdentity

	// RoleARN is the target role to assume.
	// Required.
	RoleARN string

	// SessionDuration is the requested credential duration.
	// Optional - defaults to 1 hour.
	SessionDuration time.Duration

	// Region is the AWS region for the STS endpoint.
	// Optional - uses Lambda's region if not specified.
	Region string

	// SessionID is the session ID to stamp as a session tag.
	// Optional - if empty, no session tag is added.
	SessionID string

	// ApprovalID is the ID of the approved request that allowed this credential issuance.
	// Optional - if empty, indicates direct access (policy allowed).
	// Included in SourceIdentity for audit trail and SCP differentiation.
	ApprovalID string
}

// VendOutput contains the result of credential vending.
type VendOutput struct {
	// Credentials are the vended AWS credentials in container format.
	Credentials *TVMResponse

	// SourceIdentity is the stamped identity for logging/correlation.
	SourceIdentity *identity.SourceIdentity
}

// VendCredentials vends AWS credentials by assuming a role with SourceIdentity stamping.
// It creates an STS client using the Lambda's execution role and performs AssumeRole
// with a SourceIdentity derived from the caller's identity.
func VendCredentials(ctx context.Context, input *VendInput) (*VendOutput, error) {
	// Load AWS config using Lambda's execution role
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(input.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create STS client from config
	stsClient := sts.NewFromConfig(cfg)

	return VendCredentialsWithClient(ctx, input, stsClient)
}

// VendCredentialsWithClient vends AWS credentials using a provided STS client.
// This variant enables testing by accepting a mock STSClient.
func VendCredentialsWithClient(ctx context.Context, input *VendInput, client STSClient) (*VendOutput, error) {
	// Validate input
	if err := validateVendInput(input); err != nil {
		return nil, err
	}

	// Apply defaults
	applyVendDefaults(input)

	// Extract username from caller ARN
	username, err := extractUsername(input.Caller.UserARN)
	if err != nil {
		return nil, fmt.Errorf("failed to extract username: %w", err)
	}

	// Generate request-id
	requestID := identity.NewRequestID()

	// Create SourceIdentity (includes approval ID if via approved request)
	sourceIdentity, err := identity.New(username, input.ApprovalID, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to create SourceIdentity: %w", err)
	}

	// Build RoleSessionName
	roleSessionName := fmt.Sprintf("tvm-%s-%s", username, requestID)

	// Build AssumeRole input
	assumeRoleInput := &sts.AssumeRoleInput{
		RoleArn:         aws.String(input.RoleARN),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int32(int32(input.SessionDuration.Seconds())),
		SourceIdentity:  aws.String(sourceIdentity.Format()),
	}

	// Add session tag if session tracking is enabled
	if input.SessionID != "" {
		assumeRoleInput.Tags = []types.Tag{{
			Key:   aws.String("SentinelSessionID"),
			Value: aws.String(input.SessionID),
		}}
	}

	// Call STS AssumeRole
	resp, err := client.AssumeRole(ctx, assumeRoleInput)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role %s: %w", input.RoleARN, err)
	}

	// Convert STS response to TVMResponse
	credentials := &TVMResponse{
		AccessKeyId:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		Token:           *resp.Credentials.SessionToken,
		Expiration:      resp.Credentials.Expiration.UTC().Format(time.RFC3339),
	}

	return &VendOutput{
		Credentials:    credentials,
		SourceIdentity: sourceIdentity,
	}, nil
}

// validateVendInput checks that all required fields are present.
func validateVendInput(input *VendInput) error {
	if input.Caller == nil {
		return ErrMissingCaller
	}
	if input.RoleARN == "" {
		return ErrMissingRoleARN
	}
	return nil
}

// applyVendDefaults sets default values for optional fields.
func applyVendDefaults(input *VendInput) {
	if input.SessionDuration == 0 {
		input.SessionDuration = DefaultVendDuration
	}
}

// extractUsername extracts a sanitized username from an AWS ARN.
// Supported ARN formats:
//   - IAM user: arn:aws:iam::123456789012:user/alice -> "alice"
//   - Assumed role: arn:aws:sts::123456789012:assumed-role/RoleName/SessionName -> "SessionName"
//   - SSO: arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_.../user@example.com -> sanitized email
//   - Federated user: arn:aws:sts::123456789012:federated-user/fed-user -> "feduser"
func extractUsername(userARN string) (string, error) {
	if userARN == "" {
		return "", ErrInvalidARN
	}

	// ARN format: arn:aws:SERVICE:REGION:ACCOUNT:RESOURCE
	// Split by ':'
	parts := strings.Split(userARN, ":")
	if len(parts) < 6 {
		return "", ErrInvalidARN
	}

	// Validate it looks like an ARN
	if parts[0] != "arn" {
		return "", ErrInvalidARN
	}

	resource := parts[5]
	if resource == "" {
		return "", ErrEmptyUsername
	}

	var rawUsername string

	// Handle different resource types
	switch {
	case strings.HasPrefix(resource, "user/"):
		// IAM user: user/alice
		rawUsername = strings.TrimPrefix(resource, "user/")
		// Handle paths: user/path/to/alice -> alice
		if lastSlash := strings.LastIndex(rawUsername, "/"); lastSlash != -1 {
			rawUsername = rawUsername[lastSlash+1:]
		}

	case strings.HasPrefix(resource, "assumed-role/"):
		// Assumed role: assumed-role/RoleName/SessionName
		// Extract SessionName (last component)
		trimmed := strings.TrimPrefix(resource, "assumed-role/")
		slashIndex := strings.Index(trimmed, "/")
		if slashIndex == -1 || slashIndex == len(trimmed)-1 {
			// No session name found, use role name
			if slashIndex == -1 {
				rawUsername = trimmed
			} else {
				rawUsername = trimmed[:slashIndex]
			}
		} else {
			rawUsername = trimmed[slashIndex+1:]
		}

	case strings.HasPrefix(resource, "federated-user/"):
		// Federated user: federated-user/fed-user
		rawUsername = strings.TrimPrefix(resource, "federated-user/")

	default:
		// Unknown format, try to extract last path component
		if lastSlash := strings.LastIndex(resource, "/"); lastSlash != -1 {
			rawUsername = resource[lastSlash+1:]
		} else {
			rawUsername = resource
		}
	}

	if rawUsername == "" {
		return "", ErrEmptyUsername
	}

	// Sanitize using identity package
	return identity.SanitizeUser(rawUsername)
}
