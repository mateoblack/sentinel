// Package sentinel provides Sentinel's credential issuance with SourceIdentity stamping.
// It wraps AWS STS AssumeRole to ensure all Sentinel-issued credentials carry a
// SourceIdentity stamp for visibility and enforceability inside AWS.
package sentinel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/vault"
)

// Sentinel-specific errors for input validation.
var (
	// ErrMissingRoleARN indicates the RoleARN field is empty.
	ErrMissingRoleARN = errors.New("RoleARN is required")

	// ErrMissingSourceIdentity indicates the SourceIdentity field is nil.
	ErrMissingSourceIdentity = errors.New("SourceIdentity is required")

	// ErrMissingCredsProvider indicates the CredsProvider field is nil.
	ErrMissingCredsProvider = errors.New("CredsProvider is required")

	// ErrInvalidSourceIdentity indicates the SourceIdentity is not valid.
	ErrInvalidSourceIdentity = errors.New("SourceIdentity is invalid")
)

// Default values for SentinelAssumeRole.
const (
	// DefaultDuration is the default session duration (1 hour, matching aws-vault).
	DefaultDuration = time.Hour
)

// SentinelAssumeRoleInput contains the parameters for SentinelAssumeRole.
type SentinelAssumeRoleInput struct {
	// CredsProvider provides the base credentials (from aws-vault).
	// Required.
	CredsProvider aws.CredentialsProvider

	// RoleARN is the ARN of the role to assume.
	// Required.
	RoleARN string

	// RoleSessionName is the name for the assumed role session.
	// Optional - defaults to "sentinel-{timestamp}".
	RoleSessionName string

	// Duration is the session duration.
	// Optional - defaults to 1 hour.
	Duration time.Duration

	// SourceIdentity is the Sentinel identity stamp to apply.
	// Required.
	SourceIdentity *identity.SourceIdentity

	// Region is the AWS region for the STS endpoint.
	Region string

	// STSRegionalEndpoints controls regional vs global endpoints.
	// Optional - "legacy" or "regional".
	STSRegionalEndpoints string

	// EndpointURL is a custom STS endpoint URL.
	// Optional.
	EndpointURL string

	// ExternalID is used for cross-account role assumption.
	// Optional.
	ExternalID string
}

// SentinelAssumeRoleOutput contains the result of SentinelAssumeRole.
type SentinelAssumeRoleOutput struct {
	// Credentials are the temporary AWS credentials.
	Credentials aws.Credentials

	// SourceIdentity is the stamped SourceIdentity value.
	SourceIdentity string

	// AssumedRoleArn is the ARN of the assumed role.
	AssumedRoleArn string

	// AssumedRoleId is the unique identifier for the assumed role session.
	AssumedRoleId string
}

// SentinelAssumeRole assumes an AWS role with SourceIdentity stamping.
// It validates input, creates an STS client, and calls AssumeRole with
// the SourceIdentity from the input.
//
// This is the core mechanism for Sentinel Fingerprint - all credentials
// issued by Sentinel carry a SourceIdentity stamp that identifies the
// Sentinel user and request for correlation with CloudTrail.
func SentinelAssumeRole(ctx context.Context, input *SentinelAssumeRoleInput) (*SentinelAssumeRoleOutput, error) {
	// Validate input
	if err := validateInput(input); err != nil {
		return nil, err
	}

	// Apply defaults
	applyDefaults(input)

	// Create STS client using vault pattern
	cfg := vault.NewAwsConfigWithCredsProvider(
		input.CredsProvider,
		input.Region,
		input.STSRegionalEndpoints,
		input.EndpointURL,
	)
	stsClient := sts.NewFromConfig(cfg)

	// Build AssumeRole input with SourceIdentity
	assumeRoleInput := &sts.AssumeRoleInput{
		RoleArn:         aws.String(input.RoleARN),
		RoleSessionName: aws.String(input.RoleSessionName),
		DurationSeconds: aws.Int32(int32(input.Duration.Seconds())),
		SourceIdentity:  aws.String(input.SourceIdentity.Format()),
	}

	// Add ExternalID if provided
	if input.ExternalID != "" {
		assumeRoleInput.ExternalId = aws.String(input.ExternalID)
	}

	// Call STS AssumeRole
	resp, err := stsClient.AssumeRole(ctx, assumeRoleInput)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role %s: %w", input.RoleARN, err)
	}

	// Log the assumption
	log.Printf("Assumed role %s with SourceIdentity %s, expires in %s",
		input.RoleARN,
		input.SourceIdentity.Format(),
		time.Until(*resp.Credentials.Expiration).String(),
	)

	return &SentinelAssumeRoleOutput{
		Credentials: aws.Credentials{
			AccessKeyID:     *resp.Credentials.AccessKeyId,
			SecretAccessKey: *resp.Credentials.SecretAccessKey,
			SessionToken:    *resp.Credentials.SessionToken,
			CanExpire:       true,
			Expires:         *resp.Credentials.Expiration,
		},
		SourceIdentity: input.SourceIdentity.Format(),
		AssumedRoleArn: *resp.AssumedRoleUser.Arn,
		AssumedRoleId:  *resp.AssumedRoleUser.AssumedRoleId,
	}, nil
}

// validateInput checks that all required fields are present and valid.
func validateInput(input *SentinelAssumeRoleInput) error {
	if input.CredsProvider == nil {
		return ErrMissingCredsProvider
	}
	if input.RoleARN == "" {
		return ErrMissingRoleARN
	}
	if input.SourceIdentity == nil {
		return ErrMissingSourceIdentity
	}
	if !input.SourceIdentity.IsValid() {
		return ErrInvalidSourceIdentity
	}
	return nil
}

// applyDefaults sets default values for optional fields.
func applyDefaults(input *SentinelAssumeRoleInput) {
	if input.RoleSessionName == "" {
		input.RoleSessionName = fmt.Sprintf("sentinel-%d", time.Now().UTC().UnixNano())
	}
	if input.Duration == 0 {
		input.Duration = DefaultDuration
	}
}
