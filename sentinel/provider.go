// Package sentinel provides Sentinel's credential issuance with SourceIdentity stamping.
// This file implements the TwoHopCredentialProvider which chains aws-vault base
// credentials through SentinelAssumeRole to stamp SourceIdentity on all credentials.
package sentinel

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/identity"
)

// TwoHopCredentialProvider validation errors.
var (
	// ErrMissingBaseCredsProvider indicates the BaseCredsProvider field is nil.
	ErrMissingBaseCredsProvider = errors.New("BaseCredsProvider is required")

	// ErrMissingUser indicates the User field is empty.
	ErrMissingUser = errors.New("User is required for SourceIdentity")
)

// TwoHopCredentialProviderInput contains the parameters for creating a TwoHopCredentialProvider.
type TwoHopCredentialProviderInput struct {
	// BaseCredsProvider provides the base credentials from aws-vault
	// (session tokens, SSO, stored creds, etc.).
	// Required.
	BaseCredsProvider aws.CredentialsProvider

	// RoleARN is the ARN of the target role to assume.
	// Required.
	RoleARN string

	// User is the username for SourceIdentity stamping.
	// This will be sanitized for AWS SourceIdentity constraints.
	// Required.
	User string

	// Region is the AWS region for the STS endpoint.
	// Optional.
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

	// SessionDuration is the session duration for the assumed role.
	// Optional - defaults to 1 hour.
	SessionDuration time.Duration

	// RequestID is an optional pre-generated request-id for correlation.
	// If empty, a new request-id will be generated during Retrieve().
	// Optional.
	RequestID string
}

// TwoHopCredentialProvider implements aws.CredentialsProvider by chaining
// aws-vault base credentials through SentinelAssumeRole.
//
// This provider implements the core credential flow for Sentinel Fingerprint:
// 1. Get base credentials from aws-vault (session tokens, SSO, stored creds)
// 2. Generate unique SourceIdentity (sentinel:<user>:<request-id>)
// 3. Assume target role with SourceIdentity stamped
//
// Each Retrieve() call generates a fresh request-id (unless pre-generated),
// ensuring all credentials can be correlated with their Sentinel issuance.
type TwoHopCredentialProvider struct {
	Input TwoHopCredentialProviderInput

	// LastSourceIdentity is set after Retrieve() completes successfully.
	// It contains the SourceIdentity used for the most recent credential request.
	// Callers can use this to retrieve the actual SourceIdentity for logging/correlation.
	LastSourceIdentity *identity.SourceIdentity
}

// NewTwoHopCredentialProvider creates a new TwoHopCredentialProvider with the given input.
// It validates required fields before returning.
func NewTwoHopCredentialProvider(input TwoHopCredentialProviderInput) (*TwoHopCredentialProvider, error) {
	if err := validateProviderInput(&input); err != nil {
		return nil, err
	}

	return &TwoHopCredentialProvider{
		Input: input,
	}, nil
}

// NewTwoHopProvider is a convenience constructor for the common use case.
// It creates a TwoHopCredentialProvider with minimal required inputs.
func NewTwoHopProvider(baseProvider aws.CredentialsProvider, roleARN, user, region string) (*TwoHopCredentialProvider, error) {
	return NewTwoHopCredentialProvider(TwoHopCredentialProviderInput{
		BaseCredsProvider: baseProvider,
		RoleARN:           roleARN,
		User:              user,
		Region:            region,
	})
}

// Retrieve generates new credentials by assuming the target role with SourceIdentity.
// If Input.RequestID is provided, it uses that; otherwise generates a new request-id.
// After successful completion, LastSourceIdentity is populated for caller retrieval.
//
// Implements aws.CredentialsProvider interface.
func (p *TwoHopCredentialProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	// Use pre-generated request-id if provided, otherwise generate new one
	requestID := p.Input.RequestID
	if requestID == "" {
		requestID = identity.NewRequestID()
	}

	// Sanitize username for SourceIdentity constraints
	sanitizedUser, err := identity.SanitizeUser(p.Input.User)
	if err != nil {
		return aws.Credentials{}, err
	}

	// Create SourceIdentity with sanitized user and request-id
	sourceIdentity, err := identity.New(sanitizedUser, requestID)
	if err != nil {
		return aws.Credentials{}, err
	}

	// Store the SourceIdentity for caller retrieval
	p.LastSourceIdentity = sourceIdentity

	// Determine session duration (use default if not specified)
	duration := p.Input.SessionDuration
	if duration == 0 {
		duration = DefaultDuration
	}

	// Build SentinelAssumeRole input
	assumeRoleInput := &SentinelAssumeRoleInput{
		CredsProvider:        p.Input.BaseCredsProvider,
		RoleARN:              p.Input.RoleARN,
		SourceIdentity:       sourceIdentity,
		Region:               p.Input.Region,
		STSRegionalEndpoints: p.Input.STSRegionalEndpoints,
		EndpointURL:          p.Input.EndpointURL,
		ExternalID:           p.Input.ExternalID,
		Duration:             duration,
	}

	// Call SentinelAssumeRole to get credentials with SourceIdentity stamp
	result, err := SentinelAssumeRole(ctx, assumeRoleInput)
	if err != nil {
		return aws.Credentials{}, err
	}

	return result.Credentials, nil
}

// validateProviderInput checks that all required fields are present.
func validateProviderInput(input *TwoHopCredentialProviderInput) error {
	if input.BaseCredsProvider == nil {
		return ErrMissingBaseCredsProvider
	}
	if input.RoleARN == "" {
		return ErrMissingRoleARN
	}
	if input.User == "" {
		return ErrMissingUser
	}
	return nil
}
