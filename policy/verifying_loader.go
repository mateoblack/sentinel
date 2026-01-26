// Package policy provides SSM-based policy loading for Sentinel.
// This file implements a verifying policy loader that validates signatures before returning policies.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// Error types for signature verification.
var (
	// ErrSignatureInvalid indicates the policy signature verification failed.
	ErrSignatureInvalid = errors.New("policy signature verification failed")
	// ErrSignatureMissing indicates the policy has no signature.
	ErrSignatureMissing = errors.New("policy signature missing")
	// ErrSignatureEnforced indicates signature enforcement is enabled but the policy is unsigned.
	ErrSignatureEnforced = errors.New("policy not signed (signature enforcement enabled)")
)

// RawPolicyLoader is the interface for loading raw policy YAML content.
// This is needed for signature verification which operates on raw bytes.
type RawPolicyLoader interface {
	LoadRaw(ctx context.Context, parameterName string) ([]byte, error)
}

// VerifyingLoader wraps a policy loader and validates signatures before returning policies.
// It provides fail-closed security with configurable enforcement modes.
type VerifyingLoader struct {
	policyLoader RawPolicyLoader // Underlying loader for policy YAML
	sigLoader    RawPolicyLoader // Loader for signature parameters
	signer       *PolicySigner   // For signature verification
	enforce      bool            // If true, reject unsigned policies. If false, warn only.
}

// VerifyingLoaderOption configures a VerifyingLoader.
type VerifyingLoaderOption func(*VerifyingLoader)

// WithEnforcement configures whether signature enforcement is enabled.
// When enabled (true), unsigned policies are rejected.
// When disabled (false), unsigned policies log a warning but are still loaded.
func WithEnforcement(enforce bool) VerifyingLoaderOption {
	return func(v *VerifyingLoader) {
		v.enforce = enforce
	}
}

// NewVerifyingLoader creates a new VerifyingLoader.
// policyLoader is used to load the policy YAML content.
// sigLoader is used to load the signature parameters (can be the same loader, different prefix).
// signer is used for cryptographic signature verification.
func NewVerifyingLoader(policyLoader, sigLoader RawPolicyLoader, signer *PolicySigner, opts ...VerifyingLoaderOption) *VerifyingLoader {
	v := &VerifyingLoader{
		policyLoader: policyLoader,
		sigLoader:    sigLoader,
		signer:       signer,
		enforce:      false, // Default: warn only, for backward compatibility
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Load fetches a policy from the underlying loader and verifies its signature.
// Returns:
//   - The policy if signature is valid or signature checking is disabled
//   - ErrSignatureInvalid if the signature doesn't match the policy
//   - ErrSignatureEnforced if enforcement is enabled and no signature exists
//   - Passthrough errors from the underlying loaders
func (v *VerifyingLoader) Load(ctx context.Context, parameterName string) (*Policy, error) {
	// Step 1: Load policy YAML
	policyYAML, err := v.policyLoader.LoadRaw(ctx, parameterName)
	if err != nil {
		return nil, err
	}

	// Step 2: Compute signature parameter name
	sigParamName := SignatureParameterName(parameterName)

	// Step 3: Load signature
	sigData, err := v.sigLoader.LoadRaw(ctx, sigParamName)
	if err != nil {
		// Handle missing signature
		if errors.Is(err, ErrPolicyNotFound) {
			if v.enforce {
				return nil, fmt.Errorf("%s: %w", parameterName, ErrSignatureEnforced)
			}
			// Warn but continue without verification
			log.Printf("WARNING: policy %s has no signature, loading without verification", parameterName)
			return ParsePolicy(policyYAML)
		}
		return nil, fmt.Errorf("failed to load signature for %s: %w", parameterName, err)
	}

	// Step 4: Parse signature metadata
	var sigEnvelope SignatureEnvelope
	if err := json.Unmarshal(sigData, &sigEnvelope); err != nil {
		return nil, fmt.Errorf("failed to parse signature for %s: %w", parameterName, err)
	}

	// Step 5: Verify signature
	valid, err := v.signer.Verify(ctx, policyYAML, sigEnvelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature verification error for %s: %w", parameterName, err)
	}
	if !valid {
		return nil, fmt.Errorf("%s: %w", parameterName, ErrSignatureInvalid)
	}

	// Step 6: Parse and return the policy
	return ParsePolicy(policyYAML)
}

// SignatureEnvelope is the JSON structure stored in the signature parameter.
// It contains the raw signature bytes and metadata about the signing operation.
type SignatureEnvelope struct {
	// Signature is the raw signature bytes from KMS.
	Signature []byte `json:"signature"`
	// Metadata contains information about the signing operation.
	Metadata SignatureMetadata `json:"metadata"`
}

// LoaderWithRaw wraps a standard Loader to provide RawPolicyLoader functionality.
type LoaderWithRaw struct {
	client SSMAPI
}

// NewLoaderWithRaw creates a new LoaderWithRaw using the provided SSM client.
func NewLoaderWithRaw(client SSMAPI) *LoaderWithRaw {
	return &LoaderWithRaw{client: client}
}

// LoadRaw fetches raw YAML bytes from SSM Parameter Store.
func (l *LoaderWithRaw) LoadRaw(ctx context.Context, parameterName string) ([]byte, error) {
	output, err := l.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(parameterName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		var notFound *types.ParameterNotFound
		if errors.As(err, &notFound) {
			return nil, fmt.Errorf("%s: %w", parameterName, ErrPolicyNotFound)
		}
		return nil, err
	}
	return []byte(aws.ToString(output.Parameter.Value)), nil
}
