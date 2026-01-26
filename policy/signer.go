// Package policy provides SSM-based policy loading for Sentinel.
// This file implements KMS-based policy signing for preventing policy cache poisoning attacks.
package policy

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAPI defines the KMS operations used by PolicySigner.
// This interface enables testing with mock implementations.
type KMSAPI interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

// DefaultSigningAlgorithm is the default algorithm used for policy signing.
// RSASSA_PSS_SHA_256 provides strong security with good compatibility.
const DefaultSigningAlgorithm = types.SigningAlgorithmSpecRsassaPssSha256

// PolicySigner signs and verifies policies using AWS KMS asymmetric keys.
// It uses the RSASSA_PSS_SHA_256 algorithm by default for strong security.
//
// Example usage:
//
//	signer := NewPolicySigner(awsCfg, "alias/sentinel-policy-signing")
//	signature, err := signer.Sign(ctx, policyYAML)
//	if err != nil {
//	    return err
//	}
//	valid, err := signer.Verify(ctx, policyYAML, signature)
type PolicySigner struct {
	client    KMSAPI
	keyID     string
	algorithm types.SigningAlgorithmSpec
}

// NewPolicySigner creates a new PolicySigner using the provided AWS configuration.
// The keyID can be a KMS key ID, key ARN, alias name, or alias ARN.
//
// Example key IDs:
//   - Key ID: "1234abcd-12ab-34cd-56ef-1234567890ab"
//   - Key ARN: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
//   - Alias name: "alias/sentinel-policy-signing"
//   - Alias ARN: "arn:aws:kms:us-east-1:123456789012:alias/sentinel-policy-signing"
func NewPolicySigner(cfg aws.Config, keyID string) *PolicySigner {
	return &PolicySigner{
		client:    kms.NewFromConfig(cfg),
		keyID:     keyID,
		algorithm: DefaultSigningAlgorithm,
	}
}

// NewPolicySignerWithClient creates a PolicySigner with a custom KMS client.
// This is primarily used for testing with mock clients.
func NewPolicySignerWithClient(client KMSAPI, keyID string) *PolicySigner {
	return &PolicySigner{
		client:    client,
		keyID:     keyID,
		algorithm: DefaultSigningAlgorithm,
	}
}

// Sign creates a cryptographic signature for the given policy YAML content.
// The signature can be used to verify the policy hasn't been tampered with.
//
// The policy YAML is signed directly as the message (MessageType MESSAGE),
// not as a pre-computed digest. This ensures the signature covers the
// exact bytes that will be verified later.
//
// Returns the raw signature bytes on success, or an error if signing fails
// (e.g., key not found, permission denied, invalid key type).
func (s *PolicySigner) Sign(ctx context.Context, policyYAML []byte) ([]byte, error) {
	output, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          policyYAML,
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: s.algorithm,
	})
	if err != nil {
		return nil, err
	}

	return output.Signature, nil
}

// Verify checks if the signature is valid for the given policy YAML content.
// Returns:
//   - (true, nil) if the signature is valid
//   - (false, nil) if the signature is invalid (normal validation result)
//   - (false, error) if verification failed due to KMS errors (key not found, etc.)
//
// Note: An invalid signature is NOT an error - it's a normal validation outcome.
// Errors are reserved for infrastructure issues like missing keys or network failures.
func (s *PolicySigner) Verify(ctx context.Context, policyYAML []byte, signature []byte) (bool, error) {
	output, err := s.client.Verify(ctx, &kms.VerifyInput{
		KeyId:            aws.String(s.keyID),
		Message:          policyYAML,
		MessageType:      types.MessageTypeRaw,
		Signature:        signature,
		SigningAlgorithm: s.algorithm,
	})
	if err != nil {
		// KMS returns InvalidSignature as an error, but we want to treat
		// invalid signatures as a normal validation result (false, nil)
		var invalidSig *types.KMSInvalidSignatureException
		if isKMSInvalidSignature(err, &invalidSig) {
			return false, nil
		}
		return false, err
	}

	return output.SignatureValid, nil
}

// isKMSInvalidSignature checks if the error is a KMS invalid signature exception.
// This is a helper to handle the case where KMS returns an error for invalid signatures.
func isKMSInvalidSignature(err error, target **types.KMSInvalidSignatureException) bool {
	// Use type assertion to check for KMSInvalidSignatureException
	if e, ok := err.(*types.KMSInvalidSignatureException); ok {
		*target = e
		return true
	}
	return false
}
