// Package policy provides SSM-based policy loading for Sentinel.
// This file defines signature types and storage schema for signed policies.
package policy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Parameter path prefixes for policies and signatures in SSM Parameter Store.
const (
	// PolicyParameterPrefix is the SSM parameter path prefix for policies.
	PolicyParameterPrefix = "/sentinel/policies/"
	// SignatureParameterPrefix is the SSM parameter path prefix for policy signatures.
	SignatureParameterPrefix = "/sentinel/signatures/"
)

// SignatureMetadata contains metadata about a policy signature.
// This is stored alongside the signature to enable verification and auditing.
type SignatureMetadata struct {
	// KeyID is the KMS key ARN or ID used for signing.
	KeyID string `json:"key_id"`
	// Algorithm is the signing algorithm (e.g., RSASSA_PSS_SHA_256).
	Algorithm string `json:"algorithm"`
	// SignedAt is the timestamp when the signature was created.
	SignedAt time.Time `json:"signed_at"`
	// PolicyHash is the SHA-256 hash of the policy YAML content (hex encoded).
	// This allows quick verification that the signature matches the policy.
	PolicyHash string `json:"policy_hash"`
}

// SignedPolicy combines a policy with its cryptographic signature and metadata.
// This is the complete unit of trust for policy verification.
type SignedPolicy struct {
	// Policy is the parsed policy object.
	Policy *Policy `json:"policy"`
	// Signature is the raw signature bytes from KMS.
	Signature []byte `json:"signature"`
	// SignatureBase64 is the base64-encoded signature for storage/transmission.
	SignatureBase64 string `json:"signature_base64"`
	// Metadata contains information about the signing operation.
	Metadata SignatureMetadata `json:"metadata"`
}

// SignatureParameterName converts a policy parameter path to its corresponding
// signature parameter path.
//
// Example:
//
//	SignatureParameterName("/sentinel/policies/production") returns "/sentinel/signatures/production"
//	SignatureParameterName("/sentinel/policies/team/dev") returns "/sentinel/signatures/team/dev"
func SignatureParameterName(policyParam string) string {
	if !strings.HasPrefix(policyParam, PolicyParameterPrefix) {
		// If not a standard policy path, just append to signature prefix
		return SignatureParameterPrefix + strings.TrimPrefix(policyParam, "/")
	}
	// Replace policy prefix with signature prefix
	suffix := strings.TrimPrefix(policyParam, PolicyParameterPrefix)
	return SignatureParameterPrefix + suffix
}

// PolicyParameterName converts a signature parameter path to its corresponding
// policy parameter path.
//
// Example:
//
//	PolicyParameterName("/sentinel/signatures/production") returns "/sentinel/policies/production"
//	PolicyParameterName("/sentinel/signatures/team/dev") returns "/sentinel/policies/team/dev"
func PolicyParameterName(signatureParam string) string {
	if !strings.HasPrefix(signatureParam, SignatureParameterPrefix) {
		// If not a standard signature path, just append to policy prefix
		return PolicyParameterPrefix + strings.TrimPrefix(signatureParam, "/")
	}
	// Replace signature prefix with policy prefix
	suffix := strings.TrimPrefix(signatureParam, SignatureParameterPrefix)
	return PolicyParameterPrefix + suffix
}

// ComputePolicyHash computes the SHA-256 hash of policy YAML content.
// Returns the hash as a lowercase hex-encoded string.
//
// This hash is used to:
// - Quickly verify that a signature matches a policy without calling KMS
// - Detect if a policy has been modified since signing
// - Provide a stable identifier for a specific policy version
func ComputePolicyHash(policyYAML []byte) string {
	hash := sha256.Sum256(policyYAML)
	return hex.EncodeToString(hash[:])
}

// Validate checks that the SignatureMetadata has all required fields.
// Returns an error describing the first missing field, or nil if valid.
func (m *SignatureMetadata) Validate() error {
	if m.KeyID == "" {
		return errors.New("signature metadata: key_id is required")
	}
	if m.Algorithm == "" {
		return errors.New("signature metadata: algorithm is required")
	}
	if m.SignedAt.IsZero() {
		return errors.New("signature metadata: signed_at is required")
	}
	if m.PolicyHash == "" {
		return errors.New("signature metadata: policy_hash is required")
	}
	return nil
}

// ValidateHash checks if the metadata's PolicyHash matches the hash of the
// provided policy YAML content.
//
// This is a quick check to detect policy tampering without calling KMS.
// Note: A matching hash does not guarantee the signature is valid - it only
// confirms the policy content hasn't changed since the metadata was created.
// Always use PolicySigner.Verify() for cryptographic verification.
//
// Uses constant-time comparison to prevent timing attacks that could leak
// information about the expected hash value.
func (s *SignedPolicy) ValidateHash(policyYAML []byte) bool {
	if s.Metadata.PolicyHash == "" {
		return false
	}
	computedHash := ComputePolicyHash(policyYAML)
	return subtle.ConstantTimeCompare([]byte(s.Metadata.PolicyHash), []byte(computedHash)) == 1
}
