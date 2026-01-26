package policy_test

import (
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/policy"
)

func TestSignatureParameterName(t *testing.T) {
	tests := []struct {
		name        string
		policyParam string
		want        string
	}{
		{
			name:        "simple policy path",
			policyParam: "/sentinel/policies/production",
			want:        "/sentinel/signatures/production",
		},
		{
			name:        "nested policy path",
			policyParam: "/sentinel/policies/team/dev",
			want:        "/sentinel/signatures/team/dev",
		},
		{
			name:        "deeply nested policy path",
			policyParam: "/sentinel/policies/org/team/project/env",
			want:        "/sentinel/signatures/org/team/project/env",
		},
		{
			name:        "non-standard path",
			policyParam: "/custom/path/policy",
			want:        "/sentinel/signatures/custom/path/policy",
		},
		{
			name:        "path without leading slash",
			policyParam: "sentinel/policies/test",
			want:        "/sentinel/signatures/sentinel/policies/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.SignatureParameterName(tt.policyParam)
			if got != tt.want {
				t.Errorf("SignatureParameterName(%q) = %q, want %q", tt.policyParam, got, tt.want)
			}
		})
	}
}

func TestPolicyParameterName(t *testing.T) {
	tests := []struct {
		name           string
		signatureParam string
		want           string
	}{
		{
			name:           "simple signature path",
			signatureParam: "/sentinel/signatures/production",
			want:           "/sentinel/policies/production",
		},
		{
			name:           "nested signature path",
			signatureParam: "/sentinel/signatures/team/dev",
			want:           "/sentinel/policies/team/dev",
		},
		{
			name:           "deeply nested signature path",
			signatureParam: "/sentinel/signatures/org/team/project/env",
			want:           "/sentinel/policies/org/team/project/env",
		},
		{
			name:           "non-standard path",
			signatureParam: "/custom/path/signature",
			want:           "/sentinel/policies/custom/path/signature",
		},
		{
			name:           "path without leading slash",
			signatureParam: "sentinel/signatures/test",
			want:           "/sentinel/policies/sentinel/signatures/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.PolicyParameterName(tt.signatureParam)
			if got != tt.want {
				t.Errorf("PolicyParameterName(%q) = %q, want %q", tt.signatureParam, got, tt.want)
			}
		})
	}
}

func TestSignatureParameterName_RoundTrip(t *testing.T) {
	// Test that converting policy -> signature -> policy returns the original
	original := "/sentinel/policies/production"
	signature := policy.SignatureParameterName(original)
	roundTrip := policy.PolicyParameterName(signature)

	if roundTrip != original {
		t.Errorf("round trip failed: %q -> %q -> %q", original, signature, roundTrip)
	}
}

func TestComputePolicyHash(t *testing.T) {
	tests := []struct {
		name       string
		policyYAML []byte
	}{
		{
			name:       "simple policy",
			policyYAML: []byte("version: '1'\nrules: []"),
		},
		{
			name:       "empty content",
			policyYAML: []byte(""),
		},
		{
			name:       "complex policy",
			policyYAML: []byte("version: '1'\nrules:\n  - name: test\n    effect: allow\n    conditions:\n      profiles:\n        - production"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.ComputePolicyHash(tt.policyYAML)

			// Verify hash is valid hex format (64 chars for SHA-256)
			if len(got) != 64 {
				t.Errorf("ComputePolicyHash() returned hash of length %d, want 64", len(got))
			}

			// Verify all characters are valid hex
			for _, c := range got {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("ComputePolicyHash() returned non-hex character: %c", c)
				}
			}

			// Verify hash is consistent (same input produces same output)
			got2 := policy.ComputePolicyHash(tt.policyYAML)
			if got != got2 {
				t.Errorf("ComputePolicyHash() not deterministic: %q != %q", got, got2)
			}
		})
	}
}

func TestComputePolicyHash_EmptyString(t *testing.T) {
	// SHA-256 of empty string is a well-known value
	got := policy.ComputePolicyHash([]byte(""))
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("ComputePolicyHash(empty) = %q, want %q", got, want)
	}
}

func TestComputePolicyHash_Deterministic(t *testing.T) {
	// Same content should always produce the same hash
	content := []byte("version: '1'\nrules: []\n")

	hash1 := policy.ComputePolicyHash(content)
	hash2 := policy.ComputePolicyHash(content)

	if hash1 != hash2 {
		t.Errorf("hash not deterministic: %q != %q", hash1, hash2)
	}
}

func TestComputePolicyHash_DifferentContent(t *testing.T) {
	// Different content should produce different hashes
	content1 := []byte("version: '1'\nrules: []")
	content2 := []byte("version: '1'\nrules: []\n") // Added newline

	hash1 := policy.ComputePolicyHash(content1)
	hash2 := policy.ComputePolicyHash(content2)

	if hash1 == hash2 {
		t.Error("different content produced same hash")
	}
}

func TestSignatureMetadata_Validate(t *testing.T) {
	validMetadata := policy.SignatureMetadata{
		KeyID:      "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
		Algorithm:  "RSASSA_PSS_SHA_256",
		SignedAt:   time.Now(),
		PolicyHash: "abcdef1234567890",
	}

	tests := []struct {
		name     string
		metadata policy.SignatureMetadata
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid metadata",
			metadata: validMetadata,
			wantErr:  false,
		},
		{
			name: "missing key_id",
			metadata: policy.SignatureMetadata{
				Algorithm:  "RSASSA_PSS_SHA_256",
				SignedAt:   time.Now(),
				PolicyHash: "abcdef1234567890",
			},
			wantErr: true,
			errMsg:  "key_id is required",
		},
		{
			name: "missing algorithm",
			metadata: policy.SignatureMetadata{
				KeyID:      "arn:aws:kms:...",
				SignedAt:   time.Now(),
				PolicyHash: "abcdef1234567890",
			},
			wantErr: true,
			errMsg:  "algorithm is required",
		},
		{
			name: "missing signed_at",
			metadata: policy.SignatureMetadata{
				KeyID:      "arn:aws:kms:...",
				Algorithm:  "RSASSA_PSS_SHA_256",
				PolicyHash: "abcdef1234567890",
			},
			wantErr: true,
			errMsg:  "signed_at is required",
		},
		{
			name: "missing policy_hash",
			metadata: policy.SignatureMetadata{
				KeyID:     "arn:aws:kms:...",
				Algorithm: "RSASSA_PSS_SHA_256",
				SignedAt:  time.Now(),
			},
			wantErr: true,
			errMsg:  "policy_hash is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.metadata.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSignedPolicy_ValidateHash(t *testing.T) {
	policyYAML := []byte("version: '1'\nrules: []")
	correctHash := policy.ComputePolicyHash(policyYAML)

	tests := []struct {
		name       string
		signed     policy.SignedPolicy
		policyYAML []byte
		want       bool
	}{
		{
			name: "matching hash",
			signed: policy.SignedPolicy{
				Metadata: policy.SignatureMetadata{
					PolicyHash: correctHash,
				},
			},
			policyYAML: policyYAML,
			want:       true,
		},
		{
			name: "mismatched hash",
			signed: policy.SignedPolicy{
				Metadata: policy.SignatureMetadata{
					PolicyHash: "wrong-hash-value",
				},
			},
			policyYAML: policyYAML,
			want:       false,
		},
		{
			name: "empty hash in metadata",
			signed: policy.SignedPolicy{
				Metadata: policy.SignatureMetadata{
					PolicyHash: "",
				},
			},
			policyYAML: policyYAML,
			want:       false,
		},
		{
			name: "tampered policy content",
			signed: policy.SignedPolicy{
				Metadata: policy.SignatureMetadata{
					PolicyHash: correctHash,
				},
			},
			policyYAML: []byte("version: '1'\nrules: []\n# tampered"),
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.signed.ValidateHash(tt.policyYAML)
			if got != tt.want {
				t.Errorf("ValidateHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function for error message checking
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
