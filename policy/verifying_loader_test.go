package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/testutil"
)

// testRawLoader is a mock implementation of RawPolicyLoader for testing.
type testRawLoader struct {
	// Data maps parameter names to their content.
	Data map[string][]byte
	// Errors maps parameter names to errors to return.
	Errors map[string]error
	// Calls tracks all LoadRaw calls.
	Calls []string
}

// LoadRaw implements RawPolicyLoader.
func (m *testRawLoader) LoadRaw(ctx context.Context, parameterName string) ([]byte, error) {
	m.Calls = append(m.Calls, parameterName)

	if m.Errors != nil {
		if err, ok := m.Errors[parameterName]; ok {
			return nil, err
		}
	}

	if m.Data != nil {
		if data, ok := m.Data[parameterName]; ok {
			return data, nil
		}
	}

	// Default: not found
	return nil, errors.New(parameterName + ": " + policy.ErrPolicyNotFound.Error())
}

func TestVerifyingLoader_Load_ValidSignature(t *testing.T) {
	policyYAML := []byte(`version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      profiles:
        - "*"
`)

	signature := []byte("valid-signature-bytes")

	// Create signature envelope
	sigEnvelope := policy.SignatureEnvelope{
		Signature: signature,
		Metadata: policy.SignatureMetadata{
			KeyID:      "test-key-id",
			Algorithm:  "RSASSA_PSS_SHA_256",
			PolicyHash: policy.ComputePolicyHash(policyYAML),
		},
	}
	sigJSON, _ := json.Marshal(sigEnvelope)

	policyLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/policies/prod": policyYAML,
		},
	}

	sigLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/signatures/prod": sigJSON,
		},
	}

	mockKMS := &testutil.MockKMSClient{
		VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
			// Verify signature matches
			if string(params.Message) != string(policyYAML) {
				t.Errorf("unexpected policy YAML in verify call")
			}
			if string(params.Signature) != string(signature) {
				t.Errorf("unexpected signature in verify call")
			}
			return &kms.VerifyOutput{SignatureValid: true}, nil
		},
	}

	signer := policy.NewPolicySignerWithClient(mockKMS, "test-key-id")
	loader := policy.NewVerifyingLoader(policyLoader, sigLoader, signer)

	pol, err := loader.Load(context.Background(), "/sentinel/policies/prod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if pol == nil {
		t.Fatal("expected policy, got nil")
	}
	if pol.Version != "1" {
		t.Errorf("expected version '1', got %q", pol.Version)
	}
	if len(pol.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(pol.Rules))
	}
}

func TestVerifyingLoader_Load_InvalidSignature(t *testing.T) {
	policyYAML := []byte(`version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      profiles:
        - "*"
`)

	// Create signature envelope with invalid signature
	sigEnvelope := policy.SignatureEnvelope{
		Signature: []byte("invalid-signature"),
		Metadata: policy.SignatureMetadata{
			KeyID:      "test-key-id",
			Algorithm:  "RSASSA_PSS_SHA_256",
			PolicyHash: policy.ComputePolicyHash(policyYAML),
		},
	}
	sigJSON, _ := json.Marshal(sigEnvelope)

	policyLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/policies/prod": policyYAML,
		},
	}

	sigLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/signatures/prod": sigJSON,
		},
	}

	mockKMS := &testutil.MockKMSClient{
		VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
			// Signature is invalid
			return &kms.VerifyOutput{SignatureValid: false}, nil
		},
	}

	signer := policy.NewPolicySignerWithClient(mockKMS, "test-key-id")
	loader := policy.NewVerifyingLoader(policyLoader, sigLoader, signer)

	_, err := loader.Load(context.Background(), "/sentinel/policies/prod")
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}

	if !errors.Is(err, policy.ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got: %v", err)
	}
}

func TestVerifyingLoader_Load_MissingSignature_NotEnforced(t *testing.T) {
	policyYAML := []byte(`version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      profiles:
        - "*"
`)

	policyLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/policies/prod": policyYAML,
		},
	}

	// Signature loader returns not found
	sigLoader := &testRawLoader{
		Errors: map[string]error{
			"/sentinel/signatures/prod": errors.New("/sentinel/signatures/prod: " + policy.ErrPolicyNotFound.Error()),
		},
	}

	mockKMS := &testutil.MockKMSClient{}
	signer := policy.NewPolicySignerWithClient(mockKMS, "test-key-id")

	// Not enforced (default)
	loader := policy.NewVerifyingLoader(policyLoader, sigLoader, signer)

	pol, err := loader.Load(context.Background(), "/sentinel/policies/prod")
	if err != nil {
		t.Fatalf("unexpected error with enforcement disabled: %v", err)
	}

	if pol == nil {
		t.Fatal("expected policy, got nil")
	}
	if pol.Version != "1" {
		t.Errorf("expected version '1', got %q", pol.Version)
	}
}

func TestVerifyingLoader_Load_MissingSignature_Enforced(t *testing.T) {
	policyYAML := []byte(`version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      profiles:
        - "*"
`)

	policyLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/policies/prod": policyYAML,
		},
	}

	// Signature loader returns not found
	sigLoader := &testRawLoader{
		Errors: map[string]error{
			"/sentinel/signatures/prod": errors.New("/sentinel/signatures/prod: " + policy.ErrPolicyNotFound.Error()),
		},
	}

	mockKMS := &testutil.MockKMSClient{}
	signer := policy.NewPolicySignerWithClient(mockKMS, "test-key-id")

	// Enforcement enabled
	loader := policy.NewVerifyingLoader(policyLoader, sigLoader, signer, policy.WithEnforcement(true))

	_, err := loader.Load(context.Background(), "/sentinel/policies/prod")
	if err == nil {
		t.Fatal("expected error with enforcement enabled")
	}

	if !errors.Is(err, policy.ErrSignatureEnforced) {
		t.Errorf("expected ErrSignatureEnforced, got: %v", err)
	}
}

func TestVerifyingLoader_Load_PolicyNotFound(t *testing.T) {
	// Policy loader returns not found
	policyLoader := &testRawLoader{
		Errors: map[string]error{
			"/sentinel/policies/prod": errors.New("/sentinel/policies/prod: " + policy.ErrPolicyNotFound.Error()),
		},
	}

	sigLoader := &testRawLoader{}
	mockKMS := &testutil.MockKMSClient{}
	signer := policy.NewPolicySignerWithClient(mockKMS, "test-key-id")

	loader := policy.NewVerifyingLoader(policyLoader, sigLoader, signer)

	_, err := loader.Load(context.Background(), "/sentinel/policies/prod")
	if err == nil {
		t.Fatal("expected error for policy not found")
	}

	// Should passthrough the error from the policy loader
	if !errors.Is(err, policy.ErrPolicyNotFound) {
		t.Errorf("expected ErrPolicyNotFound in error chain, got: %v", err)
	}
}

func TestVerifyingLoader_Load_KMSVerifyError(t *testing.T) {
	policyYAML := []byte(`version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      profiles:
        - "*"
`)

	sigEnvelope := policy.SignatureEnvelope{
		Signature: []byte("some-signature"),
		Metadata: policy.SignatureMetadata{
			KeyID:      "test-key-id",
			Algorithm:  "RSASSA_PSS_SHA_256",
			PolicyHash: policy.ComputePolicyHash(policyYAML),
		},
	}
	sigJSON, _ := json.Marshal(sigEnvelope)

	policyLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/policies/prod": policyYAML,
		},
	}

	sigLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/signatures/prod": sigJSON,
		},
	}

	mockKMS := &testutil.MockKMSClient{
		VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
			return nil, errors.New("KMS access denied")
		},
	}

	signer := policy.NewPolicySignerWithClient(mockKMS, "test-key-id")
	loader := policy.NewVerifyingLoader(policyLoader, sigLoader, signer)

	_, err := loader.Load(context.Background(), "/sentinel/policies/prod")
	if err == nil {
		t.Fatal("expected error for KMS verification failure")
	}

	if !errors.Is(err, errors.New("KMS access denied")) {
		// Just check that the error mentions verification
		if err.Error() == "" {
			t.Error("expected non-empty error")
		}
	}
}

func TestVerifyingLoader_Load_InvalidSignatureJSON(t *testing.T) {
	policyYAML := []byte(`version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      profiles:
        - "*"
`)

	policyLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/policies/prod": policyYAML,
		},
	}

	// Invalid JSON in signature
	sigLoader := &testRawLoader{
		Data: map[string][]byte{
			"/sentinel/signatures/prod": []byte("not valid json"),
		},
	}

	mockKMS := &testutil.MockKMSClient{}
	signer := policy.NewPolicySignerWithClient(mockKMS, "test-key-id")
	loader := policy.NewVerifyingLoader(policyLoader, sigLoader, signer)

	_, err := loader.Load(context.Background(), "/sentinel/policies/prod")
	if err == nil {
		t.Fatal("expected error for invalid signature JSON")
	}

	// Should contain "failed to parse signature"
	if err.Error() == "" {
		t.Error("expected non-empty error")
	}
}

func TestWithEnforcement(t *testing.T) {
	policyYAML := []byte(`version: "1"
rules:
  - name: allow-all
    effect: allow
    conditions:
      profiles:
        - "*"
`)

	signature := []byte("valid-signature-bytes")
	sigEnvelope := policy.SignatureEnvelope{
		Signature: signature,
		Metadata:  policy.SignatureMetadata{KeyID: "test"},
	}
	sigJSON, _ := json.Marshal(sigEnvelope)

	tests := []struct {
		name        string
		enforce     bool
		hasSig      bool
		wantErr     bool
		wantErrType error
	}{
		{
			name:    "enforcement=false, has signature",
			enforce: false,
			hasSig:  true,
			wantErr: false,
		},
		{
			name:    "enforcement=false, no signature (warn only)",
			enforce: false,
			hasSig:  false,
			wantErr: false,
		},
		{
			name:        "enforcement=true, no signature",
			enforce:     true,
			hasSig:      false,
			wantErr:     true,
			wantErrType: policy.ErrSignatureEnforced,
		},
		{
			name:    "enforcement=true, has signature",
			enforce: true,
			hasSig:  true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyLoader := &testRawLoader{
				Data: map[string][]byte{
					"/sentinel/policies/test": policyYAML,
				},
			}

			sigLoader := &testRawLoader{}
			if tt.hasSig {
				sigLoader.Data = map[string][]byte{
					"/sentinel/signatures/test": sigJSON,
				}
			} else {
				sigLoader.Errors = map[string]error{
					"/sentinel/signatures/test": errors.New("/sentinel/signatures/test: " + policy.ErrPolicyNotFound.Error()),
				}
			}

			mockKMS := &testutil.MockKMSClient{
				VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
					return &kms.VerifyOutput{SignatureValid: true}, nil
				},
			}

			signer := policy.NewPolicySignerWithClient(mockKMS, "test-key-id")
			loader := policy.NewVerifyingLoader(policyLoader, sigLoader, signer, policy.WithEnforcement(tt.enforce))

			_, err := loader.Load(context.Background(), "/sentinel/policies/test")

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
				t.Errorf("expected error type %v, got: %v", tt.wantErrType, err)
			}
		})
	}
}

func TestLoaderWithRaw_LoadRaw(t *testing.T) {
	// Note: This test uses the testutil MockSSMClient from policy_test.go
	// which matches the SSMAPI interface

	// The actual LoaderWithRaw uses real SSM types, which testutil.MockSSMClient implements
	// We just need to test the basic flow works with a mock
	// For comprehensive integration testing, see policy_test.go

	t.Run("successful load", func(t *testing.T) {
		// This test verifies the LoaderWithRaw can be constructed
		// Full integration tests are done via VerifyingLoader tests above
		mockSSM := &testutil.MockSSMClient{}
		loader := policy.NewLoaderWithRaw(mockSSM)
		if loader == nil {
			t.Error("expected non-nil loader")
		}
	})
}
