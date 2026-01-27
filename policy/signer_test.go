package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/testutil"
)

func TestPolicySigner_Sign_Success(t *testing.T) {
	tests := []struct {
		name       string
		policyYAML []byte
		wantSig    []byte
	}{
		{
			name:       "simple policy",
			policyYAML: []byte("version: '1'\nrules: []"),
			wantSig:    []byte("signature-bytes-123"),
		},
		{
			name:       "complex policy",
			policyYAML: []byte("version: '1'\nrules:\n  - name: test\n    effect: allow"),
			wantSig:    []byte("signature-bytes-456"),
		},
		{
			name:       "empty policy",
			policyYAML: []byte(""),
			wantSig:    []byte("signature-empty"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &testutil.MockKMSClient{
				SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
					// Verify correct parameters
					if params.KeyId == nil || *params.KeyId != "test-key-id" {
						t.Errorf("unexpected KeyId: %v", params.KeyId)
					}
					if params.MessageType != types.MessageTypeRaw {
						t.Errorf("expected MessageType RAW, got %v", params.MessageType)
					}
					if params.SigningAlgorithm != policy.DefaultSigningAlgorithm {
						t.Errorf("expected algorithm %v, got %v", policy.DefaultSigningAlgorithm, params.SigningAlgorithm)
					}
					if string(params.Message) != string(tt.policyYAML) {
						t.Errorf("expected message %q, got %q", tt.policyYAML, params.Message)
					}
					return &kms.SignOutput{
						Signature: tt.wantSig,
					}, nil
				},
			}

			signer := policy.NewPolicySignerWithClient(mock, "test-key-id")
			signature, err := signer.Sign(context.Background(), tt.policyYAML)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(signature) != string(tt.wantSig) {
				t.Errorf("got signature %q, want %q", signature, tt.wantSig)
			}
		})
	}
}

func TestPolicySigner_Sign_KMSError(t *testing.T) {
	tests := []struct {
		name    string
		kmsErr  error
		wantErr string
	}{
		{
			name:    "key not found",
			kmsErr:  &types.NotFoundException{Message: aws.String("key not found")},
			wantErr: "key not found",
		},
		{
			name:    "access denied",
			kmsErr:  &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "access denied"},
			wantErr: "access denied",
		},
		{
			name:    "invalid key state",
			kmsErr:  &types.KMSInvalidStateException{Message: aws.String("key is disabled")},
			wantErr: "key is disabled",
		},
		{
			name:    "generic error",
			kmsErr:  errors.New("network timeout"),
			wantErr: "network timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &testutil.MockKMSClient{
				SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
					return nil, tt.kmsErr
				},
			}

			signer := policy.NewPolicySignerWithClient(mock, "test-key-id")
			_, err := signer.Sign(context.Background(), []byte("policy"))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tt.kmsErr.Error() {
				t.Errorf("got error %q, want %q", err.Error(), tt.kmsErr.Error())
			}
		})
	}
}

func TestPolicySigner_Verify_Valid(t *testing.T) {
	tests := []struct {
		name       string
		policyYAML []byte
		signature  []byte
	}{
		{
			name:       "valid signature",
			policyYAML: []byte("version: '1'\nrules: []"),
			signature:  []byte("valid-signature"),
		},
		{
			name:       "another valid signature",
			policyYAML: []byte("version: '1'\nrules:\n  - name: test"),
			signature:  []byte("another-valid-signature"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &testutil.MockKMSClient{
				VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
					// Verify correct parameters
					if params.KeyId == nil || *params.KeyId != "test-key-id" {
						t.Errorf("unexpected KeyId: %v", params.KeyId)
					}
					if params.MessageType != types.MessageTypeRaw {
						t.Errorf("expected MessageType RAW, got %v", params.MessageType)
					}
					if string(params.Message) != string(tt.policyYAML) {
						t.Errorf("expected message %q, got %q", tt.policyYAML, params.Message)
					}
					if string(params.Signature) != string(tt.signature) {
						t.Errorf("expected signature %q, got %q", tt.signature, params.Signature)
					}
					return &kms.VerifyOutput{
						SignatureValid: true,
					}, nil
				},
			}

			signer := policy.NewPolicySignerWithClient(mock, "test-key-id")
			valid, err := signer.Verify(context.Background(), tt.policyYAML, tt.signature)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !valid {
				t.Error("expected valid=true, got false")
			}
		})
	}
}

func TestPolicySigner_Verify_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		policyYAML []byte
		signature  []byte
		kmsResult  bool // What KMS returns for SignatureValid
	}{
		{
			name:       "KMS returns false for invalid signature",
			policyYAML: []byte("version: '1'\nrules: []"),
			signature:  []byte("invalid-signature"),
			kmsResult:  false,
		},
		{
			name:       "tampered policy",
			policyYAML: []byte("version: '1'\nrules:\n  - name: tampered"),
			signature:  []byte("original-signature"),
			kmsResult:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &testutil.MockKMSClient{
				VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
					return &kms.VerifyOutput{
						SignatureValid: tt.kmsResult,
					}, nil
				},
			}

			signer := policy.NewPolicySignerWithClient(mock, "test-key-id")
			valid, err := signer.Verify(context.Background(), tt.policyYAML, tt.signature)
			if err != nil {
				t.Fatalf("unexpected error: %v (invalid signature should return false, nil)", err)
			}
			if valid {
				t.Error("expected valid=false, got true")
			}
		})
	}
}

func TestPolicySigner_Verify_KMSInvalidSignatureException(t *testing.T) {
	// Test that KMSInvalidSignatureException is handled as (false, nil), not as an error
	mock := &testutil.MockKMSClient{
		VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
			return nil, &types.KMSInvalidSignatureException{
				Message: aws.String("signature is invalid"),
			}
		},
	}

	signer := policy.NewPolicySignerWithClient(mock, "test-key-id")
	valid, err := signer.Verify(context.Background(), []byte("policy"), []byte("bad-sig"))
	if err != nil {
		t.Fatalf("expected no error for invalid signature, got: %v", err)
	}
	if valid {
		t.Error("expected valid=false for invalid signature")
	}
}

func TestPolicySigner_Verify_KMSError(t *testing.T) {
	tests := []struct {
		name    string
		kmsErr  error
		wantErr string
	}{
		{
			name:    "key not found",
			kmsErr:  &types.NotFoundException{Message: aws.String("key not found")},
			wantErr: "key not found",
		},
		{
			name:    "access denied",
			kmsErr:  &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "access denied"},
			wantErr: "access denied",
		},
		{
			name:    "invalid key state",
			kmsErr:  &types.KMSInvalidStateException{Message: aws.String("key is disabled")},
			wantErr: "key is disabled",
		},
		{
			name:    "network error",
			kmsErr:  errors.New("connection refused"),
			wantErr: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &testutil.MockKMSClient{
				VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
					return nil, tt.kmsErr
				},
			}

			signer := policy.NewPolicySignerWithClient(mock, "test-key-id")
			valid, err := signer.Verify(context.Background(), []byte("policy"), []byte("sig"))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if valid {
				t.Error("expected valid=false on error")
			}
			if err.Error() != tt.kmsErr.Error() {
				t.Errorf("got error %q, want %q", err.Error(), tt.kmsErr.Error())
			}
		})
	}
}

func TestNewPolicySignerWithClient(t *testing.T) {
	// Verify that NewPolicySignerWithClient creates a working signer
	mock := &testutil.MockKMSClient{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			// Verify key ID is passed correctly
			if aws.ToString(params.KeyId) != "test-key" {
				t.Errorf("expected keyID %q, got %q", "test-key", aws.ToString(params.KeyId))
			}
			return &kms.SignOutput{Signature: []byte("sig")}, nil
		},
	}

	signer := policy.NewPolicySignerWithClient(mock, "test-key")
	_, err := signer.Sign(context.Background(), []byte("policy"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
