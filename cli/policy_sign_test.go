package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/testutil"
)

func TestPolicySignCommand_Run_Success(t *testing.T) {
	// Create temp file with valid policy
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: []byte("test-signature-bytes"),
			}, nil
		},
	}

	input := PolicySignCommandInput{
		PolicyFile: policyFile,
		KeyID:      "alias/test-key",
		Stdout:     &stdout,
		Stderr:     &stderr,
		KMSClient:  mockKMS,
	}

	exitCode, err := PolicySignCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0. stderr: %s", exitCode, stderr.String())
	}

	// Verify output is valid JSON
	var output SignatureOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("failed to parse output JSON: %v", err)
	}

	// Verify signature is base64 encoded
	sig, err := base64.StdEncoding.DecodeString(output.Signature)
	if err != nil {
		t.Errorf("failed to decode signature: %v", err)
	}
	if string(sig) != "test-signature-bytes" {
		t.Errorf("signature = %q, want %q", string(sig), "test-signature-bytes")
	}

	// Verify metadata
	if output.Metadata.KeyID != "alias/test-key" {
		t.Errorf("key_id = %q, want %q", output.Metadata.KeyID, "alias/test-key")
	}
	if output.Metadata.PolicyHash == "" {
		t.Error("policy_hash should not be empty")
	}
	if output.Metadata.Algorithm == "" {
		t.Error("algorithm should not be empty")
	}
}

func TestPolicySignCommand_Run_WriteToFile(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	outputFile, err := os.CreateTemp("", "sig-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	var stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: []byte("test-signature"),
			}, nil
		},
	}

	input := PolicySignCommandInput{
		PolicyFile: policyFile,
		KeyID:      "alias/test-key",
		OutputFile: outputFile.Name(),
		Stderr:     &stderr,
		KMSClient:  mockKMS,
	}

	exitCode, err := PolicySignCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0. stderr: %s", exitCode, stderr.String())
	}

	// Verify file was written
	content, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var output SignatureOutput
	if err := json.Unmarshal(content, &output); err != nil {
		t.Fatalf("failed to parse output JSON: %v", err)
	}

	if output.Signature == "" {
		t.Error("signature should not be empty")
	}

	// Verify stderr message
	if !strings.Contains(stderr.String(), "Signature written to") {
		t.Errorf("stderr should contain 'Signature written to', got: %s", stderr.String())
	}
}

func TestPolicySignCommand_Run_InvalidPolicy(t *testing.T) {
	// Create temp file with invalid policy (no rules)
	invalidPolicy := `version: "1"
rules: []
`
	policyFile := createTempPolicyFile(t, invalidPolicy)
	defer os.Remove(policyFile)

	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{}

	input := PolicySignCommandInput{
		PolicyFile: policyFile,
		KeyID:      "alias/test-key",
		Stdout:     &stdout,
		Stderr:     &stderr,
		KMSClient:  mockKMS,
	}

	exitCode, err := PolicySignCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for invalid policy", exitCode)
	}

	if !strings.Contains(stderr.String(), "validation error") {
		t.Errorf("stderr should contain 'validation error', got: %s", stderr.String())
	}
}

func TestPolicySignCommand_Run_FileNotFound(t *testing.T) {
	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{}

	input := PolicySignCommandInput{
		PolicyFile: "/nonexistent/policy.yaml",
		KeyID:      "alias/test-key",
		Stdout:     &stdout,
		Stderr:     &stderr,
		KMSClient:  mockKMS,
	}

	exitCode, err := PolicySignCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for file not found", exitCode)
	}

	if !strings.Contains(stderr.String(), "file not found") {
		t.Errorf("stderr should contain 'file not found', got: %s", stderr.String())
	}
}

func TestPolicySignCommand_Run_KMSError(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return nil, errors.New("access denied to KMS key")
		},
	}

	input := PolicySignCommandInput{
		PolicyFile: policyFile,
		KeyID:      "alias/test-key",
		Stdout:     &stdout,
		Stderr:     &stderr,
		KMSClient:  mockKMS,
	}

	exitCode, err := PolicySignCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for KMS error", exitCode)
	}

	if !strings.Contains(stderr.String(), "failed to sign policy") {
		t.Errorf("stderr should contain 'failed to sign policy', got: %s", stderr.String())
	}
}

func TestPolicyVerifyCommand_Run_Valid(t *testing.T) {
	policyYAML := validPolicyYAML()
	policyFile := createTempPolicyFile(t, policyYAML)
	defer os.Remove(policyFile)

	// Create signature file
	sigOutput := SignatureOutput{
		Signature: base64.StdEncoding.EncodeToString([]byte("valid-signature")),
		Metadata: policy.SignatureMetadata{
			KeyID:      "alias/test-key",
			Algorithm:  "RSASSA_PSS_SHA_256",
			PolicyHash: policy.ComputePolicyHash([]byte(policyYAML)),
		},
	}
	sigJSON, _ := json.Marshal(sigOutput)
	sigFile := createTempPolicyFile(t, string(sigJSON))
	defer os.Remove(sigFile)

	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{
		VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
			return &kms.VerifyOutput{SignatureValid: true}, nil
		},
	}

	input := PolicyVerifyCommandInput{
		PolicyFile:    policyFile,
		KeyID:         "alias/test-key",
		SignatureFile: sigFile,
		Stdout:        &stdout,
		Stderr:        &stderr,
		KMSClient:     mockKMS,
	}

	exitCode, err := PolicyVerifyCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 for valid signature. stderr: %s", exitCode, stderr.String())
	}

	if !strings.Contains(stdout.String(), "Signature valid") {
		t.Errorf("stdout should contain 'Signature valid', got: %s", stdout.String())
	}
}

func TestPolicyVerifyCommand_Run_Invalid(t *testing.T) {
	policyYAML := validPolicyYAML()
	policyFile := createTempPolicyFile(t, policyYAML)
	defer os.Remove(policyFile)

	// Create signature file
	sigOutput := SignatureOutput{
		Signature: base64.StdEncoding.EncodeToString([]byte("invalid-signature")),
		Metadata: policy.SignatureMetadata{
			KeyID:      "alias/test-key",
			Algorithm:  "RSASSA_PSS_SHA_256",
			PolicyHash: policy.ComputePolicyHash([]byte(policyYAML)),
		},
	}
	sigJSON, _ := json.Marshal(sigOutput)
	sigFile := createTempPolicyFile(t, string(sigJSON))
	defer os.Remove(sigFile)

	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{
		VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
			// Signature is invalid
			return &kms.VerifyOutput{SignatureValid: false}, nil
		},
	}

	input := PolicyVerifyCommandInput{
		PolicyFile:    policyFile,
		KeyID:         "alias/test-key",
		SignatureFile: sigFile,
		Stdout:        &stdout,
		Stderr:        &stderr,
		KMSClient:     mockKMS,
	}

	exitCode, err := PolicyVerifyCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for invalid signature", exitCode)
	}

	if !strings.Contains(stdout.String(), "Signature invalid") {
		t.Errorf("stdout should contain 'Signature invalid', got: %s", stdout.String())
	}
}

func TestPolicyVerifyCommand_Run_HashMismatch(t *testing.T) {
	policyYAML := validPolicyYAML()
	policyFile := createTempPolicyFile(t, policyYAML)
	defer os.Remove(policyFile)

	// Create signature file with wrong hash
	sigOutput := SignatureOutput{
		Signature: base64.StdEncoding.EncodeToString([]byte("signature")),
		Metadata: policy.SignatureMetadata{
			KeyID:      "alias/test-key",
			Algorithm:  "RSASSA_PSS_SHA_256",
			PolicyHash: "wronghashvalue123456789", // Doesn't match policy
		},
	}
	sigJSON, _ := json.Marshal(sigOutput)
	sigFile := createTempPolicyFile(t, string(sigJSON))
	defer os.Remove(sigFile)

	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{}

	input := PolicyVerifyCommandInput{
		PolicyFile:    policyFile,
		KeyID:         "alias/test-key",
		SignatureFile: sigFile,
		Stdout:        &stdout,
		Stderr:        &stderr,
		KMSClient:     mockKMS,
	}

	exitCode, err := PolicyVerifyCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for hash mismatch", exitCode)
	}

	if !strings.Contains(stderr.String(), "does not match") {
		t.Errorf("stderr should contain 'does not match', got: %s", stderr.String())
	}
}

func TestPolicyVerifyCommand_Run_PolicyFileNotFound(t *testing.T) {
	// Create signature file
	sigOutput := SignatureOutput{
		Signature: base64.StdEncoding.EncodeToString([]byte("signature")),
		Metadata:  policy.SignatureMetadata{},
	}
	sigJSON, _ := json.Marshal(sigOutput)
	sigFile := createTempPolicyFile(t, string(sigJSON))
	defer os.Remove(sigFile)

	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{}

	input := PolicyVerifyCommandInput{
		PolicyFile:    "/nonexistent/policy.yaml",
		KeyID:         "alias/test-key",
		SignatureFile: sigFile,
		Stdout:        &stdout,
		Stderr:        &stderr,
		KMSClient:     mockKMS,
	}

	exitCode, err := PolicyVerifyCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for file not found", exitCode)
	}

	if !strings.Contains(stderr.String(), "policy file not found") {
		t.Errorf("stderr should contain 'policy file not found', got: %s", stderr.String())
	}
}

func TestPolicyVerifyCommand_Run_SignatureFileNotFound(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{}

	input := PolicyVerifyCommandInput{
		PolicyFile:    policyFile,
		KeyID:         "alias/test-key",
		SignatureFile: "/nonexistent/sig.json",
		Stdout:        &stdout,
		Stderr:        &stderr,
		KMSClient:     mockKMS,
	}

	exitCode, err := PolicyVerifyCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for file not found", exitCode)
	}

	if !strings.Contains(stderr.String(), "signature file not found") {
		t.Errorf("stderr should contain 'signature file not found', got: %s", stderr.String())
	}
}

func TestPolicyVerifyCommand_Run_InvalidSignatureJSON(t *testing.T) {
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	// Create invalid JSON signature file
	sigFile := createTempPolicyFile(t, "not valid json")
	defer os.Remove(sigFile)

	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{}

	input := PolicyVerifyCommandInput{
		PolicyFile:    policyFile,
		KeyID:         "alias/test-key",
		SignatureFile: sigFile,
		Stdout:        &stdout,
		Stderr:        &stderr,
		KMSClient:     mockKMS,
	}

	exitCode, err := PolicyVerifyCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for invalid JSON", exitCode)
	}

	if !strings.Contains(stderr.String(), "failed to parse signature file") {
		t.Errorf("stderr should contain 'failed to parse signature file', got: %s", stderr.String())
	}
}

func TestPolicyVerifyCommand_Run_KMSError(t *testing.T) {
	policyYAML := validPolicyYAML()
	policyFile := createTempPolicyFile(t, policyYAML)
	defer os.Remove(policyFile)

	// Create signature file
	sigOutput := SignatureOutput{
		Signature: base64.StdEncoding.EncodeToString([]byte("signature")),
		Metadata: policy.SignatureMetadata{
			KeyID:      "alias/test-key",
			Algorithm:  "RSASSA_PSS_SHA_256",
			PolicyHash: policy.ComputePolicyHash([]byte(policyYAML)),
		},
	}
	sigJSON, _ := json.Marshal(sigOutput)
	sigFile := createTempPolicyFile(t, string(sigJSON))
	defer os.Remove(sigFile)

	var stdout, stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{
		VerifyFunc: func(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
			return nil, errors.New("access denied to KMS key")
		},
	}

	input := PolicyVerifyCommandInput{
		PolicyFile:    policyFile,
		KeyID:         "alias/test-key",
		SignatureFile: sigFile,
		Stdout:        &stdout,
		Stderr:        &stderr,
		KMSClient:     mockKMS,
	}

	exitCode, err := PolicyVerifyCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected fatal error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1 for KMS error", exitCode)
	}

	if !strings.Contains(stderr.String(), "failed to verify signature") {
		t.Errorf("stderr should contain 'failed to verify signature', got: %s", stderr.String())
	}
}

// TestPolicySignCommand_OutputFilePermissions verifies that signature output files
// have secure permissions (0600) as required by SEC-03 security hardening.
func TestPolicySignCommand_OutputFilePermissions(t *testing.T) {
	// Skip on Windows - file permissions work differently
	if os.Getenv("GOOS") == "windows" {
		t.Skip("File permissions test not applicable on Windows")
	}

	// Create temp directory
	tmpDir := t.TempDir()
	outputFile := tmpDir + "/signature-output.json"

	// Create temp policy file
	policyFile := createTempPolicyFile(t, validPolicyYAML())
	defer os.Remove(policyFile)

	var stderr bytes.Buffer

	mockKMS := &testutil.MockKMSClient{
		SignFunc: func(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: []byte("test-signature-for-perms-test"),
			}, nil
		},
	}

	input := PolicySignCommandInput{
		PolicyFile: policyFile,
		KeyID:      "alias/test-key",
		OutputFile: outputFile,
		Stderr:     &stderr,
		KMSClient:  mockKMS,
	}

	exitCode, err := PolicySignCommand(context.Background(), input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0. stderr: %s", exitCode, stderr.String())
	}

	// Verify file was created
	info, err := os.Stat(outputFile)
	if err != nil {
		t.Fatalf("failed to stat output file: %v", err)
	}

	// Verify file has 0600 permissions (SEC-03)
	expectedPerm := os.FileMode(0600)
	actualPerm := info.Mode().Perm()
	if actualPerm != expectedPerm {
		t.Errorf("Signature output file should have %o permissions (SEC-03), got %o", expectedPerm, actualPerm)
	}
}
