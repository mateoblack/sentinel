package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/byteness/aws-vault/v7/deploy"
)

// ============================================================================
// Mock Client for SSM CLI Tests
// ============================================================================

// mockSSMHardenCLIClient implements ssmHardenAPI for testing.
type mockSSMHardenCLIClient struct {
	GetParameterFunc        func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParametersByPathFunc func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
	GetParameterHistoryFunc func(ctx context.Context, params *ssm.GetParameterHistoryInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error)
	PutParameterFunc        func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

func (m *mockSSMHardenCLIClient) GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if m.GetParameterFunc != nil {
		return m.GetParameterFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetParameter not implemented")
}

func (m *mockSSMHardenCLIClient) GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	if m.GetParametersByPathFunc != nil {
		return m.GetParametersByPathFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetParametersByPath not implemented")
}

func (m *mockSSMHardenCLIClient) GetParameterHistory(ctx context.Context, params *ssm.GetParameterHistoryInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error) {
	if m.GetParameterHistoryFunc != nil {
		return m.GetParameterHistoryFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetParameterHistory not implemented")
}

func (m *mockSSMHardenCLIClient) PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	if m.PutParameterFunc != nil {
		return m.PutParameterFunc(ctx, params, optFns...)
	}
	return nil, errors.New("PutParameter not implemented")
}

// ============================================================================
// Mock KMS Client for CLI Tests (SEC-05)
// ============================================================================

// mockKMSCLIClient implements deploy.KMSEncryptAPI for testing.
type mockKMSCLIClient struct {
	EncryptFunc func(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	DecryptFunc func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

func (m *mockKMSCLIClient) Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if m.EncryptFunc != nil {
		return m.EncryptFunc(ctx, params, optFns...)
	}
	// Default: simple XOR "encryption" for testing
	ciphertext := make([]byte, len(params.Plaintext))
	for i, b := range params.Plaintext {
		ciphertext[i] = b ^ 0x42
	}
	return &kms.EncryptOutput{
		CiphertextBlob: ciphertext,
		KeyId:          params.KeyId,
	}, nil
}

func (m *mockKMSCLIClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if m.DecryptFunc != nil {
		return m.DecryptFunc(ctx, params, optFns...)
	}
	// Default: simple XOR "decryption" for testing
	plaintext := make([]byte, len(params.CiphertextBlob))
	for i, b := range params.CiphertextBlob {
		plaintext[i] = b ^ 0x42
	}
	return &kms.DecryptOutput{
		Plaintext: plaintext,
		KeyId:     params.KeyId,
	}, nil
}

// createMockSSMHardener creates a hardener with mock client for testing (without KMS).
func createMockSSMHardener(client *mockSSMHardenCLIClient) *deploy.SSMHardener {
	return deploy.NewSSMHardenerWithClient(client)
}

// createMockSSMHardenerWithKMS creates a hardener with mock SSM and KMS clients (SEC-05).
func createMockSSMHardenerWithKMS(ssmClient *mockSSMHardenCLIClient, kmsClient *mockKMSCLIClient, kmsKeyID string) *deploy.SSMHardener {
	return deploy.NewSSMHardenerWithKMS(ssmClient, kmsClient, kmsKeyID)
}

// encryptForTest creates a base64-encoded XOR "ciphertext" for testing (matches mockKMSCLIClient).
func encryptForTest(plaintext string) string {
	ciphertext := make([]byte, len(plaintext))
	for i, b := range []byte(plaintext) {
		ciphertext[i] = b ^ 0x42
	}
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// ============================================================================
// SSM Backup CLI Tests
// ============================================================================

func TestSSMBackupCommand_AutoDiscovery(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory for backup
	tmpDir, err := os.MkdirTemp("", "ssm-backup-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backupDir := filepath.Join(tmpDir, "test-backup")

	ssmClient := &mockSSMHardenCLIClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/production"), Type: types.ParameterTypeString, Version: 3, LastModifiedDate: &lastMod},
					{Name: aws.String("/sentinel/policies/staging"), Type: types.ParameterTypeString, Version: 2, LastModifiedDate: &lastMod},
				},
			}, nil
		},
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			name := *params.Name
			values := map[string]string{
				"/sentinel/policies/production": "policy: production",
				"/sentinel/policies/staging":    "policy: staging",
			}
			versions := map[string]int64{
				"/sentinel/policies/production": 3,
				"/sentinel/policies/staging":    2,
			}
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Value:            aws.String(values[name]),
					Version:          versions[name],
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{} // Default XOR "encryption"

	// SEC-05: Create hardener with KMS
	hardener := createMockSSMHardenerWithKMS(ssmClient, kmsClient, "arn:aws:kms:us-east-1:123456789012:key/test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMBackupCommandInput{
		OutputDir: backupDir,
		KMSKeyID:  "arn:aws:kms:us-east-1:123456789012:key/test-key",
		Hardener:  hardener,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	exitCode := SSMBackupCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Should show discovered parameters
	if !strings.Contains(output, "/sentinel/policies/production") {
		t.Error("expected output to contain /sentinel/policies/production")
	}
	if !strings.Contains(output, "/sentinel/policies/staging") {
		t.Error("expected output to contain /sentinel/policies/staging")
	}
	if !strings.Contains(output, "Backed up 2 parameters") {
		t.Error("expected output to show backup success message")
	}

	// Verify files were created
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("failed to read backup dir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 backup files, got %d", len(entries))
	}
}

func TestSSMBackupCommand_ExplicitParameters(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory for backup
	tmpDir, err := os.MkdirTemp("", "ssm-backup-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backupDir := filepath.Join(tmpDir, "test-backup")

	client := &mockSSMHardenCLIClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Value:            aws.String("explicit-param-value"),
					Version:          5,
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMBackupCommandInput{
		Parameters: []string{"/my/custom/param"},
		OutputDir:  backupDir,
		KMSKeyID:   "test-key",
		Hardener:   hardener,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := SSMBackupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "/my/custom/param") {
		t.Error("expected output to contain /my/custom/param")
	}
}

func TestSSMBackupCommand_CustomOutputDir(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory for backup
	tmpDir, err := os.MkdirTemp("", "ssm-backup-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	customDir := filepath.Join(tmpDir, "my-custom-backup-dir")

	client := &mockSSMHardenCLIClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/test"), Type: types.ParameterTypeString, Version: 1, LastModifiedDate: &lastMod},
				},
			}, nil
		},
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Value:            aws.String("test-value"),
					Version:          1,
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMBackupCommandInput{
		OutputDir: customDir,
		KMSKeyID:  "test-key",
		Hardener:  hardener,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	exitCode := SSMBackupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Verify custom directory was used
	if _, err := os.Stat(customDir); os.IsNotExist(err) {
		t.Error("expected custom backup directory to be created")
	}
}

func TestSSMBackupCommand_JSONOutput(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory for backup
	tmpDir, err := os.MkdirTemp("", "ssm-backup-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backupDir := filepath.Join(tmpDir, "test-backup")

	client := &mockSSMHardenCLIClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/production"), Type: types.ParameterTypeString, Version: 3, LastModifiedDate: &lastMod},
				},
			}, nil
		},
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Value:            aws.String("policy-value"),
					Version:          3,
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMBackupCommandInput{
		OutputDir:  backupDir,
		KMSKeyID:   "test-key",
		JSONOutput: true,
		Hardener:   hardener,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := SSMBackupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Check JSON structure
	if !strings.Contains(output, `"parameters"`) {
		t.Error("expected JSON output to contain 'parameters' field")
	}
	if !strings.Contains(output, `"backup_dir"`) {
		t.Error("expected JSON output to contain 'backup_dir' field")
	}
	if !strings.Contains(output, `"count"`) {
		t.Error("expected JSON output to contain 'count' field")
	}
	if !strings.Contains(output, `"version": 3`) {
		t.Error("expected JSON output to contain version: 3")
	}
}

func TestSSMBackupCommand_NoParametersFound(t *testing.T) {
	ctx := context.Background()

	client := &mockSSMHardenCLIClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{},
			}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMBackupCommandInput{
		KMSKeyID: "test-key",
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SSMBackupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 when no parameters found, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "No Sentinel parameters found") {
		t.Error("expected output to indicate no parameters found")
	}
}

func TestSSMBackupCommand_AccessDenied(t *testing.T) {
	ctx := context.Background()

	client := &mockSSMHardenCLIClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return nil, errors.New("AccessDeniedException: User not authorized")
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMBackupCommandInput{
		KMSKeyID: "test-key",
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SSMBackupCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for access denied, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	output := buf.String()

	if !strings.Contains(output, "Permission denied") {
		t.Error("expected error message about permission denied")
	}
}

// ============================================================================
// SSM Restore CLI Tests
// ============================================================================

func TestSSMRestoreCommand_RestoresParameters(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// SEC-05: Create encrypted backup file
	encValue := encryptForTest("restored-value")
	backupData := `{"name":"/sentinel/policies/production","type":"String","encrypted_value":"` + encValue + `","version":3,"backup_at":"2026-01-27T10:00:00Z","kms_key_id":"test-key"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-production.json"), []byte(backupData), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	putCalled := false
	client := &mockSSMHardenCLIClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Version:          5, // Different from backup (3)
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
		PutParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			putCalled = true
			return &ssm.PutParameterOutput{Version: 6}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMRestoreCommandInput{
		BackupDir: tmpDir,
		KMSKeyID:  "test-key",
		Force:     true,
		Hardener:  hardener,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	exitCode := SSMRestoreCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if !putCalled {
		t.Error("expected PutParameter to be called")
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Restored") {
		t.Error("expected output to show restore success")
	}
}

func TestSSMRestoreCommand_ParameterFilter(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create multiple backup files
	// SEC-05: Create encrypted backup files
	backupData1 := `{"name":"/sentinel/policies/production","type":"String","encrypted_value":"` + encryptForTest("prod") + `","version":3,"backup_at":"2026-01-27T10:00:00Z","kms_key_id":"test-key"}`
	backupData2 := `{"name":"/sentinel/policies/staging","type":"String","encrypted_value":"` + encryptForTest("staging") + `","version":2,"backup_at":"2026-01-27T10:00:00Z","kms_key_id":"test-key"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-production.json"), []byte(backupData1), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-staging.json"), []byte(backupData2), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	restoredParams := []string{}
	client := &mockSSMHardenCLIClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Version:          1, // Old version
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
		PutParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			restoredParams = append(restoredParams, *params.Name)
			return &ssm.PutParameterOutput{}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMRestoreCommandInput{
		BackupDir:  tmpDir,
		Parameters: []string{"/sentinel/policies/production"}, // Only restore production
		KMSKeyID:   "test-key",
		Force:      true,
		Hardener:   hardener,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := SSMRestoreCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if len(restoredParams) != 1 {
		t.Errorf("expected 1 parameter restored, got %d: %v", len(restoredParams), restoredParams)
	}

	if len(restoredParams) > 0 && restoredParams[0] != "/sentinel/policies/production" {
		t.Errorf("expected production to be restored, got %s", restoredParams[0])
	}
}

func TestSSMRestoreCommand_ConfirmationPrompt(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backupData := `{"name":"/sentinel/test","type":"String","encrypted_value":"` + encryptForTest("test") + `","version":3,"backup_at":"2026-01-27T10:00:00Z","kms_key_id":"test-key"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-test.json"), []byte(backupData), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	client := &mockSSMHardenCLIClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Version:          1, // Different from backup
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	stdin, _ := os.CreateTemp("", "stdin")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())
	defer os.Remove(stdin.Name())

	// Simulate user typing "n" (cancel)
	stdin.WriteString("n\n")
	stdin.Seek(0, 0)

	input := SSMRestoreCommandInput{
		BackupDir: tmpDir,
		KMSKeyID:  "test-key",
		Hardener:  hardener,
		Stdout:    stdout,
		Stderr:    stderr,
		Stdin:     stdin,
	}

	exitCode := SSMRestoreCommand(ctx, input)

	if exitCode != 2 {
		t.Errorf("expected exit code 2 for user cancel, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Cancelled") {
		t.Error("expected output to contain 'Cancelled'")
	}
}

func TestSSMRestoreCommand_ForceBypassesConfirmation(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backupData := `{"name":"/sentinel/test","type":"String","encrypted_value":"` + encryptForTest("test") + `","version":3,"backup_at":"2026-01-27T10:00:00Z","kms_key_id":"test-key"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-test.json"), []byte(backupData), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	restored := false
	client := &mockSSMHardenCLIClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Version:          1, // Different from backup
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
		PutParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			restored = true
			return &ssm.PutParameterOutput{}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMRestoreCommandInput{
		BackupDir: tmpDir,
		KMSKeyID:  "test-key",
		Force:     true, // Skip confirmation
		Hardener:  hardener,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	exitCode := SSMRestoreCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if !restored {
		t.Error("expected parameter to be restored with --force")
	}
}

func TestSSMRestoreCommand_JSONOutput(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backupData := `{"name":"/sentinel/test","type":"String","encrypted_value":"` + encryptForTest("test") + `","version":3,"backup_at":"2026-01-27T10:00:00Z","kms_key_id":"test-key"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-test.json"), []byte(backupData), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	client := &mockSSMHardenCLIClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Version:          1,
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
		PutParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			return &ssm.PutParameterOutput{}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMRestoreCommandInput{
		BackupDir:  tmpDir,
		KMSKeyID:   "test-key",
		Force:      true,
		JSONOutput: true,
		Hardener:   hardener,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := SSMRestoreCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Check JSON structure
	if !strings.Contains(output, `"restored"`) {
		t.Error("expected JSON output to contain 'restored' field")
	}
	if !strings.Contains(output, `"skipped"`) {
		t.Error("expected JSON output to contain 'skipped' field")
	}
	if !strings.Contains(output, `"failed"`) {
		t.Error("expected JSON output to contain 'failed' field")
	}
	if !strings.Contains(output, `"count"`) {
		t.Error("expected JSON output to contain 'count' field")
	}
}

func TestSSMRestoreCommand_BackupDirNotFound(t *testing.T) {
	ctx := context.Background()

	hardener := createMockSSMHardener(&mockSSMHardenCLIClient{})

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMRestoreCommandInput{
		BackupDir: "/nonexistent/directory",
		KMSKeyID:  "test-key",
		Force:     true,
		Hardener:  hardener,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	exitCode := SSMRestoreCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing directory, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	output := buf.String()

	if !strings.Contains(output, "Error reading backup directory") {
		t.Error("expected error about backup directory")
	}
}

func TestSSMRestoreCommand_SkipsMatchingVersion(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Backup with version 3
	backupData := `{"name":"/sentinel/test","type":"String","encrypted_value":"` + encryptForTest("test") + `","version":3,"backup_at":"2026-01-27T10:00:00Z","kms_key_id":"test-key"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-test.json"), []byte(backupData), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	putCalled := false
	client := &mockSSMHardenCLIClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Version:          3, // Same as backup
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
		PutParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			putCalled = true
			return &ssm.PutParameterOutput{}, nil
		},
	}

	kmsClient := &mockKMSCLIClient{}
	hardener := createMockSSMHardenerWithKMS(client, kmsClient, "test-key")

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SSMRestoreCommandInput{
		BackupDir: tmpDir,
		KMSKeyID:  "test-key",
		Force:     true,
		Hardener:  hardener,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	exitCode := SSMRestoreCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if putCalled {
		t.Error("expected PutParameter NOT to be called when versions match")
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "already at backup version") {
		t.Error("expected output to indicate versions match")
	}
}
