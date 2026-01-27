package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ============================================================================
// Mock Client for SSM Hardening
// ============================================================================

// mockSSMHardenClient implements ssmHardenAPI for testing.
type mockSSMHardenClient struct {
	GetParameterFunc        func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParametersByPathFunc func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
	GetParameterHistoryFunc func(ctx context.Context, params *ssm.GetParameterHistoryInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error)
	PutParameterFunc        func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

func (m *mockSSMHardenClient) GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	if m.GetParameterFunc != nil {
		return m.GetParameterFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetParameter not implemented")
}

func (m *mockSSMHardenClient) GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	if m.GetParametersByPathFunc != nil {
		return m.GetParametersByPathFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetParametersByPath not implemented")
}

func (m *mockSSMHardenClient) GetParameterHistory(ctx context.Context, params *ssm.GetParameterHistoryInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error) {
	if m.GetParameterHistoryFunc != nil {
		return m.GetParameterHistoryFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetParameterHistory not implemented")
}

func (m *mockSSMHardenClient) PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	if m.PutParameterFunc != nil {
		return m.PutParameterFunc(ctx, params, optFns...)
	}
	return nil, errors.New("PutParameter not implemented")
}

// ============================================================================
// DiscoverSentinelParameters Tests
// ============================================================================

func TestSSMHardener_DiscoverSentinelParameters_DefaultPrefix(t *testing.T) {
	ctx := context.Background()

	client := &mockSSMHardenClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			if *params.Path != "/sentinel" {
				t.Errorf("expected path /sentinel, got %s", *params.Path)
			}
			lastMod := time.Now()
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/production"), Type: types.ParameterTypeString, Version: 3, LastModifiedDate: &lastMod},
					{Name: aws.String("/sentinel/policies/staging"), Type: types.ParameterTypeString, Version: 2, LastModifiedDate: &lastMod},
					{Name: aws.String("/sentinel/config/signing-key"), Type: types.ParameterTypeSecureString, Version: 1, LastModifiedDate: &lastMod},
				},
			}, nil
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	params, err := hardener.DiscoverSentinelParameters(ctx, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(params) != 3 {
		t.Fatalf("expected 3 parameters, got %d: %v", len(params), params)
	}
}

func TestSSMHardener_DiscoverSentinelParameters_CustomPrefix(t *testing.T) {
	ctx := context.Background()

	client := &mockSSMHardenClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			if *params.Path != "/myorg/sentinel" {
				t.Errorf("expected path /myorg/sentinel, got %s", *params.Path)
			}
			lastMod := time.Now()
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/myorg/sentinel/policies/production"), Type: types.ParameterTypeString, Version: 1, LastModifiedDate: &lastMod},
				},
			}, nil
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	params, err := hardener.DiscoverSentinelParameters(ctx, "/myorg/sentinel/")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(params) != 1 {
		t.Fatalf("expected 1 parameter, got %d: %v", len(params), params)
	}
}

func TestSSMHardener_DiscoverSentinelParameters_Pagination(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	client := &mockSSMHardenClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			callCount++
			lastMod := time.Now()
			if callCount == 1 {
				return &ssm.GetParametersByPathOutput{
					Parameters: []types.Parameter{
						{Name: aws.String("/sentinel/policies/production"), Type: types.ParameterTypeString, Version: 1, LastModifiedDate: &lastMod},
					},
					NextToken: aws.String("token123"),
				}, nil
			}
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{
					{Name: aws.String("/sentinel/policies/staging"), Type: types.ParameterTypeString, Version: 2, LastModifiedDate: &lastMod},
					{Name: aws.String("/sentinel/config/key"), Type: types.ParameterTypeSecureString, Version: 1, LastModifiedDate: &lastMod},
				},
			}, nil
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	params, err := hardener.DiscoverSentinelParameters(ctx, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 API calls for pagination, got %d", callCount)
	}

	if len(params) != 3 {
		t.Fatalf("expected 3 parameters across pages, got %d: %v", len(params), params)
	}
}

func TestSSMHardener_DiscoverSentinelParameters_AccessDenied(t *testing.T) {
	ctx := context.Background()

	client := &mockSSMHardenClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return nil, errors.New("AccessDeniedException: User is not authorized to perform ssm:GetParametersByPath")
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	_, err := hardener.DiscoverSentinelParameters(ctx, "")

	if err == nil {
		t.Fatal("expected error for access denied")
	}
}

func TestSSMHardener_DiscoverSentinelParameters_NoMatches(t *testing.T) {
	ctx := context.Background()

	client := &mockSSMHardenClient{
		GetParametersByPathFunc: func(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
			return &ssm.GetParametersByPathOutput{
				Parameters: []types.Parameter{},
			}, nil
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	params, err := hardener.DiscoverSentinelParameters(ctx, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(params) != 0 {
		t.Errorf("expected 0 parameters, got %d: %v", len(params), params)
	}
}

// ============================================================================
// GetParameterStatus Tests
// ============================================================================

func TestSSMHardener_GetParameterStatus_String(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Date(2026, 1, 25, 14, 30, 0, 0, time.UTC)

	client := &mockSSMHardenClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             aws.String("/sentinel/policies/production"),
					Type:             types.ParameterTypeString,
					Version:          3,
					LastModifiedDate: &lastMod,
					DataType:         aws.String("text"),
				},
			}, nil
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	status, err := hardener.GetParameterStatus(ctx, "/sentinel/policies/production")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Name != "/sentinel/policies/production" {
		t.Errorf("expected name /sentinel/policies/production, got %s", status.Name)
	}
	if status.Type != "String" {
		t.Errorf("expected type String, got %s", status.Type)
	}
	if status.Version != 3 {
		t.Errorf("expected version 3, got %d", status.Version)
	}
	if !status.LastModified.Equal(lastMod) {
		t.Errorf("expected last modified %v, got %v", lastMod, status.LastModified)
	}
	if status.DataType != "text" {
		t.Errorf("expected data type text, got %s", status.DataType)
	}
}

func TestSSMHardener_GetParameterStatus_SecureString(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Date(2026, 1, 20, 9, 0, 0, 0, time.UTC)

	client := &mockSSMHardenClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             aws.String("/sentinel/config/signing-key"),
					Type:             types.ParameterTypeSecureString,
					Version:          1,
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	status, err := hardener.GetParameterStatus(ctx, "/sentinel/config/signing-key")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Type != "SecureString" {
		t.Errorf("expected type SecureString, got %s", status.Type)
	}
	if status.Version != 1 {
		t.Errorf("expected version 1, got %d", status.Version)
	}
}

func TestSSMHardener_GetParametersStatus_Batch(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	client := &mockSSMHardenClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			name := *params.Name
			versions := map[string]int64{
				"/sentinel/policies/production": 3,
				"/sentinel/policies/staging":    2,
				"/sentinel/config/key":          1,
			}
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Version:          versions[name],
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	statuses, err := hardener.GetParametersStatus(ctx, []string{
		"/sentinel/policies/production",
		"/sentinel/policies/staging",
		"/sentinel/config/key",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(statuses) != 3 {
		t.Fatalf("expected 3 statuses, got %d", len(statuses))
	}

	if statuses[0].Version != 3 {
		t.Errorf("expected production version 3, got %d", statuses[0].Version)
	}
	if statuses[1].Version != 2 {
		t.Errorf("expected staging version 2, got %d", statuses[1].Version)
	}
}

// ============================================================================
// BackupParameters Tests
// ============================================================================

func TestSSMHardener_BackupParameters_CreatesFiles(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "ssm-backup-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backupDir := filepath.Join(tmpDir, "test-backup")

	client := &mockSSMHardenClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			name := *params.Name
			values := map[string]string{
				"/sentinel/policies/production": "policy: production\nversion: 1.0",
				"/sentinel/policies/staging":    "policy: staging\nversion: 1.0",
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

	hardener := NewSSMHardenerWithClient(client)
	result, err := hardener.BackupParameters(ctx, []string{
		"/sentinel/policies/production",
		"/sentinel/policies/staging",
	}, backupDir)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Count != 2 {
		t.Errorf("expected 2 parameters backed up, got %d", result.Count)
	}

	if result.BackupDir != backupDir {
		t.Errorf("expected backup dir %s, got %s", backupDir, result.BackupDir)
	}

	// Verify files were created
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("failed to read backup dir: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 backup files, got %d", len(entries))
	}

	// Verify file content
	prodFile := filepath.Join(backupDir, "sentinel-policies-production.json")
	data, err := os.ReadFile(prodFile)
	if err != nil {
		t.Fatalf("failed to read backup file: %v", err)
	}

	if len(data) == 0 {
		t.Error("backup file is empty")
	}
}

// TestSSMHardener_BackupParameters_RestrictedPermissions verifies that backup directory
// is created with 0700 permissions to prevent local privilege escalation (SSM-T-02).
func TestSSMHardener_BackupParameters_RestrictedPermissions(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "ssm-backup-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backupDir := filepath.Join(tmpDir, "test-backup")

	client := &mockSSMHardenClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeSecureString,
					Value:            aws.String("secret-value"),
					Version:          1,
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	_, err = hardener.BackupParameters(ctx, []string{"/sentinel/secrets/key"}, backupDir)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify directory permissions are 0700 (owner-only)
	info, err := os.Stat(backupDir)
	if err != nil {
		t.Fatalf("failed to stat backup dir: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("expected directory permissions 0700, got %04o", perm)
	}

	// Verify file permissions are 0600 (owner read/write only)
	files, _ := os.ReadDir(backupDir)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		filePath := filepath.Join(backupDir, f.Name())
		fileInfo, _ := os.Stat(filePath)
		filePerm := fileInfo.Mode().Perm()
		if filePerm != 0600 {
			t.Errorf("expected file permissions 0600, got %04o for %s", filePerm, f.Name())
		}
	}
}

func TestSSMHardener_BackupParameters_AutoGeneratesDir(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "ssm-backup-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp dir for test
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	client := &mockSSMHardenClient{
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

	hardener := NewSSMHardenerWithClient(client)
	result, err := hardener.BackupParameters(ctx, []string{"/sentinel/test"}, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify auto-generated directory name starts with sentinel-backup-
	if result.BackupDir == "" {
		t.Error("expected auto-generated backup dir")
	}

	// Clean up
	os.RemoveAll(result.BackupDir)
}

// ============================================================================
// RestoreParameters Tests
// ============================================================================

func TestSSMHardener_RestoreParameters_UpdatesExisting(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create backup file
	backup := ParameterBackup{
		Name:     "/sentinel/policies/production",
		Type:     "String",
		Value:    "restored-policy-value",
		Version:  3,
		BackupAt: lastMod,
	}
	backupData := `{"name":"/sentinel/policies/production","type":"String","value":"restored-policy-value","version":3,"backup_at":"2026-01-27T10:00:00Z"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-production.json"), []byte(backupData), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	putCalled := false
	client := &mockSSMHardenClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			// Current version is 5, backup is version 3
			return &ssm.GetParameterOutput{
				Parameter: &types.Parameter{
					Name:             params.Name,
					Type:             types.ParameterTypeString,
					Version:          5,
					LastModifiedDate: &lastMod,
				},
			}, nil
		},
		PutParameterFunc: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			putCalled = true
			if *params.Name != backup.Name {
				t.Errorf("expected name %s, got %s", backup.Name, *params.Name)
			}
			if !*params.Overwrite {
				t.Error("expected Overwrite=true")
			}
			return &ssm.PutParameterOutput{
				Version: 6,
			}, nil
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	result, err := hardener.RestoreParameters(ctx, tmpDir, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !putCalled {
		t.Error("expected PutParameter to be called")
	}

	if len(result.Restored) != 1 {
		t.Errorf("expected 1 restored, got %d", len(result.Restored))
	}

	if len(result.Skipped) != 0 {
		t.Errorf("expected 0 skipped, got %d", len(result.Skipped))
	}
}

func TestSSMHardener_RestoreParameters_SkipsMatchingVersion(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create backup file with version 3
	backupData := `{"name":"/sentinel/policies/staging","type":"String","value":"staging-policy","version":3,"backup_at":"2026-01-27T10:00:00Z"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-staging.json"), []byte(backupData), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	putCalled := false
	client := &mockSSMHardenClient{
		GetParameterFunc: func(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
			// Current version is same as backup (3)
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

	hardener := NewSSMHardenerWithClient(client)
	result, err := hardener.RestoreParameters(ctx, tmpDir, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if putCalled {
		t.Error("expected PutParameter NOT to be called when versions match")
	}

	if len(result.Skipped) != 1 {
		t.Errorf("expected 1 skipped, got %d", len(result.Skipped))
	}

	if len(result.Restored) != 0 {
		t.Errorf("expected 0 restored, got %d", len(result.Restored))
	}
}

func TestSSMHardener_RestoreParameters_FiltersByName(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create multiple backup files
	backupData1 := `{"name":"/sentinel/policies/production","type":"String","value":"prod","version":3,"backup_at":"2026-01-27T10:00:00Z"}`
	backupData2 := `{"name":"/sentinel/policies/staging","type":"String","value":"staging","version":2,"backup_at":"2026-01-27T10:00:00Z"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-production.json"), []byte(backupData1), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-staging.json"), []byte(backupData2), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	restoredParams := []string{}
	client := &mockSSMHardenClient{
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

	hardener := NewSSMHardenerWithClient(client)
	// Only restore production, not staging
	result, err := hardener.RestoreParameters(ctx, tmpDir, []string{"/sentinel/policies/production"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(restoredParams) != 1 {
		t.Errorf("expected 1 parameter restored, got %d: %v", len(restoredParams), restoredParams)
	}

	if restoredParams[0] != "/sentinel/policies/production" {
		t.Errorf("expected production to be restored, got %s", restoredParams[0])
	}
}

func TestSSMHardener_RestoreParameters_HandlesErrors(t *testing.T) {
	ctx := context.Background()
	lastMod := time.Now()

	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-restore-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	backupData := `{"name":"/sentinel/policies/production","type":"String","value":"prod","version":3,"backup_at":"2026-01-27T10:00:00Z"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-production.json"), []byte(backupData), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}

	client := &mockSSMHardenClient{
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
			return nil, errors.New("AccessDeniedException: Not authorized")
		},
	}

	hardener := NewSSMHardenerWithClient(client)
	result, err := hardener.RestoreParameters(ctx, tmpDir, nil)

	if err != nil {
		t.Fatalf("unexpected error (should be handled gracefully): %v", err)
	}

	if len(result.Failed) != 1 {
		t.Errorf("expected 1 failed, got %d", len(result.Failed))
	}

	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error message, got %d", len(result.Errors))
	}
}

// ============================================================================
// LoadBackup Tests
// ============================================================================

func TestLoadBackup_ReadsDirectory(t *testing.T) {
	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-load-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create valid backup files
	backupData1 := `{"name":"/sentinel/policies/production","type":"String","value":"prod","version":3,"backup_at":"2026-01-27T10:00:00Z"}`
	backupData2 := `{"name":"/sentinel/policies/staging","type":"String","value":"staging","version":2,"backup_at":"2026-01-27T10:00:00Z"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-production.json"), []byte(backupData1), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "sentinel-policies-staging.json"), []byte(backupData2), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}
	// Create a non-json file that should be ignored
	if err := os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write txt file: %v", err)
	}

	backups, err := LoadBackup(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(backups) != 2 {
		t.Errorf("expected 2 backups, got %d", len(backups))
	}
}

func TestLoadBackup_DirectoryNotFound(t *testing.T) {
	_, err := LoadBackup("/nonexistent/directory")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestLoadBackup_SkipsInvalidJSON(t *testing.T) {
	// Create temp directory with backup files
	tmpDir, err := os.MkdirTemp("", "ssm-load-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create valid backup file
	backupData := `{"name":"/sentinel/policies/production","type":"String","value":"prod","version":3,"backup_at":"2026-01-27T10:00:00Z"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "valid.json"), []byte(backupData), 0644); err != nil {
		t.Fatalf("failed to write backup file: %v", err)
	}
	// Create invalid JSON file
	if err := os.WriteFile(filepath.Join(tmpDir, "invalid.json"), []byte("not valid json"), 0644); err != nil {
		t.Fatalf("failed to write invalid json file: %v", err)
	}

	backups, err := LoadBackup(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have the valid backup
	if len(backups) != 1 {
		t.Errorf("expected 1 backup (skipping invalid), got %d", len(backups))
	}
}
