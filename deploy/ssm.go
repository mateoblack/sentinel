package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// DefaultSentinelSSMPrefix is the default prefix for Sentinel SSM parameters.
const DefaultSentinelSSMPrefix = "/sentinel/"

// ssmHardenAPI extends audit operations with hardening capabilities.
type ssmHardenAPI interface {
	// Audit operations (from ssmAuditAPI)
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)

	// Hardening operations
	GetParameterHistory(ctx context.Context, params *ssm.GetParameterHistoryInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error)
	PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// SSMHardener provides backup and restore capabilities for SSM parameters.
type SSMHardener struct {
	client ssmHardenAPI
}

// ParameterStatus represents the current state of an SSM parameter.
type ParameterStatus struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Version      int64     `json:"version"`
	LastModified time.Time `json:"last_modified"`
	DataType     string    `json:"data_type,omitempty"`
}

// ParameterBackup represents a backed up parameter.
type ParameterBackup struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Value    string    `json:"value"`
	Version  int64     `json:"version"`
	BackupAt time.Time `json:"backup_at"`
}

// BackupResult contains the result of a backup operation.
type BackupResult struct {
	Parameters []ParameterBackup `json:"parameters"`
	BackupDir  string            `json:"backup_dir"`
	Count      int               `json:"count"`
}

// RestoreResult contains the result of a restore operation.
type RestoreResult struct {
	Restored []string `json:"restored"`
	Skipped  []string `json:"skipped"`
	Failed   []string `json:"failed"`
	Errors   []string `json:"errors,omitempty"`
}

// NewSSMHardener creates a new SSMHardener using the provided AWS configuration.
func NewSSMHardener(cfg aws.Config) *SSMHardener {
	return &SSMHardener{
		client: ssm.NewFromConfig(cfg),
	}
}

// NewSSMHardenerWithClient creates an SSMHardener with a custom client for testing.
func NewSSMHardenerWithClient(client ssmHardenAPI) *SSMHardener {
	return &SSMHardener{
		client: client,
	}
}

// DiscoverSentinelParameters finds all SSM parameters matching the Sentinel prefix pattern.
// Default prefix is "/sentinel/" but can be customized.
func (h *SSMHardener) DiscoverSentinelParameters(ctx context.Context, prefix string) ([]string, error) {
	if prefix == "" {
		prefix = DefaultSentinelSSMPrefix
	}

	// Ensure prefix has trailing slash for path queries
	if !strings.HasSuffix(prefix, "/") {
		prefix = prefix + "/"
	}
	// Remove trailing slash for query (AWS GetParametersByPath expects path without trailing /)
	queryPath := strings.TrimSuffix(prefix, "/")

	var paramNames []string
	var nextToken *string

	for {
		input := &ssm.GetParametersByPathInput{
			Path:      aws.String(queryPath),
			Recursive: aws.Bool(true),
			NextToken: nextToken,
		}

		output, err := h.client.GetParametersByPath(ctx, input)
		if err != nil {
			return nil, err
		}

		for _, param := range output.Parameters {
			if param.Name != nil {
				paramNames = append(paramNames, *param.Name)
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return paramNames, nil
}

// GetParameterStatus returns the current status for a parameter including version info.
func (h *SSMHardener) GetParameterStatus(ctx context.Context, paramName string) (*ParameterStatus, error) {
	output, err := h.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false), // We just need metadata, not the actual value
	})
	if err != nil {
		return nil, err
	}

	if output.Parameter == nil {
		return nil, fmt.Errorf("parameter not found: %s", paramName)
	}

	param := output.Parameter
	status := &ParameterStatus{
		Name:    aws.ToString(param.Name),
		Type:    string(param.Type),
		Version: param.Version,
	}

	if param.LastModifiedDate != nil {
		status.LastModified = *param.LastModifiedDate
	}

	if param.DataType != nil {
		status.DataType = *param.DataType
	}

	return status, nil
}

// GetParametersStatus returns status for multiple parameters.
func (h *SSMHardener) GetParametersStatus(ctx context.Context, paramNames []string) ([]*ParameterStatus, error) {
	var statuses []*ParameterStatus

	for _, name := range paramNames {
		status, err := h.GetParameterStatus(ctx, name)
		if err != nil {
			// Skip parameters that can't be read (e.g., deleted or access denied)
			// but include an error in the response
			if isAccessDenied(err) {
				statuses = append(statuses, &ParameterStatus{
					Name: name,
					Type: "UNKNOWN",
				})
				continue
			}
			// For other errors, propagate
			return nil, err
		}
		statuses = append(statuses, status)
	}

	return statuses, nil
}

// BackupParameters creates local backups of parameter values.
// Writes each parameter to a JSON file in the backup directory.
// If backupDir is empty, creates a timestamped directory in current directory.
func (h *SSMHardener) BackupParameters(ctx context.Context, paramNames []string, backupDir string) (*BackupResult, error) {
	if backupDir == "" {
		backupDir = fmt.Sprintf("sentinel-backup-%s", time.Now().Format("20060102-150405"))
	}

	// Create backup directory
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	result := &BackupResult{
		BackupDir: backupDir,
	}

	backupTime := time.Now()

	for _, paramName := range paramNames {
		// Get parameter with decryption to backup the actual value
		output, err := h.client.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(paramName),
			WithDecryption: aws.Bool(true),
		})
		if err != nil {
			// Skip parameters that can't be read
			continue
		}

		if output.Parameter == nil {
			continue
		}

		param := output.Parameter
		backup := ParameterBackup{
			Name:     aws.ToString(param.Name),
			Type:     string(param.Type),
			Value:    aws.ToString(param.Value),
			Version:  param.Version,
			BackupAt: backupTime,
		}

		// Create filename from parameter name (replace / with -)
		filename := strings.ReplaceAll(strings.TrimPrefix(backup.Name, "/"), "/", "-")
		filename = filename + ".json"
		filepath := filepath.Join(backupDir, filename)

		// Write backup file
		data, err := json.MarshalIndent(backup, "", "  ")
		if err != nil {
			continue
		}

		if err := os.WriteFile(filepath, data, 0600); err != nil {
			continue
		}

		result.Parameters = append(result.Parameters, backup)
	}

	result.Count = len(result.Parameters)
	return result, nil
}

// RestoreParameters restores parameters from backup files.
// Only restores parameters that exist in both backup and paramNames list.
// Uses Overwrite mode to update existing parameters.
func (h *SSMHardener) RestoreParameters(ctx context.Context, backupDir string, paramNames []string) (*RestoreResult, error) {
	result := &RestoreResult{
		Restored: []string{},
		Skipped:  []string{},
		Failed:   []string{},
		Errors:   []string{},
	}

	// Load all backups from directory
	backups, err := LoadBackup(backupDir)
	if err != nil {
		return nil, err
	}

	// Create a map for quick lookup of which parameters to restore
	paramFilter := make(map[string]bool)
	if len(paramNames) > 0 {
		for _, name := range paramNames {
			paramFilter[name] = true
		}
	}

	for _, backup := range backups {
		// If paramNames is specified, filter to only those parameters
		if len(paramNames) > 0 && !paramFilter[backup.Name] {
			continue
		}

		// Check current parameter version
		currentStatus, err := h.GetParameterStatus(ctx, backup.Name)
		if err != nil {
			// If parameter doesn't exist or can't be read, we'll try to create/update it anyway
			if !isAccessDenied(err) && !strings.Contains(err.Error(), "ParameterNotFound") {
				result.Failed = append(result.Failed, backup.Name)
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", backup.Name, err))
				continue
			}
		}

		// Skip if current version matches backup version (no change needed)
		if currentStatus != nil && currentStatus.Version == backup.Version {
			result.Skipped = append(result.Skipped, backup.Name)
			continue
		}

		// Restore the parameter
		paramType := types.ParameterType(backup.Type)
		_, err = h.client.PutParameter(ctx, &ssm.PutParameterInput{
			Name:      aws.String(backup.Name),
			Value:     aws.String(backup.Value),
			Type:      paramType,
			Overwrite: aws.Bool(true),
		})
		if err != nil {
			result.Failed = append(result.Failed, backup.Name)
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", backup.Name, err))
			continue
		}

		result.Restored = append(result.Restored, backup.Name)
	}

	return result, nil
}

// LoadBackup reads backup files from a directory.
func LoadBackup(backupDir string) ([]ParameterBackup, error) {
	var backups []ParameterBackup

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(backupDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var backup ParameterBackup
		if err := json.Unmarshal(data, &backup); err != nil {
			continue
		}

		backups = append(backups, backup)
	}

	return backups, nil
}
