package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/deploy"
)

// SSMBackupCommandInput contains the input for the ssm backup command.
type SSMBackupCommandInput struct {
	Parameters []string // Specific parameters to backup (empty = auto-discover)
	Prefix     string   // Prefix for auto-discovery (default: "/sentinel/")
	OutputDir  string   // Directory for backup files (default: "./sentinel-backup-{timestamp}")
	JSONOutput bool     // Output in JSON format
	AWSProfile string   // AWS profile for credentials
	Region     string   // AWS region

	// For testing
	Hardener *deploy.SSMHardener
	Stdout   *os.File
	Stderr   *os.File
	Stdin    *os.File // For confirmation prompt
}

// SSMRestoreCommandInput contains the input for the ssm restore command.
type SSMRestoreCommandInput struct {
	BackupDir  string   // Directory containing backup files (required)
	Parameters []string // Specific parameters to restore (empty = all in backup)
	Force      bool     // Skip confirmation prompt
	JSONOutput bool     // Output in JSON format
	AWSProfile string   // AWS profile for credentials
	Region     string   // AWS region

	// For testing
	Hardener *deploy.SSMHardener
	Stdout   *os.File
	Stderr   *os.File
	Stdin    *os.File // For confirmation prompt
}

// ConfigureSSMCommands sets up the ssm backup and restore commands.
func ConfigureSSMCommands(app *kingpin.Application, s *Sentinel) {
	backupInput := SSMBackupCommandInput{}
	restoreInput := SSMRestoreCommandInput{}

	// Create ssm command group
	ssmCmd := app.Command("ssm", "SSM parameter operations")

	// Create backup subcommand
	backupCmd := ssmCmd.Command("backup", "Backup Sentinel SSM parameters to local files")

	backupCmd.Flag("parameter", "Specific parameter name to backup (repeatable, default: auto-discover)").
		StringsVar(&backupInput.Parameters)

	backupCmd.Flag("prefix", "Parameter prefix for auto-discovery").
		Default(deploy.DefaultSentinelSSMPrefix).
		StringVar(&backupInput.Prefix)

	backupCmd.Flag("output-dir", "Output directory for backup files").
		Short('o').
		StringVar(&backupInput.OutputDir)

	backupCmd.Flag("json", "Output in JSON format").
		BoolVar(&backupInput.JSONOutput)

	backupCmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&backupInput.AWSProfile)

	backupCmd.Flag("region", "AWS region for API operations").
		StringVar(&backupInput.Region)

	backupCmd.Action(func(c *kingpin.ParseContext) error {
		exitCode := SSMBackupCommand(context.Background(), backupInput)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})

	// Create restore subcommand
	restoreCmd := ssmCmd.Command("restore", "Restore Sentinel SSM parameters from backup files")

	restoreCmd.Flag("backup-dir", "Directory containing backup files (required)").
		Short('d').
		Required().
		StringVar(&restoreInput.BackupDir)

	restoreCmd.Flag("parameter", "Specific parameter to restore (repeatable, default: all)").
		StringsVar(&restoreInput.Parameters)

	restoreCmd.Flag("force", "Skip confirmation prompt").
		Short('f').
		BoolVar(&restoreInput.Force)

	restoreCmd.Flag("json", "Output in JSON format").
		BoolVar(&restoreInput.JSONOutput)

	restoreCmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&restoreInput.AWSProfile)

	restoreCmd.Flag("region", "AWS region for API operations").
		StringVar(&restoreInput.Region)

	restoreCmd.Action(func(c *kingpin.ParseContext) error {
		exitCode := SSMRestoreCommand(context.Background(), restoreInput)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// SSMBackupOutput represents the JSON output structure for backup.
type SSMBackupOutput struct {
	Parameters []SSMBackupParameterResult `json:"parameters"`
	BackupDir  string                     `json:"backup_dir"`
	Count      int                        `json:"count"`
}

// SSMBackupParameterResult represents a single parameter result in JSON output.
type SSMBackupParameterResult struct {
	Name    string `json:"name"`
	Version int64  `json:"version"`
	File    string `json:"file"`
}

// SSMRestoreOutput represents the JSON output structure for restore.
type SSMRestoreOutput struct {
	Restored []string `json:"restored"`
	Skipped  []string `json:"skipped"`
	Failed   []string `json:"failed"`
	Count    int      `json:"count"`
}

// SSMBackupCommand executes the ssm backup command logic.
// Returns exit code: 0=success, 1=failure, 2=user cancelled.
func SSMBackupCommand(ctx context.Context, input SSMBackupCommandInput) int {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	stdin := input.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}

	// Create hardener if not provided (for testing)
	hardener := input.Hardener
	if hardener == nil {
		awsCfgOpts := []func(*config.LoadOptions) error{}
		if input.AWSProfile != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(input.AWSProfile))
		}
		if input.Region != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to load AWS config: %v\n", err)
			return 1
		}
		hardener = deploy.NewSSMHardener(awsCfg)
	}

	// Determine parameters to backup
	var paramNames []string
	if len(input.Parameters) > 0 {
		// Use explicitly specified parameters
		paramNames = input.Parameters
	} else {
		// Auto-discover parameters by prefix
		discovered, err := hardener.DiscoverSentinelParameters(ctx, input.Prefix)
		if err != nil {
			if strings.Contains(err.Error(), "AccessDenied") {
				fmt.Fprintf(stderr, "Error: Permission denied. Ensure you have ssm:GetParametersByPath permission.\n")
				return 1
			}
			fmt.Fprintf(stderr, "Error discovering parameters: %v\n", err)
			return 1
		}
		paramNames = discovered
	}

	if len(paramNames) == 0 {
		if input.JSONOutput {
			output := SSMBackupOutput{
				Parameters: []SSMBackupParameterResult{},
				BackupDir:  "",
				Count:      0,
			}
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Fprintln(stdout, string(jsonBytes))
		} else {
			fmt.Fprintln(stdout, "No Sentinel parameters found to backup.")
			if len(input.Parameters) == 0 {
				fmt.Fprintf(stdout, "Searched for parameters with prefix: %s\n", input.Prefix)
			}
		}
		return 0
	}

	// Get current status for all parameters
	statuses, err := hardener.GetParametersStatus(ctx, paramNames)
	if err != nil {
		fmt.Fprintf(stderr, "Error getting parameter status: %v\n", err)
		return 1
	}

	// Determine backup directory
	backupDir := input.OutputDir
	if backupDir == "" {
		backupDir = fmt.Sprintf("sentinel-backup-%s", time.Now().Format("20060102-150405"))
	}

	// Show status preview
	if !input.JSONOutput {
		fmt.Fprintln(stdout, "Sentinel SSM Backup")
		fmt.Fprintln(stdout, "===================")
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Parameters to backup (%d found):\n", len(paramNames))
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "  Parameter                              Type          Version    Last Modified")
		fmt.Fprintln(stdout, "  ---------                              ----          -------    -------------")
		for _, status := range statuses {
			lastMod := "N/A"
			if !status.LastModified.IsZero() {
				lastMod = status.LastModified.Format("2006-01-02 15:04:05")
			}
			fmt.Fprintf(stdout, "  %-40s %-13s %-10d %s\n", status.Name, status.Type, status.Version, lastMod)
		}
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Backup directory: %s/\n", backupDir)
		fmt.Fprintln(stdout)
	}

	// Perform the backup
	result, err := hardener.BackupParameters(ctx, paramNames, backupDir)
	if err != nil {
		fmt.Fprintf(stderr, "Error creating backup: %v\n", err)
		return 1
	}

	// Output results
	if input.JSONOutput {
		output := SSMBackupOutput{
			Parameters: make([]SSMBackupParameterResult, len(result.Parameters)),
			BackupDir:  result.BackupDir,
			Count:      result.Count,
		}
		for i, param := range result.Parameters {
			// Generate filename from parameter name
			filename := strings.ReplaceAll(strings.TrimPrefix(param.Name, "/"), "/", "-")
			filename = filename + ".json"
			output.Parameters[i] = SSMBackupParameterResult{
				Name:    param.Name,
				Version: param.Version,
				File:    filename,
			}
		}
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Fprintln(stdout, string(jsonBytes))
	} else {
		// Human-readable output
		fmt.Fprintf(stdout, "v Backed up %d parameters to %s/\n", result.Count, result.BackupDir)
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Files created:")
		for _, param := range result.Parameters {
			filename := strings.ReplaceAll(strings.TrimPrefix(param.Name, "/"), "/", "-")
			filename = filename + ".json"
			fmt.Fprintf(stdout, "  %s (v%d)\n", filename, param.Version)
		}
	}

	return 0
}

// SSMRestoreCommand executes the ssm restore command logic.
// Returns exit code: 0=success, 1=failure, 2=user cancelled.
func SSMRestoreCommand(ctx context.Context, input SSMRestoreCommandInput) int {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	stdin := input.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}

	// Create hardener if not provided (for testing)
	hardener := input.Hardener
	if hardener == nil {
		awsCfgOpts := []func(*config.LoadOptions) error{}
		if input.AWSProfile != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(input.AWSProfile))
		}
		if input.Region != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to load AWS config: %v\n", err)
			return 1
		}
		hardener = deploy.NewSSMHardener(awsCfg)
	}

	// Load backup files
	backups, err := deploy.LoadBackup(input.BackupDir)
	if err != nil {
		fmt.Fprintf(stderr, "Error reading backup directory: %v\n", err)
		return 1
	}

	if len(backups) == 0 {
		if input.JSONOutput {
			output := SSMRestoreOutput{
				Restored: []string{},
				Skipped:  []string{},
				Failed:   []string{},
				Count:    0,
			}
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Fprintln(stdout, string(jsonBytes))
		} else {
			fmt.Fprintln(stdout, "No backup files found in directory.")
		}
		return 0
	}

	// Filter to specified parameters if provided
	var filteredBackups []deploy.ParameterBackup
	if len(input.Parameters) > 0 {
		paramFilter := make(map[string]bool)
		for _, name := range input.Parameters {
			paramFilter[name] = true
		}
		for _, backup := range backups {
			if paramFilter[backup.Name] {
				filteredBackups = append(filteredBackups, backup)
			}
		}
		backups = filteredBackups
	}

	if len(backups) == 0 {
		if input.JSONOutput {
			output := SSMRestoreOutput{
				Restored: []string{},
				Skipped:  []string{},
				Failed:   []string{},
				Count:    0,
			}
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Fprintln(stdout, string(jsonBytes))
		} else {
			fmt.Fprintln(stdout, "No matching parameters found in backup.")
		}
		return 0
	}

	// Get current status for comparison
	paramNames := make([]string, len(backups))
	for i, backup := range backups {
		paramNames[i] = backup.Name
	}

	currentStatuses, _ := hardener.GetParametersStatus(ctx, paramNames)
	currentVersions := make(map[string]int64)
	for _, status := range currentStatuses {
		currentVersions[status.Name] = status.Version
	}

	// Count changes needed
	var changesToMake []string
	allUpToDate := true
	for _, backup := range backups {
		currentVersion := currentVersions[backup.Name]
		if currentVersion != backup.Version {
			changesToMake = append(changesToMake, backup.Name)
			allUpToDate = false
		}
	}

	// Get backup time from first backup file
	var backupTime time.Time
	if len(backups) > 0 {
		backupTime = backups[0].BackupAt
	}

	// Show status preview
	if !input.JSONOutput {
		fmt.Fprintln(stdout, "Sentinel SSM Restore")
		fmt.Fprintln(stdout, "====================")
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Backup from: %s/\n", input.BackupDir)
		if !backupTime.IsZero() {
			fmt.Fprintf(stdout, "Backup date: %s\n", backupTime.Format("2006-01-02 15:04:05"))
		}
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Parameters to restore (%d found):\n", len(backups))
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "  Parameter                              Backup Version    Current Version")
		fmt.Fprintln(stdout, "  ---------                              --------------    ---------------")
		for _, backup := range backups {
			currentVersion := currentVersions[backup.Name]
			currentStr := fmt.Sprintf("%d", currentVersion)
			if currentVersion == backup.Version {
				currentStr = fmt.Sprintf("%d (no change)", currentVersion)
			}
			fmt.Fprintf(stdout, "  %-40s %-17d %s\n", backup.Name, backup.Version, currentStr)
		}
		fmt.Fprintln(stdout)
	}

	// If all up to date, report and exit
	if allUpToDate {
		if input.JSONOutput {
			output := SSMRestoreOutput{
				Restored: []string{},
				Skipped:  paramNames,
				Failed:   []string{},
				Count:    0,
			}
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Fprintln(stdout, string(jsonBytes))
		} else {
			fmt.Fprintf(stdout, "All %d parameters are already at backup versions.\n", len(backups))
		}
		return 0
	}

	// Prompt for confirmation unless --force
	if !input.Force && !input.JSONOutput {
		fmt.Fprintln(stdout, "Warning: This will overwrite current parameter values.")
		fmt.Fprintf(stdout, "Restore %d parameters? [y/N] ", len(changesToMake))

		reader := bufio.NewReader(stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(stderr, "Error reading input: %v\n", err)
			return 1
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Fprintln(stdout, "Cancelled.")
			return 2
		}
		fmt.Fprintln(stdout)
	}

	// Perform the restore
	result, err := hardener.RestoreParameters(ctx, input.BackupDir, input.Parameters)
	if err != nil {
		fmt.Fprintf(stderr, "Error restoring parameters: %v\n", err)
		return 1
	}

	// Output results
	if input.JSONOutput {
		output := SSMRestoreOutput{
			Restored: result.Restored,
			Skipped:  result.Skipped,
			Failed:   result.Failed,
			Count:    len(result.Restored),
		}
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Fprintln(stdout, string(jsonBytes))
	} else {
		// Human-readable output
		for _, name := range result.Restored {
			// Find the backup version
			var backupVersion int64
			for _, backup := range backups {
				if backup.Name == name {
					backupVersion = backup.Version
					break
				}
			}
			fmt.Fprintf(stdout, "v %s: Restored (v%d)\n", name, backupVersion)
		}
		for _, name := range result.Skipped {
			fmt.Fprintf(stdout, "- %s: Skipped (already at backup version)\n", name)
		}
		for _, name := range result.Failed {
			fmt.Fprintf(stdout, "x %s: Failed\n", name)
		}
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Summary: %d restored, %d skipped", len(result.Restored), len(result.Skipped))
		if len(result.Failed) > 0 {
			fmt.Fprintf(stdout, ", %d failed", len(result.Failed))
		}
		fmt.Fprintln(stdout)
	}

	// Return exit code based on results
	if len(result.Failed) > 0 {
		return 1
	}
	return 0
}
