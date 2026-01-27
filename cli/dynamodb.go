package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/deploy"
)

// DynamoDBHardenCommandInput contains the input for the dynamodb harden command.
type DynamoDBHardenCommandInput struct {
	Tables     []string // Specific tables to harden (empty = auto-discover)
	Prefix     string   // Prefix for auto-discovery (default: "sentinel-")
	NoPITR     bool     // Skip enabling PITR (default: enable both)
	Force      bool     // Skip confirmation prompt
	JSONOutput bool     // Output in JSON format
	AWSProfile string   // AWS profile for credentials
	Region     string   // AWS region

	// For testing
	Hardener *deploy.DynamoDBHardener
	Stdout   *os.File
	Stderr   *os.File
	Stdin    *os.File // For confirmation prompt
}

// ConfigureDynamoDBHardenCommand sets up the dynamodb harden command.
func ConfigureDynamoDBHardenCommand(app *kingpin.Application, s *Sentinel) {
	input := DynamoDBHardenCommandInput{}

	// Create dynamodb command group
	dynamodbCmd := app.Command("dynamodb", "DynamoDB operations")

	// Create harden subcommand
	cmd := dynamodbCmd.Command("harden", "Enable deletion protection and point-in-time recovery on Sentinel DynamoDB tables")

	cmd.Flag("table", "Specific table name to harden (repeatable, default: auto-discover)").
		StringsVar(&input.Tables)

	cmd.Flag("prefix", "Table prefix for auto-discovery").
		Default(deploy.DefaultSentinelTablePrefix).
		StringVar(&input.Prefix)

	cmd.Flag("no-pitr", "Skip enabling point-in-time recovery (only enable deletion protection)").
		BoolVar(&input.NoPITR)

	cmd.Flag("force", "Skip confirmation prompt").
		Short('f').
		BoolVar(&input.Force)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Flag("region", "AWS region for API operations").
		StringVar(&input.Region)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode := DynamoDBHardenCommand(context.Background(), input)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// DynamoDBHardenOutput represents the JSON output structure.
type DynamoDBHardenOutput struct {
	Tables    []DynamoDBHardenTableResult `json:"tables"`
	Total     int                         `json:"total"`
	Succeeded int                         `json:"succeeded"`
	Failed    int                         `json:"failed"`
}

// DynamoDBHardenTableResult represents a single table result in JSON output.
type DynamoDBHardenTableResult struct {
	TableName                 string `json:"table_name"`
	DeletionProtectionChanged bool   `json:"deletion_protection_changed"`
	PITRChanged               bool   `json:"pitr_changed"`
	Error                     string `json:"error,omitempty"`
}

// DynamoDBHardenCommand executes the dynamodb harden command logic.
// Returns exit code: 0=success, 1=failure, 2=user cancelled.
func DynamoDBHardenCommand(ctx context.Context, input DynamoDBHardenCommandInput) int {
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
		hardener = deploy.NewDynamoDBHardener(awsCfg)
	}

	// Determine tables to harden
	var tableNames []string
	if len(input.Tables) > 0 {
		// Use explicitly specified tables
		tableNames = input.Tables
	} else {
		// Auto-discover tables by prefix
		discovered, err := hardener.DiscoverSentinelTables(ctx, input.Prefix)
		if err != nil {
			if strings.Contains(err.Error(), "AccessDenied") {
				fmt.Fprintf(stderr, "Error: Permission denied. Ensure you have dynamodb:ListTables permission.\n")
				return 1
			}
			fmt.Fprintf(stderr, "Error discovering tables: %v\n", err)
			return 1
		}
		tableNames = discovered
	}

	if len(tableNames) == 0 {
		if input.JSONOutput {
			output := DynamoDBHardenOutput{
				Tables:    []DynamoDBHardenTableResult{},
				Total:     0,
				Succeeded: 0,
				Failed:    0,
			}
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Fprintln(stdout, string(jsonBytes))
		} else {
			fmt.Fprintln(stdout, "No Sentinel tables found to harden.")
			if len(input.Tables) == 0 {
				fmt.Fprintf(stdout, "Searched for tables with prefix: %s\n", input.Prefix)
			}
		}
		return 0
	}

	// Get current status for all tables
	var statuses []*deploy.TableProtectionStatus
	for _, tableName := range tableNames {
		status, err := hardener.GetTableStatus(ctx, tableName)
		if err != nil {
			if strings.Contains(err.Error(), "AccessDenied") {
				fmt.Fprintf(stderr, "Error: Permission denied checking table %s.\n", tableName)
				return 1
			}
			if strings.Contains(err.Error(), "ResourceNotFoundException") {
				fmt.Fprintf(stderr, "Error: Table %s not found.\n", tableName)
				return 1
			}
			fmt.Fprintf(stderr, "Error getting status for table %s: %v\n", tableName, err)
			return 1
		}
		statuses = append(statuses, status)
	}

	// Determine what changes are needed
	enablePITR := !input.NoPITR
	var changesToMake []string
	allAlreadyProtected := true

	for _, status := range statuses {
		var tableChanges []string
		if !status.DeletionProtection {
			tableChanges = append(tableChanges, "Enable deletion protection")
			allAlreadyProtected = false
		}
		if enablePITR && !status.PITREnabled {
			tableChanges = append(tableChanges, "Enable PITR")
			allAlreadyProtected = false
		}
		if len(tableChanges) > 0 {
			changesToMake = append(changesToMake, fmt.Sprintf("- %s: %s", status.TableName, strings.Join(tableChanges, ", ")))
		}
	}

	// If all tables are already protected, report and exit
	if allAlreadyProtected {
		if input.JSONOutput {
			output := DynamoDBHardenOutput{
				Tables:    make([]DynamoDBHardenTableResult, len(tableNames)),
				Total:     len(tableNames),
				Succeeded: len(tableNames),
				Failed:    0,
			}
			for i, name := range tableNames {
				output.Tables[i] = DynamoDBHardenTableResult{
					TableName:                 name,
					DeletionProtectionChanged: false,
					PITRChanged:               false,
				}
			}
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Fprintln(stdout, string(jsonBytes))
		} else {
			fmt.Fprintln(stdout, "Sentinel DynamoDB Hardening")
			fmt.Fprintln(stdout, "===========================")
			fmt.Fprintln(stdout)
			fmt.Fprintf(stdout, "All %d tables are already fully protected.\n", len(tableNames))
			fmt.Fprintln(stdout)
			for _, status := range statuses {
				protection := "Enabled"
				pitr := "Enabled"
				if !status.DeletionProtection {
					protection = "Disabled"
				}
				if !status.PITREnabled {
					pitr = "Disabled"
				}
				fmt.Fprintf(stdout, "  %s: Deletion Protection %s, PITR %s\n", status.TableName, protection, pitr)
			}
		}
		return 0
	}

	// Show status and changes to apply
	if !input.JSONOutput {
		fmt.Fprintln(stdout, "Sentinel DynamoDB Hardening")
		fmt.Fprintln(stdout, "===========================")
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Tables to harden (%d found):\n", len(tableNames))
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "  Table                    Deletion Protection    PITR")
		fmt.Fprintln(stdout, "  -----                    -------------------    ----")
		for _, status := range statuses {
			protection := "Disabled"
			if status.DeletionProtection {
				protection = "Enabled"
			}
			pitr := "Disabled"
			if status.PITREnabled {
				pitr = "Enabled"
			}
			fmt.Fprintf(stdout, "  %-24s %-22s %s\n", status.TableName, protection, pitr)
		}
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Changes to apply:")
		for _, change := range changesToMake {
			fmt.Fprintln(stdout, change)
		}
		fmt.Fprintln(stdout)
	}

	// Prompt for confirmation unless --force
	if !input.Force && !input.JSONOutput {
		fmt.Fprintf(stdout, "Harden %d tables? [y/N] ", len(tableNames))

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

	// Harden the tables
	results, err := hardener.HardenTables(ctx, tableNames, true, enablePITR)
	if err != nil {
		fmt.Fprintf(stderr, "Error hardening tables: %v\n", err)
		return 1
	}

	// Count successes and failures
	succeeded := 0
	failed := 0
	for _, result := range results {
		if result.Error != nil {
			failed++
		} else {
			succeeded++
		}
	}

	// Output results
	if input.JSONOutput {
		output := DynamoDBHardenOutput{
			Tables:    make([]DynamoDBHardenTableResult, len(results)),
			Total:     len(results),
			Succeeded: succeeded,
			Failed:    failed,
		}
		for i, result := range results {
			tableResult := DynamoDBHardenTableResult{
				TableName:                 result.TableName,
				DeletionProtectionChanged: result.DeletionProtectionChanged,
				PITRChanged:               result.PITRChanged,
			}
			if result.Error != nil {
				tableResult.Error = result.Error.Error()
			}
			output.Tables[i] = tableResult
		}
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Fprintln(stdout, string(jsonBytes))
	} else {
		// Human-readable output
		for _, result := range results {
			if result.Error != nil {
				fmt.Fprintf(stdout, "x %s: Error - %v\n", result.TableName, result.Error)
			} else {
				var changes []string
				if result.DeletionProtectionChanged {
					changes = append(changes, "Deletion protection enabled")
				}
				if result.PITRChanged {
					changes = append(changes, "PITR enabled")
				}
				if len(changes) == 0 {
					changes = append(changes, "Already protected")
				}
				fmt.Fprintf(stdout, "v %s: %s\n", result.TableName, strings.Join(changes, ", "))
			}
		}
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Summary: %d/%d tables hardened successfully\n", succeeded, len(results))
	}

	// Return exit code based on results
	if failed > 0 {
		return 1
	}
	return 0
}
