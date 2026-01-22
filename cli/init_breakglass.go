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
	"github.com/byteness/aws-vault/v7/infrastructure"
)

// DefaultBreakGlassTableName is the default name for the break-glass events table.
const DefaultBreakGlassTableName = "sentinel-breakglass"

// InitBreakGlassCommandInput contains the input for the init breakglass command.
type InitBreakGlassCommandInput struct {
	TableName   string
	Region      string
	AWSProfile  string
	Plan        bool
	Yes         bool
	GenerateIAM bool

	// Provisioner is an optional TableProvisioner for testing.
	// If nil, a new TableProvisioner will be created using AWS config.
	Provisioner *infrastructure.TableProvisioner

	// Stdin is an optional reader for confirmation prompts (for testing).
	// If nil, os.Stdin will be used.
	Stdin *bufio.Scanner

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File
}

// ConfigureInitBreakGlassCommand sets up the init breakglass command as a subcommand of init.
func ConfigureInitBreakGlassCommand(app *kingpin.Application, s *Sentinel) {
	input := InitBreakGlassCommandInput{}

	// Get or create the init command
	initCmd := app.GetCommand("init")
	if initCmd == nil {
		initCmd = app.Command("init", "Initialize Sentinel infrastructure")
	}

	// Create breakglass as a subcommand of init
	cmd := initCmd.Command("breakglass", "Provision the DynamoDB break-glass events table")

	cmd.Flag("table", "DynamoDB table name").
		Default(DefaultBreakGlassTableName).
		StringVar(&input.TableName)

	cmd.Flag("region", "AWS region for DynamoDB operations").
		Required().
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Flag("plan", "Show what would be created without creating").
		BoolVar(&input.Plan)

	cmd.Flag("yes", "Skip confirmation prompt").
		Short('y').
		BoolVar(&input.Yes)

	cmd.Flag("generate-iam", "Output IAM policy document for table access").
		BoolVar(&input.GenerateIAM)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := InitBreakGlassCommand(context.Background(), input)
		app.FatalIfError(err, "init breakglass")
		return nil
	})
}

// InitBreakGlassCommand executes the init breakglass command logic.
// It creates the DynamoDB break-glass events table with correct schema, GSIs, and TTL configuration.
func InitBreakGlassCommand(ctx context.Context, input InitBreakGlassCommandInput) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Handle --generate-iam flag
	if input.GenerateIAM {
		policy := generateBreakGlassTableIAMPolicy(input.TableName, input.Region)
		fmt.Fprintln(stdout, policy)
		return nil
	}

	// Get or create provisioner
	provisioner := input.Provisioner
	if provisioner == nil {
		// Load AWS config
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
			return err
		}
		provisioner = infrastructure.NewTableProvisioner(awsCfg, input.Region)
	}

	// Get schema
	schema := infrastructure.BreakGlassTableSchema(input.TableName)

	// Handle --plan flag
	if input.Plan {
		plan, err := provisioner.Plan(ctx, schema)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to generate plan: %v\n", err)
			return err
		}

		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Sentinel Init Break-Glass - Plan")
		fmt.Fprintln(stdout, strings.Repeat("=", 50))
		fmt.Fprintln(stdout, "")

		if plan.WouldCreate {
			fmt.Fprintf(stdout, "  + Table:        %s\n", plan.TableName)
			fmt.Fprintf(stdout, "  + Billing Mode: %s\n", plan.BillingMode)
			if len(plan.GSIs) > 0 {
				fmt.Fprintf(stdout, "  + GSIs:         %s\n", strings.Join(plan.GSIs, ", "))
			}
			if plan.TTLAttribute != "" {
				fmt.Fprintf(stdout, "  + TTL:          %s\n", plan.TTLAttribute)
			}
		} else {
			fmt.Fprintf(stdout, "  Table %s already exists\n", plan.TableName)
		}

		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "No changes made (--plan mode)")
		return nil
	}

	// Print what will be created
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "Sentinel Init Break-Glass")
	fmt.Fprintln(stdout, strings.Repeat("=", 50))
	fmt.Fprintln(stdout, "")
	fmt.Fprintf(stdout, "Table:        %s\n", schema.TableName)
	fmt.Fprintf(stdout, "Region:       %s\n", input.Region)
	fmt.Fprintf(stdout, "Billing Mode: %s\n", schema.BillingMode)
	fmt.Fprintf(stdout, "GSIs:         %s\n", strings.Join(schema.GSINames(), ", "))
	fmt.Fprintf(stdout, "TTL:          %s\n", schema.TTLAttribute)
	fmt.Fprintln(stdout, "")

	// Prompt for confirmation if not auto-approved
	if !input.Yes {
		fmt.Fprint(stdout, "Create this table? [y/N]: ")

		scanner := input.Stdin
		if scanner == nil {
			scanner = bufio.NewScanner(os.Stdin)
		}

		if !scanner.Scan() {
			fmt.Fprintln(stderr, "Error reading input")
			return fmt.Errorf("error reading input")
		}

		response := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if response != "y" && response != "yes" {
			fmt.Fprintln(stdout, "Cancelled.")
			return nil
		}
	}

	// Create table
	result, err := provisioner.Create(ctx, schema)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to create table: %v\n", err)
		return err
	}

	// Print result
	fmt.Fprintln(stdout, "")
	switch result.Status {
	case infrastructure.StatusCreated:
		fmt.Fprintf(stdout, "# Table created successfully\n")
		fmt.Fprintf(stdout, "  ARN: %s\n", result.ARN)
	case infrastructure.StatusExists:
		fmt.Fprintf(stdout, "= Table already exists\n")
		fmt.Fprintf(stdout, "  ARN: %s\n", result.ARN)
	case infrastructure.StatusFailed:
		fmt.Fprintf(stderr, "X Table creation failed\n")
		if result.Error != nil {
			fmt.Fprintf(stderr, "  Error: %v\n", result.Error)
		}
		return result.Error
	}

	// Print next steps
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "Next steps:")
	fmt.Fprintf(stdout, "  1. Configure --breakglass-table %s in your Sentinel commands\n", input.TableName)
	fmt.Fprintln(stdout, "  2. Or set SENTINEL_BREAKGLASS_TABLE environment variable")
	fmt.Fprintln(stdout, "")
	fmt.Fprintf(stdout, "  Run 'sentinel init breakglass --generate-iam --table %s --region %s'\n", input.TableName, input.Region)
	fmt.Fprintln(stdout, "  to generate the IAM policy document for table access.")

	return nil
}

// generateBreakGlassTableIAMPolicy generates an IAM policy document for DynamoDB break-glass table access.
// The policy includes permissions for table creation, status checks, and data operations.
func generateBreakGlassTableIAMPolicy(tableName, region string) string {
	// Use account placeholder - user will need to substitute
	account := "*"

	tableARN := fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s", region, account, tableName)
	indexARN := fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s/index/*", region, account, tableName)

	policy := IAMPolicyDocument{
		Version: "2012-10-17",
		Statement: []IAMPolicyStatement{
			{
				Sid:    "SentinelBreakGlassTableProvisioning",
				Effect: "Allow",
				Action: []string{
					"dynamodb:CreateTable",
					"dynamodb:DescribeTable",
					"dynamodb:UpdateTimeToLive",
				},
				Resource: []string{tableARN},
			},
			{
				Sid:    "SentinelBreakGlassTableOperations",
				Effect: "Allow",
				Action: []string{
					"dynamodb:GetItem",
					"dynamodb:PutItem",
					"dynamodb:UpdateItem",
					"dynamodb:DeleteItem",
					"dynamodb:Query",
					"dynamodb:Scan",
				},
				Resource: []string{tableARN, indexARN},
			},
		},
	}

	jsonBytes, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to generate policy: %v"}`, err)
	}

	return string(jsonBytes)
}
