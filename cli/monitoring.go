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

// MonitoringSetupCommandInput contains the input for the monitoring setup command.
type MonitoringSetupCommandInput struct {
	CloudTrailLogGroup string   // CloudTrail log group name (required)
	SNSTopicName       string   // SNS topic name (default: "sentinel-security-alerts")
	Email              string   // Email for notifications (optional)
	Alarms             []string // Specific alarms to create (empty = all)
	DryRun             bool     // Preview without creating
	Force              bool     // Skip confirmation prompt
	JSONOutput         bool     // Output in JSON format
	AWSProfile         string   // AWS profile for credentials
	Region             string   // AWS region

	// For testing
	Setup  *deploy.MonitoringSetup
	Stdout *os.File
	Stderr *os.File
	Stdin  *os.File
}

// ConfigureMonitoringCommands sets up the monitoring commands.
func ConfigureMonitoringCommands(app *kingpin.Application, s *Sentinel) {
	input := MonitoringSetupCommandInput{}

	// Create monitoring command group
	monitoringCmd := app.Command("monitoring", "CloudTrail monitoring operations")

	// Create setup subcommand
	cmd := monitoringCmd.Command("setup", "Create CloudWatch alarms for Sentinel security event monitoring")

	cmd.Flag("log-group", "CloudTrail log group name (required)").
		Short('l').
		Required().
		StringVar(&input.CloudTrailLogGroup)

	cmd.Flag("topic-name", "SNS topic name for notifications").
		Default(deploy.DefaultSNSTopicName).
		StringVar(&input.SNSTopicName)

	cmd.Flag("email", "Email address for notifications (optional)").
		Short('e').
		StringVar(&input.Email)

	cmd.Flag("alarm", "Specific alarm to create (repeatable): kms, dynamodb, ssm, assume-role").
		StringsVar(&input.Alarms)

	cmd.Flag("dry-run", "Preview what would be created without creating").
		BoolVar(&input.DryRun)

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
		exitCode := MonitoringSetupCommand(context.Background(), input)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// MonitoringSetupOutput represents the JSON output structure.
type MonitoringSetupOutput struct {
	SNSTopicARN     string   `json:"sns_topic_arn"`
	AlarmsCreated   []string `json:"alarms_created"`
	FiltersCreated  []string `json:"filters_created"`
	AlarmsSkipped   []string `json:"alarms_skipped,omitempty"`
	EmailSubscribed string   `json:"email_subscribed,omitempty"`
	Errors          []string `json:"errors,omitempty"`
}

// alarmAliases maps short alarm names to full names.
var alarmAliases = map[string]string{
	"kms":         "sentinel-kms-key-changes",
	"dynamodb":    "sentinel-dynamodb-delete",
	"ssm":         "sentinel-ssm-delete",
	"assume-role": "sentinel-unmanaged-assume-role",
}

// alarmDescriptions provides human-readable descriptions for alarms.
var alarmDescriptions = map[string]struct {
	EventType string
	Trigger   string
}{
	"sentinel-kms-key-changes":       {EventType: "KMS DisableKey/Delete", Trigger: "Single occurrence"},
	"sentinel-dynamodb-delete":       {EventType: "DynamoDB DeleteTable", Trigger: "Single occurrence"},
	"sentinel-ssm-delete":            {EventType: "SSM DeleteParameter", Trigger: "Single occurrence"},
	"sentinel-unmanaged-assume-role": {EventType: "AssumeRole no identity", Trigger: "Single occurrence"},
}

// resolveAlarmNames converts short names (kms, dynamodb) to full alarm names.
func resolveAlarmNames(aliases []string) []string {
	if len(aliases) == 0 {
		return deploy.GetAlarmNames()
	}

	var resolved []string
	for _, alias := range aliases {
		if fullName, ok := alarmAliases[alias]; ok {
			resolved = append(resolved, fullName)
		} else {
			// Assume it's already a full name
			resolved = append(resolved, alias)
		}
	}
	return resolved
}

// MonitoringSetupCommand executes the monitoring setup command logic.
// Returns exit code: 0=success, 1=failure, 2=user cancelled.
func MonitoringSetupCommand(ctx context.Context, input MonitoringSetupCommandInput) int {
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

	// Create setup if not provided (for testing)
	setup := input.Setup
	if setup == nil {
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
		setup = deploy.NewMonitoringSetup(awsCfg)
	}

	// Resolve alarm names from short aliases
	alarmNames := resolveAlarmNames(input.Alarms)

	// Show preview
	if !input.JSONOutput {
		fmt.Fprintln(stdout, "Sentinel CloudTrail Monitoring Setup")
		fmt.Fprintln(stdout, "=====================================")
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "CloudTrail Log Group: %s\n", input.CloudTrailLogGroup)
		fmt.Fprintf(stdout, "SNS Topic: %s\n", input.SNSTopicName)
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "Alarms to create (%d):\n", len(alarmNames))
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "  Alarm Name                         Event Type              Trigger")
		fmt.Fprintln(stdout, "  ----------                         ----------              -------")
		for _, name := range alarmNames {
			desc := alarmDescriptions[name]
			fmt.Fprintf(stdout, "  %-36s %-23s %s\n", name, desc.EventType, desc.Trigger)
		}
		fmt.Fprintln(stdout)
		if input.Email != "" {
			fmt.Fprintf(stdout, "Notifications will be sent to: %s\n", input.Email)
			fmt.Fprintln(stdout)
		}
	}

	// If dry-run, show preview and exit
	if input.DryRun {
		if input.JSONOutput {
			output := MonitoringSetupOutput{
				SNSTopicARN:    "(dry-run)",
				AlarmsCreated:  []string{},
				FiltersCreated: []string{},
			}
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Fprintln(stdout, string(jsonBytes))
		} else {
			fmt.Fprintln(stdout, "(Dry-run: no resources created)")
		}
		return 0
	}

	// Prompt for confirmation unless --force
	if !input.Force && !input.JSONOutput {
		fmt.Fprintf(stdout, "Create monitoring resources? [Y/n] ")

		reader := bufio.NewReader(stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(stderr, "Error reading input: %v\n", err)
			return 1
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response == "n" || response == "no" {
			fmt.Fprintln(stdout, "Cancelled.")
			return 2
		}
		fmt.Fprintln(stdout)
	}

	// Create monitoring resources
	var result *deploy.MonitoringResult
	var err error

	if len(input.Alarms) > 0 {
		// Create only selected alarms
		result, err = setup.SetupSelectedAlarms(ctx, input.CloudTrailLogGroup, input.SNSTopicName, input.Email, alarmNames)
	} else {
		// Create all alarms
		result, err = setup.SetupSentinelMonitoring(ctx, input.CloudTrailLogGroup, input.SNSTopicName, input.Email)
	}

	if err != nil {
		if strings.Contains(err.Error(), "AccessDenied") {
			fmt.Fprintf(stderr, "Error: Permission denied. Ensure you have required CloudWatch, SNS, and CloudWatch Logs permissions.\n")
			return 1
		}
		fmt.Fprintf(stderr, "Error creating monitoring resources: %v\n", err)
		return 1
	}

	// Output results
	if input.JSONOutput {
		output := MonitoringSetupOutput{
			SNSTopicARN:    result.SNSTopicARN,
			AlarmsCreated:  result.AlarmsCreated,
			FiltersCreated: result.FiltersCreated,
			AlarmsSkipped:  result.AlarmsSkipped,
			Errors:         result.Errors,
		}
		if input.Email != "" {
			output.EmailSubscribed = input.Email
		}
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Fprintln(stdout, string(jsonBytes))
	} else {
		// Human-readable output
		fmt.Fprintln(stdout, "Creating SNS topic...")
		fmt.Fprintf(stdout, "v SNS topic created: %s\n", result.SNSTopicARN)
		fmt.Fprintln(stdout)

		fmt.Fprintln(stdout, "Creating metric filters...")
		for _, name := range result.FiltersCreated {
			fmt.Fprintf(stdout, "v %s filter created\n", name)
		}
		fmt.Fprintln(stdout)

		fmt.Fprintln(stdout, "Creating CloudWatch alarms...")
		for _, name := range result.AlarmsCreated {
			fmt.Fprintf(stdout, "v %s alarm created\n", name)
		}
		fmt.Fprintln(stdout)

		if input.Email != "" {
			fmt.Fprintf(stdout, "Email subscription requested: %s\n", input.Email)
			fmt.Fprintln(stdout, "Note: Check inbox and confirm subscription to receive alerts.")
			fmt.Fprintln(stdout)
		}

		if len(result.Errors) > 0 {
			fmt.Fprintln(stdout, "Warnings:")
			for _, e := range result.Errors {
				fmt.Fprintf(stdout, "  ! %s\n", e)
			}
			fmt.Fprintln(stdout)
		}

		fmt.Fprintf(stdout, "Summary: %d alarms created, notifications to %s\n", len(result.AlarmsCreated), input.SNSTopicName)
	}

	// Return 0 on success (even with partial errors, as long as SNS topic was created)
	return 0
}
