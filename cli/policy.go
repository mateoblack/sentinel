package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/byteness/aws-vault/v7/bootstrap"
	"github.com/byteness/aws-vault/v7/policy"
)

// PolicyPullCommandInput contains the input for policy pull.
type PolicyPullCommandInput struct {
	Profile         string // Positional arg - the AWS profile name to pull policy for
	PolicyRoot      string // --policy-root flag, default bootstrap.DefaultPolicyRoot
	PolicyParameter string // --policy-parameter flag, explicit SSM path override
	OutputFile      string // --output / -o flag, empty = stdout
	Region          string // --region flag for SSM operations
	AWSProfile      string // --aws-profile flag for credentials

	// For testing
	Stdout    *os.File
	Stderr    *os.File
	SSMClient policy.SSMAPI // For testing, nil = create from AWS config
}

// PolicyPushCommandInput contains the input for policy push.
type PolicyPushCommandInput struct {
	Profile         string // Positional arg - target profile
	InputFile       string // Positional arg - path to policy YAML file
	PolicyRoot      string // --policy-root flag, default bootstrap.DefaultPolicyRoot
	PolicyParameter string // --policy-parameter flag, explicit SSM path override
	Region          string // --region flag for SSM operations
	AWSProfile      string // --aws-profile flag for credentials
	NoBackup        bool   // --no-backup flag, skip fetching existing policy as backup
	Force           bool   // --force flag, skip confirmation prompt

	// For testing
	Stdin     io.Reader     // For testing confirmation input
	Stdout    *os.File      // Not used currently, but for consistency
	Stderr    *os.File      // For output messages
	SSMClient policy.SSMAPI // For testing, nil = create from AWS config
}

// policyCmd holds the policy command reference for subcommand registration.
var policyCmd *kingpin.CmdClause

// ConfigurePolicyCommand sets up the policy command with its subcommands.
func ConfigurePolicyCommand(app *kingpin.Application, s *Sentinel) {
	policyCmd = app.Command("policy", "Policy management commands")

	input := PolicyPullCommandInput{}

	cmd := policyCmd.Command("pull", "Pull policy from SSM Parameter Store")

	cmd.Arg("profile", "AWS profile name to pull policy for").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("policy-root", "SSM parameter path prefix for policies").
		Default(bootstrap.DefaultPolicyRoot).
		StringVar(&input.PolicyRoot)

	cmd.Flag("policy-parameter", "Explicit SSM parameter path (overrides profile-based path)").
		StringVar(&input.PolicyParameter)

	cmd.Flag("output", "Output file path (omit for stdout)").
		Short('o').
		StringVar(&input.OutputFile)

	cmd.Flag("region", "AWS region for SSM operations").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for SSM credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := PolicyPullCommand(context.Background(), input)
		if err != nil {
			app.FatalIfError(err, "policy pull")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})

	// Configure push subcommand
	pushInput := PolicyPushCommandInput{}

	pushCmd := policyCmd.Command("push", "Push policy to SSM Parameter Store")

	pushCmd.Arg("profile", "Target profile name for the policy").
		Required().
		StringVar(&pushInput.Profile)

	pushCmd.Arg("input-file", "Path to policy YAML file").
		Required().
		StringVar(&pushInput.InputFile)

	pushCmd.Flag("policy-root", "SSM parameter path prefix for policies").
		Default(bootstrap.DefaultPolicyRoot).
		StringVar(&pushInput.PolicyRoot)

	pushCmd.Flag("policy-parameter", "Explicit SSM parameter path (overrides profile-based path)").
		StringVar(&pushInput.PolicyParameter)

	pushCmd.Flag("region", "AWS region for SSM operations").
		StringVar(&pushInput.Region)

	pushCmd.Flag("aws-profile", "AWS profile for SSM credentials (optional, uses default chain if not specified)").
		StringVar(&pushInput.AWSProfile)

	pushCmd.Flag("no-backup", "Skip fetching existing policy as backup").
		BoolVar(&pushInput.NoBackup)

	pushCmd.Flag("force", "Skip confirmation prompt").
		Short('f').
		BoolVar(&pushInput.Force)

	pushCmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := PolicyPushCommand(context.Background(), pushInput)
		if err != nil {
			app.FatalIfError(err, "policy push")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// PolicyPullCommand executes the policy pull command logic.
// It returns exit code (0=success, 1=error) and any fatal error.
func PolicyPullCommand(ctx context.Context, input PolicyPullCommandInput) (int, error) {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Determine SSM parameter path
	parameterPath := input.PolicyParameter
	if parameterPath == "" {
		parameterPath = bootstrap.DefaultPolicyParameterName(input.PolicyRoot, input.Profile)
	}

	// Create policy loader
	var loader *policy.Loader
	if input.SSMClient != nil {
		// Use injected client for testing
		loader = policy.NewLoaderWithClient(input.SSMClient)
	} else {
		// Load AWS config
		var opts []func(*awsconfig.LoadOptions) error
		if input.AWSProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(input.AWSProfile))
		}
		if input.Region != "" {
			opts = append(opts, awsconfig.WithRegion(input.Region))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to load AWS config: %v\n", err)
			fmt.Fprintf(stderr, "\nSuggestion: check AWS credentials and region configuration\n")
			return 1, nil
		}
		loader = policy.NewLoader(awsCfg)
	}

	// Load policy from SSM
	pol, err := loader.Load(ctx, parameterPath)
	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			fmt.Fprintf(stderr, "Error: policy not found at %s\n", parameterPath)
			fmt.Fprintf(stderr, "\nSuggestion: verify the SSM parameter exists and you have ssm:GetParameter permission\n")
			fmt.Fprintf(stderr, "You can create a policy using: sentinel bootstrap plan --policy-root %s\n", input.PolicyRoot)
			return 1, nil
		}
		fmt.Fprintf(stderr, "Error: failed to load policy: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: verify AWS credentials and SSM permissions\n")
		return 1, nil
	}

	// Marshal policy to YAML
	yamlData, err := policy.MarshalPolicy(pol)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to marshal policy: %v\n", err)
		return 1, nil
	}

	// Output policy
	if input.OutputFile != "" {
		// Write to file
		if err := os.WriteFile(input.OutputFile, yamlData, 0644); err != nil {
			fmt.Fprintf(stderr, "Error: failed to write file: %v\n", err)
			return 1, nil
		}
		fmt.Fprintf(stderr, "Policy written to %s\n", input.OutputFile)
	} else {
		// Write to stdout (clean, no prefix)
		fmt.Fprint(stdout, string(yamlData))
	}

	return 0, nil
}

// PolicyPushCommand executes the policy push command logic.
// It validates the policy, optionally fetches backup, prompts for confirmation,
// and uploads to SSM Parameter Store.
// Returns exit code (0=success, 1=error) and any fatal error.
func PolicyPushCommand(ctx context.Context, input PolicyPushCommandInput) (int, error) {
	// Set up I/O
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	stdin := input.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}

	// Read policy file from disk
	policyData, err := os.ReadFile(input.InputFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "Error: file not found: %s\n", input.InputFile)
			fmt.Fprintf(stderr, "\nSuggestion: verify the file path is correct\n")
			return 1, nil
		}
		fmt.Fprintf(stderr, "Error: failed to read file: %v\n", err)
		return 1, nil
	}

	// Validate policy using policy.ValidatePolicy(data)
	if err := policy.ValidatePolicy(policyData); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: fix the policy YAML and try again\n")
		return 1, nil
	}

	// Determine SSM parameter path
	parameterPath := input.PolicyParameter
	if parameterPath == "" {
		parameterPath = bootstrap.DefaultPolicyParameterName(input.PolicyRoot, input.Profile)
	}

	// Create SSM client
	var ssmClient policy.SSMAPI
	if input.SSMClient != nil {
		ssmClient = input.SSMClient
	} else {
		var opts []func(*awsconfig.LoadOptions) error
		if input.AWSProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(input.AWSProfile))
		}
		if input.Region != "" {
			opts = append(opts, awsconfig.WithRegion(input.Region))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to load AWS config: %v\n", err)
			fmt.Fprintf(stderr, "\nSuggestion: check AWS credentials and region configuration\n")
			return 1, nil
		}
		ssmClient = ssm.NewFromConfig(awsCfg)
	}

	// Fetch existing policy as backup (unless --no-backup)
	backupExists := false
	if !input.NoBackup {
		output, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(parameterPath),
			WithDecryption: aws.Bool(true),
		})
		if err != nil {
			var notFound *types.ParameterNotFound
			if !errors.As(err, &notFound) {
				// Real error, not just "not found"
				fmt.Fprintf(stderr, "Warning: failed to fetch existing policy for backup: %v\n", err)
			}
			// Not found is fine - this is a new parameter
		} else {
			backupExists = true
			fmt.Fprintf(stderr, "Existing policy found (version %d)\n", output.Parameter.Version)
		}
	}

	// Confirmation prompt (unless --force)
	if !input.Force {
		fmt.Fprintf(stderr, "\n")
		fmt.Fprintf(stderr, "Parameter path: %s\n", parameterPath)
		if backupExists {
			fmt.Fprintf(stderr, "Status: updating existing policy\n")
		} else {
			fmt.Fprintf(stderr, "Status: creating new policy\n")
		}
		fmt.Fprintf(stderr, "\n")
		fmt.Fprintf(stderr, "Proceed? [y/N]: ")

		reader := bufio.NewReader(stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(stderr, "\nError: failed to read input: %v\n", err)
			return 1, nil
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Fprintf(stderr, "Cancelled.\n")
			return 0, nil
		}
	}

	// Call PutParameter with Overwrite=true
	_, err = ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(parameterPath),
		Value:     aws.String(string(policyData)),
		Type:      types.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to write policy to SSM: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: verify AWS credentials and ssm:PutParameter permission\n")
		return 1, nil
	}

	fmt.Fprintf(stderr, "Policy successfully pushed to %s\n", parameterPath)
	return 0, nil
}
