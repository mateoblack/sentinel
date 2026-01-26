package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/alecthomas/kingpin/v2"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
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
