package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/identity"
)

// WhoamiCommandInput contains the input for the whoami command.
type WhoamiCommandInput struct {
	Region     string
	Profile    string
	JSONOutput bool

	// STSClient is an optional STS client for testing.
	// If nil, a new client will be created from AWS config.
	STSClient identity.STSAPI

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File

	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File
}

// WhoamiResult represents the JSON output format for the whoami command.
type WhoamiResult struct {
	ARN            string `json:"arn"`
	AccountID      string `json:"account_id"`
	IdentityType   string `json:"identity_type"`
	RawUsername    string `json:"raw_username"`
	PolicyUsername string `json:"policy_username"`
}

// ConfigureWhoamiCommand sets up the whoami command as a top-level command.
func ConfigureWhoamiCommand(app *kingpin.Application, s *Sentinel) {
	input := WhoamiCommandInput{}

	cmd := app.Command("whoami", "Show current AWS identity and policy username")

	cmd.Flag("region", "AWS region for STS operations").
		StringVar(&input.Region)

	cmd.Flag("profile", "AWS profile for credentials (uses SSO credential provider if profile is SSO-configured)").
		StringVar(&input.Profile)

	cmd.Flag("json", "Output in JSON format").
		BoolVar(&input.JSONOutput)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := WhoamiCommand(context.Background(), input)
		app.FatalIfError(err, "whoami")
		return nil
	})
}

// WhoamiCommand executes the whoami command logic.
// It queries STS for the caller identity and displays the AWS identity information
// including the policy username used for Sentinel policy evaluation.
// On success, outputs identity to stdout. On failure, outputs error to stderr and returns error.
func WhoamiCommand(ctx context.Context, input WhoamiCommandInput) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Get or create STS client
	stsClient := input.STSClient
	if stsClient == nil {
		// Load AWS config
		awsCfgOpts := []func(*config.LoadOptions) error{}
		if input.Profile != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(input.Profile))
		}
		if input.Region != "" {
			awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
		if err != nil {
			FormatErrorWithSuggestionTo(stderr, err)
			return err
		}
		stsClient = sts.NewFromConfig(awsCfg)
	}

	// Get AWS identity
	awsIdentity, err := identity.GetAWSIdentity(ctx, stsClient)
	if err != nil {
		FormatErrorWithSuggestionTo(stderr, err)
		return err
	}

	// Build result
	result := WhoamiResult{
		ARN:            awsIdentity.ARN,
		AccountID:      awsIdentity.AccountID,
		IdentityType:   string(awsIdentity.Type),
		RawUsername:    awsIdentity.RawUsername,
		PolicyUsername: awsIdentity.Username,
	}

	// Output results
	if input.JSONOutput {
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "Failed to format identity as JSON: %v\n", err)
			return err
		}
		fmt.Fprintln(stdout, string(jsonBytes))
	} else {
		fmt.Fprintln(stdout, "AWS Identity")
		fmt.Fprintln(stdout, "============")
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "ARN:             %s\n", result.ARN)
		fmt.Fprintf(stdout, "Account:         %s\n", result.AccountID)
		fmt.Fprintf(stdout, "Identity Type:   %s\n", result.IdentityType)
		fmt.Fprintf(stdout, "Raw Username:    %s\n", result.RawUsername)
		fmt.Fprintf(stdout, "Policy Username: %s\n", result.PolicyUsername)
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "The policy username is used for matching against Sentinel policy rules.")
	}

	return nil
}
