package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/byteness/aws-vault/v7/policy"
)

// PolicySignCommandInput contains the input for policy sign.
type PolicySignCommandInput struct {
	PolicyFile string // Positional arg - path to policy YAML file
	KeyID      string // --key-id flag - KMS key ARN or alias
	OutputFile string // --output / -o flag - output file for signature (default: stdout)
	Region     string // --region flag for KMS operations
	AWSProfile string // --aws-profile flag for credentials

	// For testing
	Stdout    io.Writer     // For signature output
	Stderr    io.Writer     // For messages
	KMSClient policy.KMSAPI // For testing, nil = create from AWS config
}

// PolicyVerifyCommandInput contains the input for policy verify.
type PolicyVerifyCommandInput struct {
	PolicyFile    string // Positional arg - path to policy YAML file
	KeyID         string // --key-id flag - KMS key for verification
	SignatureFile string // --signature / -s flag - signature file (JSON format)
	Region        string // --region flag for KMS operations
	AWSProfile    string // --aws-profile flag for credentials

	// For testing
	Stdout    io.Writer     // For output
	Stderr    io.Writer     // For messages
	KMSClient policy.KMSAPI // For testing, nil = create from AWS config
}

// SignatureOutput is the JSON format for signature files.
type SignatureOutput struct {
	Signature string                   `json:"signature"` // Base64-encoded signature
	Metadata  policy.SignatureMetadata `json:"metadata"`
}

// ConfigurePolicySign sets up the policy sign subcommand.
func ConfigurePolicySign(app *kingpin.Application, s *Sentinel) {
	input := PolicySignCommandInput{}

	cmd := policyCmd.Command("sign", "Sign a policy file with KMS")

	cmd.Arg("policy-file", "Path to policy YAML file to sign").
		Required().
		StringVar(&input.PolicyFile)

	cmd.Flag("key-id", "KMS key ARN or alias for signing").
		Required().
		StringVar(&input.KeyID)

	cmd.Flag("output", "Output file for signature (omit for stdout)").
		Short('o').
		StringVar(&input.OutputFile)

	cmd.Flag("region", "AWS region for KMS operations").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for KMS credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := PolicySignCommand(context.Background(), input)
		if err != nil {
			app.FatalIfError(err, "policy sign")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// ConfigurePolicyVerify sets up the policy verify subcommand.
func ConfigurePolicyVerify(app *kingpin.Application, s *Sentinel) {
	input := PolicyVerifyCommandInput{}

	cmd := policyCmd.Command("verify", "Verify a policy signature locally")

	cmd.Arg("policy-file", "Path to policy YAML file to verify").
		Required().
		StringVar(&input.PolicyFile)

	cmd.Flag("key-id", "KMS key ARN or alias for verification").
		Required().
		StringVar(&input.KeyID)

	cmd.Flag("signature", "Signature file (JSON format from sign command)").
		Short('s').
		Required().
		StringVar(&input.SignatureFile)

	cmd.Flag("region", "AWS region for KMS operations").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for KMS credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := PolicyVerifyCommand(context.Background(), input)
		if err != nil {
			app.FatalIfError(err, "policy verify")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// PolicySignCommand executes the policy sign command logic.
// Returns exit code (0=success, 1=error) and any fatal error.
func PolicySignCommand(ctx context.Context, input PolicySignCommandInput) (int, error) {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Read policy file from disk
	policyData, err := os.ReadFile(input.PolicyFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "Error: file not found: %s\n", input.PolicyFile)
			fmt.Fprintf(stderr, "\nSuggestion: verify the file path is correct\n")
			return 1, nil
		}
		fmt.Fprintf(stderr, "Error: failed to read file: %v\n", err)
		return 1, nil
	}

	// Validate policy parses correctly (fail early on invalid YAML)
	if err := policy.ValidatePolicy(policyData); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: fix the policy YAML and try again\n")
		return 1, nil
	}

	// Create KMS client
	var kmsClient policy.KMSAPI
	if input.KMSClient != nil {
		kmsClient = input.KMSClient
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
		kmsClient = kms.NewFromConfig(awsCfg)
	}

	// Create PolicySigner and sign
	signer := policy.NewPolicySignerWithClient(kmsClient, input.KeyID)
	signature, err := signer.Sign(ctx, policyData)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to sign policy: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: verify KMS key ID and permissions\n")
		return 1, nil
	}

	// Create signature metadata
	metadata := policy.SignatureMetadata{
		KeyID:      input.KeyID,
		Algorithm:  string(policy.DefaultSigningAlgorithm),
		SignedAt:   time.Now().UTC(),
		PolicyHash: policy.ComputePolicyHash(policyData),
	}

	// Create output JSON
	output := SignatureOutput{
		Signature: base64.StdEncoding.EncodeToString(signature),
		Metadata:  metadata,
	}

	outputJSON, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to marshal signature: %v\n", err)
		return 1, nil
	}

	// Write to output
	if input.OutputFile != "" {
		// Use SensitiveFileMode (0600) for signature output - security artifact (SEC-03)
		if err := os.WriteFile(input.OutputFile, outputJSON, SensitiveFileMode); err != nil {
			fmt.Fprintf(stderr, "Error: failed to write signature file: %v\n", err)
			return 1, nil
		}
		fmt.Fprintf(stderr, "Signature written to %s\n", input.OutputFile)
	} else {
		fmt.Fprintln(stdout, string(outputJSON))
	}

	return 0, nil
}

// PolicyVerifyCommand executes the policy verify command logic.
// Returns exit code 0 if valid, 1 if invalid (for scripting).
func PolicyVerifyCommand(ctx context.Context, input PolicyVerifyCommandInput) (int, error) {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Read policy file from disk
	policyData, err := os.ReadFile(input.PolicyFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "Error: policy file not found: %s\n", input.PolicyFile)
			fmt.Fprintf(stderr, "\nSuggestion: verify the file path is correct\n")
			return 1, nil
		}
		fmt.Fprintf(stderr, "Error: failed to read policy file: %v\n", err)
		return 1, nil
	}

	// Read signature file from disk
	sigData, err := os.ReadFile(input.SignatureFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "Error: signature file not found: %s\n", input.SignatureFile)
			fmt.Fprintf(stderr, "\nSuggestion: verify the signature file path is correct\n")
			return 1, nil
		}
		fmt.Fprintf(stderr, "Error: failed to read signature file: %v\n", err)
		return 1, nil
	}

	// Parse signature JSON
	var sigOutput SignatureOutput
	if err := json.Unmarshal(sigData, &sigOutput); err != nil {
		fmt.Fprintf(stderr, "Error: failed to parse signature file: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: verify the signature file is valid JSON from 'policy sign'\n")
		return 1, nil
	}

	// Validate policy hash matches metadata
	computedHash := policy.ComputePolicyHash(policyData)
	if sigOutput.Metadata.PolicyHash != "" && sigOutput.Metadata.PolicyHash != computedHash {
		fmt.Fprintf(stderr, "Signature invalid: policy content does not match signature\n")
		fmt.Fprintf(stderr, "  Expected hash: %s\n", sigOutput.Metadata.PolicyHash)
		fmt.Fprintf(stderr, "  Computed hash: %s\n", computedHash)
		return 1, nil
	}

	// Decode base64 signature
	signature, err := base64.StdEncoding.DecodeString(sigOutput.Signature)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to decode signature: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: verify the signature file is not corrupted\n")
		return 1, nil
	}

	// Create KMS client
	var kmsClient policy.KMSAPI
	if input.KMSClient != nil {
		kmsClient = input.KMSClient
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
		kmsClient = kms.NewFromConfig(awsCfg)
	}

	// Create PolicySigner and verify
	signer := policy.NewPolicySignerWithClient(kmsClient, input.KeyID)
	valid, err := signer.Verify(ctx, policyData, signature)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to verify signature: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: verify KMS key ID and permissions\n")
		return 1, nil
	}

	if !valid {
		fmt.Fprintln(stdout, "Signature invalid")
		return 1, nil
	}

	fmt.Fprintln(stdout, "Signature valid")
	return 0, nil
}
