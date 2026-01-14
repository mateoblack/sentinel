package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/iso8601"
	"github.com/byteness/aws-vault/v7/policy"
)

// CredentialsCommandInput contains the input for the credentials command.
type CredentialsCommandInput struct {
	ProfileName     string
	PolicyParameter string // SSM parameter path, e.g., /sentinel/policies/default
	Region          string
	NoSession       bool
	SessionDuration time.Duration
}

// CredentialProcessOutput represents the JSON output format for AWS credential_process.
// See https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
type CredentialProcessOutput struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

// ConfigureCredentialsCommand sets up the credentials command with kingpin.
func ConfigureCredentialsCommand(app *kingpin.Application, s *Sentinel) {
	input := CredentialsCommandInput{}

	cmd := app.Command("credentials", "Retrieve AWS credentials after policy evaluation")

	cmd.Flag("profile", "Name of the AWS profile").
		Required().
		StringVar(&input.ProfileName)

	cmd.Flag("policy-parameter", "SSM parameter path containing the policy (e.g., /sentinel/policies/default)").
		Required().
		StringVar(&input.PolicyParameter)

	cmd.Flag("region", "The AWS region").
		StringVar(&input.Region)

	cmd.Flag("no-session", "Skip creating STS session with GetSessionToken").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Flag("duration", "Duration of the temporary or assume-role session. Defaults to 1h").
		Short('d').
		DurationVar(&input.SessionDuration)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := CredentialsCommand(context.Background(), input, s)
		app.FatalIfError(err, "credentials")
		return nil
	})
}

// CredentialsCommand executes the credentials command logic.
// It evaluates policy before retrieving credentials.
// On success, outputs JSON to stdout. On failure, outputs error to stderr and returns non-zero.
func CredentialsCommand(ctx context.Context, input CredentialsCommandInput, s *Sentinel) error {
	// 1. Get current user
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current user: %v\n", err)
		return err
	}
	username := currentUser.Username

	// 2. Create AWS config for SSM
	awsCfgOpts := []func(*config.LoadOptions) error{}
	if input.Region != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load AWS config: %v\n", err)
		return err
	}

	// 3. Create policy loader chain
	loader := policy.NewLoader(awsCfg)
	cachedLoader := policy.NewCachedLoader(loader, 5*time.Minute)

	// 4. Load policy
	loadedPolicy, err := cachedLoader.Load(ctx, input.PolicyParameter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		return err
	}

	// 5. Build policy.Request
	policyRequest := &policy.Request{
		User:    username,
		Profile: input.ProfileName,
		Time:    time.Now(),
	}

	// 6. Evaluate policy
	decision := policy.Evaluate(loadedPolicy, policyRequest)

	// 7. Handle decision
	if decision.Effect == policy.EffectDeny {
		fmt.Fprintf(os.Stderr, "Access denied: %s\n", decision.String())
		return fmt.Errorf("access denied")
	}

	// EffectAllow: proceed to credential retrieval
	// Create credential request
	credReq := SentinelCredentialRequest{
		ProfileName:     input.ProfileName,
		Region:          input.Region,
		NoSession:       input.NoSession,
		SessionDuration: input.SessionDuration,
	}

	// Retrieve credentials
	creds, err := s.GetCredentials(ctx, credReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to retrieve credentials: %v\n", err)
		return err
	}

	// Build credential_process output
	output := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
	}

	// Only include Expiration if credentials can expire
	if creds.CanExpire {
		output.Expiration = iso8601.Format(creds.Expiration)
	}

	// Marshal to JSON with indentation (matches cli/export.go pattern)
	jsonBytes, err := json.MarshalIndent(&output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal credentials to JSON: %v\n", err)
		return err
	}

	// Output to stdout
	fmt.Println(string(jsonBytes))

	return nil
}
