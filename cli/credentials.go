package cli

import (
	"context"
	"fmt"
	"os/user"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
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
func CredentialsCommand(ctx context.Context, input CredentialsCommandInput, s *Sentinel) error {
	// 1. Get current user
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}
	username := currentUser.Username

	// 2. Create AWS config for SSM
	awsCfgOpts := []func(*config.LoadOptions) error{}
	if input.Region != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// 3. Create policy loader chain
	loader := policy.NewLoader(awsCfg)
	cachedLoader := policy.NewCachedLoader(loader, 5*time.Minute)

	// 4. Load policy
	loadedPolicy, err := cachedLoader.Load(ctx, input.PolicyParameter)
	if err != nil {
		return fmt.Errorf("failed to load policy from %s: %w", input.PolicyParameter, err)
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
		return fmt.Errorf("access denied: %s", decision.String())
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
	_, err = s.GetCredentials(ctx, credReq)
	if err != nil {
		return fmt.Errorf("failed to retrieve credentials: %w", err)
	}

	// Placeholder output - JSON format will be implemented in 05-02
	fmt.Printf("Credentials retrieved for %s\n", input.ProfileName)

	return nil
}
