package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/enforce"
)

// EnforceGenerateTrustPolicyCommandInput contains the input for the enforce generate trust-policy command.
type EnforceGenerateTrustPolicyCommandInput struct {
	// Pattern is the trust policy pattern (any-sentinel, specific-users, migration).
	Pattern string
	// PrincipalARN is the AWS principal ARN.
	PrincipalARN string
	// Users is the list of usernames for specific-users pattern.
	Users []string
	// LegacyPrincipal is the legacy principal ARN for migration pattern.
	LegacyPrincipal string

	// Stdout is an optional writer for output (for testing).
	// If nil, os.Stdout will be used.
	Stdout *os.File
	// Stderr is an optional writer for errors (for testing).
	// If nil, os.Stderr will be used.
	Stderr *os.File
}

// ConfigureEnforceGenerateTrustPolicyCommand sets up the enforce generate trust-policy command.
// It adds a "generate" subcommand group under "enforce" and then "trust-policy" under "generate".
func ConfigureEnforceGenerateTrustPolicyCommand(app *kingpin.Application, s *Sentinel) {
	input := EnforceGenerateTrustPolicyCommandInput{}

	// Get or create the enforce command (might already exist from enforce plan)
	enforceCmd := app.GetCommand("enforce")
	if enforceCmd == nil {
		enforceCmd = app.Command("enforce", "Enforcement status and guidance")
	}

	// Create generate subcommand under enforce
	generateCmd := enforceCmd.Command("generate", "Generate enforcement artifacts")

	// Create trust-policy subcommand under generate
	cmd := generateCmd.Command("trust-policy", "Generate IAM trust policy JSON with Sentinel conditions")

	cmd.Flag("pattern", "Trust policy pattern: any-sentinel, specific-users, or migration").
		Required().
		EnumVar(&input.Pattern, "any-sentinel", "specific-users", "migration")

	cmd.Flag("principal", "AWS principal ARN (e.g., arn:aws:iam::123456789012:root)").
		Required().
		StringVar(&input.PrincipalARN)

	cmd.Flag("users", "Username for specific-users pattern (repeatable)").
		StringsVar(&input.Users)

	cmd.Flag("legacy-principal", "Legacy principal ARN for migration pattern").
		StringVar(&input.LegacyPrincipal)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := EnforceGenerateTrustPolicyCommand(context.Background(), input)
		app.FatalIfError(err, "enforce generate trust-policy")
		return nil
	})
}

// EnforceGenerateTrustPolicyCommand executes the enforce generate trust-policy command logic.
// It generates trust policy JSON based on the specified pattern and outputs to stdout.
func EnforceGenerateTrustPolicyCommand(ctx context.Context, input EnforceGenerateTrustPolicyCommandInput) error {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Validate pattern
	pattern := enforce.TrustPolicyPattern(input.Pattern)
	if !pattern.IsValid() {
		fmt.Fprintf(stderr, "Error: invalid pattern: %s\n", input.Pattern)
		return fmt.Errorf("invalid pattern: %s (must be one of: any-sentinel, specific-users, migration)", input.Pattern)
	}

	// Validate principal ARN
	if input.PrincipalARN == "" {
		fmt.Fprintln(stderr, "Error: --principal is required")
		return fmt.Errorf("--principal is required")
	}

	// Pattern-specific validation
	switch pattern {
	case enforce.PatternB:
		if len(input.Users) == 0 {
			fmt.Fprintln(stderr, "Error: --users is required for specific-users pattern")
			return fmt.Errorf("--users is required for specific-users pattern")
		}
	case enforce.PatternC:
		if input.LegacyPrincipal == "" {
			fmt.Fprintln(stderr, "Error: --legacy-principal is required for migration pattern")
			return fmt.Errorf("--legacy-principal is required for migration pattern")
		}
	}

	// Generate the trust policy
	genInput := enforce.GenerateInput{
		Pattern:         pattern,
		PrincipalARN:    input.PrincipalARN,
		Users:           input.Users,
		LegacyPrincipal: input.LegacyPrincipal,
	}

	output, err := enforce.GenerateTrustPolicy(genInput)
	if err != nil {
		fmt.Fprintf(stderr, "Error generating trust policy: %v\n", err)
		return err
	}

	// Output JSON with indentation
	jsonBytes, err := json.MarshalIndent(output.Policy, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "Error formatting JSON: %v\n", err)
		return err
	}

	fmt.Fprintln(stdout, string(jsonBytes))
	return nil
}
