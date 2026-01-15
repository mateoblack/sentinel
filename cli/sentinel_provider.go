package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/byteness/aws-vault/v7/sentinel"
	"github.com/byteness/aws-vault/v7/vault"
)

// SentinelCredentialRequest contains the input for credential retrieval.
type SentinelCredentialRequest struct {
	ProfileName     string
	NoSession       bool // Skip STS session creation
	SessionDuration time.Duration
	Region          string
	User            string // Username for SourceIdentity (required for two-hop flow)
}

// SentinelCredentialResult contains retrieved credentials.
type SentinelCredentialResult struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	CanExpire       bool
}

// GetCredentials retrieves AWS credentials for a profile using aws-vault's provider chain.
// This is the integration point where Sentinel will later inject policy evaluation.
func (s *Sentinel) GetCredentials(ctx context.Context, req SentinelCredentialRequest) (*SentinelCredentialResult, error) {
	// Get config file
	configFile, err := s.AwsConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Get keyring
	keyringImpl, err := s.Keyring()
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	// Create profile config with Region and session duration
	profileConfig := vault.ProfileConfig{
		Region: req.Region,
	}
	if req.SessionDuration > 0 {
		profileConfig.NonChainedGetSessionTokenDuration = req.SessionDuration
		profileConfig.AssumeRoleDuration = req.SessionDuration
	}

	// Load profile configuration using vault.NewConfigLoader
	config, err := vault.NewConfigLoader(profileConfig, configFile, req.ProfileName).GetProfileConfig(req.ProfileName)
	if err != nil {
		return nil, fmt.Errorf("failed to load profile config for %s: %w", req.ProfileName, err)
	}

	// Create credential provider using vault.NewTempCredentialsProvider
	// This follows the pattern from cli/exec.go lines 183-191
	credsProvider, err := vault.NewTempCredentialsProvider(config, &vault.CredentialKeyring{Keyring: keyringImpl}, req.NoSession, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials provider: %w", err)
	}

	// Retrieve credentials
	creds, err := credsProvider.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials for %s: %w", req.ProfileName, err)
	}

	// Map aws.Credentials to SentinelCredentialResult
	result := &SentinelCredentialResult{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		CanExpire:       creds.CanExpire,
	}

	if creds.CanExpire {
		result.Expiration = creds.Expires
	}

	return result, nil
}

// GetCredentialsWithSourceIdentity retrieves AWS credentials with SourceIdentity stamping.
// For profiles with role_arn, it uses the two-hop pattern:
// 1. Get base credentials (without AssumeRole)
// 2. Use TwoHopCredentialProvider to AssumeRole with SourceIdentity stamp
//
// For profiles without role_arn, it falls back to GetCredentials (no SourceIdentity possible).
func (s *Sentinel) GetCredentialsWithSourceIdentity(ctx context.Context, req SentinelCredentialRequest) (*SentinelCredentialResult, error) {
	// Get config file
	configFile, err := s.AwsConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Get keyring
	keyringImpl, err := s.Keyring()
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	// Create profile config with Region and session duration
	profileConfig := vault.ProfileConfig{
		Region: req.Region,
	}
	if req.SessionDuration > 0 {
		profileConfig.NonChainedGetSessionTokenDuration = req.SessionDuration
		profileConfig.AssumeRoleDuration = req.SessionDuration
	}

	// Load profile configuration using vault.NewConfigLoader
	config, err := vault.NewConfigLoader(profileConfig, configFile, req.ProfileName).GetProfileConfig(req.ProfileName)
	if err != nil {
		return nil, fmt.Errorf("failed to load profile config for %s: %w", req.ProfileName, err)
	}

	// Check if profile has RoleARN - determines whether to use two-hop pattern
	if config.RoleARN == "" {
		// No role assumption needed - use standard credential retrieval
		// SourceIdentity cannot be stamped without AssumeRole
		return s.GetCredentials(ctx, req)
	}

	// Profile has RoleARN - use two-hop pattern for SourceIdentity stamping
	// Step 1: Create base credentials provider WITHOUT the role assumption
	baseConfig := *config
	baseConfig.RoleARN = "" // Remove role_arn so we get base credentials only

	baseProvider, err := vault.NewTempCredentialsProvider(&baseConfig, &vault.CredentialKeyring{Keyring: keyringImpl}, req.NoSession, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create base credentials provider: %w", err)
	}

	// Step 2: Determine session duration
	sessionDuration := req.SessionDuration
	if sessionDuration == 0 {
		sessionDuration = config.AssumeRoleDuration
	}

	// Step 3: Create TwoHopCredentialProvider for role assumption with SourceIdentity
	twoHopInput := sentinel.TwoHopCredentialProviderInput{
		BaseCredsProvider:    baseProvider,
		RoleARN:              config.RoleARN,
		User:                 req.User,
		Region:               config.Region,
		STSRegionalEndpoints: config.STSRegionalEndpoints,
		EndpointURL:          config.EndpointURL,
		ExternalID:           config.ExternalID,
		SessionDuration:      sessionDuration,
	}

	twoHopProvider, err := sentinel.NewTwoHopCredentialProvider(twoHopInput)
	if err != nil {
		return nil, fmt.Errorf("failed to create two-hop provider: %w", err)
	}

	// Step 4: Retrieve credentials with SourceIdentity stamp
	creds, err := twoHopProvider.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials with SourceIdentity for %s: %w", req.ProfileName, err)
	}

	// Map aws.Credentials to SentinelCredentialResult
	result := &SentinelCredentialResult{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		CanExpire:       creds.CanExpire,
	}

	if creds.CanExpire {
		result.Expiration = creds.Expires
	}

	return result, nil
}
