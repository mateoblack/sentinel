// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/mdm"
	"github.com/byteness/aws-vault/v7/mfa"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/ratelimit"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/session"
)

// Environment variable names for TVM configuration.
const (
	EnvPolicyParameter = "SENTINEL_POLICY_PARAMETER"
	EnvPolicyRoot      = "SENTINEL_POLICY_ROOT"
	EnvApprovalTable   = "SENTINEL_APPROVAL_TABLE"
	EnvBreakGlassTable = "SENTINEL_BREAKGLASS_TABLE"
	EnvSessionTable    = "SENTINEL_SESSION_TABLE"
	EnvRegion          = "AWS_REGION"

	// MDM configuration environment variables.
	EnvMDMProvider    = "SENTINEL_MDM_PROVIDER"      // "jamf", "intune", "kandji", "none"
	EnvMDMBaseURL     = "SENTINEL_MDM_BASE_URL"      // MDM server URL (e.g., Jamf Pro URL)
	EnvMDMAPISecretID = "SENTINEL_MDM_API_SECRET_ID" // Secrets Manager secret ID/ARN (preferred)
	EnvMDMAPIToken    = "SENTINEL_MDM_API_TOKEN"     // Bearer token (deprecated - use Secrets Manager)
	EnvRequireDevice  = "SENTINEL_REQUIRE_DEVICE"    // "true" to require device verification

	// Rate limiting configuration environment variables.
	EnvRateLimitRequests = "SENTINEL_RATE_LIMIT_REQUESTS" // Max requests per window (default: 100, 0 to disable)
	EnvRateLimitWindow   = "SENTINEL_RATE_LIMIT_WINDOW"   // Window duration in seconds (default: 60)

	// Policy signing configuration environment variables.
	EnvPolicySigningKey     = "SENTINEL_POLICY_SIGNING_KEY"     // KMS key ARN for verifying policy signatures
	EnvEnforcePolicySigning = "SENTINEL_ENFORCE_POLICY_SIGNING" // "true" to reject unsigned policies (default: true if signing key set)

	// MFA configuration environment variables.
	// TOTP secrets and SMS phones are stored in SSM as JSON.
	EnvMFATOTPSecretsParam = "SENTINEL_MFA_TOTP_SECRETS_PARAM" // SSM parameter path for TOTP secrets JSON
	EnvMFASMSPhonesParam   = "SENTINEL_MFA_SMS_PHONES_PARAM"   // SSM parameter path for SMS phone numbers JSON

	// Log signing and CloudWatch forwarding configuration environment variables.
	EnvLogSigningKey    = "SENTINEL_LOG_SIGNING_KEY"      // Hex-encoded HMAC key (64 chars for 32 bytes)
	EnvLogSigningKeyID  = "SENTINEL_LOG_SIGNING_KEY_ID"   // Key identifier for rotation
	EnvCloudWatchGroup  = "SENTINEL_CLOUDWATCH_LOG_GROUP" // CloudWatch log group (optional)
	EnvCloudWatchStream = "SENTINEL_CLOUDWATCH_STREAM"    // CloudWatch log stream (default: function name)

	// Distributed rate limiting configuration environment variable.
	// EnvRateLimitTable is the DynamoDB table for distributed rate limiting.
	// If set, uses DynamoDB instead of in-memory rate limiting.
	// Table must have PK (string) partition key, TTL attribute named "TTL".
	EnvRateLimitTable = "SENTINEL_RATE_LIMIT_TABLE"
)

// Default configuration values.
const (
	// DefaultTVMDuration is the default session duration if not specified.
	// Matches server mode (15 minutes) for consistency.
	DefaultTVMDuration = 15 * time.Minute

	// DefaultPolicyCacheTTL is the default TTL for policy caching.
	// Short TTL ensures policy changes take effect quickly while reducing SSM API calls.
	DefaultPolicyCacheTTL = 30 * time.Second

	// DefaultRateLimitRequests is the default max requests per window.
	DefaultRateLimitRequests = 100

	// DefaultRateLimitWindow is the default rate limit window duration.
	DefaultRateLimitWindow = 60 * time.Second
)

// TVMConfig contains configuration for the Lambda TVM handler.
// This mirrors SentinelServerConfig for consistency with server mode.
type TVMConfig struct {
	// PolicyParameter is the SSM parameter path for policy (required).
	PolicyParameter string

	// PolicyRoot is the SSM path root for policy discovery (e.g., "/sentinel/policies").
	// Used by profile discovery endpoint.
	// If empty, defaults to extracting from PolicyParameter.
	PolicyRoot string

	// PolicyLoader is the cached policy loader.
	PolicyLoader policy.PolicyLoader

	// ApprovalStore is the optional approval request store.
	// If nil, approval checking is disabled.
	ApprovalStore request.Store

	// BreakGlassStore is the optional break-glass store.
	// If nil, break-glass checking is disabled.
	BreakGlassStore breakglass.Store

	// SessionStore is the optional session store.
	// If nil, session tracking is disabled.
	SessionStore session.Store

	// SessionTableName is the DynamoDB table name for sessions.
	// Passed to policy.Request for require_server_session evaluation.
	SessionTableName string

	// Logger is used for decision logging.
	// If nil, logging is disabled.
	Logger logging.Logger

	// STSClient is an optional custom STS client for testing.
	STSClient STSClient

	// Region is the AWS region.
	Region string

	// DefaultDuration is the default session duration if not specified.
	// Defaults to 15 minutes (matching server mode).
	DefaultDuration time.Duration

	// MDMProvider queries MDM for device posture verification.
	// If nil, device posture checking is disabled (credentials issued without device verification).
	MDMProvider mdm.Provider

	// RequireDevicePosture when true, rejects credentials if MDM lookup fails.
	// When false (default), MDM failure is logged but credentials are issued.
	RequireDevicePosture bool

	// SecretsLoader loads secrets from Secrets Manager. If nil, created automatically.
	// Exposed for testing (inject MockSecretsLoader).
	SecretsLoader SecretsLoader

	// RateLimiter limits API request rates per caller.
	// If nil, rate limiting is disabled.
	// Rate limits by caller's IAM user ARN (not IP) since IAM auth identifies the caller.
	RateLimiter ratelimit.RateLimiter

	// PolicySigningKeyID is the KMS key ARN for verifying policy signatures.
	// If set, policies will have their signatures validated before use.
	// Unsigned policies are handled based on EnforcePolicySigning.
	// Environment variable: SENTINEL_POLICY_SIGNING_KEY
	PolicySigningKeyID string

	// EnforcePolicySigning controls whether unsigned policies are rejected.
	// If true, policies without valid signatures return an error.
	// If false, unsigned policies are allowed with a warning log.
	// Default: true when PolicySigningKeyID is set.
	// Environment variable: SENTINEL_ENFORCE_POLICY_SIGNING (default: "true" if signing key set)
	EnforcePolicySigning bool

	// MFAVerifier is the optional MFA verifier for break-glass secondary verification.
	// If nil, MFA verification is disabled.
	// Environment variables: SENTINEL_MFA_TOTP_SECRETS_PARAM, SENTINEL_MFA_SMS_PHONES_PARAM
	MFAVerifier mfa.Verifier

	// LogSigningKey is the HMAC key for signing log entries.
	// If set, all log entries will include a signature for integrity verification.
	// Environment variable: SENTINEL_LOG_SIGNING_KEY (hex-encoded, 64 chars for 32 bytes)
	LogSigningKey []byte

	// LogSigningKeyID identifies the signing key for key rotation.
	// Environment variable: SENTINEL_LOG_SIGNING_KEY_ID
	LogSigningKeyID string

	// CloudWatchLogGroup is the log group for CloudWatch forwarding.
	// If empty, CloudWatch forwarding is disabled (logs go to stdout only).
	// Environment variable: SENTINEL_CLOUDWATCH_LOG_GROUP
	CloudWatchLogGroup string

	// CloudWatchStream is the log stream name within the group.
	// Defaults to AWS_LAMBDA_FUNCTION_NAME if not set.
	// Environment variable: SENTINEL_CLOUDWATCH_STREAM
	CloudWatchStream string

	// RateLimitTableName is the DynamoDB table for distributed rate limiting.
	// If set, uses DynamoDB rate limiter instead of in-memory.
	// Required for consistent rate limiting across Lambda instances.
	// Environment variable: SENTINEL_RATE_LIMIT_TABLE
	RateLimitTableName string
}

// LoadConfigFromEnv creates a TVMConfig from environment variables.
// This is the primary way to configure the Lambda TVM in production.
func LoadConfigFromEnv(ctx context.Context) (*TVMConfig, error) {
	cfg := &TVMConfig{
		PolicyParameter:  os.Getenv(EnvPolicyParameter),
		PolicyRoot:       os.Getenv(EnvPolicyRoot),
		SessionTableName: os.Getenv(EnvSessionTable),
		Region:           os.Getenv(EnvRegion),
		DefaultDuration:  DefaultTVMDuration,
	}

	// Load AWS config for creating clients
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Configure policy signing verification first to determine loader chain.
	// This needs to be done early to properly wrap the policy loader.
	cfg.PolicySigningKeyID = os.Getenv(EnvPolicySigningKey)
	if cfg.PolicySigningKeyID != "" {
		// Default to enforcing signatures when a signing key is configured
		cfg.EnforcePolicySigning = true

		// Allow explicit override via environment variable
		if enforceStr := os.Getenv(EnvEnforcePolicySigning); enforceStr != "" {
			cfg.EnforcePolicySigning = enforceStr == "true"
		}
	} else {
		// No signing key - check if enforcement was explicitly requested
		if enforceStr := os.Getenv(EnvEnforcePolicySigning); enforceStr == "true" {
			cfg.EnforcePolicySigning = true
		}
	}

	// Validate signing configuration
	if err := cfg.ValidateSigning(); err != nil {
		return nil, err
	}

	// Create SSM-based policy loader with caching.
	// The loader chain depends on whether signing is configured:
	// - Without signing: SSM Loader -> CachedLoader
	// - With signing: SSM RawLoader -> VerifyingLoader -> CachedLoader
	var basePolicyLoader policy.PolicyLoader

	if cfg.PolicySigningKeyID != "" {
		// Create verifying loader chain for signed policies
		ssmClient := ssm.NewFromConfig(awsCfg)
		rawPolicyLoader := policy.NewLoaderWithRaw(ssmClient)
		rawSigLoader := policy.NewLoaderWithRaw(ssmClient)

		signer := policy.NewPolicySigner(awsCfg, cfg.PolicySigningKeyID)
		basePolicyLoader = policy.NewVerifyingLoader(
			rawPolicyLoader,
			rawSigLoader,
			signer,
			policy.WithEnforcement(cfg.EnforcePolicySigning),
		)

		log.Printf("INFO: Policy signature verification enabled (key: %s, enforce: %v)",
			cfg.PolicySigningKeyID, cfg.EnforcePolicySigning)
	} else {
		// Use simple SSM loader without signature verification
		basePolicyLoader = policy.NewLoader(awsCfg)
		log.Printf("INFO: Policy signature verification disabled (%s not set)", EnvPolicySigningKey)
	}

	// Wrap with cache for both paths
	cfg.PolicyLoader = policy.NewCachedLoader(basePolicyLoader, DefaultPolicyCacheTTL)

	// Create DynamoDB stores if tables are configured
	if approvalTable := os.Getenv(EnvApprovalTable); approvalTable != "" {
		cfg.ApprovalStore = request.NewDynamoDBStore(awsCfg, approvalTable)
	}

	if breakglassTable := os.Getenv(EnvBreakGlassTable); breakglassTable != "" {
		cfg.BreakGlassStore = breakglass.NewDynamoDBStore(awsCfg, breakglassTable)
	}

	if cfg.SessionTableName != "" {
		cfg.SessionStore = session.NewDynamoDBStore(awsCfg, cfg.SessionTableName)
	}

	// Configure logger based on signing and CloudWatch settings
	cfg.Logger, err = configureLogger(awsCfg, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to configure logger: %w", err)
	}

	// Derive policy root from policy parameter if not explicitly set
	// e.g., "/sentinel/policies/production" -> "/sentinel/policies"
	if cfg.PolicyRoot == "" && cfg.PolicyParameter != "" {
		cfg.PolicyRoot = extractPolicyRoot(cfg.PolicyParameter)
	}

	// Configure MDM provider from environment
	mdmProvider := os.Getenv(EnvMDMProvider)
	if mdmProvider != "" && mdmProvider != "none" {
		// Load MDM API token - prefer Secrets Manager over environment variable
		mdmAPIToken, err := loadMDMAPIToken(ctx, awsCfg, cfg.SecretsLoader)
		if err != nil {
			return nil, fmt.Errorf("failed to load MDM API token: %w", err)
		}

		mdmConfig := &mdm.MDMConfig{
			ProviderType: mdmProvider,
			BaseURL:      os.Getenv(EnvMDMBaseURL),
			APIToken:     mdmAPIToken,
		}

		switch mdmProvider {
		case "jamf":
			provider, err := mdm.NewJamfProvider(mdmConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to create Jamf MDM provider: %w", err)
			}
			cfg.MDMProvider = provider
		case "intune":
			// Intune provider not yet implemented
			log.Printf("WARNING: MDM provider 'intune' is not yet implemented, using NoopProvider")
			cfg.MDMProvider = &mdm.NoopProvider{}
		case "kandji":
			// Kandji provider not yet implemented
			log.Printf("WARNING: MDM provider 'kandji' is not yet implemented, using NoopProvider")
			cfg.MDMProvider = &mdm.NoopProvider{}
		default:
			log.Printf("WARNING: Unknown MDM provider '%s', device posture checking disabled", mdmProvider)
		}
	}

	// Parse RequireDevicePosture
	if requireDevice := os.Getenv(EnvRequireDevice); requireDevice == "true" {
		cfg.RequireDevicePosture = true
	}

	// Configure rate limiting
	rateLimitRequests := DefaultRateLimitRequests
	if reqStr := os.Getenv(EnvRateLimitRequests); reqStr != "" {
		req, err := strconv.Atoi(reqStr)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", EnvRateLimitRequests, err)
		}
		rateLimitRequests = req
	}

	rateLimitWindow := DefaultRateLimitWindow
	if windowStr := os.Getenv(EnvRateLimitWindow); windowStr != "" {
		windowSec, err := strconv.Atoi(windowStr)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", EnvRateLimitWindow, err)
		}
		rateLimitWindow = time.Duration(windowSec) * time.Second
	}

	// Create rate limiter if enabled (requests > 0)
	if rateLimitRequests > 0 {
		rateLimitTable := os.Getenv(EnvRateLimitTable)
		if rateLimitTable != "" {
			// Use DynamoDB for distributed rate limiting (recommended for Lambda)
			cfg.RateLimitTableName = rateLimitTable
			limiter, err := ratelimit.NewDynamoDBRateLimiter(
				dynamodb.NewFromConfig(awsCfg),
				rateLimitTable,
				ratelimit.Config{
					RequestsPerWindow: rateLimitRequests,
					Window:            rateLimitWindow,
				},
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create DynamoDB rate limiter: %w", err)
			}
			cfg.RateLimiter = limiter
			log.Printf("INFO: Distributed rate limiting enabled: %d requests per %v (table: %s)",
				rateLimitRequests, rateLimitWindow, rateLimitTable)
		} else {
			// Fall back to in-memory (single instance only - NOT recommended for Lambda)
			limiter, err := ratelimit.NewMemoryRateLimiter(ratelimit.Config{
				RequestsPerWindow: rateLimitRequests,
				Window:            rateLimitWindow,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create rate limiter: %w", err)
			}
			cfg.RateLimiter = limiter
			log.Printf("WARNING: Using in-memory rate limiting - not effective across Lambda instances. Set %s for distributed rate limiting.",
				EnvRateLimitTable)
		}
	} else {
		log.Printf("INFO: Rate limiting disabled")
	}

	// Configure MFA verifiers from SSM parameters
	ssmClient := ssm.NewFromConfig(awsCfg)
	mfaVerifier, err := loadMFAVerifiers(ctx, ssmClient)
	if err != nil {
		return nil, fmt.Errorf("failed to load MFA configuration: %w", err)
	}
	if mfaVerifier != nil {
		cfg.MFAVerifier = mfaVerifier
		log.Printf("INFO: MFA verification enabled")
	} else {
		log.Printf("INFO: MFA verification disabled (no configuration)")
	}

	return cfg, nil
}

// extractPolicyRoot extracts the policy root directory from a full parameter path.
// For example, "/sentinel/policies/production" -> "/sentinel/policies".
func extractPolicyRoot(parameterPath string) string {
	lastSlash := strings.LastIndex(parameterPath, "/")
	if lastSlash <= 0 {
		return "/sentinel/policies" // Default fallback
	}
	return parameterPath[:lastSlash]
}

// loadMDMAPIToken loads the MDM API token from Secrets Manager or environment variable.
// Prefers Secrets Manager (EnvMDMAPISecretID) over environment variable (EnvMDMAPIToken).
//
// Priority:
//  1. If SENTINEL_MDM_API_SECRET_ID is set, load from Secrets Manager (recommended)
//  2. If SENTINEL_MDM_API_TOKEN is set, use env var (deprecated, logs warning)
//  3. If neither is set, return empty string (MDM provider creation will fail)
//
// The secretsLoader parameter is optional - if nil, a new CachedSecretsLoader is created.
func loadMDMAPIToken(ctx context.Context, awsCfg aws.Config, secretsLoader SecretsLoader) (string, error) {
	secretID := os.Getenv(EnvMDMAPISecretID)
	envToken := os.Getenv(EnvMDMAPIToken)

	// If Secrets Manager secret ID is configured, load from Secrets Manager
	if secretID != "" {
		// Create SecretsLoader if not provided (nil means use default)
		loader := secretsLoader
		if loader == nil {
			var err error
			loader, err = NewCachedSecretsLoader(awsCfg)
			if err != nil {
				return "", fmt.Errorf("failed to create secrets loader: %w", err)
			}
		}

		token, err := loader.GetSecret(ctx, secretID)
		if err != nil {
			return "", fmt.Errorf("failed to load MDM API token from Secrets Manager: %w", err)
		}

		// Warn if both are set (env var will be ignored)
		if envToken != "" {
			log.Printf("WARNING: Both %s and %s are set. Using Secrets Manager (env var ignored).",
				EnvMDMAPISecretID, EnvMDMAPIToken)
		}

		return token, nil
	}

	// Fall back to environment variable (deprecated)
	if envToken != "" {
		log.Printf("WARNING: %s is deprecated. Migrate to Secrets Manager using %s for improved security.",
			EnvMDMAPIToken, EnvMDMAPISecretID)
		return envToken, nil
	}

	// Neither configured - return empty (MDM provider will fail to initialize)
	return "", nil
}

// ValidateSigning validates the policy signing configuration.
// Returns an error if enforcement is enabled but no signing key is set.
func (c *TVMConfig) ValidateSigning() error {
	if c.EnforcePolicySigning && c.PolicySigningKeyID == "" {
		return fmt.Errorf("%s required when %s=true", EnvPolicySigningKey, EnvEnforcePolicySigning)
	}
	return nil
}

// SSMAPI defines the SSM operations used by MFA configuration loading.
// This interface enables testing with mock implementations.
type SSMAPI interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// loadMFAVerifiers creates MFA verifiers from environment configuration.
// Returns nil if no MFA configuration is present (MFA disabled).
//
// Configuration is stored in SSM as JSON:
//   - TOTP secrets: {"user1": {"secret": "BASE32SECRET"}, "user2": {...}}
//   - SMS phones: {"user1": "+1XXXXXXXXXX", "user2": "+1YYYYYYYYYY"}
func loadMFAVerifiers(ctx context.Context, ssmClient SSMAPI) (mfa.Verifier, error) {
	totpParam := os.Getenv(EnvMFATOTPSecretsParam)
	smsParam := os.Getenv(EnvMFASMSPhonesParam)

	if totpParam == "" && smsParam == "" {
		return nil, nil // MFA not configured
	}

	var verifiers []mfa.Verifier

	// Load TOTP secrets if configured
	if totpParam != "" {
		secrets, err := loadTOTPSecrets(ctx, ssmClient, totpParam)
		if err != nil {
			return nil, fmt.Errorf("load TOTP secrets: %w", err)
		}
		verifiers = append(verifiers, mfa.NewTOTPVerifier(secrets))
		log.Printf("INFO: TOTP MFA configured with %d users", len(secrets))
	}

	// Load SMS phones if configured
	if smsParam != "" {
		phones, err := loadSMSPhones(ctx, ssmClient, smsParam)
		if err != nil {
			return nil, fmt.Errorf("load SMS phones: %w", err)
		}
		// Note: SMS verifier requires AWS config for SNS, but we're in Lambda context
		// For now, return nil - SMS will be configured when aws.Config is available
		log.Printf("INFO: SMS MFA configured with %d users", len(phones))
		// TODO: SMS verifier creation needs aws.Config - defer to handler setup
		_ = phones
	}

	if len(verifiers) == 0 {
		return nil, nil
	}

	// Return single verifier or composite
	if len(verifiers) == 1 {
		return verifiers[0], nil
	}
	return mfa.NewMultiVerifier(verifiers...), nil
}

// loadTOTPSecrets loads TOTP secrets from an SSM parameter.
// The parameter value should be JSON: {"user1": {"secret": "BASE32SECRET"}, ...}
func loadTOTPSecrets(ctx context.Context, client SSMAPI, paramPath string) (map[string]mfa.TOTPConfig, error) {
	output, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           &paramPath,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("get parameter %s: %w", paramPath, err)
	}

	if output.Parameter == nil || output.Parameter.Value == nil {
		return nil, fmt.Errorf("parameter %s has no value", paramPath)
	}

	// Parse JSON to map
	var secrets map[string]mfa.TOTPConfig
	if err := json.Unmarshal([]byte(*output.Parameter.Value), &secrets); err != nil {
		return nil, fmt.Errorf("parse TOTP secrets JSON: %w", err)
	}

	return secrets, nil
}

// loadSMSPhones loads SMS phone numbers from an SSM parameter.
// The parameter value should be JSON: {"user1": "+1XXXXXXXXXX", ...}
func loadSMSPhones(ctx context.Context, client SSMAPI, paramPath string) (map[string]string, error) {
	output, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           &paramPath,
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("get parameter %s: %w", paramPath, err)
	}

	if output.Parameter == nil || output.Parameter.Value == nil {
		return nil, fmt.Errorf("parameter %s has no value", paramPath)
	}

	// Parse JSON to map
	var phones map[string]string
	if err := json.Unmarshal([]byte(*output.Parameter.Value), &phones); err != nil {
		return nil, fmt.Errorf("parse SMS phones JSON: %w", err)
	}

	return phones, nil
}

// configureLogger creates the appropriate Logger based on configuration.
// The logger selection depends on signing and CloudWatch settings:
//   - No signing, no CloudWatch: JSONLogger to stdout (existing behavior)
//   - Signing, no CloudWatch: SignedLogger to stdout
//   - Signing + CloudWatch: CloudWatchLogger with SignConfig
//   - No signing + CloudWatch: CloudWatchLogger without SignConfig
func configureLogger(awsCfg aws.Config, cfg *TVMConfig) (logging.Logger, error) {
	// Parse log signing configuration
	signingKeyHex := os.Getenv(EnvLogSigningKey)
	cfg.LogSigningKeyID = os.Getenv(EnvLogSigningKeyID)
	cfg.CloudWatchLogGroup = os.Getenv(EnvCloudWatchGroup)
	cfg.CloudWatchStream = os.Getenv(EnvCloudWatchStream)

	// Default stream name to Lambda function name
	if cfg.CloudWatchStream == "" {
		cfg.CloudWatchStream = os.Getenv("AWS_LAMBDA_FUNCTION_NAME")
	}

	// Parse and validate signing key if provided
	if signingKeyHex != "" {
		keyBytes, err := hex.DecodeString(signingKeyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: must be hex-encoded: %w", EnvLogSigningKey, err)
		}
		if len(keyBytes) < logging.MinKeyLength {
			return nil, fmt.Errorf("invalid %s: must be at least %d bytes (got %d)",
				EnvLogSigningKey, logging.MinKeyLength, len(keyBytes))
		}
		cfg.LogSigningKey = keyBytes
	}

	// Build logger based on configuration
	if cfg.CloudWatchLogGroup != "" {
		// CloudWatch forwarding enabled
		cwConfig := &logging.CloudWatchConfig{
			LogGroupName:  cfg.CloudWatchLogGroup,
			LogStreamName: cfg.CloudWatchStream,
		}
		if len(cfg.LogSigningKey) > 0 {
			cwConfig.SignConfig = &logging.SignatureConfig{
				KeyID:     cfg.LogSigningKeyID,
				SecretKey: cfg.LogSigningKey,
			}
			log.Printf("INFO: CloudWatch logging enabled with signing (group: %s, key: %s)",
				cfg.CloudWatchLogGroup, cfg.LogSigningKeyID)
		} else {
			log.Printf("INFO: CloudWatch logging enabled without signing (group: %s)", cfg.CloudWatchLogGroup)
		}
		return logging.NewCloudWatchLogger(awsCfg, cwConfig), nil
	} else if len(cfg.LogSigningKey) > 0 {
		// Signing enabled, stdout output
		signConfig := &logging.SignatureConfig{
			KeyID:     cfg.LogSigningKeyID,
			SecretKey: cfg.LogSigningKey,
		}
		log.Printf("INFO: Signed logging enabled to stdout (key: %s)", cfg.LogSigningKeyID)
		return logging.NewSignedLogger(os.Stdout, signConfig), nil
	}

	// Default: unsigned stdout (existing behavior)
	log.Printf("INFO: Logging to stdout (unsigned)")
	return logging.NewJSONLogger(os.Stdout), nil
}
