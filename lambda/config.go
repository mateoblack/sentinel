// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/mdm"
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

	// Create JSON Lines logger (writes to stdout, captured by CloudWatch)
	cfg.Logger = logging.NewJSONLogger(os.Stdout)

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
		limiter, err := ratelimit.NewMemoryRateLimiter(ratelimit.Config{
			RequestsPerWindow: rateLimitRequests,
			Window:            rateLimitWindow,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create rate limiter: %w", err)
		}
		cfg.RateLimiter = limiter
		log.Printf("INFO: Rate limiting enabled: %d requests per %v", rateLimitRequests, rateLimitWindow)
	} else {
		log.Printf("INFO: Rate limiting disabled")
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
