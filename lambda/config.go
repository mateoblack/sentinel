// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/mdm"
	"github.com/byteness/aws-vault/v7/policy"
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
	EnvMDMProvider   = "SENTINEL_MDM_PROVIDER"   // "jamf", "intune", "kandji", "none"
	EnvMDMBaseURL    = "SENTINEL_MDM_BASE_URL"   // MDM server URL (e.g., Jamf Pro URL)
	EnvMDMAPIToken   = "SENTINEL_MDM_API_TOKEN"  // Bearer token (from Secrets Manager)
	EnvRequireDevice = "SENTINEL_REQUIRE_DEVICE" // "true" to require device verification
)

// Default configuration values.
const (
	// DefaultTVMDuration is the default session duration if not specified.
	// Matches server mode (15 minutes) for consistency.
	DefaultTVMDuration = 15 * time.Minute

	// DefaultPolicyCacheTTL is the default TTL for policy caching.
	// Short TTL ensures policy changes take effect quickly while reducing SSM API calls.
	DefaultPolicyCacheTTL = 30 * time.Second
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

	// Create SSM-based policy loader with caching.
	// The Loader implements PolicyLoader interface and uses SSM to fetch policies.
	ssmLoader := policy.NewLoader(awsCfg)
	cfg.PolicyLoader = policy.NewCachedLoader(ssmLoader, DefaultPolicyCacheTTL)

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
		mdmConfig := &mdm.MDMConfig{
			ProviderType: mdmProvider,
			BaseURL:      os.Getenv(EnvMDMBaseURL),
			APIToken:     os.Getenv(EnvMDMAPIToken),
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
