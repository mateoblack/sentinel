// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/session"
)

// Environment variable names for TVM configuration.
const (
	EnvPolicyParameter = "SENTINEL_POLICY_PARAMETER"
	EnvApprovalTable   = "SENTINEL_APPROVAL_TABLE"
	EnvBreakGlassTable = "SENTINEL_BREAKGLASS_TABLE"
	EnvSessionTable    = "SENTINEL_SESSION_TABLE"
	EnvRegion          = "AWS_REGION"
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
}

// LoadConfigFromEnv creates a TVMConfig from environment variables.
// This is the primary way to configure the Lambda TVM in production.
func LoadConfigFromEnv(ctx context.Context) (*TVMConfig, error) {
	cfg := &TVMConfig{
		PolicyParameter:  os.Getenv(EnvPolicyParameter),
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

	return cfg, nil
}
