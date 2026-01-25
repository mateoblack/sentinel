// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
// This file implements secrets management using AWS Secrets Manager with caching.
package lambda

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretsLoader loads secrets from a secrets management service.
// This interface enables mocking in tests and future extension (e.g., fallback to env var in dev).
type SecretsLoader interface {
	// GetSecret retrieves a secret value by its ID or ARN.
	// Returns the secret string value or an error if the secret cannot be retrieved.
	GetSecret(ctx context.Context, secretID string) (string, error)
}

// CacheConfig contains configuration options for the secrets cache.
type CacheConfig struct {
	// TTL is the cache time-to-live. Cached secrets are refreshed after this duration.
	// Default: 1 hour (optimized for Lambda cold starts - secrets rarely change).
	TTL time.Duration
}

// DefaultSecretsCacheTTL is the default TTL for cached secrets.
// 1 hour is appropriate for Lambda where cold starts are infrequent and
// secrets (like API tokens) rarely change.
const DefaultSecretsCacheTTL = 1 * time.Hour

// secretsManagerAPI is an interface for the Secrets Manager client operations we use.
// This enables test mocking without requiring the full AWS SDK client.
type secretsManagerAPI interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// cachedSecret holds a secret value and its expiration time.
type cachedSecret struct {
	value     string
	expiresAt time.Time
}

// CachedSecretsLoader implements SecretsLoader with in-process caching.
// It wraps the AWS Secrets Manager client and caches secret values to reduce
// API calls and improve Lambda performance.
//
// Cache semantics:
//   - Secrets are cached for the configured TTL (default 1 hour)
//   - Cache is in-process only (not shared across Lambda invocations)
//   - Expired secrets are refreshed on next access
//   - Cache misses result in a Secrets Manager API call
type CachedSecretsLoader struct {
	client secretsManagerAPI
	ttl    time.Duration

	mu    sync.RWMutex
	cache map[string]*cachedSecret
}

// NewCachedSecretsLoader creates a new CachedSecretsLoader with the given AWS config.
// Options can be used to customize cache behavior (e.g., TTL override).
//
// Example:
//
//	loader, err := NewCachedSecretsLoader(awsCfg)
//	if err != nil {
//	    return err
//	}
//	secret, err := loader.GetSecret(ctx, "arn:aws:secretsmanager:us-east-1:123456789:secret:my-secret")
func NewCachedSecretsLoader(awsCfg aws.Config, options ...func(*CacheConfig)) (*CachedSecretsLoader, error) {
	cfg := &CacheConfig{
		TTL: DefaultSecretsCacheTTL,
	}

	for _, opt := range options {
		opt(cfg)
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	return &CachedSecretsLoader{
		client: client,
		ttl:    cfg.TTL,
		cache:  make(map[string]*cachedSecret),
	}, nil
}

// WithTTL returns an option that sets the cache TTL.
func WithTTL(ttl time.Duration) func(*CacheConfig) {
	return func(cfg *CacheConfig) {
		cfg.TTL = ttl
	}
}

// GetSecret retrieves a secret value by its ID or ARN.
// Returns cached value if available and not expired, otherwise fetches from Secrets Manager.
//
// The secretID can be either:
//   - A secret name: "my-secret"
//   - A secret ARN: "arn:aws:secretsmanager:us-east-1:123456789:secret:my-secret-AbCdEf"
//
// Returns an error if:
//   - The secret does not exist
//   - Access is denied (IAM permissions)
//   - The secret is not a string type (binary secrets not supported)
//   - Secrets Manager API is unavailable
func (l *CachedSecretsLoader) GetSecret(ctx context.Context, secretID string) (string, error) {
	if secretID == "" {
		return "", fmt.Errorf("secret ID is required")
	}

	// Check cache first (read lock)
	l.mu.RLock()
	if cached, ok := l.cache[secretID]; ok && time.Now().Before(cached.expiresAt) {
		l.mu.RUnlock()
		return cached.value, nil
	}
	l.mu.RUnlock()

	// Cache miss or expired - fetch from Secrets Manager
	output, err := l.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %q: %w", secretID, err)
	}

	// We only support string secrets, not binary
	if output.SecretString == nil {
		return "", fmt.Errorf("secret %q is not a string type (binary secrets not supported)", secretID)
	}

	value := *output.SecretString

	// Update cache (write lock)
	l.mu.Lock()
	l.cache[secretID] = &cachedSecret{
		value:     value,
		expiresAt: time.Now().Add(l.ttl),
	}
	l.mu.Unlock()

	return value, nil
}

// withClient sets a custom Secrets Manager client for testing.
// This is an internal method used by tests.
func (l *CachedSecretsLoader) withClient(client secretsManagerAPI) *CachedSecretsLoader {
	l.client = client
	return l
}
