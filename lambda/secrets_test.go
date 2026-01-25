package lambda

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// MockSecretsLoader is a mock implementation of SecretsLoader for testing.
// It allows tests to control the returned values without hitting AWS.
type MockSecretsLoader struct {
	// Secrets maps secret IDs to their values.
	Secrets map[string]string

	// Err is the error to return (if set, takes precedence over Secrets).
	Err error

	// GetSecretCalls tracks calls to GetSecret for verification.
	GetSecretCalls []string
}

// NewMockSecretsLoader creates a new MockSecretsLoader with the given secrets.
func NewMockSecretsLoader(secrets map[string]string) *MockSecretsLoader {
	return &MockSecretsLoader{
		Secrets:        secrets,
		GetSecretCalls: make([]string, 0),
	}
}

// GetSecret implements SecretsLoader.
func (m *MockSecretsLoader) GetSecret(_ context.Context, secretID string) (string, error) {
	m.GetSecretCalls = append(m.GetSecretCalls, secretID)

	if m.Err != nil {
		return "", m.Err
	}

	if value, ok := m.Secrets[secretID]; ok {
		return value, nil
	}

	return "", errors.New("secret not found: " + secretID)
}

// mockSecretsManagerClient is a mock for the AWS Secrets Manager client.
type mockSecretsManagerClient struct {
	// GetSecretValueFunc is called when GetSecretValue is invoked.
	GetSecretValueFunc func(ctx context.Context, params *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)

	// Calls tracks all GetSecretValue calls for verification.
	Calls []string
}

func (m *mockSecretsManagerClient) GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if params.SecretId != nil {
		m.Calls = append(m.Calls, *params.SecretId)
	}
	if m.GetSecretValueFunc != nil {
		return m.GetSecretValueFunc(ctx, params)
	}
	return nil, errors.New("mock not configured")
}

func TestMockSecretsLoader(t *testing.T) {
	secrets := map[string]string{
		"secret-1": "value-1",
		"secret-2": "value-2",
	}

	mock := NewMockSecretsLoader(secrets)
	ctx := context.Background()

	// Test successful retrieval
	value, err := mock.GetSecret(ctx, "secret-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if value != "value-1" {
		t.Errorf("expected value-1, got %s", value)
	}

	// Test call tracking
	if len(mock.GetSecretCalls) != 1 || mock.GetSecretCalls[0] != "secret-1" {
		t.Errorf("expected GetSecretCalls to contain secret-1, got %v", mock.GetSecretCalls)
	}

	// Test not found
	_, err = mock.GetSecret(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent secret")
	}

	// Test error override
	mock.Err = errors.New("forced error")
	_, err = mock.GetSecret(ctx, "secret-1")
	if err == nil || err.Error() != "forced error" {
		t.Errorf("expected forced error, got %v", err)
	}
}

func TestCachedSecretsLoader_GetSecret(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		secretID      string
		mockResponse  *secretsmanager.GetSecretValueOutput
		mockErr       error
		wantValue     string
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:     "success with string secret",
			secretID: "test-secret",
			mockResponse: &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("my-secret-value"),
			},
			wantValue: "my-secret-value",
			wantErr:   false,
		},
		{
			name:          "empty secret ID",
			secretID:      "",
			wantErr:       true,
			wantErrSubstr: "secret ID is required",
		},
		{
			name:          "secret not found",
			secretID:      "nonexistent",
			mockErr:       errors.New("ResourceNotFoundException: secret not found"),
			wantErr:       true,
			wantErrSubstr: "failed to get secret",
		},
		{
			name:     "binary secret not supported",
			secretID: "binary-secret",
			mockResponse: &secretsmanager.GetSecretValueOutput{
				SecretBinary: []byte("binary-data"),
				// SecretString is nil
			},
			wantErr:       true,
			wantErrSubstr: "not a string type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockSecretsManagerClient{
				GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
					if tt.mockErr != nil {
						return nil, tt.mockErr
					}
					return tt.mockResponse, nil
				},
			}

			loader := &CachedSecretsLoader{
				client: mockClient,
				ttl:    time.Hour,
				cache:  make(map[string]*cachedSecret),
			}

			value, err := loader.GetSecret(ctx, tt.secretID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.wantErrSubstr != "" && !containsSubstring(err.Error(), tt.wantErrSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErrSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if value != tt.wantValue {
				t.Errorf("expected %q, got %q", tt.wantValue, value)
			}
		})
	}
}

func TestCachedSecretsLoader_Caching(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	mockClient := &mockSecretsManagerClient{
		GetSecretValueFunc: func(_ context.Context, params *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			callCount++
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("cached-value"),
			}, nil
		},
	}

	loader := &CachedSecretsLoader{
		client: mockClient,
		ttl:    time.Hour,
		cache:  make(map[string]*cachedSecret),
	}

	// First call - should hit Secrets Manager
	value1, err := loader.GetSecret(ctx, "test-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value1 != "cached-value" {
		t.Errorf("expected cached-value, got %s", value1)
	}
	if callCount != 1 {
		t.Errorf("expected 1 API call, got %d", callCount)
	}

	// Second call - should use cache, not call API
	value2, err := loader.GetSecret(ctx, "test-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value2 != "cached-value" {
		t.Errorf("expected cached-value, got %s", value2)
	}
	if callCount != 1 {
		t.Errorf("expected still 1 API call (cached), got %d", callCount)
	}

	// Different secret ID - should hit API again
	_, err = loader.GetSecret(ctx, "different-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls (different secret), got %d", callCount)
	}
}

func TestCachedSecretsLoader_CacheExpiry(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	mockClient := &mockSecretsManagerClient{
		GetSecretValueFunc: func(_ context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			callCount++
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("value"),
			}, nil
		},
	}

	// Use very short TTL for testing
	loader := &CachedSecretsLoader{
		client: mockClient,
		ttl:    10 * time.Millisecond,
		cache:  make(map[string]*cachedSecret),
	}

	// First call
	_, err := loader.GetSecret(ctx, "test-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 API call, got %d", callCount)
	}

	// Immediate second call - should use cache
	_, err = loader.GetSecret(ctx, "test-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected still 1 API call (cached), got %d", callCount)
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// Third call - should hit API again due to expiry
	_, err = loader.GetSecret(ctx, "test-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 API calls (cache expired), got %d", callCount)
	}
}

func TestCacheConfig_Defaults(t *testing.T) {
	// Verify default TTL is reasonable for Lambda
	if DefaultSecretsCacheTTL != time.Hour {
		t.Errorf("expected default TTL of 1 hour, got %v", DefaultSecretsCacheTTL)
	}
}

func TestWithTTL(t *testing.T) {
	cfg := &CacheConfig{TTL: time.Hour}

	// Apply custom TTL
	WithTTL(5 * time.Minute)(cfg)

	if cfg.TTL != 5*time.Minute {
		t.Errorf("expected TTL of 5 minutes, got %v", cfg.TTL)
	}
}

// containsSubstring checks if s contains substr (case-sensitive).
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
