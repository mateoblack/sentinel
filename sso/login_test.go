package sso

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
)

// mockOIDCClient implements OIDCClient for testing.
type mockOIDCClient struct {
	RegisterClientFunc           func(ctx context.Context, params *ssooidc.RegisterClientInput, optFns ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorizationFunc func(ctx context.Context, params *ssooidc.StartDeviceAuthorizationInput, optFns ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error)
	CreateTokenFunc              func(ctx context.Context, params *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}

func (m *mockOIDCClient) RegisterClient(ctx context.Context, params *ssooidc.RegisterClientInput, optFns ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
	if m.RegisterClientFunc != nil {
		return m.RegisterClientFunc(ctx, params, optFns...)
	}
	return &ssooidc.RegisterClientOutput{
		ClientId:              aws.String("mock-client-id"),
		ClientSecret:          aws.String("mock-client-secret"),
		ClientSecretExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}, nil
}

func (m *mockOIDCClient) StartDeviceAuthorization(ctx context.Context, params *ssooidc.StartDeviceAuthorizationInput, optFns ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
	if m.StartDeviceAuthorizationFunc != nil {
		return m.StartDeviceAuthorizationFunc(ctx, params, optFns...)
	}
	return &ssooidc.StartDeviceAuthorizationOutput{
		DeviceCode:              aws.String("mock-device-code"),
		UserCode:                aws.String("ABCD-1234"),
		VerificationUri:         aws.String("https://device.sso.us-east-1.amazonaws.com/"),
		VerificationUriComplete: aws.String("https://device.sso.us-east-1.amazonaws.com/?user_code=ABCD-1234"),
		ExpiresIn:               600, // 10 minutes
		Interval:                1,   // 1 second for faster tests
	}, nil
}

func (m *mockOIDCClient) CreateToken(ctx context.Context, params *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	if m.CreateTokenFunc != nil {
		return m.CreateTokenFunc(ctx, params, optFns...)
	}
	return &ssooidc.CreateTokenOutput{
		AccessToken: aws.String("mock-access-token"),
		TokenType:   aws.String("Bearer"),
		ExpiresIn:   3600, // 1 hour
	}, nil
}

func TestNewSSOLoginManager_ValidConfig(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL: "https://my-sso.awsapps.com/start",
		Region:   "us-east-1",
	}

	mock := &mockOIDCClient{}
	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manager == nil {
		t.Fatal("expected manager to be non-nil")
	}
	if manager.config.ClientName != "sentinel" {
		t.Errorf("expected default client name 'sentinel', got %q", manager.config.ClientName)
	}
}

func TestNewSSOLoginManager_MissingStartURL(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		Region: "us-east-1",
	}

	_, err := NewSSOLoginManager(ctx, config, nil)
	if err == nil {
		t.Fatal("expected error for missing StartURL")
	}
	if err.Error() != "sso: StartURL is required" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewSSOLoginManager_MissingRegion(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL: "https://my-sso.awsapps.com/start",
	}

	_, err := NewSSOLoginManager(ctx, config, nil)
	if err == nil {
		t.Fatal("expected error for missing Region")
	}
	if err.Error() != "sso: Region is required" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewSSOLoginManager_CustomClientName(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL:   "https://my-sso.awsapps.com/start",
		Region:     "us-east-1",
		ClientName: "my-custom-app",
	}

	mock := &mockOIDCClient{}
	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manager.config.ClientName != "my-custom-app" {
		t.Errorf("expected client name 'my-custom-app', got %q", manager.config.ClientName)
	}
}

func TestTriggerSSOLogin_Success(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL:  "https://my-sso.awsapps.com/start",
		Region:    "us-east-1",
		UseStdout: true, // Suppress browser opening
	}

	mock := &mockOIDCClient{}
	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}

	result, err := manager.TriggerSSOLogin(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result to be non-nil")
	}
	if result.AccessToken != "mock-access-token" {
		t.Errorf("unexpected access token: %q", result.AccessToken)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("unexpected token type: %q", result.TokenType)
	}
}

func TestTriggerSSOLogin_AuthorizationPendingThenSuccess(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL:  "https://my-sso.awsapps.com/start",
		Region:    "us-east-1",
		UseStdout: true,
	}

	var callCount int32
	mock := &mockOIDCClient{
		CreateTokenFunc: func(ctx context.Context, params *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
			count := atomic.AddInt32(&callCount, 1)
			if count < 3 {
				// Return AuthorizationPending for first 2 calls
				return nil, &ssooidctypes.AuthorizationPendingException{
					Message: aws.String("Authorization pending"),
				}
			}
			// Return success on 3rd call
			return &ssooidc.CreateTokenOutput{
				AccessToken: aws.String("mock-access-token"),
				TokenType:   aws.String("Bearer"),
				ExpiresIn:   3600,
			}, nil
		},
	}

	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}
	// Speed up polling for tests
	manager.deviceAuthorizationPollInterval = 10 * time.Millisecond

	result, err := manager.TriggerSSOLogin(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AccessToken != "mock-access-token" {
		t.Errorf("unexpected access token: %q", result.AccessToken)
	}
	if callCount != 3 {
		t.Errorf("expected 3 CreateToken calls, got %d", callCount)
	}
}

func TestTriggerSSOLogin_SlowDownException(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL:  "https://my-sso.awsapps.com/start",
		Region:    "us-east-1",
		UseStdout: true,
	}

	var callCount int32
	mock := &mockOIDCClient{
		CreateTokenFunc: func(ctx context.Context, params *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
			count := atomic.AddInt32(&callCount, 1)
			if count == 1 {
				// Return SlowDown on first call
				return nil, &ssooidctypes.SlowDownException{
					Message: aws.String("Slow down"),
				}
			}
			// Return success on 2nd call
			return &ssooidc.CreateTokenOutput{
				AccessToken: aws.String("mock-access-token"),
				TokenType:   aws.String("Bearer"),
				ExpiresIn:   3600,
			}, nil
		},
	}

	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}
	// Speed up polling for tests
	manager.deviceAuthorizationPollInterval = 10 * time.Millisecond
	manager.deviceAuthorizationSlowDownDelay = 10 * time.Millisecond

	result, err := manager.TriggerSSOLogin(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AccessToken != "mock-access-token" {
		t.Errorf("unexpected access token: %q", result.AccessToken)
	}
	if callCount != 2 {
		t.Errorf("expected 2 CreateToken calls, got %d", callCount)
	}
}

func TestTriggerSSOLogin_RegisterClientError(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL:  "https://my-sso.awsapps.com/start",
		Region:    "us-east-1",
		UseStdout: true,
	}

	mock := &mockOIDCClient{
		RegisterClientFunc: func(ctx context.Context, params *ssooidc.RegisterClientInput, optFns ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
			return nil, errors.New("registration failed")
		},
	}

	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}

	_, err = manager.TriggerSSOLogin(ctx)
	if err == nil {
		t.Fatal("expected error from RegisterClient")
	}
	if !errors.Is(err, errors.Unwrap(err)) && err.Error() != "sso: failed to register client: registration failed" {
		// Check error message contains expected info
		if err.Error() != "sso: failed to register client: registration failed" {
			t.Errorf("unexpected error message: %v", err)
		}
	}
}

func TestTriggerSSOLogin_StartDeviceAuthorizationError(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL:  "https://my-sso.awsapps.com/start",
		Region:    "us-east-1",
		UseStdout: true,
	}

	mock := &mockOIDCClient{
		StartDeviceAuthorizationFunc: func(ctx context.Context, params *ssooidc.StartDeviceAuthorizationInput, optFns ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
			return nil, errors.New("device authorization failed")
		},
	}

	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}

	_, err = manager.TriggerSSOLogin(ctx)
	if err == nil {
		t.Fatal("expected error from StartDeviceAuthorization")
	}
}

func TestTriggerSSOLogin_CreateTokenError(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL:  "https://my-sso.awsapps.com/start",
		Region:    "us-east-1",
		UseStdout: true,
	}

	mock := &mockOIDCClient{
		CreateTokenFunc: func(ctx context.Context, params *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
			return nil, errors.New("create token failed")
		},
	}

	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}

	_, err = manager.TriggerSSOLogin(ctx)
	if err == nil {
		t.Fatal("expected error from CreateToken")
	}
}

func TestTriggerSSOLogin_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := SSOLoginConfig{
		StartURL:  "https://my-sso.awsapps.com/start",
		Region:    "us-east-1",
		UseStdout: true,
	}

	mock := &mockOIDCClient{
		CreateTokenFunc: func(ctx context.Context, params *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
			// Simulate slow response - check context
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				// Return pending to continue polling
				return nil, &ssooidctypes.AuthorizationPendingException{
					Message: aws.String("Authorization pending"),
				}
			}
		},
	}

	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}
	manager.deviceAuthorizationPollInterval = 50 * time.Millisecond

	// Cancel context after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_, err = manager.TriggerSSOLogin(ctx)
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
}

func TestTriggerSSOLogin_Timeout(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL:  "https://my-sso.awsapps.com/start",
		Region:    "us-east-1",
		UseStdout: true,
	}

	mock := &mockOIDCClient{
		StartDeviceAuthorizationFunc: func(ctx context.Context, params *ssooidc.StartDeviceAuthorizationInput, optFns ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error) {
			return &ssooidc.StartDeviceAuthorizationOutput{
				DeviceCode:              aws.String("mock-device-code"),
				UserCode:                aws.String("ABCD-1234"),
				VerificationUri:         aws.String("https://device.sso.us-east-1.amazonaws.com/"),
				VerificationUriComplete: aws.String("https://device.sso.us-east-1.amazonaws.com/?user_code=ABCD-1234"),
				ExpiresIn:               1, // Very short expiration for test
				Interval:                1,
			}, nil
		},
		CreateTokenFunc: func(ctx context.Context, params *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
			// Always return pending
			return nil, &ssooidctypes.AuthorizationPendingException{
				Message: aws.String("Authorization pending"),
			}
		},
	}

	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}
	manager.deviceAuthorizationPollInterval = 100 * time.Millisecond

	_, err = manager.TriggerSSOLogin(ctx)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if err.Error() != "sso: device authorization timed out" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestTriggerSSOLogin_ConvenienceFunction(t *testing.T) {
	// This test verifies the convenience function signature exists
	// but cannot actually test it without a real OIDC client
	ctx := context.Background()
	config := SSOLoginConfig{} // Empty config should fail validation

	_, err := TriggerSSOLogin(ctx, config)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestTriggerSSOLogin_ClientNameInRegisterCall(t *testing.T) {
	ctx := context.Background()
	config := SSOLoginConfig{
		StartURL:   "https://my-sso.awsapps.com/start",
		Region:     "us-east-1",
		UseStdout:  true,
		ClientName: "sentinel",
	}

	var capturedClientName string
	mock := &mockOIDCClient{
		RegisterClientFunc: func(ctx context.Context, params *ssooidc.RegisterClientInput, optFns ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error) {
			capturedClientName = aws.ToString(params.ClientName)
			return &ssooidc.RegisterClientOutput{
				ClientId:              aws.String("mock-client-id"),
				ClientSecret:          aws.String("mock-client-secret"),
				ClientSecretExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
			}, nil
		},
	}

	manager, err := NewSSOLoginManager(ctx, config, mock)
	if err != nil {
		t.Fatalf("unexpected error creating manager: %v", err)
	}

	_, err = manager.TriggerSSOLogin(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedClientName != "sentinel" {
		t.Errorf("expected client name 'sentinel' in RegisterClient call, got %q", capturedClientName)
	}
}
