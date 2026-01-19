// Package sso provides SSO error detection and login trigger infrastructure
// for automatic SSO authentication flows.
package sso

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/skratchdot/open-golang/open"
)

// SSOLoginConfig contains configuration for SSO login.
type SSOLoginConfig struct {
	// StartURL is the SSO portal URL (from profile sso_start_url).
	StartURL string

	// Region is the SSO region (from profile sso_region).
	Region string

	// UseStdout prints the verification URL instead of opening browser.
	UseStdout bool

	// ClientName is the name used when registering the OIDC client.
	// Defaults to "sentinel" if empty.
	ClientName string
}

// SSOLoginResult contains the result of a successful SSO login.
type SSOLoginResult struct {
	// AccessToken is the OIDC access token.
	AccessToken string

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time

	// TokenType is the type of token (usually "Bearer").
	TokenType string
}

// SSOLoginManager handles SSO OIDC device authorization flow.
type SSOLoginManager struct {
	// OIDCClient is the SSO OIDC client.
	OIDCClient OIDCClient

	// config holds the login configuration.
	config SSOLoginConfig

	// deviceAuthorizationPollInterval is the interval between CreateToken calls.
	// Defaults to 5 seconds per RFC 8628.
	deviceAuthorizationPollInterval time.Duration

	// deviceAuthorizationSlowDownDelay is added to poll interval on SlowDown.
	// Defaults to 5 seconds per RFC 8628.
	deviceAuthorizationSlowDownDelay time.Duration
}

// OIDCClient defines the interface for SSO OIDC operations.
// This allows for mocking in tests.
type OIDCClient interface {
	RegisterClient(ctx context.Context, params *ssooidc.RegisterClientInput, optFns ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(ctx context.Context, params *ssooidc.StartDeviceAuthorizationInput, optFns ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error)
	CreateToken(ctx context.Context, params *ssooidc.CreateTokenInput, optFns ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}

// NewSSOLoginManager creates a new SSOLoginManager with the given configuration.
// If oidcClient is nil, a new client will be created using the config region.
func NewSSOLoginManager(ctx context.Context, loginConfig SSOLoginConfig, oidcClient OIDCClient) (*SSOLoginManager, error) {
	if loginConfig.StartURL == "" {
		return nil, errors.New("sso: StartURL is required")
	}
	if loginConfig.Region == "" {
		return nil, errors.New("sso: Region is required")
	}
	if loginConfig.ClientName == "" {
		loginConfig.ClientName = "sentinel"
	}

	manager := &SSOLoginManager{
		config:                           loginConfig,
		deviceAuthorizationPollInterval:  5 * time.Second,
		deviceAuthorizationSlowDownDelay: 5 * time.Second,
	}

	if oidcClient != nil {
		manager.OIDCClient = oidcClient
	} else {
		// Create a new OIDC client for the SSO region
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(loginConfig.Region))
		if err != nil {
			return nil, fmt.Errorf("sso: failed to load AWS config: %w", err)
		}
		manager.OIDCClient = ssooidc.NewFromConfig(cfg)
	}

	return manager, nil
}

// TriggerSSOLogin initiates the SSO device authorization flow.
// It registers a client, starts device authorization, displays the verification URL,
// optionally opens the browser, and polls for the token until success or timeout.
func (m *SSOLoginManager) TriggerSSOLogin(ctx context.Context) (*SSOLoginResult, error) {
	// Step 1: Register OIDC client
	clientCreds, err := m.OIDCClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String(m.config.ClientName),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return nil, fmt.Errorf("sso: failed to register client: %w", err)
	}
	log.Printf("Created new OIDC client (expires at: %s)", time.Unix(clientCreds.ClientSecretExpiresAt, 0))

	// Step 2: Start device authorization
	deviceCreds, err := m.OIDCClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     clientCreds.ClientId,
		ClientSecret: clientCreds.ClientSecret,
		StartUrl:     aws.String(m.config.StartURL),
	})
	if err != nil {
		return nil, fmt.Errorf("sso: failed to start device authorization: %w", err)
	}
	log.Printf("Created OIDC device code for %s (expires in: %ds)", m.config.StartURL, deviceCreds.ExpiresIn)

	// Step 3: Display verification URL
	verificationURL := aws.ToString(deviceCreds.VerificationUriComplete)
	if m.config.UseStdout {
		fmt.Fprintf(os.Stderr, "Open the SSO authorization page in a browser (use Ctrl-C to abort)\n%s\n", verificationURL)
	} else {
		log.Println("Opening SSO authorization page in browser")
		fmt.Fprintf(os.Stderr, "Opening the SSO authorization page in your default browser (use Ctrl-C to abort)\n%s\n", verificationURL)
		if err := open.Run(verificationURL); err != nil {
			log.Printf("Failed to open browser: %s", err)
		}
	}

	// Step 4: Poll for token
	retryInterval := m.deviceAuthorizationPollInterval
	if i := deviceCreds.Interval; i > 0 {
		retryInterval = time.Duration(i) * time.Second
	}

	// Calculate deadline from device code expiration
	deadline := time.Now().Add(time.Duration(deviceCreds.ExpiresIn) * time.Second)

	for {
		// Check if we've exceeded the deadline
		if time.Now().After(deadline) {
			return nil, errors.New("sso: device authorization timed out")
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		token, err := m.OIDCClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     clientCreds.ClientId,
			ClientSecret: clientCreds.ClientSecret,
			DeviceCode:   deviceCreds.DeviceCode,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		})
		if err != nil {
			// Handle SlowDownException - increase poll interval
			var sde *ssooidctypes.SlowDownException
			if errors.As(err, &sde) {
				retryInterval += m.deviceAuthorizationSlowDownDelay
				time.Sleep(retryInterval)
				continue
			}

			// Handle AuthorizationPendingException - user hasn't completed auth yet
			var ape *ssooidctypes.AuthorizationPendingException
			if errors.As(err, &ape) {
				time.Sleep(retryInterval)
				continue
			}

			// Any other error is a failure
			return nil, fmt.Errorf("sso: failed to create token: %w", err)
		}

		// Success - return the result
		log.Printf("Created new OIDC access token for %s (expires in: %ds)", m.config.StartURL, token.ExpiresIn)

		return &SSOLoginResult{
			AccessToken: aws.ToString(token.AccessToken),
			ExpiresAt:   time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
			TokenType:   aws.ToString(token.TokenType),
		}, nil
	}
}

// TriggerSSOLogin is a convenience function that creates a manager and triggers login.
func TriggerSSOLogin(ctx context.Context, config SSOLoginConfig) (*SSOLoginResult, error) {
	manager, err := NewSSOLoginManager(ctx, config, nil)
	if err != nil {
		return nil, err
	}
	return manager.TriggerSSOLogin(ctx)
}
