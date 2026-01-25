package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

// RemoteCredentialClient fetches credentials from a remote TVM (Token Vending Machine).
// Supports both SigV4-signed requests (for API Gateway) and token-based auth (for local server).
type RemoteCredentialClient struct {
	URL        string       // TVM URL (e.g., https://api.example.com/sentinel?profile=myprofile)
	AuthToken  string       // Optional auth token for local server mode (empty = use SigV4)
	HTTPClient *http.Client // HTTP client (nil = use default)
}

// RemoteCredentialResult contains credentials fetched from the remote TVM.
// Matches AWS container credentials format.
type RemoteCredentialResult struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// NewRemoteCredentialClient creates a new client for fetching credentials from a remote TVM.
// If authToken is empty, SigV4 signing will be used for API Gateway authentication.
func NewRemoteCredentialClient(url string, authToken string) *RemoteCredentialClient {
	return &RemoteCredentialClient{
		URL:       url,
		AuthToken: authToken,
	}
}

// GetCredentials fetches credentials from the remote TVM.
// Uses SigV4 signing if AuthToken is empty (API Gateway mode).
// Uses Authorization header if AuthToken is set (local server mode).
func (c *RemoteCredentialClient) GetCredentials(ctx context.Context) (*RemoteCredentialResult, error) {
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Sign request or add auth token
	if c.AuthToken != "" {
		// Local server mode: use bearer token
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	} else {
		// API Gateway mode: use SigV4 signing
		if err := c.signRequest(ctx, req); err != nil {
			return nil, fmt.Errorf("failed to sign request: %w", err)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credentials: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse error response
		var tvmErr struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		}
		if json.Unmarshal(body, &tvmErr) == nil && tvmErr.Message != "" {
			return nil, fmt.Errorf("TVM error (%s): %s", tvmErr.Code, tvmErr.Message)
		}
		return nil, fmt.Errorf("TVM returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse container credentials format
	var creds struct {
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      string `json:"Expiration"`
	}
	if err := json.Unmarshal(body, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	// Validate required fields
	if creds.AccessKeyId == "" || creds.SecretAccessKey == "" {
		return nil, fmt.Errorf("invalid credential response: missing AccessKeyId or SecretAccessKey")
	}

	// Parse expiration time (RFC3339 format)
	var expiration time.Time
	if creds.Expiration != "" {
		expiration, err = time.Parse(time.RFC3339, creds.Expiration)
		if err != nil {
			return nil, fmt.Errorf("failed to parse expiration time: %w", err)
		}
	}

	return &RemoteCredentialResult{
		AccessKeyID:     creds.AccessKeyId,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.Token,
		Expiration:      expiration,
	}, nil
}

// signRequest signs an HTTP request with SigV4 for API Gateway authentication.
// Uses the default AWS credential chain.
func (c *RemoteCredentialClient) signRequest(ctx context.Context, req *http.Request) error {
	// Load default AWS config
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Get credentials
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to get AWS credentials: %w", err)
	}

	// Create SigV4 signer
	signer := v4.NewSigner()

	// Determine the region for signing
	// Use the region from the config, or extract from URL if not set
	region := cfg.Region
	if region == "" {
		region = "us-east-1" // Default region for API Gateway
	}

	// Hash of empty body for GET request
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA256 of empty string

	// Sign the request
	err = signer.SignHTTP(ctx, creds, req, payloadHash, "execute-api", region, time.Now())
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	return nil
}

// signRequestWithConfig signs an HTTP request with SigV4 using the provided AWS config.
// This variant is useful when you already have a loaded config.
func (c *RemoteCredentialClient) signRequestWithConfig(ctx context.Context, req *http.Request, cfg aws.Config) error {
	// Get credentials
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to get AWS credentials: %w", err)
	}

	// Create SigV4 signer
	signer := v4.NewSigner()

	// Use the region from the config
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	// Hash of empty body for GET request
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Sign the request
	err = signer.SignHTTP(ctx, creds, req, payloadHash, "execute-api", region, time.Now())
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	return nil
}
