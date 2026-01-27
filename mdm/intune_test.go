package mdm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewIntuneProvider(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *MDMConfig
		wantErr string
	}{
		{
			name:    "nil config returns error",
			cfg:     nil,
			wantErr: "config is required",
		},
		{
			name: "missing TenantID returns error",
			cfg: &MDMConfig{
				ProviderType: "intune",
				BaseURL:      "https://graph.microsoft.com",
				APIToken:     "client_id:client_secret",
			},
			wantErr: "tenant_id is required",
		},
		{
			name: "missing APIToken returns error",
			cfg: &MDMConfig{
				ProviderType: "intune",
				BaseURL:      "https://graph.microsoft.com",
				TenantID:     "test-tenant-id",
			},
			wantErr: "api_token is required",
		},
		{
			name: "invalid APIToken format (no colon) returns error",
			cfg: &MDMConfig{
				ProviderType: "intune",
				TenantID:     "test-tenant-id",
				APIToken:     "invalid_token_without_colon",
			},
			wantErr: "api_token must be in format",
		},
		{
			name: "invalid APIToken format (empty client_id) returns error",
			cfg: &MDMConfig{
				ProviderType: "intune",
				TenantID:     "test-tenant-id",
				APIToken:     ":client_secret",
			},
			wantErr: "api_token must be in format",
		},
		{
			name: "invalid APIToken format (empty client_secret) returns error",
			cfg: &MDMConfig{
				ProviderType: "intune",
				TenantID:     "test-tenant-id",
				APIToken:     "client_id:",
			},
			wantErr: "api_token must be in format",
		},
		{
			name: "valid config creates provider",
			cfg: &MDMConfig{
				ProviderType: "intune",
				TenantID:     "test-tenant-id",
				APIToken:     "client_id:client_secret",
			},
			wantErr: "",
		},
		{
			name: "default timeout applied when not specified",
			cfg: &MDMConfig{
				ProviderType: "intune",
				TenantID:     "test-tenant-id",
				APIToken:     "client_id:client_secret",
				Timeout:      0, // Zero triggers default
			},
			wantErr: "",
		},
		{
			name: "custom timeout applied when specified",
			cfg: &MDMConfig{
				ProviderType: "intune",
				TenantID:     "test-tenant-id",
				APIToken:     "client_id:client_secret",
				Timeout:      30 * time.Second,
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewIntuneProvider(tt.cfg)

			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if provider == nil {
				t.Error("expected non-nil provider")
				return
			}

			if provider.Name() != "intune" {
				t.Errorf("expected provider name %q, got %q", "intune", provider.Name())
			}

			if provider.tenantID != tt.cfg.TenantID {
				t.Errorf("expected tenantID %q, got %q", tt.cfg.TenantID, provider.tenantID)
			}

			// Verify default timeout is applied
			if tt.cfg.Timeout == 0 && provider.timeout != DefaultTimeout {
				t.Errorf("expected default timeout %v, got %v", DefaultTimeout, provider.timeout)
			}

			// Verify custom timeout is applied
			if tt.cfg.Timeout > 0 && provider.timeout != tt.cfg.Timeout {
				t.Errorf("expected custom timeout %v, got %v", tt.cfg.Timeout, provider.timeout)
			}
		})
	}
}

func TestIntuneProvider_getAccessToken_Success(t *testing.T) {
	// Track number of token requests
	tokenRequestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a token request
		if strings.Contains(r.URL.Path, "oauth2/v2.0/token") {
			tokenRequestCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"access_token": "test-access-token",
				"expires_in": 3600,
				"token_type": "Bearer"
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Override the HTTP client to use our test server
	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			// Forward to test server
			req.URL.Host = strings.TrimPrefix(server.URL, "http://")
			req.URL.Scheme = "http"
			return http.DefaultClient.Do(req)
		},
	})

	ctx := context.Background()

	// First call should fetch token
	token1, err := provider.getAccessToken(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token1 != "test-access-token" {
		t.Errorf("expected token %q, got %q", "test-access-token", token1)
	}
	if tokenRequestCount != 1 {
		t.Errorf("expected 1 token request, got %d", tokenRequestCount)
	}

	// Second call should use cached token (no additional HTTP request)
	token2, err := provider.getAccessToken(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token2 != "test-access-token" {
		t.Errorf("expected token %q, got %q", "test-access-token", token2)
	}
	if tokenRequestCount != 1 {
		t.Errorf("expected 1 token request (cached), got %d", tokenRequestCount)
	}
}

func TestIntuneProvider_getAccessToken_Refresh(t *testing.T) {
	tokenRequestCount := 0

	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "oauth2/v2.0/token") {
				tokenRequestCount++
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token": "test-token",
						"expires_in": 3600,
						"token_type": "Bearer"
					}`)),
				}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	})

	ctx := context.Background()

	// First call
	_, err = provider.getAccessToken(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenRequestCount != 1 {
		t.Errorf("expected 1 token request, got %d", tokenRequestCount)
	}

	// Simulate expired token by setting expiry in the past
	provider.tokenMu.Lock()
	provider.tokenExpiry = time.Now().Add(-1 * time.Hour)
	provider.tokenMu.Unlock()

	// Next call should refresh
	_, err = provider.getAccessToken(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenRequestCount != 2 {
		t.Errorf("expected 2 token requests after expiry, got %d", tokenRequestCount)
	}
}

func TestIntuneProvider_getAccessToken_AuthFailed(t *testing.T) {
	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "invalid:credentials",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader(`{"error": "invalid_client"}`)),
			}, nil
		},
	})

	ctx := context.Background()
	_, err = provider.getAccessToken(ctx)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrMDMAuthFailed) {
		t.Errorf("expected ErrMDMAuthFailed, got %v", err)
	}
}

func TestIntuneProvider_getAccessToken_NetworkError(t *testing.T) {
	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("network error")
		},
	})

	ctx := context.Background()
	_, err = provider.getAccessToken(ctx)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrMDMUnavailable) {
		t.Errorf("expected ErrMDMUnavailable, got %v", err)
	}
}

func TestIntuneProvider_getAccessToken_InvalidJSON(t *testing.T) {
	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{invalid json`)),
			}, nil
		},
	})

	ctx := context.Background()
	_, err = provider.getAccessToken(ctx)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "parse token response") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestIntuneProvider_LookupDevice_Success(t *testing.T) {
	// Create mock HTTP server returning valid Intune response
	requestCount := 0
	var authHeader string

	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			// Token request
			if strings.Contains(req.URL.String(), "oauth2/v2.0/token") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token": "test-bearer-token",
						"expires_in": 3600,
						"token_type": "Bearer"
					}`)),
				}, nil
			}

			// Device lookup request
			if strings.Contains(req.URL.String(), "managedDevices") {
				requestCount++
				authHeader = req.Header.Get("Authorization")

				// Verify Accept header
				if req.Header.Get("Accept") != "application/json" {
					t.Errorf("expected Accept header 'application/json', got %q", req.Header.Get("Accept"))
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"value": [{
							"id": "device-123",
							"deviceName": "John's Windows PC",
							"complianceState": "compliant",
							"lastSyncDateTime": "2026-01-25T12:00:00Z",
							"operatingSystem": "Windows",
							"osVersion": "10.0.19045.1234",
							"azureADDeviceId": "azure-device-id-123",
							"isEncrypted": true,
							"jailBroken": "Unknown"
						}]
					}`)),
				}, nil
			}

			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	})

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "azure-device-id-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Authorization header
	if authHeader != "Bearer test-bearer-token" {
		t.Errorf("expected Authorization header 'Bearer test-bearer-token', got %q", authHeader)
	}

	if info == nil {
		t.Fatal("expected non-nil MDMDeviceInfo")
	}

	// Verify MDMDeviceInfo fields
	if info.DeviceID != "azure-device-id-123" {
		t.Errorf("expected DeviceID %q, got %q", "azure-device-id-123", info.DeviceID)
	}
	if !info.Enrolled {
		t.Error("expected Enrolled to be true")
	}
	if !info.Compliant {
		t.Error("expected Compliant to be true")
	}
	if info.DeviceName != "John's Windows PC" {
		t.Errorf("expected DeviceName %q, got %q", "John's Windows PC", info.DeviceName)
	}
	if info.OSVersion != "10.0.19045.1234" {
		t.Errorf("expected OSVersion %q, got %q", "10.0.19045.1234", info.OSVersion)
	}
	if info.MDMProvider != "intune" {
		t.Errorf("expected MDMProvider %q, got %q", "intune", info.MDMProvider)
	}
	if info.LastCheckIn.IsZero() {
		t.Error("expected LastCheckIn to be populated")
	}
	if info.ComplianceDetails != "" {
		t.Errorf("expected empty ComplianceDetails for compliant device, got %q", info.ComplianceDetails)
	}
}

func TestIntuneProvider_LookupDevice_NonCompliant(t *testing.T) {
	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "oauth2/v2.0/token") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token": "test-token",
						"expires_in": 3600,
						"token_type": "Bearer"
					}`)),
				}, nil
			}

			if strings.Contains(req.URL.String(), "managedDevices") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"value": [{
							"id": "device-456",
							"deviceName": "NonCompliant Device",
							"complianceState": "noncompliant",
							"lastSyncDateTime": "2026-01-20T10:00:00Z",
							"osVersion": "10.0.18363.0",
							"azureADDeviceId": "noncompliant-device-id"
						}]
					}`)),
				}, nil
			}

			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	})

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "noncompliant-device-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Compliant {
		t.Error("expected Compliant to be false for noncompliant device")
	}

	if !strings.Contains(info.ComplianceDetails, "noncompliant") {
		t.Errorf("expected ComplianceDetails to contain 'noncompliant', got %q", info.ComplianceDetails)
	}
}

func TestIntuneProvider_LookupDevice_NotFound(t *testing.T) {
	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "oauth2/v2.0/token") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token": "test-token",
						"expires_in": 3600,
						"token_type": "Bearer"
					}`)),
				}, nil
			}

			// Return empty results
			if strings.Contains(req.URL.String(), "managedDevices") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"value": []}`)),
				}, nil
			}

			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	})

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "nonexistent-device")

	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Should return ErrDeviceNotFound
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Errorf("expected ErrDeviceNotFound, got %v", err)
	}
}

func TestIntuneProvider_LookupDevice_AuthFailed(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"401 Unauthorized", http.StatusUnauthorized},
		{"403 Forbidden", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewIntuneProvider(&MDMConfig{
				ProviderType: "intune",
				TenantID:     "test-tenant",
				APIToken:     "invalid:credentials",
			})
			if err != nil {
				t.Fatalf("failed to create provider: %v", err)
			}

			provider.withHTTPClient(&mockIntuneHTTPClient{
				handler: func(req *http.Request) (*http.Response, error) {
					if strings.Contains(req.URL.String(), "oauth2/v2.0/token") {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body: io.NopCloser(strings.NewReader(`{
								"access_token": "test-token",
								"expires_in": 3600,
								"token_type": "Bearer"
							}`)),
						}, nil
					}

					// Device lookup returns auth failure
					return &http.Response{
						StatusCode: tt.statusCode,
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				},
			})

			ctx := context.Background()
			info, err := provider.LookupDevice(ctx, "test-device")

			if info != nil {
				t.Errorf("expected nil info, got %+v", info)
			}

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			// Should wrap ErrMDMAuthFailed
			var mdmErr *MDMError
			if !errors.As(err, &mdmErr) {
				t.Fatalf("expected MDMError, got %T", err)
			}

			if !errors.Is(mdmErr.Err, ErrMDMAuthFailed) {
				t.Errorf("expected ErrMDMAuthFailed, got %v", mdmErr.Err)
			}
		})
	}
}

func TestIntuneProvider_LookupDevice_Timeout(t *testing.T) {
	// Create a server that delays response beyond timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than the timeout
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
		Timeout:      50 * time.Millisecond, // Short timeout
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "test-device")

	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Should wrap ErrMDMUnavailable for timeout
	var mdmErr *MDMError
	if !errors.As(err, &mdmErr) {
		t.Fatalf("expected MDMError, got %T: %v", err, err)
	}

	// Token fetch failure results in ErrMDMUnavailable
	if !errors.Is(mdmErr.Err, ErrMDMUnavailable) && !errors.Is(err, ErrMDMUnavailable) {
		t.Errorf("expected ErrMDMUnavailable, got %v", err)
	}
}

func TestIntuneProvider_LookupDevice_EmptyDeviceID(t *testing.T) {
	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "")

	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}

	if !errors.Is(err, ErrDeviceNotFound) {
		t.Errorf("expected ErrDeviceNotFound, got %v", err)
	}
}

func TestIntuneProvider_ImplementsProviderInterface(t *testing.T) {
	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Verify IntuneProvider implements Provider interface
	var _ Provider = provider
}

func TestIntuneProvider_LookupDevice_ServerError(t *testing.T) {
	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "oauth2/v2.0/token") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token": "test-token",
						"expires_in": 3600,
						"token_type": "Bearer"
					}`)),
				}, nil
			}

			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		},
	})

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "test-device")

	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Should be an MDMError with unexpected status code message
	var mdmErr *MDMError
	if !errors.As(err, &mdmErr) {
		t.Fatalf("expected MDMError, got %T", err)
	}

	if !strings.Contains(mdmErr.Err.Error(), "unexpected status code") {
		t.Errorf("expected error about unexpected status code, got %v", mdmErr.Err)
	}
}

func TestIntuneProvider_parseIntuneResponse(t *testing.T) {
	provider, _ := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})

	tests := []struct {
		name        string
		body        string
		wantErr     error
		wantEnroll  bool
		wantComply  bool
		wantDetails string
	}{
		{
			name: "valid response with compliant device",
			body: `{
				"value": [{
					"id": "123",
					"deviceName": "Test Device",
					"complianceState": "compliant",
					"lastSyncDateTime": "2026-01-25T10:00:00Z",
					"osVersion": "10.0.19045",
					"azureADDeviceId": "azure-123"
				}]
			}`,
			wantErr:    nil,
			wantEnroll: true,
			wantComply: true,
		},
		{
			name: "valid response with noncompliant device",
			body: `{
				"value": [{
					"id": "456",
					"deviceName": "NonCompliant",
					"complianceState": "noncompliant",
					"lastSyncDateTime": "2026-01-25T10:00:00Z",
					"azureADDeviceId": "azure-456"
				}]
			}`,
			wantErr:     nil,
			wantEnroll:  true,
			wantComply:  false,
			wantDetails: "Device compliance state: noncompliant",
		},
		{
			name: "valid response with inGracePeriod device",
			body: `{
				"value": [{
					"id": "789",
					"deviceName": "GracePeriod",
					"complianceState": "inGracePeriod",
					"lastSyncDateTime": "2026-01-25T10:00:00Z",
					"azureADDeviceId": "azure-789"
				}]
			}`,
			wantErr:     nil,
			wantEnroll:  true,
			wantComply:  false,
			wantDetails: "Device compliance state: inGracePeriod",
		},
		{
			name: "valid response with unknown compliance",
			body: `{
				"value": [{
					"id": "abc",
					"deviceName": "Unknown",
					"complianceState": "unknown",
					"azureADDeviceId": "azure-abc"
				}]
			}`,
			wantErr:     nil,
			wantEnroll:  true,
			wantComply:  false,
			wantDetails: "Device compliance state: unknown",
		},
		{
			name:    "empty results returns ErrDeviceNotFound",
			body:    `{"value": []}`,
			wantErr: ErrDeviceNotFound,
		},
		{
			name:    "invalid JSON returns ErrMDMUnavailable",
			body:    `{invalid json`,
			wantErr: ErrMDMUnavailable,
		},
		{
			name:    "empty body returns ErrMDMUnavailable",
			body:    ``,
			wantErr: ErrMDMUnavailable,
		},
		{
			name: "missing azureADDeviceId uses id as fallback",
			body: `{
				"value": [{
					"id": "fallback-id",
					"deviceName": "Device",
					"complianceState": "compliant"
				}]
			}`,
			wantErr:    nil,
			wantEnroll: true,
			wantComply: true,
		},
		{
			name: "alternate time format parsed",
			body: `{
				"value": [{
					"id": "123",
					"deviceName": "Test",
					"complianceState": "compliant",
					"lastSyncDateTime": "2026-01-25T10:00:00",
					"azureADDeviceId": "azure-123"
				}]
			}`,
			wantErr:    nil,
			wantEnroll: true,
			wantComply: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := provider.parseIntuneResponse([]byte(tt.body))

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if info == nil {
				t.Fatal("expected non-nil info")
			}

			if info.Enrolled != tt.wantEnroll {
				t.Errorf("expected Enrolled=%v, got %v", tt.wantEnroll, info.Enrolled)
			}

			if info.Compliant != tt.wantComply {
				t.Errorf("expected Compliant=%v, got %v", tt.wantComply, info.Compliant)
			}

			if tt.wantDetails != "" && info.ComplianceDetails != tt.wantDetails {
				t.Errorf("expected ComplianceDetails=%q, got %q", tt.wantDetails, info.ComplianceDetails)
			}

			if info.MDMProvider != "intune" {
				t.Errorf("expected MDMProvider=%q, got %q", "intune", info.MDMProvider)
			}
		})
	}
}

func TestIntuneProvider_TokenCaching_ConcurrentAccess(t *testing.T) {
	requestCount := 0
	var mu sync.Mutex

	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "oauth2/v2.0/token") {
				mu.Lock()
				requestCount++
				mu.Unlock()
				// Small delay to increase chance of race conditions
				time.Sleep(10 * time.Millisecond)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token": "concurrent-token",
						"expires_in": 3600,
						"token_type": "Bearer"
					}`)),
				}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	})

	ctx := context.Background()
	var wg sync.WaitGroup
	concurrency := 10

	// Launch multiple concurrent token requests
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := provider.getAccessToken(ctx)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if token != "concurrent-token" {
				t.Errorf("unexpected token: %s", token)
			}
		}()
	}

	wg.Wait()

	// Should have at most a few token requests due to caching
	// (may be more than 1 if goroutines race before first cache)
	mu.Lock()
	count := requestCount
	mu.Unlock()

	if count > 3 {
		t.Errorf("expected at most 3 token requests with caching, got %d", count)
	}
}

func TestIntuneProvider_LookupDevice_FallbackToDeviceName(t *testing.T) {
	lookupAttempts := 0

	provider, err := NewIntuneProvider(&MDMConfig{
		ProviderType: "intune",
		TenantID:     "test-tenant",
		APIToken:     "client_id:client_secret",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider.withHTTPClient(&mockIntuneHTTPClient{
		handler: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "oauth2/v2.0/token") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{
						"access_token": "test-token",
						"expires_in": 3600,
						"token_type": "Bearer"
					}`)),
				}, nil
			}

			if strings.Contains(req.URL.String(), "managedDevices") {
				lookupAttempts++
				// First attempt (by azureADDeviceId) returns empty
				if strings.Contains(req.URL.String(), "azureADDeviceId") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"value": []}`)),
					}, nil
				}
				// Second attempt (by deviceName) returns device
				if strings.Contains(req.URL.String(), "deviceName") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body: io.NopCloser(strings.NewReader(`{
							"value": [{
								"id": "found-by-name",
								"deviceName": "my-device-name",
								"complianceState": "compliant",
								"azureADDeviceId": ""
							}]
						}`)),
					}, nil
				}
			}

			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	})

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "my-device-name")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info == nil {
		t.Fatal("expected device info")
	}

	// Verify we tried both lookup methods
	if lookupAttempts < 2 {
		t.Errorf("expected at least 2 lookup attempts (azureADDeviceId then deviceName), got %d", lookupAttempts)
	}

	// Device found by name should use id as fallback for DeviceID
	if info.DeviceID != "found-by-name" {
		t.Errorf("expected DeviceID %q (fallback to id), got %q", "found-by-name", info.DeviceID)
	}
}

// mockIntuneHTTPClient implements intuneAPI for testing
type mockIntuneHTTPClient struct {
	handler func(req *http.Request) (*http.Response, error)
}

func (m *mockIntuneHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.handler(req)
}
