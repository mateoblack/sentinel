package mdm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewJamfProvider(t *testing.T) {
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
			name: "missing BaseURL returns error",
			cfg: &MDMConfig{
				ProviderType: "jamf",
				APIToken:     "test-token",
			},
			wantErr: "base_url is required",
		},
		{
			name: "missing APIToken returns error",
			cfg: &MDMConfig{
				ProviderType: "jamf",
				BaseURL:      "https://test.jamfcloud.com",
			},
			wantErr: "api_token is required",
		},
		{
			name: "valid config creates provider",
			cfg: &MDMConfig{
				ProviderType: "jamf",
				BaseURL:      "https://test.jamfcloud.com",
				APIToken:     "test-token",
			},
			wantErr: "",
		},
		{
			name: "default timeout applied when not specified",
			cfg: &MDMConfig{
				ProviderType: "jamf",
				BaseURL:      "https://test.jamfcloud.com",
				APIToken:     "test-token",
				Timeout:      0, // Zero triggers default
			},
			wantErr: "",
		},
		{
			name: "custom timeout applied when specified",
			cfg: &MDMConfig{
				ProviderType: "jamf",
				BaseURL:      "https://test.jamfcloud.com",
				APIToken:     "test-token",
				Timeout:      30 * time.Second,
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewJamfProvider(tt.cfg)

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

			if provider.Name() != "jamf" {
				t.Errorf("expected provider name %q, got %q", "jamf", provider.Name())
			}

			if provider.baseURL != tt.cfg.BaseURL {
				t.Errorf("expected baseURL %q, got %q", tt.cfg.BaseURL, provider.baseURL)
			}

			if provider.apiToken != tt.cfg.APIToken {
				t.Errorf("expected apiToken %q, got %q", tt.cfg.APIToken, provider.apiToken)
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

func TestJamfProvider_LookupDevice_Success(t *testing.T) {
	// Create mock HTTP server returning valid Jamf response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization header 'Bearer test-token', got %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept header 'application/json', got %q", r.Header.Get("Accept"))
		}

		// Return valid Jamf response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"totalCount": 1,
			"results": [{
				"id": "12345",
				"general": {
					"name": "John's MacBook Pro",
					"lastContactTime": "2026-01-25T12:00:00Z",
					"managed": true,
					"managementId": "mgmt-123",
					"remoteManagement": {
						"managed": true,
						"managementUsername": "admin"
					}
				},
				"hardware": {
					"serialNumber": "C02ABC123DEF",
					"osVersion": "14.2.1"
				}
			}]
		}`))
	}))
	defer server.Close()

	provider, err := NewJamfProvider(&MDMConfig{
		ProviderType: "jamf",
		BaseURL:      server.URL,
		APIToken:     "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "test-device-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info == nil {
		t.Fatal("expected non-nil MDMDeviceInfo")
	}

	// Verify MDMDeviceInfo fields
	if info.DeviceID != "12345" {
		t.Errorf("expected DeviceID %q, got %q", "12345", info.DeviceID)
	}
	if !info.Enrolled {
		t.Error("expected Enrolled to be true")
	}
	if !info.Compliant {
		t.Error("expected Compliant to be true")
	}
	if info.DeviceName != "John's MacBook Pro" {
		t.Errorf("expected DeviceName %q, got %q", "John's MacBook Pro", info.DeviceName)
	}
	if info.OSVersion != "14.2.1" {
		t.Errorf("expected OSVersion %q, got %q", "14.2.1", info.OSVersion)
	}
	if info.MDMProvider != "jamf" {
		t.Errorf("expected MDMProvider %q, got %q", "jamf", info.MDMProvider)
	}
	if info.LastCheckIn.IsZero() {
		t.Error("expected LastCheckIn to be populated")
	}
}

func TestJamfProvider_LookupDevice_NotFound(t *testing.T) {
	// Create mock HTTP server returning empty results
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"totalCount": 0,
			"results": []
		}`))
	}))
	defer server.Close()

	provider, err := NewJamfProvider(&MDMConfig{
		ProviderType: "jamf",
		BaseURL:      server.URL,
		APIToken:     "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "nonexistent-device")

	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Should wrap ErrDeviceNotFound
	var mdmErr *MDMError
	if errors.As(err, &mdmErr) {
		if !errors.Is(mdmErr.Err, ErrDeviceNotFound) {
			t.Errorf("expected ErrDeviceNotFound, got %v", mdmErr.Err)
		}
	} else if !errors.Is(err, ErrDeviceNotFound) {
		t.Errorf("expected ErrDeviceNotFound, got %v", err)
	}
}

func TestJamfProvider_LookupDevice_AuthFailed(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"401 Unauthorized", http.StatusUnauthorized},
		{"403 Forbidden", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			provider, err := NewJamfProvider(&MDMConfig{
				ProviderType: "jamf",
				BaseURL:      server.URL,
				APIToken:     "invalid-token",
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

func TestJamfProvider_LookupDevice_Timeout(t *testing.T) {
	// Create a server that delays response beyond timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than the timeout
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider, err := NewJamfProvider(&MDMConfig{
		ProviderType: "jamf",
		BaseURL:      server.URL,
		APIToken:     "test-token",
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

	if !errors.Is(mdmErr.Err, ErrMDMUnavailable) {
		t.Errorf("expected ErrMDMUnavailable, got %v", mdmErr.Err)
	}
}

func TestJamfProvider_LookupDevice_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if context is cancelled
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	provider, err := NewJamfProvider(&MDMConfig{
		ProviderType: "jamf",
		BaseURL:      server.URL,
		APIToken:     "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Create a context that is already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	info, err := provider.LookupDevice(ctx, "test-device")

	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestJamfProvider_LookupDevice_EmptyDeviceID(t *testing.T) {
	provider, err := NewJamfProvider(&MDMConfig{
		ProviderType: "jamf",
		BaseURL:      "https://test.jamfcloud.com",
		APIToken:     "test-token",
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

func TestParseJamfResponse(t *testing.T) {
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
				"totalCount": 1,
				"results": [{
					"id": "123",
					"general": {
						"name": "Test Mac",
						"lastContactTime": "2026-01-25T10:00:00Z",
						"managed": true,
						"remoteManagement": {
							"managed": true
						}
					},
					"hardware": {
						"osVersion": "14.2.1"
					}
				}]
			}`,
			wantErr:    nil,
			wantEnroll: true,
			wantComply: true,
		},
		{
			name: "valid response with enrolled but non-compliant device",
			body: `{
				"totalCount": 1,
				"results": [{
					"id": "123",
					"general": {
						"name": "Test Mac",
						"lastContactTime": "2026-01-25T10:00:00Z",
						"managed": true,
						"remoteManagement": {
							"managed": false
						}
					},
					"hardware": {}
				}]
			}`,
			wantErr:     nil,
			wantEnroll:  true,
			wantComply:  false,
			wantDetails: "Remote management not enabled",
		},
		{
			name: "valid response with unenrolled device",
			body: `{
				"totalCount": 1,
				"results": [{
					"id": "123",
					"general": {
						"name": "Test Mac",
						"managed": false,
						"remoteManagement": {
							"managed": false
						}
					},
					"hardware": {}
				}]
			}`,
			wantErr:     nil,
			wantEnroll:  false,
			wantComply:  false,
			wantDetails: "Device not enrolled in MDM",
		},
		{
			name: "empty results returns ErrDeviceNotFound",
			body: `{
				"totalCount": 0,
				"results": []
			}`,
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
			name: "missing fields handled gracefully",
			body: `{
				"totalCount": 1,
				"results": [{
					"id": "123"
				}]
			}`,
			wantErr:     nil,
			wantEnroll:  false,
			wantComply:  false,
			wantDetails: "Device not enrolled in MDM",
		},
		{
			name: "alternate time format parsed",
			body: `{
				"totalCount": 1,
				"results": [{
					"id": "123",
					"general": {
						"name": "Test Mac",
						"lastContactTime": "2026-01-25T10:00:00",
						"managed": true,
						"remoteManagement": {"managed": true}
					},
					"hardware": {}
				}]
			}`,
			wantErr:    nil,
			wantEnroll: true,
			wantComply: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseJamfResponse([]byte(tt.body))

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

			if info.MDMProvider != "jamf" {
				t.Errorf("expected MDMProvider=%q, got %q", "jamf", info.MDMProvider)
			}
		})
	}
}

func TestJamfProvider_LookupDevice_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	provider, err := NewJamfProvider(&MDMConfig{
		ProviderType: "jamf",
		BaseURL:      server.URL,
		APIToken:     "test-token",
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

	// Should be an MDMError with unexpected status code message
	var mdmErr *MDMError
	if !errors.As(err, &mdmErr) {
		t.Fatalf("expected MDMError, got %T", err)
	}

	if !strings.Contains(mdmErr.Err.Error(), "unexpected status code") {
		t.Errorf("expected error about unexpected status code, got %v", mdmErr.Err)
	}
}

func TestJamfProvider_ImplementsProviderInterface(t *testing.T) {
	provider, err := NewJamfProvider(&MDMConfig{
		ProviderType: "jamf",
		BaseURL:      "https://test.jamfcloud.com",
		APIToken:     "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Verify JamfProvider implements Provider interface
	var _ Provider = provider
}

// mockHTTPClient implements jamfAPI for testing error scenarios
type mockHTTPClient struct {
	response *http.Response
	err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

func TestJamfProvider_LookupDevice_ReadBodyError(t *testing.T) {
	// Create a response with a body that fails to read
	provider, err := NewJamfProvider(&MDMConfig{
		ProviderType: "jamf",
		BaseURL:      "https://test.jamfcloud.com",
		APIToken:     "test-token",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Use mock client with error-producing body
	mockClient := &mockHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(&errorReader{}),
		},
	}
	provider.withHTTPClient(mockClient)

	ctx := context.Background()
	info, err := provider.LookupDevice(ctx, "test-device")

	if info != nil {
		t.Errorf("expected nil info, got %+v", info)
	}

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var mdmErr *MDMError
	if !errors.As(err, &mdmErr) {
		t.Fatalf("expected MDMError, got %T", err)
	}

	if !errors.Is(mdmErr.Err, ErrMDMUnavailable) {
		t.Errorf("expected ErrMDMUnavailable, got %v", mdmErr.Err)
	}
}

// errorReader always returns an error when Read is called
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}
