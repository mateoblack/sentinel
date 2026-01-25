package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRemoteCredentialClient_GetCredentials_ValidResponse(t *testing.T) {
	// Create mock TVM server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodGet {
			t.Errorf("expected GET request, got %s", r.Method)
		}

		// Return valid container credentials response
		resp := `{
			"AccessKeyId": "ASIATESTACCESSKEY",
			"SecretAccessKey": "testsecretaccesskey",
			"Token": "testtoken123",
			"Expiration": "2024-01-01T12:00:00Z"
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer server.Close()

	client := NewRemoteCredentialClient(server.URL, "test-token")
	result, err := client.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify parsed credentials
	if result.AccessKeyID != "ASIATESTACCESSKEY" {
		t.Errorf("expected AccessKeyID 'ASIATESTACCESSKEY', got %q", result.AccessKeyID)
	}
	if result.SecretAccessKey != "testsecretaccesskey" {
		t.Errorf("expected SecretAccessKey 'testsecretaccesskey', got %q", result.SecretAccessKey)
	}
	if result.SessionToken != "testtoken123" {
		t.Errorf("expected SessionToken 'testtoken123', got %q", result.SessionToken)
	}

	expectedExpiration, _ := time.Parse(time.RFC3339, "2024-01-01T12:00:00Z")
	if !result.Expiration.Equal(expectedExpiration) {
		t.Errorf("expected Expiration %v, got %v", expectedExpiration, result.Expiration)
	}
}

func TestRemoteCredentialClient_GetCredentials_WithAuthToken(t *testing.T) {
	// Create mock TVM server that verifies auth token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer my-auth-token" {
			t.Errorf("expected Authorization 'Bearer my-auth-token', got %q", authHeader)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Return valid response
		resp := `{
			"AccessKeyId": "ASIATOKENTEST",
			"SecretAccessKey": "secretwithtokenauth",
			"Token": "tokenauth123",
			"Expiration": "2024-02-01T12:00:00Z"
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer server.Close()

	client := NewRemoteCredentialClient(server.URL, "my-auth-token")
	result, err := client.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessKeyID != "ASIATOKENTEST" {
		t.Errorf("expected AccessKeyID 'ASIATOKENTEST', got %q", result.AccessKeyID)
	}
}

func TestRemoteCredentialClient_GetCredentials_HTTPError(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		expectedErrMsg string
	}{
		{
			name:           "server returns 403 with TVM error",
			statusCode:     http.StatusForbidden,
			responseBody:   `{"Code": "POLICY_DENY", "Message": "Access denied by policy"}`,
			expectedErrMsg: "TVM error (POLICY_DENY): Access denied by policy",
		},
		{
			name:           "server returns 500",
			statusCode:     http.StatusInternalServerError,
			responseBody:   `{"Code": "INTERNAL_ERROR", "Message": "Internal server error"}`,
			expectedErrMsg: "TVM error (INTERNAL_ERROR): Internal server error",
		},
		{
			name:           "server returns 401",
			statusCode:     http.StatusUnauthorized,
			responseBody:   `{"Code": "UNAUTHORIZED", "Message": "Authentication failed"}`,
			expectedErrMsg: "TVM error (UNAUTHORIZED): Authentication failed",
		},
		{
			name:           "server returns non-JSON error",
			statusCode:     http.StatusServiceUnavailable,
			responseBody:   `Service Unavailable`,
			expectedErrMsg: "TVM returned status 503",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.responseBody))
			}))
			defer server.Close()

			client := NewRemoteCredentialClient(server.URL, "test-token")
			_, err := client.GetCredentials(context.Background())
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tc.expectedErrMsg) {
				t.Errorf("expected error to contain %q, got: %v", tc.expectedErrMsg, err)
			}
		})
	}
}

func TestRemoteCredentialClient_GetCredentials_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	client := NewRemoteCredentialClient(server.URL, "test-token")
	_, err := client.GetCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse credentials") {
		t.Errorf("expected error to mention 'failed to parse credentials', got: %v", err)
	}
}

func TestRemoteCredentialClient_GetCredentials_MissingFields(t *testing.T) {
	tests := []struct {
		name         string
		responseBody string
	}{
		{
			name:         "missing AccessKeyId",
			responseBody: `{"SecretAccessKey": "secret", "Token": "token", "Expiration": "2024-01-01T12:00:00Z"}`,
		},
		{
			name:         "missing SecretAccessKey",
			responseBody: `{"AccessKeyId": "ASIA123", "Token": "token", "Expiration": "2024-01-01T12:00:00Z"}`,
		},
		{
			name:         "empty AccessKeyId",
			responseBody: `{"AccessKeyId": "", "SecretAccessKey": "secret", "Token": "token", "Expiration": "2024-01-01T12:00:00Z"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tc.responseBody))
			}))
			defer server.Close()

			client := NewRemoteCredentialClient(server.URL, "test-token")
			_, err := client.GetCredentials(context.Background())
			if err == nil {
				t.Fatal("expected error for missing required field, got nil")
			}
			if !strings.Contains(err.Error(), "invalid credential response") {
				t.Errorf("expected error to mention 'invalid credential response', got: %v", err)
			}
		})
	}
}

func TestRemoteCredentialClient_GetCredentials_InvalidExpiration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := `{
			"AccessKeyId": "ASIA123",
			"SecretAccessKey": "secret123",
			"Token": "token123",
			"Expiration": "not-a-valid-date"
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer server.Close()

	client := NewRemoteCredentialClient(server.URL, "test-token")
	_, err := client.GetCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid expiration date, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse expiration time") {
		t.Errorf("expected error to mention 'failed to parse expiration time', got: %v", err)
	}
}

func TestRemoteCredentialClient_GetCredentials_NoExpiration(t *testing.T) {
	// Credentials without expiration should still work (non-expiring credentials)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := `{
			"AccessKeyId": "ASIA123",
			"SecretAccessKey": "secret123",
			"Token": "token123"
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer server.Close()

	client := NewRemoteCredentialClient(server.URL, "test-token")
	result, err := client.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessKeyID != "ASIA123" {
		t.Errorf("expected AccessKeyID 'ASIA123', got %q", result.AccessKeyID)
	}
	if !result.Expiration.IsZero() {
		t.Errorf("expected zero expiration for credentials without Expiration field, got %v", result.Expiration)
	}
}

func TestRemoteCredentialClient_Constructor(t *testing.T) {
	t.Run("NewRemoteCredentialClient sets URL and AuthToken", func(t *testing.T) {
		client := NewRemoteCredentialClient("https://api.example.com/tvm", "my-token")
		if client.URL != "https://api.example.com/tvm" {
			t.Errorf("expected URL 'https://api.example.com/tvm', got %q", client.URL)
		}
		if client.AuthToken != "my-token" {
			t.Errorf("expected AuthToken 'my-token', got %q", client.AuthToken)
		}
		if client.HTTPClient != nil {
			t.Error("expected HTTPClient to be nil by default")
		}
	})

	t.Run("NewRemoteCredentialClient with empty auth token for SigV4", func(t *testing.T) {
		client := NewRemoteCredentialClient("https://api.example.com/tvm", "")
		if client.URL != "https://api.example.com/tvm" {
			t.Errorf("expected URL 'https://api.example.com/tvm', got %q", client.URL)
		}
		if client.AuthToken != "" {
			t.Errorf("expected empty AuthToken for SigV4 mode, got %q", client.AuthToken)
		}
	})
}

func TestRemoteCredentialClient_GetCredentials_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewRemoteCredentialClient(server.URL, "test-token")

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetCredentials(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

// mockTVMServer creates a mock TVM server for testing.
// Returns credentials in AWS container credentials format.
func mockTVMServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := `{
			"AccessKeyId": "ASIATESTACCESSKEY",
			"SecretAccessKey": "testsecret",
			"Token": "testtoken",
			"Expiration": "2024-01-01T00:00:00Z"
		}`
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
	}))
}

func TestMockTVMServer(t *testing.T) {
	// Test that the mock server helper works correctly
	server := mockTVMServer(t)
	defer server.Close()

	client := NewRemoteCredentialClient(server.URL, "test-token")
	result, err := client.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AccessKeyID != "ASIATESTACCESSKEY" {
		t.Errorf("expected AccessKeyID 'ASIATESTACCESSKEY', got %q", result.AccessKeyID)
	}
}

func TestRemoteCredentialClient_WithDeviceID(t *testing.T) {
	// Create mock TVM server that captures and verifies the device_id parameter
	var capturedDeviceID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the device_id query parameter
		capturedDeviceID = r.URL.Query().Get("device_id")

		// Return valid credentials
		resp := `{
			"AccessKeyId": "ASIADEVICEIDTEST",
			"SecretAccessKey": "secretwithdeviceid",
			"Token": "deviceidtoken123",
			"Expiration": "2024-01-01T12:00:00Z"
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer server.Close()

	// Test with a valid device ID (64-char lowercase hex)
	deviceID := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	client := &RemoteCredentialClient{
		URL:       server.URL,
		AuthToken: "test-token",
		DeviceID:  deviceID,
	}

	result, err := client.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify device_id was sent in request
	if capturedDeviceID != deviceID {
		t.Errorf("expected device_id %q in request, got %q", deviceID, capturedDeviceID)
	}

	// Verify response was parsed correctly
	if result.AccessKeyID != "ASIADEVICEIDTEST" {
		t.Errorf("expected AccessKeyID 'ASIADEVICEIDTEST', got %q", result.AccessKeyID)
	}
}

func TestRemoteCredentialClient_WithoutDeviceID(t *testing.T) {
	// Create mock TVM server that verifies no device_id parameter is present
	var capturedDeviceID string
	var hasDeviceIDParam bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if device_id is present at all
		_, hasDeviceIDParam = r.URL.Query()["device_id"]
		capturedDeviceID = r.URL.Query().Get("device_id")

		// Return valid credentials
		resp := `{
			"AccessKeyId": "ASIANODEVICEID",
			"SecretAccessKey": "secretnodeviceid",
			"Token": "nodeviceidtoken",
			"Expiration": "2024-01-01T12:00:00Z"
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer server.Close()

	// Test without device ID (backward compatibility)
	client := NewRemoteCredentialClient(server.URL, "test-token")

	result, err := client.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no device_id was sent in request
	if hasDeviceIDParam {
		t.Errorf("expected no device_id parameter, but found: %q", capturedDeviceID)
	}

	// Verify response was parsed correctly
	if result.AccessKeyID != "ASIANODEVICEID" {
		t.Errorf("expected AccessKeyID 'ASIANODEVICEID', got %q", result.AccessKeyID)
	}
}

func TestRemoteCredentialClient_WithExistingQueryParams(t *testing.T) {
	// Create mock TVM server that captures all query parameters
	var capturedProfile string
	var capturedDeviceID string
	var capturedDuration string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture all query parameters
		capturedProfile = r.URL.Query().Get("profile")
		capturedDeviceID = r.URL.Query().Get("device_id")
		capturedDuration = r.URL.Query().Get("duration")

		// Return valid credentials
		resp := `{
			"AccessKeyId": "ASIAMULTIPARAM",
			"SecretAccessKey": "secretmultiparam",
			"Token": "multiparamtoken",
			"Expiration": "2024-01-01T12:00:00Z"
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer server.Close()

	// Test with existing query parameters (profile and duration) plus device_id
	deviceID := "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
	urlWithParams := server.URL + "?profile=production&duration=3600"
	client := &RemoteCredentialClient{
		URL:       urlWithParams,
		AuthToken: "test-token",
		DeviceID:  deviceID,
	}

	result, err := client.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all query parameters are present
	if capturedProfile != "production" {
		t.Errorf("expected profile 'production', got %q", capturedProfile)
	}
	if capturedDuration != "3600" {
		t.Errorf("expected duration '3600', got %q", capturedDuration)
	}
	if capturedDeviceID != deviceID {
		t.Errorf("expected device_id %q, got %q", deviceID, capturedDeviceID)
	}

	// Verify response was parsed correctly
	if result.AccessKeyID != "ASIAMULTIPARAM" {
		t.Errorf("expected AccessKeyID 'ASIAMULTIPARAM', got %q", result.AccessKeyID)
	}
}

func TestRemoteCredentialClient_DeviceIDField(t *testing.T) {
	t.Run("DeviceID field is empty by default", func(t *testing.T) {
		client := NewRemoteCredentialClient("https://api.example.com/tvm", "token")
		if client.DeviceID != "" {
			t.Errorf("expected DeviceID to be empty by default, got %q", client.DeviceID)
		}
	})

	t.Run("DeviceID field can be set", func(t *testing.T) {
		deviceID := "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
		client := &RemoteCredentialClient{
			URL:       "https://api.example.com/tvm",
			AuthToken: "token",
			DeviceID:  deviceID,
		}
		if client.DeviceID != deviceID {
			t.Errorf("expected DeviceID %q, got %q", deviceID, client.DeviceID)
		}
	})
}
