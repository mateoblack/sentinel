package lambda

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/byteness/aws-vault/v7/device"
	"github.com/byteness/aws-vault/v7/mdm"
)

// mockMDMProvider implements mdm.Provider for testing.
type mockMDMProvider struct {
	lookupFunc func(ctx context.Context, deviceID string) (*mdm.MDMDeviceInfo, error)
	name       string
}

func (m *mockMDMProvider) LookupDevice(ctx context.Context, deviceID string) (*mdm.MDMDeviceInfo, error) {
	if m.lookupFunc != nil {
		return m.lookupFunc(ctx, deviceID)
	}
	return nil, mdm.ErrDeviceNotFound
}

func (m *mockMDMProvider) Name() string {
	if m.name != "" {
		return m.name
	}
	return "mock"
}

// successfulMDMResponse returns a mock compliant device response.
func successfulMDMResponse(deviceID string) *mdm.MDMDeviceInfo {
	return &mdm.MDMDeviceInfo{
		DeviceID:    deviceID,
		Enrolled:    true,
		Compliant:   true,
		LastCheckIn: time.Now().Add(-time.Hour),
		OSVersion:   "14.2.1",
		DeviceName:  "Test MacBook Pro",
		MDMProvider: "mock",
	}
}

// nonCompliantMDMResponse returns a mock non-compliant device response.
func nonCompliantMDMResponse(deviceID string) *mdm.MDMDeviceInfo {
	return &mdm.MDMDeviceInfo{
		DeviceID:          deviceID,
		Enrolled:          true,
		Compliant:         false,
		ComplianceDetails: "Remote management not enabled",
		LastCheckIn:       time.Now().Add(-time.Hour),
		OSVersion:         "14.0.0",
		DeviceName:        "Test MacBook Pro",
		MDMProvider:       "mock",
	}
}

// validDeviceID returns a valid 64-character hex device ID (SHA256 output).
func validDeviceID() string {
	// 64 lowercase hex characters
	return "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
}

// ============================================================================
// extractDeviceID Tests
// ============================================================================

func TestExtractDeviceID_Valid(t *testing.T) {
	deviceID := validDeviceID()
	req := events.APIGatewayV2HTTPRequest{
		QueryStringParameters: map[string]string{
			"device_id": deviceID,
		},
	}

	got := extractDeviceID(req)
	if got != deviceID {
		t.Errorf("extractDeviceID() = %s, want %s", got, deviceID)
	}
}

func TestExtractDeviceID_Missing(t *testing.T) {
	req := events.APIGatewayV2HTTPRequest{
		QueryStringParameters: map[string]string{},
	}

	got := extractDeviceID(req)
	if got != "" {
		t.Errorf("extractDeviceID() = %s, want empty string", got)
	}
}

func TestExtractDeviceID_Invalid_TooShort(t *testing.T) {
	req := events.APIGatewayV2HTTPRequest{
		QueryStringParameters: map[string]string{
			"device_id": "a1b2c3d4", // Only 8 chars, need 64
		},
	}

	got := extractDeviceID(req)
	if got != "" {
		t.Errorf("extractDeviceID() = %s, want empty string for invalid format", got)
	}
}

func TestExtractDeviceID_Invalid_NotHex(t *testing.T) {
	req := events.APIGatewayV2HTTPRequest{
		QueryStringParameters: map[string]string{
			// 64 chars but contains non-hex characters
			"device_id": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
		},
	}

	got := extractDeviceID(req)
	if got != "" {
		t.Errorf("extractDeviceID() = %s, want empty string for invalid format", got)
	}
}

func TestExtractDeviceID_Invalid_UpperCase(t *testing.T) {
	// Valid length but uppercase (should be lowercase per device.ValidateDeviceIdentifier)
	req := events.APIGatewayV2HTTPRequest{
		QueryStringParameters: map[string]string{
			"device_id": "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
		},
	}

	got := extractDeviceID(req)
	if got != "" {
		t.Errorf("extractDeviceID() = %s, want empty string for uppercase hex", got)
	}
}

// ============================================================================
// queryDevicePosture Tests
// ============================================================================

func TestQueryDevicePosture_Success(t *testing.T) {
	deviceID := validDeviceID()
	provider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			if id != deviceID {
				t.Errorf("LookupDevice called with wrong ID: %s, want %s", id, deviceID)
			}
			return successfulMDMResponse(id), nil
		},
	}

	ctx := context.Background()
	posture, err := queryDevicePosture(ctx, provider, deviceID)
	if err != nil {
		t.Fatalf("queryDevicePosture() error: %v", err)
	}

	if posture == nil {
		t.Fatal("queryDevicePosture() returned nil posture")
	}

	// Verify mapping from MDMDeviceInfo to DevicePosture
	if posture.DeviceID != deviceID {
		t.Errorf("Posture.DeviceID = %s, want %s", posture.DeviceID, deviceID)
	}
	if posture.Status != device.StatusCompliant {
		t.Errorf("Posture.Status = %s, want %s", posture.Status, device.StatusCompliant)
	}
	if !posture.HasMDMEnrollment() {
		t.Error("Posture.HasMDMEnrollment() = false, want true")
	}
	if !posture.HasMDMCompliance() {
		t.Error("Posture.HasMDMCompliance() = false, want true")
	}
	if posture.OSVersion != "14.2.1" {
		t.Errorf("Posture.OSVersion = %s, want 14.2.1", posture.OSVersion)
	}
	if posture.CollectedAt.IsZero() {
		t.Error("Posture.CollectedAt should not be zero")
	}
}

func TestQueryDevicePosture_NonCompliant(t *testing.T) {
	deviceID := validDeviceID()
	provider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			return nonCompliantMDMResponse(id), nil
		},
	}

	ctx := context.Background()
	posture, err := queryDevicePosture(ctx, provider, deviceID)
	if err != nil {
		t.Fatalf("queryDevicePosture() error: %v", err)
	}

	if posture.Status != device.StatusNonCompliant {
		t.Errorf("Posture.Status = %s, want %s", posture.Status, device.StatusNonCompliant)
	}
	if !posture.HasMDMEnrollment() {
		t.Error("Posture.HasMDMEnrollment() = false, want true (enrolled but not compliant)")
	}
	if posture.HasMDMCompliance() {
		t.Error("Posture.HasMDMCompliance() = true, want false")
	}
}

func TestQueryDevicePosture_NotFound(t *testing.T) {
	deviceID := validDeviceID()
	provider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			return nil, mdm.ErrDeviceNotFound
		},
	}

	ctx := context.Background()
	posture, err := queryDevicePosture(ctx, provider, deviceID)
	if err != mdm.ErrDeviceNotFound {
		t.Errorf("queryDevicePosture() error = %v, want ErrDeviceNotFound", err)
	}
	if posture != nil {
		t.Error("queryDevicePosture() should return nil posture on error")
	}
}

func TestQueryDevicePosture_AuthFailed(t *testing.T) {
	deviceID := validDeviceID()
	provider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			return nil, mdm.ErrMDMAuthFailed
		},
	}

	ctx := context.Background()
	posture, err := queryDevicePosture(ctx, provider, deviceID)
	if err != mdm.ErrMDMAuthFailed {
		t.Errorf("queryDevicePosture() error = %v, want ErrMDMAuthFailed", err)
	}
	if posture != nil {
		t.Error("queryDevicePosture() should return nil posture on error")
	}
}

func TestQueryDevicePosture_Unavailable(t *testing.T) {
	deviceID := validDeviceID()
	provider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			return nil, mdm.ErrMDMUnavailable
		},
	}

	ctx := context.Background()
	posture, err := queryDevicePosture(ctx, provider, deviceID)
	if err != mdm.ErrMDMUnavailable {
		t.Errorf("queryDevicePosture() error = %v, want ErrMDMUnavailable", err)
	}
	if posture != nil {
		t.Error("queryDevicePosture() should return nil posture on error")
	}
}

// ============================================================================
// Handler MDM Integration Tests
// ============================================================================

func TestHandler_MDMIntegration_Success(t *testing.T) {
	deviceID := validDeviceID()

	mockSTS := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			expiration := time.Now().Add(time.Hour).UTC()
			return &sts.AssumeRoleOutput{
				Credentials: &types.Credentials{
					AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
					SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
					SessionToken:    aws.String("FwoGZXIvYXdzEBYaDCpjfvk..."),
					Expiration:      &expiration,
				},
				AssumedRoleUser: &types.AssumedRoleUser{
					Arn:           aws.String("arn:aws:sts::123456789012:assumed-role/test-role/tvm-testuser-a1b2c3d4"),
					AssumedRoleId: aws.String("AROA3XFRBF535EXAMPLE:tvm-testuser-a1b2c3d4"),
				},
			}, nil
		},
	}

	mdmProvider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			if id == deviceID {
				return successfulMDMResponse(id), nil
			}
			return nil, mdm.ErrDeviceNotFound
		},
	}

	logger := &mockLogger{}

	cfg := &TVMConfig{
		PolicyParameter: "/test/policy",
		PolicyLoader:    &mockPolicyLoader{policy: allowAllPolicy()},
		MDMProvider:     mdmProvider,
		Logger:          logger,
		STSClient:       mockSTS,
		Region:          "us-east-1",
		DefaultDuration: 15 * time.Minute,
	}
	handler := NewHandler(cfg)
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["device_id"] = deviceID

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify logger captured device posture
	if len(logger.entries) != 1 {
		t.Fatalf("Logger entries = %d, want 1", len(logger.entries))
	}

	entry := logger.entries[0]
	if entry.DeviceID != deviceID {
		t.Errorf("Log entry DeviceID = %s, want %s", entry.DeviceID, deviceID)
	}
	if entry.DeviceStatus != "compliant" {
		t.Errorf("Log entry DeviceStatus = %s, want compliant", entry.DeviceStatus)
	}
	if !entry.DeviceMDMEnrolled {
		t.Error("Log entry DeviceMDMEnrolled = false, want true")
	}
}

func TestHandler_MDMIntegration_NoDeviceID(t *testing.T) {
	// When no device_id is provided, handler should proceed without MDM check
	mockSTS := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			expiration := time.Now().Add(time.Hour).UTC()
			return &sts.AssumeRoleOutput{
				Credentials: &types.Credentials{
					AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
					SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
					SessionToken:    aws.String("FwoGZXIvYXdzEBYaDCpjfvk..."),
					Expiration:      &expiration,
				},
				AssumedRoleUser: &types.AssumedRoleUser{
					Arn:           aws.String("arn:aws:sts::123456789012:assumed-role/test-role/tvm-testuser-a1b2c3d4"),
					AssumedRoleId: aws.String("AROA3XFRBF535EXAMPLE:tvm-testuser-a1b2c3d4"),
				},
			}, nil
		},
	}

	mdmProvider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			t.Error("MDM should not be called when no device_id provided")
			return nil, mdm.ErrDeviceNotFound
		},
	}

	cfg := &TVMConfig{
		PolicyParameter: "/test/policy",
		PolicyLoader:    &mockPolicyLoader{policy: allowAllPolicy()},
		MDMProvider:     mdmProvider,
		STSClient:       mockSTS,
		Region:          "us-east-1",
		DefaultDuration: 15 * time.Minute,
	}
	handler := NewHandler(cfg)
	ctx := context.Background()

	// Request without device_id
	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestHandler_MDMIntegration_NoMDMConfigured(t *testing.T) {
	// When MDM is not configured, handler should proceed even with device_id
	mockSTS := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			expiration := time.Now().Add(time.Hour).UTC()
			return &sts.AssumeRoleOutput{
				Credentials: &types.Credentials{
					AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
					SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
					SessionToken:    aws.String("FwoGZXIvYXdzEBYaDCpjfvk..."),
					Expiration:      &expiration,
				},
				AssumedRoleUser: &types.AssumedRoleUser{
					Arn:           aws.String("arn:aws:sts::123456789012:assumed-role/test-role/tvm-testuser-a1b2c3d4"),
					AssumedRoleId: aws.String("AROA3XFRBF535EXAMPLE:tvm-testuser-a1b2c3d4"),
				},
			}, nil
		},
	}

	cfg := &TVMConfig{
		PolicyParameter: "/test/policy",
		PolicyLoader:    &mockPolicyLoader{policy: allowAllPolicy()},
		MDMProvider:     nil, // MDM not configured
		STSClient:       mockSTS,
		Region:          "us-east-1",
		DefaultDuration: 15 * time.Minute,
	}
	handler := NewHandler(cfg)
	ctx := context.Background()

	deviceID := validDeviceID()
	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["device_id"] = deviceID

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Should succeed even without MDM configured
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestHandler_RequireDevice_Failure(t *testing.T) {
	// RequireDevicePosture=true and MDM fails -> deny
	deviceID := validDeviceID()

	mockSTS := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called when device verification fails with RequireDevicePosture=true")
			return nil, nil
		},
	}

	mdmProvider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			return nil, mdm.ErrDeviceNotFound
		},
	}

	cfg := &TVMConfig{
		PolicyParameter:      "/test/policy",
		PolicyLoader:         &mockPolicyLoader{policy: allowAllPolicy()},
		MDMProvider:          mdmProvider,
		RequireDevicePosture: true, // Fail-closed mode
		STSClient:            mockSTS,
		Region:               "us-east-1",
		DefaultDuration:      15 * time.Minute,
	}
	handler := NewHandler(cfg)
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["device_id"] = deviceID

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Should deny due to device verification failure
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "DEVICE_VERIFICATION_FAILED" {
		t.Errorf("Error code = %s, want DEVICE_VERIFICATION_FAILED", errResp.Code)
	}
}

func TestHandler_RequireDevice_False_FailOpen(t *testing.T) {
	// RequireDevicePosture=false (default) and MDM fails -> allow (fail-open)
	deviceID := validDeviceID()

	mockSTS := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			expiration := time.Now().Add(time.Hour).UTC()
			return &sts.AssumeRoleOutput{
				Credentials: &types.Credentials{
					AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
					SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
					SessionToken:    aws.String("FwoGZXIvYXdzEBYaDCpjfvk..."),
					Expiration:      &expiration,
				},
				AssumedRoleUser: &types.AssumedRoleUser{
					Arn:           aws.String("arn:aws:sts::123456789012:assumed-role/test-role/tvm-testuser-a1b2c3d4"),
					AssumedRoleId: aws.String("AROA3XFRBF535EXAMPLE:tvm-testuser-a1b2c3d4"),
				},
			}, nil
		},
	}

	mdmProvider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			return nil, mdm.ErrDeviceNotFound
		},
	}

	cfg := &TVMConfig{
		PolicyParameter:      "/test/policy",
		PolicyLoader:         &mockPolicyLoader{policy: allowAllPolicy()},
		MDMProvider:          mdmProvider,
		RequireDevicePosture: false, // Fail-open mode (default)
		STSClient:            mockSTS,
		Region:               "us-east-1",
		DefaultDuration:      15 * time.Minute,
	}
	handler := NewHandler(cfg)
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["device_id"] = deviceID

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Should allow despite MDM lookup failure (fail-open)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleRequest() statusCode = %d, want %d (fail-open should allow)", resp.StatusCode, http.StatusOK)
	}
}

func TestHandler_RequireDevice_AuthFailure(t *testing.T) {
	// RequireDevicePosture=true and MDM auth fails -> deny
	deviceID := validDeviceID()

	mockSTS := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called when MDM auth fails with RequireDevicePosture=true")
			return nil, nil
		},
	}

	mdmProvider := &mockMDMProvider{
		lookupFunc: func(ctx context.Context, id string) (*mdm.MDMDeviceInfo, error) {
			return nil, mdm.ErrMDMAuthFailed
		},
	}

	cfg := &TVMConfig{
		PolicyParameter:      "/test/policy",
		PolicyLoader:         &mockPolicyLoader{policy: allowAllPolicy()},
		MDMProvider:          mdmProvider,
		RequireDevicePosture: true,
		STSClient:            mockSTS,
		Region:               "us-east-1",
		DefaultDuration:      15 * time.Minute,
	}
	handler := NewHandler(cfg)
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["device_id"] = deviceID

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// ============================================================================
// Error Chain Helper Tests
// ============================================================================

func TestContainsError_Direct(t *testing.T) {
	if !containsError(mdm.ErrDeviceNotFound, mdm.ErrDeviceNotFound) {
		t.Error("containsError should match direct error")
	}
}

func TestContainsError_Wrapped(t *testing.T) {
	wrapped := &mdm.MDMError{
		Provider: "test",
		DeviceID: "abc123",
		Err:      mdm.ErrDeviceNotFound,
	}
	if !containsError(wrapped, mdm.ErrDeviceNotFound) {
		t.Error("containsError should find wrapped error")
	}
}

func TestContainsError_Nil(t *testing.T) {
	if containsError(nil, mdm.ErrDeviceNotFound) {
		t.Error("containsError(nil, ...) should return false")
	}
}

func TestContainsError_Different(t *testing.T) {
	if containsError(mdm.ErrMDMAuthFailed, mdm.ErrDeviceNotFound) {
		t.Error("containsError should not match different error")
	}
}
