package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// testSTSClient implements STSClient for handler testing.
type testSTSClient struct {
	AssumeRoleFunc func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

func (m *testSTSClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.AssumeRoleFunc != nil {
		return m.AssumeRoleFunc(ctx, params, optFns...)
	}
	return nil, errors.New("AssumeRoleFunc not implemented")
}

// successfulTestSTSResponse returns a mock successful AssumeRole response.
func successfulTestSTSResponse() *sts.AssumeRoleOutput {
	expiration := time.Now().Add(time.Hour).UTC()
	return &sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
			SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
			SessionToken:    aws.String("FwoGZXIvYXdzEBYaDCpjfvkLp..."),
			Expiration:      &expiration,
		},
		AssumedRoleUser: &types.AssumedRoleUser{
			Arn:           aws.String("arn:aws:sts::123456789012:assumed-role/test-role/tvm-testuser-a1b2c3d4"),
			AssumedRoleId: aws.String("AROA3XFRBF535EXAMPLE:tvm-testuser-a1b2c3d4"),
		},
	}
}

// validIAMRequest creates a valid API Gateway request with IAM auth.
func validIAMRequest(profile string) events.APIGatewayV2HTTPRequest {
	return events.APIGatewayV2HTTPRequest{
		QueryStringParameters: map[string]string{
			"profile": profile,
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
				IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
					AccountID: "123456789012",
					UserARN:   "arn:aws:iam::123456789012:user/testuser",
					UserID:    "AIDAEXAMPLE",
				},
			},
		},
	}
}

func TestHandleRequest_Success(t *testing.T) {
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			return successfulTestSTSResponse(), nil
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify credentials are returned in correct format
	var creds TVMResponse
	if err := json.Unmarshal([]byte(resp.Body), &creds); err != nil {
		t.Fatalf("Failed to unmarshal credentials: %v", err)
	}
	if creds.AccessKeyId != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AccessKeyId = %s, want AKIAIOSFODNN7EXAMPLE", creds.AccessKeyId)
	}
	if creds.SecretAccessKey == "" {
		t.Error("SecretAccessKey should not be empty")
	}
	if creds.Token == "" {
		t.Error("Token should not be empty")
	}
	if creds.Expiration == "" {
		t.Error("Expiration should not be empty")
	}

	// Verify expiration is valid RFC3339
	_, err = time.Parse(time.RFC3339, creds.Expiration)
	if err != nil {
		t.Errorf("Expiration should be RFC3339: %v", err)
	}
}

func TestHandleRequest_WithDuration(t *testing.T) {
	var capturedDuration int32
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			if params.DurationSeconds != nil {
				capturedDuration = *params.DurationSeconds
			}
			return successfulTestSTSResponse(), nil
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	// Request with custom duration (30 minutes = 1800 seconds)
	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["duration"] = "1800"

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify duration was passed to STS
	if capturedDuration != 1800 {
		t.Errorf("Expected duration 1800, got %d", capturedDuration)
	}
}

func TestHandleRequest_InvalidDuration_TooShort(t *testing.T) {
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called for invalid duration")
			return successfulTestSTSResponse(), nil
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	// Duration 600 seconds (10 min) - below minimum 900
	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["duration"] = "600"

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "INVALID_DURATION" {
		t.Errorf("Error code = %s, want INVALID_DURATION", errResp.Code)
	}
}

func TestHandleRequest_InvalidDuration_TooLong(t *testing.T) {
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called for invalid duration")
			return successfulTestSTSResponse(), nil
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	// Duration 50000 seconds - above maximum 43200
	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["duration"] = "50000"

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "INVALID_DURATION" {
		t.Errorf("Error code = %s, want INVALID_DURATION", errResp.Code)
	}
}

func TestHandleRequest_InvalidDuration_NotNumber(t *testing.T) {
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called for invalid duration")
			return successfulTestSTSResponse(), nil
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	// Non-numeric duration
	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["duration"] = "not-a-number"

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "INVALID_DURATION" {
		t.Errorf("Error code = %s, want INVALID_DURATION", errResp.Code)
	}
}

func TestHandleRequest_STSError(t *testing.T) {
	stsErr := errors.New("STS access denied")
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			return nil, stsErr
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Should return 500 for STS errors
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "CREDENTIAL_ERROR" {
		t.Errorf("Error code = %s, want CREDENTIAL_ERROR", errResp.Code)
	}

	// Error message should be generic (not leak STS error details)
	if errResp.Message != "Failed to vend credentials" {
		t.Errorf("Error message = %s, should be generic", errResp.Message)
	}
}

func TestHandleRequest_SourceIdentityInSTSCall(t *testing.T) {
	var capturedSourceIdentity string
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			if params.SourceIdentity != nil {
				capturedSourceIdentity = *params.SourceIdentity
			}
			return successfulTestSTSResponse(), nil
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify SourceIdentity was passed to STS
	if capturedSourceIdentity == "" {
		t.Error("SourceIdentity should be set in STS call")
	}

	// Verify format: sentinel:<user>:direct:<request-id>
	expectedPrefix := "sentinel:testuser:direct:"
	if len(capturedSourceIdentity) < len(expectedPrefix) {
		t.Errorf("SourceIdentity too short: %s", capturedSourceIdentity)
	}
	if capturedSourceIdentity[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("SourceIdentity = %s, should start with %s", capturedSourceIdentity, expectedPrefix)
	}
}

func TestHandleRequest_MissingIAMAuth(t *testing.T) {
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called without IAM auth")
			return successfulTestSTSResponse(), nil
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	req := events.APIGatewayV2HTTPRequest{
		QueryStringParameters: map[string]string{
			"profile": "arn:aws:iam::123456789012:role/prod-role",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			Authorizer: nil, // No IAM auth
		},
	}

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "IAM_AUTH_REQUIRED" {
		t.Errorf("Error code = %s, want IAM_AUTH_REQUIRED", errResp.Code)
	}
}

func TestHandleRequest_MissingProfile(t *testing.T) {
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called without profile")
			return successfulTestSTSResponse(), nil
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	req := events.APIGatewayV2HTTPRequest{
		QueryStringParameters: map[string]string{}, // No profile
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
				IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
					AccountID: "123456789012",
					UserARN:   "arn:aws:iam::123456789012:user/testuser",
				},
			},
		},
	}

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "MISSING_PROFILE" {
		t.Errorf("Error code = %s, want MISSING_PROFILE", errResp.Code)
	}
}

func TestNewHandler_DefaultRegion(t *testing.T) {
	// Set environment variable
	os.Setenv("AWS_REGION", "eu-west-1")
	defer os.Unsetenv("AWS_REGION")

	handler := NewHandler(nil)
	if handler.Region != "eu-west-1" {
		t.Errorf("Region = %s, want eu-west-1 from env", handler.Region)
	}
}

func TestNewHandler_CustomRegion(t *testing.T) {
	// Even with env set, custom region should override
	os.Setenv("AWS_REGION", "eu-west-1")
	defer os.Unsetenv("AWS_REGION")

	handler := NewHandler(&HandlerConfig{
		Region: "ap-northeast-1",
	})
	if handler.Region != "ap-northeast-1" {
		t.Errorf("Region = %s, want ap-northeast-1", handler.Region)
	}
}

func TestNewHandler_CustomSTSClient(t *testing.T) {
	mockClient := &testSTSClient{}
	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
	})
	if handler.STSClient != mockClient {
		t.Error("STSClient was not set correctly")
	}
}

func TestNewHandler_NilConfig(t *testing.T) {
	// Clear env to ensure empty region
	os.Unsetenv("AWS_REGION")

	handler := NewHandler(nil)
	if handler == nil {
		t.Error("NewHandler(nil) returned nil")
	}
	if handler.STSClient != nil {
		t.Error("STSClient should be nil with nil config")
	}
}

func TestCredentialResponseFormat(t *testing.T) {
	// Test that credential response matches AWS container credentials format
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			return successfulTestSTSResponse(), nil
		},
	}

	handler := NewHandler(&HandlerConfig{
		STSClient: mockClient,
		Region:    "us-east-1",
	})
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/test-role")
	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Verify Content-Type header
	if resp.Headers["Content-Type"] != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %s, want application/json; charset=utf-8", resp.Headers["Content-Type"])
	}

	// Verify JSON field names match AWS SDK expectations exactly
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &raw); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// AWS SDKs expect these exact field names (case-sensitive)
	requiredFields := []string{"AccessKeyId", "SecretAccessKey", "Token", "Expiration"}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{
			name:  "empty string returns zero",
			input: "",
			want:  0,
		},
		{
			name:  "minimum valid duration",
			input: "900",
			want:  15 * time.Minute,
		},
		{
			name:  "maximum valid duration",
			input: "43200",
			want:  12 * time.Hour,
		},
		{
			name:  "middle valid duration",
			input: "3600",
			want:  time.Hour,
		},
		{
			name:    "below minimum",
			input:   "899",
			wantErr: true,
		},
		{
			name:    "above maximum",
			input:   "43201",
			wantErr: true,
		},
		{
			name:    "negative",
			input:   "-100",
			wantErr: true,
		},
		{
			name:    "non-numeric",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "float",
			input:   "3600.5",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDuration(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("parseDuration() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("parseDuration() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("parseDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
