package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/byteness/aws-vault/v7/policy"
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

// mockPolicyLoader implements policy.PolicyLoader for testing.
type mockPolicyLoader struct {
	policy *policy.Policy
	err    error
}

func (m *mockPolicyLoader) Load(ctx context.Context, param string) (*policy.Policy, error) {
	return m.policy, m.err
}

// allowAllPolicy returns a policy that allows all requests.
func allowAllPolicy() *policy.Policy {
	return &policy.Policy{
		Rules: []policy.Rule{{
			Name:   "allow-all",
			Effect: policy.EffectAllow,
		}},
	}
}

// denyAllPolicy returns a policy that denies all requests.
func denyAllPolicy() *policy.Policy {
	return &policy.Policy{
		Rules: []policy.Rule{{
			Name:   "deny-all",
			Effect: policy.EffectDeny,
			Reason: "test deny reason",
		}},
	}
}

// maxDurationPolicy returns a policy that allows with a max server duration cap.
func maxDurationPolicy(duration time.Duration) *policy.Policy {
	return &policy.Policy{
		Rules: []policy.Rule{{
			Name:              "with-duration-cap",
			Effect:            policy.EffectAllow,
			MaxServerDuration: duration,
		}},
	}
}

// testTVMConfig creates a TVMConfig for testing with mock components.
func testTVMConfig(loader policy.PolicyLoader, stsClient STSClient) *TVMConfig {
	return &TVMConfig{
		PolicyParameter: "/test/policy",
		PolicyLoader:    loader,
		STSClient:       stsClient,
		Region:          "us-east-1",
		DefaultDuration: 15 * time.Minute,
	}
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

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

func TestNewHandler_WithTVMConfig(t *testing.T) {
	mockClient := &testSTSClient{}
	cfg := &TVMConfig{
		PolicyParameter: "/test/policy",
		PolicyLoader:    &mockPolicyLoader{policy: allowAllPolicy()},
		STSClient:       mockClient,
		Region:          "ap-northeast-1",
		DefaultDuration: 30 * time.Minute,
	}

	handler := NewHandler(cfg)
	if handler == nil {
		t.Error("NewHandler returned nil")
	}
	if handler.Config != cfg {
		t.Error("Config was not set correctly")
	}
	if handler.Config.Region != "ap-northeast-1" {
		t.Errorf("Region = %s, want ap-northeast-1", handler.Config.Region)
	}
	if handler.Config.STSClient != mockClient {
		t.Error("STSClient was not set correctly")
	}
}

func TestNewHandler_NilConfig(t *testing.T) {
	handler := NewHandler(nil)
	if handler == nil {
		t.Error("NewHandler(nil) returned nil")
	}
	if handler.Config != nil {
		t.Error("Config should be nil with nil input")
	}
}

func TestCredentialResponseFormat(t *testing.T) {
	// Test that credential response matches AWS container credentials format
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			return successfulTestSTSResponse(), nil
		},
	}

	cfg := testTVMConfig(&mockPolicyLoader{policy: allowAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
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

// Policy integration tests

func TestHandleRequest_PolicyDeny(t *testing.T) {
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called when policy denies")
			return successfulTestSTSResponse(), nil
		},
	}

	cfg := testTVMConfig(&mockPolicyLoader{policy: denyAllPolicy()}, mockClient)
	handler := NewHandler(cfg)
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Should return 403 for policy deny
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "POLICY_DENY" {
		t.Errorf("Error code = %s, want POLICY_DENY", errResp.Code)
	}
	// Error message should contain the deny reason
	if errResp.Message != "Policy denied: test deny reason" {
		t.Errorf("Error message = %s, want 'Policy denied: test deny reason'", errResp.Message)
	}
}

func TestHandleRequest_PolicyLoadError(t *testing.T) {
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called when policy load fails")
			return successfulTestSTSResponse(), nil
		},
	}

	cfg := testTVMConfig(&mockPolicyLoader{err: errors.New("SSM connection error")}, mockClient)
	handler := NewHandler(cfg)
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Should return 500 for policy load errors
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "POLICY_ERROR" {
		t.Errorf("Error code = %s, want POLICY_ERROR", errResp.Code)
	}
}

func TestHandleRequest_MaxServerDuration(t *testing.T) {
	var capturedDuration int32
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			if params.DurationSeconds != nil {
				capturedDuration = *params.DurationSeconds
			}
			return successfulTestSTSResponse(), nil
		},
	}

	// Policy caps duration to 10 minutes (600 seconds)
	cfg := testTVMConfig(&mockPolicyLoader{policy: maxDurationPolicy(10 * time.Minute)}, mockClient)
	handler := NewHandler(cfg)
	ctx := context.Background()

	// Request with longer duration (30 minutes = 1800 seconds)
	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	req.QueryStringParameters["duration"] = "1800"

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Duration should be capped to policy max (10 minutes = 600 seconds)
	if capturedDuration != 600 {
		t.Errorf("Expected duration capped to 600, got %d", capturedDuration)
	}
}

func TestHandleRequest_MaxServerDuration_NoDurationRequested(t *testing.T) {
	var capturedDuration int32
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			if params.DurationSeconds != nil {
				capturedDuration = *params.DurationSeconds
			}
			return successfulTestSTSResponse(), nil
		},
	}

	// Policy caps duration to 5 minutes (300 seconds) - less than default
	cfg := testTVMConfig(&mockPolicyLoader{policy: maxDurationPolicy(5 * time.Minute)}, mockClient)
	handler := NewHandler(cfg)
	ctx := context.Background()

	// Request without explicit duration - should use policy max instead of default
	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Duration should use policy max (5 minutes = 300 seconds)
	if capturedDuration != 300 {
		t.Errorf("Expected duration 300 (policy max), got %d", capturedDuration)
	}
}

func TestHandleRequest_MissingPolicyLoader(t *testing.T) {
	mockClient := &testSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			t.Error("STS should not be called without policy loader")
			return successfulTestSTSResponse(), nil
		},
	}

	cfg := &TVMConfig{
		PolicyParameter: "/test/policy",
		PolicyLoader:    nil, // No policy loader
		STSClient:       mockClient,
		Region:          "us-east-1",
	}
	handler := NewHandler(cfg)
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Should return 500 for missing policy loader
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "CONFIG_ERROR" {
		t.Errorf("Error code = %s, want CONFIG_ERROR", errResp.Code)
	}
}

func TestHandleRequest_NilConfig(t *testing.T) {
	handler := NewHandler(nil)
	ctx := context.Background()

	req := validIAMRequest("arn:aws:iam::123456789012:role/prod-role")
	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Should return 500 for nil config
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}

	var errResp TVMError
	if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
		t.Fatalf("Failed to unmarshal error: %v", err)
	}
	if errResp.Code != "CONFIG_ERROR" {
		t.Errorf("Error code = %s, want CONFIG_ERROR", errResp.Code)
	}
}
