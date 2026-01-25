package lambda

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// mockSTSClient implements STSClient for testing.
type mockSTSClient struct {
	AssumeRoleFunc func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

func (m *mockSTSClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	if m.AssumeRoleFunc != nil {
		return m.AssumeRoleFunc(ctx, params, optFns...)
	}
	return nil, errors.New("AssumeRoleFunc not implemented")
}

// successfulSTSResponse returns a mock successful AssumeRole response.
func successfulSTSResponse() *sts.AssumeRoleOutput {
	expiration := time.Now().Add(time.Hour).UTC()
	return &sts.AssumeRoleOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
			SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
			SessionToken:    aws.String("FwoGZXIvYXdzEBYaDCpjfvkLp..."),
			Expiration:      &expiration,
		},
		AssumedRoleUser: &types.AssumedRoleUser{
			Arn:           aws.String("arn:aws:sts::123456789012:assumed-role/test-role/tvm-alice-a1b2c3d4"),
			AssumedRoleId: aws.String("AROA3XFRBF535EXAMPLE:tvm-alice-a1b2c3d4"),
		},
	}
}

func TestVendCredentials_Success(t *testing.T) {
	var capturedInput *sts.AssumeRoleInput
	mockClient := &mockSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			capturedInput = params
			return successfulSTSResponse(), nil
		},
	}

	input := &VendInput{
		Caller: &CallerIdentity{
			AccountID: "123456789012",
			UserARN:   "arn:aws:iam::123456789012:user/alice",
		},
		RoleARN: "arn:aws:iam::123456789012:role/test-role",
		Region:  "us-east-1",
	}

	output, err := VendCredentialsWithClient(context.Background(), input, mockClient)
	if err != nil {
		t.Fatalf("VendCredentialsWithClient failed: %v", err)
	}

	// Verify output structure
	if output.Credentials == nil {
		t.Error("Expected non-nil Credentials")
	}
	if output.SourceIdentity == nil {
		t.Error("Expected non-nil SourceIdentity")
	}

	// Verify credentials format
	if output.Credentials.AccessKeyId != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Expected AccessKeyId 'AKIAIOSFODNN7EXAMPLE', got %s", output.Credentials.AccessKeyId)
	}
	if output.Credentials.SecretAccessKey == "" {
		t.Error("Expected non-empty SecretAccessKey")
	}
	if output.Credentials.Token == "" {
		t.Error("Expected non-empty Token")
	}

	// Verify STS was called with correct parameters
	if capturedInput == nil {
		t.Fatal("AssumeRole was not called")
	}
	if *capturedInput.RoleArn != input.RoleARN {
		t.Errorf("Expected RoleArn %s, got %s", input.RoleARN, *capturedInput.RoleArn)
	}
	if capturedInput.SourceIdentity == nil {
		t.Error("Expected SourceIdentity to be set")
	}
}

func TestVendCredentials_MissingCaller(t *testing.T) {
	mockClient := &mockSTSClient{}
	input := &VendInput{
		Caller:  nil, // Missing caller
		RoleARN: "arn:aws:iam::123456789012:role/test-role",
	}

	_, err := VendCredentialsWithClient(context.Background(), input, mockClient)
	if !errors.Is(err, ErrMissingCaller) {
		t.Errorf("Expected ErrMissingCaller, got %v", err)
	}
}

func TestVendCredentials_MissingRoleARN(t *testing.T) {
	mockClient := &mockSTSClient{}
	input := &VendInput{
		Caller: &CallerIdentity{
			AccountID: "123456789012",
			UserARN:   "arn:aws:iam::123456789012:user/alice",
		},
		RoleARN: "", // Missing RoleARN
	}

	_, err := VendCredentialsWithClient(context.Background(), input, mockClient)
	if !errors.Is(err, ErrMissingRoleARN) {
		t.Errorf("Expected ErrMissingRoleARN, got %v", err)
	}
}

func TestVendCredentials_STSError(t *testing.T) {
	expectedErr := errors.New("STS access denied")
	mockClient := &mockSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			return nil, expectedErr
		},
	}

	input := &VendInput{
		Caller: &CallerIdentity{
			AccountID: "123456789012",
			UserARN:   "arn:aws:iam::123456789012:user/alice",
		},
		RoleARN: "arn:aws:iam::123456789012:role/test-role",
	}

	_, err := VendCredentialsWithClient(context.Background(), input, mockClient)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !errors.Is(err, expectedErr) {
		// The error is wrapped, so check it contains the original
		if err.Error() == "" {
			t.Errorf("Expected error to contain STS error, got %v", err)
		}
	}
}

func TestVendCredentials_SourceIdentityFormat(t *testing.T) {
	var capturedSourceIdentity string
	mockClient := &mockSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			if params.SourceIdentity != nil {
				capturedSourceIdentity = *params.SourceIdentity
			}
			return successfulSTSResponse(), nil
		},
	}

	input := &VendInput{
		Caller: &CallerIdentity{
			AccountID: "123456789012",
			UserARN:   "arn:aws:iam::123456789012:user/alice",
		},
		RoleARN: "arn:aws:iam::123456789012:role/test-role",
	}

	output, err := VendCredentialsWithClient(context.Background(), input, mockClient)
	if err != nil {
		t.Fatalf("VendCredentialsWithClient failed: %v", err)
	}

	// Verify SourceIdentity format: sentinel:user:direct:requestid
	// Format should be: sentinel:<user>:<approval-marker>:<request-id>
	if capturedSourceIdentity == "" {
		t.Error("Expected SourceIdentity to be captured")
	}

	// Parse the format - should start with "sentinel:alice:direct:"
	expectedPrefix := "sentinel:alice:direct:"
	if len(capturedSourceIdentity) < len(expectedPrefix) {
		t.Errorf("SourceIdentity too short: %s", capturedSourceIdentity)
	}
	if capturedSourceIdentity[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("Expected SourceIdentity to start with %s, got %s", expectedPrefix, capturedSourceIdentity)
	}

	// Verify the output SourceIdentity matches
	if output.SourceIdentity.Format() != capturedSourceIdentity {
		t.Errorf("Output SourceIdentity %s does not match captured %s",
			output.SourceIdentity.Format(), capturedSourceIdentity)
	}
}

func TestVendCredentials_DefaultDuration(t *testing.T) {
	var capturedDuration int32
	mockClient := &mockSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			if params.DurationSeconds != nil {
				capturedDuration = *params.DurationSeconds
			}
			return successfulSTSResponse(), nil
		},
	}

	input := &VendInput{
		Caller: &CallerIdentity{
			AccountID: "123456789012",
			UserARN:   "arn:aws:iam::123456789012:user/alice",
		},
		RoleARN:         "arn:aws:iam::123456789012:role/test-role",
		SessionDuration: 0, // No duration specified, should default to 1 hour
	}

	_, err := VendCredentialsWithClient(context.Background(), input, mockClient)
	if err != nil {
		t.Fatalf("VendCredentialsWithClient failed: %v", err)
	}

	// Default should be 1 hour = 3600 seconds
	expectedDuration := int32(3600)
	if capturedDuration != expectedDuration {
		t.Errorf("Expected default duration %d, got %d", expectedDuration, capturedDuration)
	}
}

func TestVendCredentials_CustomDuration(t *testing.T) {
	var capturedDuration int32
	mockClient := &mockSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			if params.DurationSeconds != nil {
				capturedDuration = *params.DurationSeconds
			}
			return successfulSTSResponse(), nil
		},
	}

	customDuration := 2 * time.Hour
	input := &VendInput{
		Caller: &CallerIdentity{
			AccountID: "123456789012",
			UserARN:   "arn:aws:iam::123456789012:user/alice",
		},
		RoleARN:         "arn:aws:iam::123456789012:role/test-role",
		SessionDuration: customDuration,
	}

	_, err := VendCredentialsWithClient(context.Background(), input, mockClient)
	if err != nil {
		t.Fatalf("VendCredentialsWithClient failed: %v", err)
	}

	// Custom duration of 2 hours = 7200 seconds
	expectedDuration := int32(7200)
	if capturedDuration != expectedDuration {
		t.Errorf("Expected custom duration %d, got %d", expectedDuration, capturedDuration)
	}
}

// extractUsername tests

func TestExtractUsername_IAMUser(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected string
	}{
		{
			name:     "simple IAM user",
			arn:      "arn:aws:iam::123456789012:user/alice",
			expected: "alice",
		},
		{
			name:     "IAM user with path",
			arn:      "arn:aws:iam::123456789012:user/engineering/alice",
			expected: "alice",
		},
		{
			name:     "IAM user with deep path",
			arn:      "arn:aws:iam::123456789012:user/org/team/alice",
			expected: "alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractUsername(tt.arn)
			if err != nil {
				t.Errorf("extractUsername(%q) error = %v", tt.arn, err)
				return
			}
			if got != tt.expected {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.arn, got, tt.expected)
			}
		})
	}
}

func TestExtractUsername_AssumedRole(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected string
	}{
		{
			name:     "assumed role with session name",
			arn:      "arn:aws:sts::123456789012:assumed-role/MyRole/SessionName",
			expected: "SessionName",
		},
		{
			name:     "assumed role with email session",
			arn:      "arn:aws:sts::123456789012:assumed-role/AdminRole/bob",
			expected: "bob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractUsername(tt.arn)
			if err != nil {
				t.Errorf("extractUsername(%q) error = %v", tt.arn, err)
				return
			}
			if got != tt.expected {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.arn, got, tt.expected)
			}
		})
	}
}

func TestExtractUsername_SSOUser(t *testing.T) {
	// SSO users have email addresses that need sanitization
	arn := "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdminAccess_abc123/user@example.com"
	expected := "userexamplecom" // @ and . removed by sanitization

	got, err := extractUsername(arn)
	if err != nil {
		t.Errorf("extractUsername(%q) error = %v", arn, err)
		return
	}
	if got != expected {
		t.Errorf("extractUsername(%q) = %q, want %q", arn, got, expected)
	}
}

func TestExtractUsername_FederatedUser(t *testing.T) {
	arn := "arn:aws:sts::123456789012:federated-user/fed-user"
	expected := "feduser" // hyphen removed by sanitization

	got, err := extractUsername(arn)
	if err != nil {
		t.Errorf("extractUsername(%q) error = %v", arn, err)
		return
	}
	if got != expected {
		t.Errorf("extractUsername(%q) = %q, want %q", arn, got, expected)
	}
}

func TestExtractUsername_InvalidARN(t *testing.T) {
	tests := []struct {
		name string
		arn  string
	}{
		{
			name: "not an ARN",
			arn:  "not-an-arn",
		},
		{
			name: "partial ARN",
			arn:  "arn:aws:iam::123456789012",
		},
		{
			name: "wrong prefix",
			arn:  "foo:aws:iam::123456789012:user/alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractUsername(tt.arn)
			if err == nil {
				t.Errorf("extractUsername(%q) expected error, got nil", tt.arn)
			}
		})
	}
}

func TestExtractUsername_EmptyARN(t *testing.T) {
	_, err := extractUsername("")
	if err == nil {
		t.Error("extractUsername(\"\") expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidARN) {
		t.Errorf("Expected ErrInvalidARN, got %v", err)
	}
}

// TVMResponse format tests

func TestVendOutput_CredentialFormat(t *testing.T) {
	mockClient := &mockSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			return successfulSTSResponse(), nil
		},
	}

	input := &VendInput{
		Caller: &CallerIdentity{
			AccountID: "123456789012",
			UserARN:   "arn:aws:iam::123456789012:user/alice",
		},
		RoleARN: "arn:aws:iam::123456789012:role/test-role",
	}

	output, err := VendCredentialsWithClient(context.Background(), input, mockClient)
	if err != nil {
		t.Fatalf("VendCredentialsWithClient failed: %v", err)
	}

	creds := output.Credentials

	// Verify TVMResponse has all required fields
	if creds.AccessKeyId == "" {
		t.Error("AccessKeyId should not be empty")
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
}

func TestVendOutput_ExpirationFormat(t *testing.T) {
	mockClient := &mockSTSClient{
		AssumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
			return successfulSTSResponse(), nil
		},
	}

	input := &VendInput{
		Caller: &CallerIdentity{
			AccountID: "123456789012",
			UserARN:   "arn:aws:iam::123456789012:user/alice",
		},
		RoleARN: "arn:aws:iam::123456789012:role/test-role",
	}

	output, err := VendCredentialsWithClient(context.Background(), input, mockClient)
	if err != nil {
		t.Fatalf("VendCredentialsWithClient failed: %v", err)
	}

	// Verify Expiration is in RFC3339 format
	_, err = time.Parse(time.RFC3339, output.Credentials.Expiration)
	if err != nil {
		t.Errorf("Expiration %q is not valid RFC3339: %v", output.Credentials.Expiration, err)
	}
}
