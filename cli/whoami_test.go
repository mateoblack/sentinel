package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ============================================================================
// Mock STS Client
// ============================================================================

// mockSTSClient implements identity.STSAPI for testing.
type mockSTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetCallerIdentityFunc not set")
}

// ============================================================================
// Test Helpers
// ============================================================================

func createWhoamiTestFiles(t *testing.T) (*os.File, *os.File, func()) {
	t.Helper()

	stdout, err := os.CreateTemp("", "whoami-stdout-*")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}

	stderr, err := os.CreateTemp("", "whoami-stderr-*")
	if err != nil {
		stdout.Close()
		os.Remove(stdout.Name())
		t.Fatalf("failed to create temp stderr: %v", err)
	}

	cleanup := func() {
		stdout.Close()
		stderr.Close()
		os.Remove(stdout.Name())
		os.Remove(stderr.Name())
	}

	return stdout, stderr, cleanup
}

func readWhoamiFile(t *testing.T, f *os.File) string {
	t.Helper()
	f.Seek(0, 0)
	content, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	return string(content)
}

// ============================================================================
// TestWhoamiCommand - Identity Type Tests
// ============================================================================

func TestWhoamiCommand_IAMUser(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:user/alice"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)

	// Check header
	if !strings.Contains(output, "AWS Identity") {
		t.Error("expected output to contain 'AWS Identity'")
	}

	// Check ARN
	if !strings.Contains(output, "arn:aws:iam::123456789012:user/alice") {
		t.Error("expected output to contain ARN")
	}

	// Check account
	if !strings.Contains(output, "123456789012") {
		t.Error("expected output to contain account ID")
	}

	// Check identity type
	if !strings.Contains(output, "user") {
		t.Error("expected output to contain identity type 'user'")
	}

	// Check raw username
	if !strings.Contains(output, "alice") {
		t.Error("expected output to contain raw username 'alice'")
	}

	// Check policy username (same as raw for simple IAM user)
	if !strings.Contains(output, "Policy Username: alice") {
		t.Error("expected output to contain policy username 'alice'")
	}

	// Check explanation footer
	if !strings.Contains(output, "policy username is used for matching") {
		t.Error("expected output to contain explanation about policy username")
	}
}

func TestWhoamiCommand_AssumedRoleWithEmail(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/SSO/bob@company.com"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AROAEXAMPLE:bob@company.com"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)

	// Check identity type
	if !strings.Contains(output, "assumed-role") {
		t.Error("expected output to contain identity type 'assumed-role'")
	}

	// Check raw username (email)
	if !strings.Contains(output, "bob@company.com") {
		t.Error("expected output to contain raw username 'bob@company.com'")
	}

	// Check policy username (sanitized email)
	if !strings.Contains(output, "bobcompanycom") {
		t.Error("expected output to contain policy username 'bobcompanycom'")
	}
}

func TestWhoamiCommand_FederatedUser(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:sts::123456789012:federated-user/carol"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("123456789012:carol"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)

	// Check identity type
	if !strings.Contains(output, "federated-user") {
		t.Error("expected output to contain identity type 'federated-user'")
	}

	// Check username
	if !strings.Contains(output, "carol") {
		t.Error("expected output to contain username 'carol'")
	}
}

func TestWhoamiCommand_RootUser(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:root"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("123456789012"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)

	// Check identity type
	if !strings.Contains(output, "root") {
		t.Error("expected output to contain identity type 'root'")
	}

	// Check raw username
	if !strings.Contains(output, "Raw Username:    root") {
		t.Error("expected output to contain raw username 'root'")
	}
}

// ============================================================================
// TestWhoamiCommand_Errors - Error Cases
// ============================================================================

func TestWhoamiCommand_STSAPIError(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return nil, errors.New("AccessDeniedException: User is not authorized to perform sts:GetCallerIdentity")
		},
	}

	input := WhoamiCommandInput{
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for STS API failure")
	}

	errOutput := readWhoamiFile(t, stderr)
	if !strings.Contains(errOutput, "Error") {
		t.Error("expected stderr to contain error message")
	}
}

func TestWhoamiCommand_EmptyARN(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String(""),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty ARN")
	}
}

func TestWhoamiCommand_InvalidARNFormat(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("invalid-arn-format"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid ARN format")
	}
}

// ============================================================================
// TestWhoamiCommand_JSONOutput - JSON Format Tests
// ============================================================================

func TestWhoamiCommand_JSONOutput(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:user/alice"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient:  mockSTS,
		JSONOutput: true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)

	// Verify output is valid JSON
	var result WhoamiResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, output)
	}

	// Verify all fields present and correct
	if result.ARN != "arn:aws:iam::123456789012:user/alice" {
		t.Errorf("expected ARN 'arn:aws:iam::123456789012:user/alice', got '%s'", result.ARN)
	}
	if result.AccountID != "123456789012" {
		t.Errorf("expected AccountID '123456789012', got '%s'", result.AccountID)
	}
	if result.IdentityType != "user" {
		t.Errorf("expected IdentityType 'user', got '%s'", result.IdentityType)
	}
	if result.RawUsername != "alice" {
		t.Errorf("expected RawUsername 'alice', got '%s'", result.RawUsername)
	}
	if result.PolicyUsername != "alice" {
		t.Errorf("expected PolicyUsername 'alice', got '%s'", result.PolicyUsername)
	}
}

func TestWhoamiCommand_JSONOutput_AssumedRoleWithEmail(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/MyRole/alice@example.com"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AROAEXAMPLE:alice@example.com"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient:  mockSTS,
		JSONOutput: true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)

	var result WhoamiResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, output)
	}

	// Check sanitization - email special chars removed
	if result.RawUsername != "alice@example.com" {
		t.Errorf("expected RawUsername 'alice@example.com', got '%s'", result.RawUsername)
	}
	if result.PolicyUsername != "aliceexamplecom" {
		t.Errorf("expected PolicyUsername 'aliceexamplecom', got '%s'", result.PolicyUsername)
	}
	if result.IdentityType != "assumed-role" {
		t.Errorf("expected IdentityType 'assumed-role', got '%s'", result.IdentityType)
	}
}

func TestWhoamiCommand_JSONOutput_AllFields(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:sts::999888777666:federated-user/test_user"),
				Account: aws.String("999888777666"),
				UserId:  aws.String("999888777666:test_user"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient:  mockSTS,
		JSONOutput: true,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)

	// Check all expected JSON field names are present
	requiredFields := []string{"arn", "account_id", "identity_type", "raw_username", "policy_username"}
	for _, field := range requiredFields {
		if !strings.Contains(output, `"`+field+`"`) {
			t.Errorf("expected JSON to contain field '%s'", field)
		}
	}
}

// ============================================================================
// TestWhoamiCommand - Table-Driven Tests for Multiple Identity Types
// ============================================================================

func TestWhoamiCommand_IdentityTypes(t *testing.T) {
	testCases := []struct {
		name             string
		arn              string
		expectedType     string
		expectedRaw      string
		expectedPolicy   string
		expectTypeInText string // what to search for in human output
	}{
		{
			name:             "IAM user",
			arn:              "arn:aws:iam::123456789012:user/alice",
			expectedType:     "user",
			expectedRaw:      "alice",
			expectedPolicy:   "alice",
			expectTypeInText: "user",
		},
		{
			name:             "IAM user with path",
			arn:              "arn:aws:iam::123456789012:user/division/team/bob",
			expectedType:     "user",
			expectedRaw:      "bob",
			expectedPolicy:   "bob",
			expectTypeInText: "user",
		},
		{
			name:             "Assumed role regular",
			arn:              "arn:aws:sts::123456789012:assumed-role/AdminRole/session123",
			expectedType:     "assumed-role",
			expectedRaw:      "session123",
			expectedPolicy:   "session123",
			expectTypeInText: "assumed-role",
		},
		{
			name:             "Assumed role SSO with email",
			arn:              "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdminAccess/carol@corp.com",
			expectedType:     "assumed-role",
			expectedRaw:      "carol@corp.com",
			expectedPolicy:   "carolcorpcom",
			expectTypeInText: "assumed-role",
		},
		{
			name:             "Federated user",
			arn:              "arn:aws:sts::123456789012:federated-user/dave",
			expectedType:     "federated-user",
			expectedRaw:      "dave",
			expectedPolicy:   "dave",
			expectTypeInText: "federated-user",
		},
		{
			name:             "Root user",
			arn:              "arn:aws:iam::123456789012:root",
			expectedType:     "root",
			expectedRaw:      "root",
			expectedPolicy:   "root",
			expectTypeInText: "root",
		},
		{
			name:             "GovCloud IAM user",
			arn:              "arn:aws-us-gov:iam::123456789012:user/eve",
			expectedType:     "user",
			expectedRaw:      "eve",
			expectedPolicy:   "eve",
			expectTypeInText: "user",
		},
		{
			name:             "China partition user",
			arn:              "arn:aws-cn:iam::123456789012:user/frank",
			expectedType:     "user",
			expectedRaw:      "frank",
			expectedPolicy:   "frank",
			expectTypeInText: "user",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, cleanup := createWhoamiTestFiles(t)
			defer cleanup()

			mockSTS := &mockSTSClient{
				GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
					return &sts.GetCallerIdentityOutput{
						Arn:     aws.String(tc.arn),
						Account: aws.String("123456789012"),
						UserId:  aws.String("EXAMPLE"),
					}, nil
				},
			}

			// Test human output
			input := WhoamiCommandInput{
				STSClient: mockSTS,
				Stdout:    stdout,
				Stderr:    stderr,
			}

			err := WhoamiCommand(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := readWhoamiFile(t, stdout)
			if !strings.Contains(output, tc.expectTypeInText) {
				t.Errorf("expected output to contain identity type '%s'", tc.expectTypeInText)
			}

			// Test JSON output
			stdout2, stderr2, cleanup2 := createWhoamiTestFiles(t)
			defer cleanup2()

			input2 := WhoamiCommandInput{
				STSClient:  mockSTS,
				JSONOutput: true,
				Stdout:     stdout2,
				Stderr:     stderr2,
			}

			err = WhoamiCommand(context.Background(), input2)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			jsonOutput := readWhoamiFile(t, stdout2)
			var result WhoamiResult
			if err := json.Unmarshal([]byte(jsonOutput), &result); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}

			if result.IdentityType != tc.expectedType {
				t.Errorf("expected identity_type '%s', got '%s'", tc.expectedType, result.IdentityType)
			}
			if result.RawUsername != tc.expectedRaw {
				t.Errorf("expected raw_username '%s', got '%s'", tc.expectedRaw, result.RawUsername)
			}
			if result.PolicyUsername != tc.expectedPolicy {
				t.Errorf("expected policy_username '%s', got '%s'", tc.expectedPolicy, result.PolicyUsername)
			}
		})
	}
}

// ============================================================================
// TestWhoamiCommand - Custom Region
// ============================================================================

func TestWhoamiCommand_CustomRegion(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	// When STSClient is provided, region flag is ignored (client already configured)
	// This test verifies the command works with the region flag set
	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:user/alice"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		Region:    "eu-west-1",
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)
	if !strings.Contains(output, "AWS Identity") {
		t.Error("expected output to contain header")
	}
}

// ============================================================================
// TestWhoamiCommand - Profile Flag
// ============================================================================

func TestWhoamiCommand_ProfileFlag(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	// When STSClient is provided, profile flag is ignored (client already configured)
	// This test verifies the command works with the profile flag set and doesn't error
	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:iam::123456789012:user/alice"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		Profile:   "my-sso-profile",
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)
	if !strings.Contains(output, "AWS Identity") {
		t.Error("expected output to contain header")
	}
	if !strings.Contains(output, "alice") {
		t.Error("expected output to contain username 'alice'")
	}
}

// ============================================================================
// TestWhoamiCommand - Output Format Verification
// ============================================================================

func TestWhoamiCommand_HumanOutputFormat(t *testing.T) {
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	mockSTS := &mockSTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String("arn:aws:sts::123456789012:assumed-role/MyRole/alice@example.com"),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AROAEXAMPLE:alice@example.com"),
			}, nil
		},
	}

	input := WhoamiCommandInput{
		STSClient: mockSTS,
		Stdout:    stdout,
		Stderr:    stderr,
	}

	err := WhoamiCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := readWhoamiFile(t, stdout)

	// Verify the exact format structure
	expectedParts := []string{
		"AWS Identity",
		"============",
		"ARN:",
		"Account:",
		"Identity Type:",
		"Raw Username:",
		"Policy Username:",
		"The policy username is used for matching against Sentinel policy rules.",
	}

	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("expected output to contain '%s'", part)
		}
	}
}

// ============================================================================
// TestWhoamiCommand - Real Command Without AWS (error handling)
// ============================================================================

func TestWhoamiCommand_RealCommand_NoAWSConfig(t *testing.T) {
	// This test just verifies the function doesn't panic with nil inputs
	// Actual AWS calls will fail, but we're testing the error handling
	stdout, stderr, cleanup := createWhoamiTestFiles(t)
	defer cleanup()

	input := WhoamiCommandInput{
		Stdout: stdout,
		Stderr: stderr,
		// No STSClient - will try to create real one
		// This will either succeed (if AWS credentials available) or fail gracefully
	}

	// We expect either success or an AWS-related error
	_ = WhoamiCommand(context.Background(), input)

	// Just verify we didn't panic and the function returns
}
