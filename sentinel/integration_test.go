// Package sentinel provides Sentinel's credential issuance with SourceIdentity stamping.
// This file contains integration tests that verify the Sentinel Fingerprint flow
// works end-to-end with real AWS resources.
//
// # Integration Test Requirements
//
// These tests require real AWS credentials and a properly configured IAM role.
// They are skipped by default and only run when the following environment
// variables are set:
//
//   - SENTINEL_TEST_ROLE_ARN: The ARN of a role that can be assumed with SourceIdentity
//   - SENTINEL_TEST_REGION: The AWS region (optional, defaults to us-east-1)
//
// The tests also require AWS credentials in the environment (via AWS_ACCESS_KEY_ID
// and AWS_SECRET_ACCESS_KEY, or AWS_PROFILE, or any method supported by the
// AWS SDK default credential chain).
//
// # Setting Up a Test Role
//
// To run these tests, you need an IAM role with a trust policy that:
// 1. Allows the caller to assume the role
// 2. Permits sts:SetSourceIdentity
//
// Example trust policy:
//
//	{
//	    "Version": "2012-10-17",
//	    "Statement": [
//	        {
//	            "Effect": "Allow",
//	            "Principal": {
//	                "AWS": "arn:aws:iam::ACCOUNT_ID:user/YOUR_IAM_USER"
//	            },
//	            "Action": [
//	                "sts:AssumeRole",
//	                "sts:SetSourceIdentity"
//	            ]
//	        }
//	    ]
//	}
//
// Replace ACCOUNT_ID and YOUR_IAM_USER with your actual values.
// The role also needs permissions for sts:GetCallerIdentity if you want
// all tests to pass.
//
// # Running Integration Tests
//
// To run integration tests:
//
//	export SENTINEL_TEST_ROLE_ARN="arn:aws:iam::123456789012:role/SentinelTestRole"
//	export SENTINEL_TEST_REGION="us-east-1"  # optional
//	go test -v ./sentinel/... -run Integration
//
// To skip integration tests (default):
//
//	go test -short ./sentinel/...
package sentinel

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/identity"
)

// integrationConfig holds configuration for integration tests.
type integrationConfig struct {
	RoleARN string
	Region  string
}

// skipIfNoIntegrationEnv skips the test if integration test environment is not configured.
// It checks for:
//   - testing.Short() - always skip in short mode
//   - SENTINEL_TEST_ROLE_ARN - required for integration tests
func skipIfNoIntegrationEnv(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	if os.Getenv("SENTINEL_TEST_ROLE_ARN") == "" {
		t.Skip("skipping integration test: SENTINEL_TEST_ROLE_ARN not set")
	}
}

// getIntegrationConfig returns the configuration for integration tests.
// It reads from environment variables:
//   - SENTINEL_TEST_ROLE_ARN: The ARN of the role to assume (required)
//   - SENTINEL_TEST_REGION: The AWS region (defaults to us-east-1)
func getIntegrationConfig(t *testing.T) integrationConfig {
	t.Helper()

	roleARN := os.Getenv("SENTINEL_TEST_ROLE_ARN")
	if roleARN == "" {
		t.Fatal("SENTINEL_TEST_ROLE_ARN environment variable is required")
	}

	region := os.Getenv("SENTINEL_TEST_REGION")
	if region == "" {
		region = "us-east-1"
	}

	return integrationConfig{
		RoleARN: roleARN,
		Region:  region,
	}
}

// TestIntegration_SentinelAssumeRole tests that SentinelAssumeRole correctly
// assumes a role with SourceIdentity stamping using real AWS credentials.
func TestIntegration_SentinelAssumeRole(t *testing.T) {
	skipIfNoIntegrationEnv(t)
	cfg := getIntegrationConfig(t)
	ctx := context.Background()

	// Load AWS credentials using default credential chain
	// This respects AWS_PROFILE, AWS_ACCESS_KEY_ID, instance profiles, etc.
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		t.Fatalf("failed to load AWS config: %v", err)
	}

	// Create SourceIdentity with test user and generated request-id
	testUser := "integrationtest"
	requestID := identity.NewRequestID()
	sourceIdentity, err := identity.New(testUser, requestID)
	if err != nil {
		t.Fatalf("failed to create SourceIdentity: %v", err)
	}

	// Call SentinelAssumeRole
	input := &SentinelAssumeRoleInput{
		CredsProvider:  awsCfg.Credentials,
		RoleARN:        cfg.RoleARN,
		SourceIdentity: sourceIdentity,
		Region:         cfg.Region,
	}

	result, err := SentinelAssumeRole(ctx, input)
	if err != nil {
		t.Fatalf("SentinelAssumeRole failed: %v", err)
	}

	// Verify credentials are populated
	if result.Credentials.AccessKeyID == "" {
		t.Error("Credentials.AccessKeyID is empty")
	}
	if result.Credentials.SecretAccessKey == "" {
		t.Error("Credentials.SecretAccessKey is empty")
	}
	if result.Credentials.SessionToken == "" {
		t.Error("Credentials.SessionToken is empty (assumed role should always have session token)")
	}

	// Verify SourceIdentity matches the formatted input
	expectedSourceIdentity := sourceIdentity.Format()
	if result.SourceIdentity != expectedSourceIdentity {
		t.Errorf("SourceIdentity = %q, want %q", result.SourceIdentity, expectedSourceIdentity)
	}

	// Verify AssumedRoleArn contains the role ARN
	// The full ARN looks like: arn:aws:sts::123456789012:assumed-role/RoleName/session-name
	if !strings.Contains(result.AssumedRoleArn, "assumed-role") {
		t.Errorf("AssumedRoleArn %q does not contain 'assumed-role'", result.AssumedRoleArn)
	}

	t.Logf("Successfully assumed role with SourceIdentity: %s", result.SourceIdentity)
	t.Logf("AssumedRoleArn: %s", result.AssumedRoleArn)
}
