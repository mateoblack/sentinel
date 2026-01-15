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
	"os"
	"testing"
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
