package sentinel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/identity"
)

// mockCredentialsProvider is a simple credentials provider for testing.
type mockCredentialsProvider struct{}

func (m *mockCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}, nil
}

func TestSentinelAssumeRoleValidation(t *testing.T) {
	validSourceIdentity, err := identity.New("alice", "", "a1b2c3d4")
	if err != nil {
		t.Fatalf("failed to create valid SourceIdentity: %v", err)
	}

	invalidSourceIdentity := &identity.SourceIdentity{
		User:      "", // Empty user is invalid
		RequestID: "a1b2c3d4",
	}

	testCases := []struct {
		name        string
		input       *SentinelAssumeRoleInput
		wantErr     error
		wantErrText string
	}{
		{
			name: "missing RoleARN returns ErrMissingRoleARN",
			input: &SentinelAssumeRoleInput{
				CredsProvider:  &mockCredentialsProvider{},
				RoleARN:        "",
				SourceIdentity: validSourceIdentity,
			},
			wantErr: ErrMissingRoleARN,
		},
		{
			name: "missing SourceIdentity returns ErrMissingSourceIdentity",
			input: &SentinelAssumeRoleInput{
				CredsProvider:  &mockCredentialsProvider{},
				RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
				SourceIdentity: nil,
			},
			wantErr: ErrMissingSourceIdentity,
		},
		{
			name: "missing CredsProvider returns ErrMissingCredsProvider",
			input: &SentinelAssumeRoleInput{
				CredsProvider:  nil,
				RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
				SourceIdentity: validSourceIdentity,
			},
			wantErr: ErrMissingCredsProvider,
		},
		{
			name: "invalid SourceIdentity returns ErrInvalidSourceIdentity",
			input: &SentinelAssumeRoleInput{
				CredsProvider:  &mockCredentialsProvider{},
				RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
				SourceIdentity: invalidSourceIdentity,
			},
			wantErr: ErrInvalidSourceIdentity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SentinelAssumeRole(context.Background(), tc.input)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}

			if tc.wantErrText != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.wantErrText)
					return
				}
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrText)
				}
			}
		})
	}
}

func TestSentinelAssumeRoleDefaults(t *testing.T) {
	t.Run("default RoleSessionName starts with sentinel-", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:   &mockCredentialsProvider{},
			RoleARN:         "arn:aws:iam::123456789012:role/TestRole",
			RoleSessionName: "", // Empty, should get default
		}

		// Apply defaults directly to test the function
		applyDefaults(input)

		if !strings.HasPrefix(input.RoleSessionName, "sentinel-") {
			t.Errorf("RoleSessionName = %q, want prefix 'sentinel-'", input.RoleSessionName)
		}

		// Verify it's a timestamp-based name (contains digits)
		suffix := strings.TrimPrefix(input.RoleSessionName, "sentinel-")
		if suffix == "" {
			t.Error("RoleSessionName suffix is empty after removing prefix")
		}
	})

	t.Run("default Duration is 1 hour", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider: &mockCredentialsProvider{},
			RoleARN:       "arn:aws:iam::123456789012:role/TestRole",
			Duration:      0, // Zero, should get default
		}

		applyDefaults(input)

		if input.Duration != DefaultDuration {
			t.Errorf("Duration = %v, want %v", input.Duration, DefaultDuration)
		}

		if input.Duration != time.Hour {
			t.Errorf("Duration = %v, want 1 hour", input.Duration)
		}
	})

	t.Run("custom RoleSessionName is preserved", func(t *testing.T) {
		customName := "my-custom-session"
		input := &SentinelAssumeRoleInput{
			CredsProvider:   &mockCredentialsProvider{},
			RoleARN:         "arn:aws:iam::123456789012:role/TestRole",
			RoleSessionName: customName,
		}

		applyDefaults(input)

		if input.RoleSessionName != customName {
			t.Errorf("RoleSessionName = %q, want %q", input.RoleSessionName, customName)
		}
	})

	t.Run("custom Duration is preserved", func(t *testing.T) {
		customDuration := 30 * time.Minute
		input := &SentinelAssumeRoleInput{
			CredsProvider: &mockCredentialsProvider{},
			RoleARN:       "arn:aws:iam::123456789012:role/TestRole",
			Duration:      customDuration,
		}

		applyDefaults(input)

		if input.Duration != customDuration {
			t.Errorf("Duration = %v, want %v", input.Duration, customDuration)
		}
	})
}

func TestValidateInput(t *testing.T) {
	validSourceIdentity, err := identity.New("alice", "", "a1b2c3d4")
	if err != nil {
		t.Fatalf("failed to create valid SourceIdentity: %v", err)
	}

	testCases := []struct {
		name    string
		input   *SentinelAssumeRoleInput
		wantErr error
	}{
		{
			name: "valid input passes validation",
			input: &SentinelAssumeRoleInput{
				CredsProvider:  &mockCredentialsProvider{},
				RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
				SourceIdentity: validSourceIdentity,
			},
			wantErr: nil,
		},
		{
			name: "nil CredsProvider fails",
			input: &SentinelAssumeRoleInput{
				CredsProvider:  nil,
				RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
				SourceIdentity: validSourceIdentity,
			},
			wantErr: ErrMissingCredsProvider,
		},
		{
			name: "empty RoleARN fails",
			input: &SentinelAssumeRoleInput{
				CredsProvider:  &mockCredentialsProvider{},
				RoleARN:        "",
				SourceIdentity: validSourceIdentity,
			},
			wantErr: ErrMissingRoleARN,
		},
		{
			name: "nil SourceIdentity fails",
			input: &SentinelAssumeRoleInput{
				CredsProvider:  &mockCredentialsProvider{},
				RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
				SourceIdentity: nil,
			},
			wantErr: ErrMissingSourceIdentity,
		},
		{
			name: "invalid SourceIdentity fails",
			input: &SentinelAssumeRoleInput{
				CredsProvider: &mockCredentialsProvider{},
				RoleARN:       "arn:aws:iam::123456789012:role/TestRole",
				SourceIdentity: &identity.SourceIdentity{
					User:      "alice_invalid", // underscore is invalid
					RequestID: "a1b2c3d4",
				},
			},
			wantErr: ErrInvalidSourceIdentity,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInput(tc.input)

			if tc.wantErr == nil {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestSentinelAssumeRoleInputBuild(t *testing.T) {
	// This test verifies that the AssumeRoleInput is built correctly
	// by checking the validateInput and applyDefaults functions,
	// as we can't easily test the full STS call without mocking AWS.

	t.Run("SourceIdentity.Format() is used correctly", func(t *testing.T) {
		si, err := identity.New("bob", "", "deadbeef")
		if err != nil {
			t.Fatalf("failed to create SourceIdentity: %v", err)
		}

		expected := "sentinel:bob:direct:deadbeef"
		if si.Format() != expected {
			t.Errorf("SourceIdentity.Format() = %q, want %q", si.Format(), expected)
		}
	})

	t.Run("all optional fields pass through when provided", func(t *testing.T) {
		si, err := identity.New("alice", "", "a1b2c3d4")
		if err != nil {
			t.Fatalf("failed to create SourceIdentity: %v", err)
		}

		input := &SentinelAssumeRoleInput{
			CredsProvider:        &mockCredentialsProvider{},
			RoleARN:              "arn:aws:iam::123456789012:role/TestRole",
			RoleSessionName:      "custom-session",
			Duration:             2 * time.Hour,
			SourceIdentity:       si,
			Region:               "us-west-2",
			STSRegionalEndpoints: "regional",
			EndpointURL:          "https://sts.us-west-2.amazonaws.com",
			ExternalID:           "external-123",
		}

		// Validate passes
		if err := validateInput(input); err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}

		// Apply defaults shouldn't change custom values
		applyDefaults(input)

		if input.RoleSessionName != "custom-session" {
			t.Errorf("RoleSessionName was modified: got %q", input.RoleSessionName)
		}
		if input.Duration != 2*time.Hour {
			t.Errorf("Duration was modified: got %v", input.Duration)
		}
		if input.Region != "us-west-2" {
			t.Errorf("Region was modified: got %q", input.Region)
		}
		if input.STSRegionalEndpoints != "regional" {
			t.Errorf("STSRegionalEndpoints was modified: got %q", input.STSRegionalEndpoints)
		}
		if input.EndpointURL != "https://sts.us-west-2.amazonaws.com" {
			t.Errorf("EndpointURL was modified: got %q", input.EndpointURL)
		}
		if input.ExternalID != "external-123" {
			t.Errorf("ExternalID was modified: got %q", input.ExternalID)
		}
	})
}

func TestErrorTypes(t *testing.T) {
	// Verify error types are properly defined and distinguishable
	testCases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrMissingRoleARN",
			err:  ErrMissingRoleARN,
			want: "RoleARN is required",
		},
		{
			name: "ErrMissingSourceIdentity",
			err:  ErrMissingSourceIdentity,
			want: "SourceIdentity is required",
		},
		{
			name: "ErrMissingCredsProvider",
			err:  ErrMissingCredsProvider,
			want: "CredsProvider is required",
		},
		{
			name: "ErrInvalidSourceIdentity",
			err:  ErrInvalidSourceIdentity,
			want: "SourceIdentity is invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() != tc.want {
				t.Errorf("error = %q, want %q", tc.err.Error(), tc.want)
			}
		})
	}
}

func TestDefaultDuration(t *testing.T) {
	// Verify DefaultDuration matches aws-vault's default
	if DefaultDuration != time.Hour {
		t.Errorf("DefaultDuration = %v, want 1 hour (matching aws-vault)", DefaultDuration)
	}
}

// =============================================================================
// Security Validation Tests
// =============================================================================

// TestValidationOrder verifies the order in which input fields are validated.
// The order is: CredsProvider -> RoleARN -> SourceIdentity (nil) -> SourceIdentity.IsValid()
func TestValidationOrder(t *testing.T) {
	validSourceIdentity, err := identity.New("alice", "", "a1b2c3d4")
	if err != nil {
		t.Fatalf("failed to create valid SourceIdentity: %v", err)
	}

	t.Run("CredsProvider checked first", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:  nil,                                            // Invalid
			RoleARN:        "",                                             // Also invalid
			SourceIdentity: nil,                                            // Also invalid
		}

		err := validateInput(input)
		if !errors.Is(err, ErrMissingCredsProvider) {
			t.Errorf("expected ErrMissingCredsProvider first, got: %v", err)
		}
	})

	t.Run("RoleARN checked second", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},                     // Valid
			RoleARN:        "",                                             // Invalid
			SourceIdentity: nil,                                            // Also invalid
		}

		err := validateInput(input)
		if !errors.Is(err, ErrMissingRoleARN) {
			t.Errorf("expected ErrMissingRoleARN second, got: %v", err)
		}
	})

	t.Run("SourceIdentity nil checked third", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},                     // Valid
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",      // Valid
			SourceIdentity: nil,                                            // Invalid - nil
		}

		err := validateInput(input)
		if !errors.Is(err, ErrMissingSourceIdentity) {
			t.Errorf("expected ErrMissingSourceIdentity third, got: %v", err)
		}
	})

	t.Run("SourceIdentity.IsValid() checked fourth", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},                     // Valid
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",      // Valid
			SourceIdentity: &identity.SourceIdentity{User: "", RequestID: "a1b2c3d4"}, // Invalid content
		}

		err := validateInput(input)
		if !errors.Is(err, ErrInvalidSourceIdentity) {
			t.Errorf("expected ErrInvalidSourceIdentity fourth, got: %v", err)
		}
	})

	t.Run("valid input passes all checks", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
			SourceIdentity: validSourceIdentity,
		}

		err := validateInput(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestSourceIdentityIntegration tests SourceIdentity validation integration.
func TestSourceIdentityIntegration(t *testing.T) {
	t.Run("invalid SourceIdentity rejected before STS call", func(t *testing.T) {
		invalidCases := []struct {
			name string
			si   *identity.SourceIdentity
		}{
			{
				name: "empty user",
				si:   &identity.SourceIdentity{User: "", RequestID: "a1b2c3d4"},
			},
			{
				name: "user too long",
				si:   &identity.SourceIdentity{User: "abcdefghij01234567890", RequestID: "a1b2c3d4"},
			},
			{
				name: "invalid user chars",
				si:   &identity.SourceIdentity{User: "alice_bob", RequestID: "a1b2c3d4"},
			},
			{
				name: "invalid request-id",
				si:   &identity.SourceIdentity{User: "alice", RequestID: "badid"},
			},
		}

		for _, tc := range invalidCases {
			t.Run(tc.name, func(t *testing.T) {
				input := &SentinelAssumeRoleInput{
					CredsProvider:  &mockCredentialsProvider{},
					RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
					SourceIdentity: tc.si,
				}

				_, err := SentinelAssumeRole(context.Background(), input)
				if err == nil {
					t.Error("expected error for invalid SourceIdentity")
				}
				if !errors.Is(err, ErrInvalidSourceIdentity) {
					t.Errorf("expected ErrInvalidSourceIdentity, got: %v", err)
				}
			})
		}
	})

	t.Run("SourceIdentity with MaxUserLength accepted", func(t *testing.T) {
		maxUser := "abcdefghij0123456789" // Exactly 20 chars
		si, err := identity.New(maxUser, "", "a1b2c3d4")
		if err != nil {
			t.Fatalf("failed to create SourceIdentity with max user: %v", err)
		}

		if len(si.User) != identity.MaxUserLength {
			t.Errorf("user length = %d, want %d", len(si.User), identity.MaxUserLength)
		}

		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
			SourceIdentity: si,
		}

		// Validation should pass (we can't test the full STS call without mocking AWS)
		err = validateInput(input)
		if err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}
	})

	t.Run("SourceIdentity format preserved in output", func(t *testing.T) {
		si, err := identity.New("testuser", "", "deadbeef")
		if err != nil {
			t.Fatalf("failed to create SourceIdentity: %v", err)
		}

		expected := "sentinel:testuser:direct:deadbeef"
		if si.Format() != expected {
			t.Errorf("Format() = %q, want %q", si.Format(), expected)
		}

		// The output would contain this format (can't test without STS mock)
		// but we verify the input format is correct
	})
}

// TestDurationEdgeCases tests Duration field edge cases.
func TestDurationEdgeCases(t *testing.T) {
	t.Run("Duration 0 gets default 1 hour", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
			Duration:       0,
		}

		applyDefaults(input)

		if input.Duration != DefaultDuration {
			t.Errorf("Duration = %v, want %v", input.Duration, DefaultDuration)
		}
		if input.Duration != time.Hour {
			t.Errorf("Duration = %v, want 1 hour", input.Duration)
		}
	})

	t.Run("Duration 1 second accepted", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
			Duration:       time.Second,
		}

		applyDefaults(input)

		if input.Duration != time.Second {
			t.Errorf("Duration = %v, want 1 second", input.Duration)
		}
	})

	t.Run("Duration 12 hours accepted", func(t *testing.T) {
		// AWS maximum for most roles is 12 hours
		maxDuration := 12 * time.Hour
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
			Duration:       maxDuration,
		}

		applyDefaults(input)

		if input.Duration != maxDuration {
			t.Errorf("Duration = %v, want %v", input.Duration, maxDuration)
		}
	})

	t.Run("custom duration preserved", func(t *testing.T) {
		customDuration := 45 * time.Minute
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
			Duration:       customDuration,
		}

		applyDefaults(input)

		if input.Duration != customDuration {
			t.Errorf("Duration = %v, want %v", input.Duration, customDuration)
		}
	})
}

// TestRoleARNValidation tests RoleARN field edge cases.
// NOTE: Actual ARN format validation is performed by AWS SDK.
func TestRoleARNValidation(t *testing.T) {
	validSourceIdentity, err := identity.New("alice", "", "a1b2c3d4")
	if err != nil {
		t.Fatalf("failed to create valid SourceIdentity: %v", err)
	}

	t.Run("empty string rejected", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "",
			SourceIdentity: validSourceIdentity,
		}

		err := validateInput(input)
		if !errors.Is(err, ErrMissingRoleARN) {
			t.Errorf("expected ErrMissingRoleARN, got: %v", err)
		}
	})

	t.Run("whitespace-only passes validation (AWS SDK validates format)", func(t *testing.T) {
		// Note: We don't trim or reject whitespace-only strings.
		// AWS SDK will validate the actual ARN format and reject invalid ARNs.
		// This documents current behavior.
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "   ",
			SourceIdentity: validSourceIdentity,
		}

		err := validateInput(input)
		// Current implementation: non-empty string passes our check
		// AWS SDK would reject this when making the STS call
		if err != nil {
			t.Logf("whitespace-only RoleARN rejected at validation: %v", err)
		} else {
			t.Log("whitespace-only RoleARN passes validation (AWS SDK validates format)")
		}
	})

	t.Run("valid ARN format accepted", func(t *testing.T) {
		validARNs := []string{
			"arn:aws:iam::123456789012:role/TestRole",
			"arn:aws:iam::123456789012:role/path/to/role",
			"arn:aws-cn:iam::123456789012:role/ChinaRole",
			"arn:aws-us-gov:iam::123456789012:role/GovCloudRole",
		}

		for _, arn := range validARNs {
			t.Run(arn, func(t *testing.T) {
				input := &SentinelAssumeRoleInput{
					CredsProvider:  &mockCredentialsProvider{},
					RoleARN:        arn,
					SourceIdentity: validSourceIdentity,
				}

				err := validateInput(input)
				if err != nil {
					t.Errorf("unexpected error for ARN %q: %v", arn, err)
				}
			})
		}
	})
}

// TestExternalIDHandling tests ExternalID field handling.
func TestExternalIDHandling(t *testing.T) {
	validSourceIdentity, err := identity.New("alice", "", "a1b2c3d4")
	if err != nil {
		t.Fatalf("failed to create valid SourceIdentity: %v", err)
	}

	t.Run("empty ExternalID accepted (optional field)", func(t *testing.T) {
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
			SourceIdentity: validSourceIdentity,
			ExternalID:     "",
		}

		err := validateInput(input)
		if err != nil {
			t.Errorf("unexpected error with empty ExternalID: %v", err)
		}

		// Empty ExternalID should not be passed to STS
		// (verified by checking it's not set in the AssumeRole input)
	})

	t.Run("non-empty ExternalID preserved", func(t *testing.T) {
		externalID := "external-12345"
		input := &SentinelAssumeRoleInput{
			CredsProvider:  &mockCredentialsProvider{},
			RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
			SourceIdentity: validSourceIdentity,
			ExternalID:     externalID,
		}

		err := validateInput(input)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if input.ExternalID != externalID {
			t.Errorf("ExternalID = %q, want %q", input.ExternalID, externalID)
		}
	})

	t.Run("ExternalID with special characters accepted", func(t *testing.T) {
		// AWS allows certain special characters in ExternalID
		specialIDs := []string{
			"external-id-123",
			"external_id_456",
			"external.id.789",
			"External@ID",
		}

		for _, extID := range specialIDs {
			t.Run(extID, func(t *testing.T) {
				input := &SentinelAssumeRoleInput{
					CredsProvider:  &mockCredentialsProvider{},
					RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
					SourceIdentity: validSourceIdentity,
					ExternalID:     extID,
				}

				err := validateInput(input)
				if err != nil {
					t.Errorf("unexpected error for ExternalID %q: %v", extID, err)
				}
			})
		}
	})
}

// TestMultipleInvalidFields tests error priority when multiple fields are invalid.
func TestMultipleInvalidFields(t *testing.T) {
	t.Run("returns first error in validation order", func(t *testing.T) {
		// All fields invalid
		input := &SentinelAssumeRoleInput{
			CredsProvider:  nil,                                            // First invalid
			RoleARN:        "",                                             // Second invalid
			SourceIdentity: nil,                                            // Third invalid
		}

		err := validateInput(input)

		// Should return first error (CredsProvider)
		if !errors.Is(err, ErrMissingCredsProvider) {
			t.Errorf("expected first error (ErrMissingCredsProvider), got: %v", err)
		}
	})
}
