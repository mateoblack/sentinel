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
	validSourceIdentity, err := identity.New("alice", "a1b2c3d4")
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
	validSourceIdentity, err := identity.New("alice", "a1b2c3d4")
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
		si, err := identity.New("bob", "deadbeef")
		if err != nil {
			t.Fatalf("failed to create SourceIdentity: %v", err)
		}

		expected := "sentinel:bob:deadbeef"
		if si.Format() != expected {
			t.Errorf("SourceIdentity.Format() = %q, want %q", si.Format(), expected)
		}
	})

	t.Run("all optional fields pass through when provided", func(t *testing.T) {
		si, err := identity.New("alice", "a1b2c3d4")
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
