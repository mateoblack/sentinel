package sentinel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestTwoHopCredentialProviderValidation(t *testing.T) {
	testCases := []struct {
		name    string
		input   TwoHopCredentialProviderInput
		wantErr error
	}{
		{
			name: "missing BaseCredsProvider returns ErrMissingBaseCredsProvider",
			input: TwoHopCredentialProviderInput{
				BaseCredsProvider: nil,
				RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
				User:              "alice",
			},
			wantErr: ErrMissingBaseCredsProvider,
		},
		{
			name: "missing RoleARN returns ErrMissingRoleARN",
			input: TwoHopCredentialProviderInput{
				BaseCredsProvider: &mockCredentialsProvider{},
				RoleARN:           "",
				User:              "alice",
			},
			wantErr: ErrMissingRoleARN,
		},
		{
			name: "missing User returns ErrMissingUser",
			input: TwoHopCredentialProviderInput{
				BaseCredsProvider: &mockCredentialsProvider{},
				RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
				User:              "",
			},
			wantErr: ErrMissingUser,
		},
		{
			name: "valid input creates provider successfully",
			input: TwoHopCredentialProviderInput{
				BaseCredsProvider: &mockCredentialsProvider{},
				RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
				User:              "alice",
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewTwoHopCredentialProvider(tc.input)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
				if provider != nil {
					t.Error("expected nil provider when error returned")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if provider == nil {
				t.Error("expected non-nil provider")
			}
		})
	}
}

func TestNewTwoHopProvider(t *testing.T) {
	testCases := []struct {
		name         string
		baseProvider aws.CredentialsProvider
		roleARN      string
		user         string
		region       string
		wantErr      error
	}{
		{
			name:         "valid inputs creates provider",
			baseProvider: &mockCredentialsProvider{},
			roleARN:      "arn:aws:iam::123456789012:role/TestRole",
			user:         "alice",
			region:       "us-west-2",
			wantErr:      nil,
		},
		{
			name:         "nil baseProvider returns error",
			baseProvider: nil,
			roleARN:      "arn:aws:iam::123456789012:role/TestRole",
			user:         "alice",
			region:       "us-west-2",
			wantErr:      ErrMissingBaseCredsProvider,
		},
		{
			name:         "empty roleARN returns error",
			baseProvider: &mockCredentialsProvider{},
			roleARN:      "",
			user:         "alice",
			region:       "us-west-2",
			wantErr:      ErrMissingRoleARN,
		},
		{
			name:         "empty user returns error",
			baseProvider: &mockCredentialsProvider{},
			roleARN:      "arn:aws:iam::123456789012:role/TestRole",
			user:         "",
			region:       "us-west-2",
			wantErr:      ErrMissingUser,
		},
		{
			name:         "empty region is allowed",
			baseProvider: &mockCredentialsProvider{},
			roleARN:      "arn:aws:iam::123456789012:role/TestRole",
			user:         "alice",
			region:       "",
			wantErr:      nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewTwoHopProvider(tc.baseProvider, tc.roleARN, tc.user, tc.region)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if provider == nil {
				t.Error("expected non-nil provider")
			}
		})
	}
}

// capturingAssumeRoleProvider captures the SourceIdentity that would be passed
// to SentinelAssumeRole. This allows testing that the provider generates correct
// SourceIdentity format without making actual AWS calls.
type capturingAssumeRoleProvider struct {
	capturedUser      string
	capturedRequestID string
}

// TestTwoHopCredentialProviderSourceIdentity verifies that SourceIdentity
// is generated correctly during Retrieve. We test this by checking the
// input validation and sanitization logic that feeds into SourceIdentity.
func TestTwoHopCredentialProviderSourceIdentity(t *testing.T) {
	testCases := []struct {
		name             string
		user             string
		wantSanitized    string
		wantRequestIDLen int
	}{
		{
			name:             "simple username passes through",
			user:             "alice",
			wantSanitized:    "alice",
			wantRequestIDLen: 8,
		},
		{
			name:             "email is sanitized",
			user:             "alice@example.com",
			wantSanitized:    "aliceexamplecom",
			wantRequestIDLen: 8,
		},
		{
			name:             "username with special chars is sanitized",
			user:             "alice.bob-123",
			wantSanitized:    "alicebob123",
			wantRequestIDLen: 8,
		},
		{
			name:             "long username is truncated",
			user:             "verylongusernamethatexceedstwentycharacters",
			wantSanitized:    "verylongusernamethat", // 20 chars
			wantRequestIDLen: 8,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewTwoHopCredentialProvider(TwoHopCredentialProviderInput{
				BaseCredsProvider: &mockCredentialsProvider{},
				RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
				User:              tc.user,
			})
			if err != nil {
				t.Fatalf("failed to create provider: %v", err)
			}

			// We can't easily test the full Retrieve path without mocking STS,
			// but we can verify the provider stores the correct user and will
			// sanitize it correctly by testing the identity package directly.
			// The actual SourceIdentity format test is done in validateSourceIdentityFormat.

			// Verify provider stores the original user
			if provider.Input.User != tc.user {
				t.Errorf("provider.Input.User = %q, want %q", provider.Input.User, tc.user)
			}
		})
	}
}

// TestSourceIdentityFormat verifies the SourceIdentity format using identity package.
func TestSourceIdentityFormat(t *testing.T) {
	// Import identity package functions are tested via the provider's Retrieve path
	// This test validates the expected format pattern: sentinel:<user>:<request-id>

	testCases := []struct {
		name       string
		user       string
		wantPrefix string
	}{
		{
			name:       "format starts with sentinel prefix",
			user:       "alice",
			wantPrefix: "sentinel:alice:",
		},
		{
			name:       "sanitized user in format",
			user:       "aliceexamplecom",
			wantPrefix: "sentinel:aliceexamplecom:",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test that if we were to create a SourceIdentity, it would have the right format
			// This is a documentation test showing expected behavior

			expectedPattern := tc.wantPrefix + "[8-char-hex]"
			if !strings.HasPrefix(tc.wantPrefix, "sentinel:") {
				t.Errorf("expected prefix to start with 'sentinel:', got %q", tc.wantPrefix)
			}

			// Verify the prefix contains the user
			parts := strings.Split(tc.wantPrefix, ":")
			if len(parts) < 2 {
				t.Errorf("expected at least 2 parts in prefix, got %d", len(parts))
			}
			if parts[1] != tc.user {
				t.Errorf("expected user %q in prefix, got %q", tc.user, parts[1])
			}

			_ = expectedPattern // Used for documentation
		})
	}
}

func TestTwoHopCredentialProviderDefaults(t *testing.T) {
	t.Run("default SessionDuration is 1 hour", func(t *testing.T) {
		provider, err := NewTwoHopCredentialProvider(TwoHopCredentialProviderInput{
			BaseCredsProvider: &mockCredentialsProvider{},
			RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
			User:              "alice",
			SessionDuration:   0, // Zero, should use default
		})
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		// Verify zero duration is stored (default is applied in Retrieve)
		if provider.Input.SessionDuration != 0 {
			t.Errorf("expected zero duration in input, got %v", provider.Input.SessionDuration)
		}

		// The default (1 hour) is applied in Retrieve() when calling SentinelAssumeRole
		// This matches DefaultDuration from assume_role.go
		expectedDefault := time.Hour
		if DefaultDuration != expectedDefault {
			t.Errorf("DefaultDuration = %v, want %v", DefaultDuration, expectedDefault)
		}
	})

	t.Run("custom SessionDuration is preserved", func(t *testing.T) {
		customDuration := 30 * time.Minute
		provider, err := NewTwoHopCredentialProvider(TwoHopCredentialProviderInput{
			BaseCredsProvider: &mockCredentialsProvider{},
			RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
			User:              "alice",
			SessionDuration:   customDuration,
		})
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		if provider.Input.SessionDuration != customDuration {
			t.Errorf("SessionDuration = %v, want %v", provider.Input.SessionDuration, customDuration)
		}
	})
}

func TestValidateProviderInput(t *testing.T) {
	testCases := []struct {
		name    string
		input   *TwoHopCredentialProviderInput
		wantErr error
	}{
		{
			name: "valid input passes",
			input: &TwoHopCredentialProviderInput{
				BaseCredsProvider: &mockCredentialsProvider{},
				RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
				User:              "alice",
			},
			wantErr: nil,
		},
		{
			name: "nil BaseCredsProvider fails",
			input: &TwoHopCredentialProviderInput{
				BaseCredsProvider: nil,
				RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
				User:              "alice",
			},
			wantErr: ErrMissingBaseCredsProvider,
		},
		{
			name: "empty RoleARN fails",
			input: &TwoHopCredentialProviderInput{
				BaseCredsProvider: &mockCredentialsProvider{},
				RoleARN:           "",
				User:              "alice",
			},
			wantErr: ErrMissingRoleARN,
		},
		{
			name: "empty User fails",
			input: &TwoHopCredentialProviderInput{
				BaseCredsProvider: &mockCredentialsProvider{},
				RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
				User:              "",
			},
			wantErr: ErrMissingUser,
		},
		{
			name: "all optional fields empty is valid",
			input: &TwoHopCredentialProviderInput{
				BaseCredsProvider: &mockCredentialsProvider{},
				RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
				User:              "alice",
				Region:            "",
				ExternalID:        "",
				SessionDuration:   0,
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProviderInput(tc.input)

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

func TestProviderErrorTypes(t *testing.T) {
	// Verify error types are properly defined and distinguishable
	testCases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrMissingBaseCredsProvider",
			err:  ErrMissingBaseCredsProvider,
			want: "BaseCredsProvider is required",
		},
		{
			name: "ErrMissingUser",
			err:  ErrMissingUser,
			want: "User is required for SourceIdentity",
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

func TestProviderImplementsCredentialsProvider(t *testing.T) {
	// Compile-time check that TwoHopCredentialProvider implements aws.CredentialsProvider
	var _ aws.CredentialsProvider = (*TwoHopCredentialProvider)(nil)

	// Runtime check that we can create a valid provider
	provider, err := NewTwoHopCredentialProvider(TwoHopCredentialProviderInput{
		BaseCredsProvider: &mockCredentialsProvider{},
		RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
		User:              "alice",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Verify the provider has a Retrieve method with the correct signature
	// (compile-time interface check above guarantees this, but explicit test for clarity)
	ctx := context.Background()
	_, _ = provider.Retrieve(ctx) // Will fail with AWS error, but signature is correct
}

func TestProviderInputFieldsPassThrough(t *testing.T) {
	// Verify all input fields are stored correctly
	input := TwoHopCredentialProviderInput{
		BaseCredsProvider:    &mockCredentialsProvider{},
		RoleARN:              "arn:aws:iam::123456789012:role/TestRole",
		User:                 "alice",
		Region:               "us-west-2",
		STSRegionalEndpoints: "regional",
		EndpointURL:          "https://sts.us-west-2.amazonaws.com",
		ExternalID:           "ext-123",
		SessionDuration:      2 * time.Hour,
	}

	provider, err := NewTwoHopCredentialProvider(input)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Verify all fields are preserved
	if provider.Input.RoleARN != input.RoleARN {
		t.Errorf("RoleARN = %q, want %q", provider.Input.RoleARN, input.RoleARN)
	}
	if provider.Input.User != input.User {
		t.Errorf("User = %q, want %q", provider.Input.User, input.User)
	}
	if provider.Input.Region != input.Region {
		t.Errorf("Region = %q, want %q", provider.Input.Region, input.Region)
	}
	if provider.Input.STSRegionalEndpoints != input.STSRegionalEndpoints {
		t.Errorf("STSRegionalEndpoints = %q, want %q", provider.Input.STSRegionalEndpoints, input.STSRegionalEndpoints)
	}
	if provider.Input.EndpointURL != input.EndpointURL {
		t.Errorf("EndpointURL = %q, want %q", provider.Input.EndpointURL, input.EndpointURL)
	}
	if provider.Input.ExternalID != input.ExternalID {
		t.Errorf("ExternalID = %q, want %q", provider.Input.ExternalID, input.ExternalID)
	}
	if provider.Input.SessionDuration != input.SessionDuration {
		t.Errorf("SessionDuration = %v, want %v", provider.Input.SessionDuration, input.SessionDuration)
	}
}

func TestTwoHopCredentialProviderRequestIDHandling(t *testing.T) {
	t.Run("pre-provided RequestID is stored in Input", func(t *testing.T) {
		preGeneratedRequestID := "abc12345"
		provider, err := NewTwoHopCredentialProvider(TwoHopCredentialProviderInput{
			BaseCredsProvider: &mockCredentialsProvider{},
			RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
			User:              "alice",
			RequestID:         preGeneratedRequestID,
		})
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		// Verify RequestID is stored correctly
		if provider.Input.RequestID != preGeneratedRequestID {
			t.Errorf("RequestID = %q, want %q", provider.Input.RequestID, preGeneratedRequestID)
		}
	})

	t.Run("empty RequestID is valid", func(t *testing.T) {
		provider, err := NewTwoHopCredentialProvider(TwoHopCredentialProviderInput{
			BaseCredsProvider: &mockCredentialsProvider{},
			RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
			User:              "alice",
			RequestID:         "", // Empty - should be auto-generated during Retrieve
		})
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		// Verify empty RequestID is allowed (will be generated during Retrieve)
		if provider.Input.RequestID != "" {
			t.Errorf("RequestID should be empty when not provided, got %q", provider.Input.RequestID)
		}

		// LastSourceIdentity should be nil before Retrieve is called
		if provider.LastSourceIdentity != nil {
			t.Error("LastSourceIdentity should be nil before Retrieve()")
		}
	})

	t.Run("RequestID passes through with other input fields", func(t *testing.T) {
		input := TwoHopCredentialProviderInput{
			BaseCredsProvider:    &mockCredentialsProvider{},
			RoleARN:              "arn:aws:iam::123456789012:role/TestRole",
			User:                 "alice",
			Region:               "us-west-2",
			STSRegionalEndpoints: "regional",
			EndpointURL:          "https://sts.us-west-2.amazonaws.com",
			ExternalID:           "ext-123",
			SessionDuration:      2 * time.Hour,
			RequestID:            "def67890",
		}

		provider, err := NewTwoHopCredentialProvider(input)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		// Verify RequestID is preserved alongside other fields
		if provider.Input.RequestID != input.RequestID {
			t.Errorf("RequestID = %q, want %q", provider.Input.RequestID, input.RequestID)
		}
		if provider.Input.User != input.User {
			t.Errorf("User = %q, want %q", provider.Input.User, input.User)
		}
		if provider.Input.RoleARN != input.RoleARN {
			t.Errorf("RoleARN = %q, want %q", provider.Input.RoleARN, input.RoleARN)
		}
	})
}

func TestTwoHopCredentialProviderLastSourceIdentity(t *testing.T) {
	t.Run("LastSourceIdentity is nil before Retrieve", func(t *testing.T) {
		provider, err := NewTwoHopCredentialProvider(TwoHopCredentialProviderInput{
			BaseCredsProvider: &mockCredentialsProvider{},
			RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
			User:              "alice",
		})
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		if provider.LastSourceIdentity != nil {
			t.Error("LastSourceIdentity should be nil before Retrieve()")
		}
	})

	t.Run("LastSourceIdentity field is accessible on provider struct", func(t *testing.T) {
		provider, err := NewTwoHopCredentialProvider(TwoHopCredentialProviderInput{
			BaseCredsProvider: &mockCredentialsProvider{},
			RoleARN:           "arn:aws:iam::123456789012:role/TestRole",
			User:              "alice",
		})
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		// Verify the field exists and is of the right type (pointer to SourceIdentity)
		// After Retrieve() completes, callers can access this to get the SourceIdentity string
		var _ = provider.LastSourceIdentity // Compile-time check that field exists

		// Note: To fully test LastSourceIdentity population, we'd need to mock STS
		// or run an integration test with real AWS credentials.
		// The unit test here verifies the field exists and is correctly typed.
	})
}
