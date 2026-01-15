package cli

import (
	"testing"
	"time"
)

func TestSentinelCredentialRequestFields(t *testing.T) {
	// Verify struct has expected fields
	req := SentinelCredentialRequest{
		ProfileName:     "test-profile",
		NoSession:       true,
		SessionDuration: 1 * time.Hour,
		Region:          "us-west-2",
	}

	if req.ProfileName != "test-profile" {
		t.Errorf("ProfileName not set correctly")
	}
	if !req.NoSession {
		t.Errorf("NoSession not set correctly")
	}
	if req.SessionDuration != 1*time.Hour {
		t.Errorf("SessionDuration not set correctly")
	}
	if req.Region != "us-west-2" {
		t.Errorf("Region not set correctly")
	}
}

func TestSentinelCredentialResultFields(t *testing.T) {
	// Verify struct has expected fields
	expiration := time.Now().Add(1 * time.Hour)
	result := SentinelCredentialResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
		Expiration:      expiration,
		CanExpire:       true,
	}

	if result.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AccessKeyID not set correctly")
	}
	if result.SecretAccessKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("SecretAccessKey not set correctly")
	}
	if result.SessionToken != "AQoDYXdzEJr..." {
		t.Errorf("SessionToken not set correctly")
	}
	if result.Expiration != expiration {
		t.Errorf("Expiration not set correctly")
	}
	if !result.CanExpire {
		t.Errorf("CanExpire not set correctly")
	}
}

func TestSentinelCredentialResultWithoutExpiration(t *testing.T) {
	// Verify result without expiration (long-lived credentials)
	result := SentinelCredentialResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "",
		CanExpire:       false,
	}

	if result.CanExpire {
		t.Errorf("CanExpire should be false for long-lived credentials")
	}
	if result.SessionToken != "" {
		t.Errorf("SessionToken should be empty for long-lived credentials")
	}
}

func TestSentinelCredentialRequest_UserField(t *testing.T) {
	// Test that User field is properly set for SourceIdentity stamping
	req := SentinelCredentialRequest{
		ProfileName: "test-profile",
		User:        "alice",
	}

	if req.User != "alice" {
		t.Errorf("expected User 'alice', got %q", req.User)
	}
}

func TestSentinelCredentialRequest_UserFieldWithAllFields(t *testing.T) {
	// Test User field alongside all other fields
	req := SentinelCredentialRequest{
		ProfileName:     "production",
		NoSession:       true,
		SessionDuration: 2 * time.Hour,
		Region:          "us-east-1",
		User:            "bob@example.com",
	}

	if req.ProfileName != "production" {
		t.Errorf("ProfileName not set correctly")
	}
	if !req.NoSession {
		t.Errorf("NoSession not set correctly")
	}
	if req.SessionDuration != 2*time.Hour {
		t.Errorf("SessionDuration not set correctly")
	}
	if req.Region != "us-east-1" {
		t.Errorf("Region not set correctly")
	}
	if req.User != "bob@example.com" {
		t.Errorf("User not set correctly, got %q", req.User)
	}
}

func TestSentinelCredentialRequest_EmptyUser(t *testing.T) {
	// Document that empty User is valid for profiles without role_arn
	// The actual validation happens in TwoHopCredentialProvider when
	// the profile has role_arn and requires SourceIdentity
	req := SentinelCredentialRequest{
		ProfileName: "no-role-profile",
		User:        "", // Empty user - valid for profiles without role_arn
	}

	if req.User != "" {
		t.Errorf("expected empty User for this test case")
	}

	// Note: For profiles WITH role_arn, empty User will cause
	// TwoHopCredentialProvider to return ErrMissingUser
	// This is tested in sentinel/provider_test.go
}

func TestSentinelCredentialRequest_RequestIDField(t *testing.T) {
	t.Run("RequestID field is accessible", func(t *testing.T) {
		req := SentinelCredentialRequest{
			ProfileName: "test-profile",
			RequestID:   "abc12345",
		}

		if req.RequestID != "abc12345" {
			t.Errorf("expected RequestID 'abc12345', got %q", req.RequestID)
		}
	})

	t.Run("empty RequestID is valid", func(t *testing.T) {
		req := SentinelCredentialRequest{
			ProfileName: "test-profile",
			RequestID:   "", // Empty - will be auto-generated during credential retrieval
		}

		if req.RequestID != "" {
			t.Errorf("expected empty RequestID, got %q", req.RequestID)
		}
	})

	t.Run("RequestID with all other fields", func(t *testing.T) {
		req := SentinelCredentialRequest{
			ProfileName:     "production",
			NoSession:       true,
			SessionDuration: 2 * time.Hour,
			Region:          "us-east-1",
			User:            "alice",
			RequestID:       "def67890",
		}

		if req.ProfileName != "production" {
			t.Errorf("ProfileName not set correctly")
		}
		if !req.NoSession {
			t.Errorf("NoSession not set correctly")
		}
		if req.SessionDuration != 2*time.Hour {
			t.Errorf("SessionDuration not set correctly")
		}
		if req.Region != "us-east-1" {
			t.Errorf("Region not set correctly")
		}
		if req.User != "alice" {
			t.Errorf("User not set correctly")
		}
		if req.RequestID != "def67890" {
			t.Errorf("RequestID not set correctly, got %q", req.RequestID)
		}
	})
}

func TestSentinelCredentialResult_SourceIdentityField(t *testing.T) {
	t.Run("SourceIdentity field is accessible", func(t *testing.T) {
		result := SentinelCredentialResult{
			AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
			SourceIdentity: "sentinel:alice:abc12345",
		}

		if result.SourceIdentity != "sentinel:alice:abc12345" {
			t.Errorf("expected SourceIdentity 'sentinel:alice:abc12345', got %q", result.SourceIdentity)
		}
	})

	t.Run("empty SourceIdentity is valid", func(t *testing.T) {
		// SourceIdentity is empty when profile has no role_arn
		result := SentinelCredentialResult{
			AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
			SourceIdentity: "", // Empty - no role assumption
		}

		if result.SourceIdentity != "" {
			t.Errorf("expected empty SourceIdentity, got %q", result.SourceIdentity)
		}
	})
}

func TestSentinelCredentialResult_RoleARNField(t *testing.T) {
	t.Run("RoleARN field is accessible", func(t *testing.T) {
		result := SentinelCredentialResult{
			AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
			RoleARN:     "arn:aws:iam::123456789012:role/ProductionRole",
		}

		if result.RoleARN != "arn:aws:iam::123456789012:role/ProductionRole" {
			t.Errorf("expected RoleARN 'arn:aws:iam::123456789012:role/ProductionRole', got %q", result.RoleARN)
		}
	})

	t.Run("empty RoleARN is valid", func(t *testing.T) {
		// RoleARN is empty when profile has no role assumption
		result := SentinelCredentialResult{
			AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
			RoleARN:     "", // Empty - no role assumption
		}

		if result.RoleARN != "" {
			t.Errorf("expected empty RoleARN, got %q", result.RoleARN)
		}
	})
}

func TestSentinelCredentialResult_AllNewFields(t *testing.T) {
	// Test that SourceIdentity and RoleARN work together with all other fields
	expiration := time.Now().Add(1 * time.Hour)
	result := SentinelCredentialResult{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
		Expiration:      expiration,
		CanExpire:       true,
		SourceIdentity:  "sentinel:bob:xyz98765",
		RoleARN:         "arn:aws:iam::987654321098:role/AdminRole",
	}

	// Verify all fields
	if result.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AccessKeyID not set correctly")
	}
	if result.SecretAccessKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("SecretAccessKey not set correctly")
	}
	if result.SessionToken != "AQoDYXdzEJr..." {
		t.Errorf("SessionToken not set correctly")
	}
	if !result.CanExpire {
		t.Errorf("CanExpire should be true")
	}
	if result.SourceIdentity != "sentinel:bob:xyz98765" {
		t.Errorf("SourceIdentity not set correctly, got %q", result.SourceIdentity)
	}
	if result.RoleARN != "arn:aws:iam::987654321098:role/AdminRole" {
		t.Errorf("RoleARN not set correctly, got %q", result.RoleARN)
	}
}
