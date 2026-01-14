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
