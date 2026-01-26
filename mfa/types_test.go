package mfa

import (
	"testing"
	"time"
)

func TestMFAMethod_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		method MFAMethod
		want   bool
	}{
		{"totp is valid", MethodTOTP, true},
		{"sms is valid", MethodSMS, true},
		{"empty is invalid", MFAMethod(""), false},
		{"unknown is invalid", MFAMethod("email"), false},
		{"uppercase is invalid", MFAMethod("TOTP"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.method.IsValid(); got != tt.want {
				t.Errorf("MFAMethod(%q).IsValid() = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestMFAMethod_String(t *testing.T) {
	tests := []struct {
		method MFAMethod
		want   string
	}{
		{MethodTOTP, "totp"},
		{MethodSMS, "sms"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.method.String(); got != tt.want {
				t.Errorf("MFAMethod.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMFAChallenge_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"not expired", time.Now().Add(5 * time.Minute), false},
		{"just expired", time.Now().Add(-1 * time.Second), true},
		{"long expired", time.Now().Add(-1 * time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &MFAChallenge{
				ExpiresAt: tt.expiresAt,
			}
			if got := c.IsExpired(); got != tt.want {
				t.Errorf("MFAChallenge.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewChallengeID(t *testing.T) {
	// Generate multiple IDs and verify format
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := NewChallengeID()

		// Check length
		if len(id) != ChallengeIDLength {
			t.Errorf("NewChallengeID() length = %d, want %d", len(id), ChallengeIDLength)
		}

		// Check validity
		if !ValidateChallengeID(id) {
			t.Errorf("NewChallengeID() = %q is not valid", id)
		}

		// Check uniqueness
		if ids[id] {
			t.Errorf("NewChallengeID() generated duplicate ID: %s", id)
		}
		ids[id] = true
	}
}

func TestValidateChallengeID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{"valid 16 hex", "abcdef0123456789", true},
		{"valid all zeros", "0000000000000000", true},
		{"valid all f", "ffffffffffffffff", true},
		{"too short", "abcdef01234567", false},
		{"too long", "abcdef01234567890", false},
		{"empty", "", false},
		{"uppercase invalid", "ABCDEF0123456789", false},
		{"mixed case invalid", "ABCDef0123456789", false},
		{"non-hex chars", "ghijkl0123456789", false},
		{"spaces", "abcdef01 3456789", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateChallengeID(tt.id); got != tt.want {
				t.Errorf("ValidateChallengeID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify constants have expected values
	if DefaultChallengeTTL != 5*time.Minute {
		t.Errorf("DefaultChallengeTTL = %v, want 5 minutes", DefaultChallengeTTL)
	}

	if CodeLength != 6 {
		t.Errorf("CodeLength = %d, want 6", CodeLength)
	}

	if ChallengeIDLength != 16 {
		t.Errorf("ChallengeIDLength = %d, want 16", ChallengeIDLength)
	}
}
