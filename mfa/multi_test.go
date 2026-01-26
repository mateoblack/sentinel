package mfa

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockVerifier implements Verifier for testing.
type mockVerifier struct {
	challengeFn func(ctx context.Context, userID string) (*MFAChallenge, error)
	verifyFn    func(ctx context.Context, challengeID string, code string) (bool, error)
}

func (m *mockVerifier) Challenge(ctx context.Context, userID string) (*MFAChallenge, error) {
	if m.challengeFn != nil {
		return m.challengeFn(ctx, userID)
	}
	return nil, ErrUserNotFound
}

func (m *mockVerifier) Verify(ctx context.Context, challengeID string, code string) (bool, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, challengeID, code)
	}
	return false, nil
}

func TestMultiVerifier_Challenge(t *testing.T) {
	t.Run("empty verifiers returns error", func(t *testing.T) {
		m := NewMultiVerifier()
		_, err := m.Challenge(context.Background(), "user1")
		if err == nil {
			t.Error("Expected error for empty verifiers")
		}
		if !errors.Is(err, ErrNoVerifiersConfigured) {
			t.Errorf("Expected ErrNoVerifiersConfigured, got %v", err)
		}
	})

	t.Run("first verifier succeeds", func(t *testing.T) {
		v1 := &mockVerifier{
			challengeFn: func(ctx context.Context, userID string) (*MFAChallenge, error) {
				return &MFAChallenge{ID: "challenge1", Method: MethodTOTP}, nil
			},
		}
		v2 := &mockVerifier{
			challengeFn: func(ctx context.Context, userID string) (*MFAChallenge, error) {
				t.Error("Second verifier should not be called")
				return nil, nil
			},
		}

		m := NewMultiVerifier(v1, v2)
		challenge, err := m.Challenge(context.Background(), "user1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if challenge.ID != "challenge1" {
			t.Errorf("Expected challenge1, got %s", challenge.ID)
		}
	})

	t.Run("first verifier fails with user not found, second succeeds", func(t *testing.T) {
		v1 := &mockVerifier{
			challengeFn: func(ctx context.Context, userID string) (*MFAChallenge, error) {
				return nil, ErrUserNotFound
			},
		}
		v2 := &mockVerifier{
			challengeFn: func(ctx context.Context, userID string) (*MFAChallenge, error) {
				return &MFAChallenge{ID: "challenge2", Method: MethodSMS}, nil
			},
		}

		m := NewMultiVerifier(v1, v2)
		challenge, err := m.Challenge(context.Background(), "user1")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if challenge.ID != "challenge2" {
			t.Errorf("Expected challenge2, got %s", challenge.ID)
		}
		if challenge.Method != MethodSMS {
			t.Errorf("Expected SMS method, got %s", challenge.Method)
		}
	})

	t.Run("all verifiers return user not found", func(t *testing.T) {
		v1 := &mockVerifier{
			challengeFn: func(ctx context.Context, userID string) (*MFAChallenge, error) {
				return nil, ErrUserNotFound
			},
		}
		v2 := &mockVerifier{
			challengeFn: func(ctx context.Context, userID string) (*MFAChallenge, error) {
				return nil, ErrUserNotFound
			},
		}

		m := NewMultiVerifier(v1, v2)
		_, err := m.Challenge(context.Background(), "unknown-user")
		if err == nil {
			t.Error("Expected error for unknown user")
		}
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("first verifier returns other error", func(t *testing.T) {
		otherErr := errors.New("network error")
		v1 := &mockVerifier{
			challengeFn: func(ctx context.Context, userID string) (*MFAChallenge, error) {
				return nil, otherErr
			},
		}
		v2 := &mockVerifier{
			challengeFn: func(ctx context.Context, userID string) (*MFAChallenge, error) {
				t.Error("Second verifier should not be called on non-user-not-found error")
				return nil, nil
			},
		}

		m := NewMultiVerifier(v1, v2)
		_, err := m.Challenge(context.Background(), "user1")
		if err == nil {
			t.Error("Expected error")
		}
		if !errors.Is(err, otherErr) {
			t.Errorf("Expected network error, got %v", err)
		}
	})
}

func TestMultiVerifier_Verify(t *testing.T) {
	t.Run("empty verifiers returns error", func(t *testing.T) {
		m := NewMultiVerifier()
		_, err := m.Verify(context.Background(), "challenge1", "123456")
		if err == nil {
			t.Error("Expected error for empty verifiers")
		}
		if !errors.Is(err, ErrNoVerifiersConfigured) {
			t.Errorf("Expected ErrNoVerifiersConfigured, got %v", err)
		}
	})

	t.Run("first verifier succeeds", func(t *testing.T) {
		v1 := &mockVerifier{
			verifyFn: func(ctx context.Context, challengeID string, code string) (bool, error) {
				return true, nil
			},
		}
		v2 := &mockVerifier{
			verifyFn: func(ctx context.Context, challengeID string, code string) (bool, error) {
				// Second verifier should NOT be called since first already succeeded
				// But this is not an error - it's just optimization behavior
				return false, nil
			},
		}

		m := NewMultiVerifier(v1, v2)
		valid, err := m.Verify(context.Background(), "challenge1", "123456")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !valid {
			t.Error("Expected valid verification")
		}
	})

	t.Run("first verifier fails, second succeeds", func(t *testing.T) {
		v1 := &mockVerifier{
			verifyFn: func(ctx context.Context, challengeID string, code string) (bool, error) {
				return false, nil
			},
		}
		v2 := &mockVerifier{
			verifyFn: func(ctx context.Context, challengeID string, code string) (bool, error) {
				return true, nil
			},
		}

		m := NewMultiVerifier(v1, v2)
		valid, err := m.Verify(context.Background(), "challenge1", "123456")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !valid {
			t.Error("Expected valid verification from second verifier")
		}
	})

	t.Run("first verifier returns error, second succeeds", func(t *testing.T) {
		v1 := &mockVerifier{
			verifyFn: func(ctx context.Context, challengeID string, code string) (bool, error) {
				return false, errors.New("challenge not found")
			},
		}
		v2 := &mockVerifier{
			verifyFn: func(ctx context.Context, challengeID string, code string) (bool, error) {
				return true, nil
			},
		}

		m := NewMultiVerifier(v1, v2)
		valid, err := m.Verify(context.Background(), "challenge1", "123456")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !valid {
			t.Error("Expected valid verification from second verifier even when first errors")
		}
	})

	t.Run("all verifiers fail", func(t *testing.T) {
		v1 := &mockVerifier{
			verifyFn: func(ctx context.Context, challengeID string, code string) (bool, error) {
				return false, nil
			},
		}
		v2 := &mockVerifier{
			verifyFn: func(ctx context.Context, challengeID string, code string) (bool, error) {
				return false, nil
			},
		}

		m := NewMultiVerifier(v1, v2)
		valid, err := m.Verify(context.Background(), "challenge1", "wrong-code")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if valid {
			t.Error("Expected invalid verification when all verifiers fail")
		}
	})
}

func TestMultiVerifier_VerifiersCount(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		m := NewMultiVerifier()
		if m.VerifiersCount() != 0 {
			t.Errorf("Expected 0, got %d", m.VerifiersCount())
		}
	})

	t.Run("single verifier", func(t *testing.T) {
		m := NewMultiVerifier(&mockVerifier{})
		if m.VerifiersCount() != 1 {
			t.Errorf("Expected 1, got %d", m.VerifiersCount())
		}
	})

	t.Run("multiple verifiers", func(t *testing.T) {
		m := NewMultiVerifier(&mockVerifier{}, &mockVerifier{}, &mockVerifier{})
		if m.VerifiersCount() != 3 {
			t.Errorf("Expected 3, got %d", m.VerifiersCount())
		}
	})
}

func TestMultiVerifier_RealVerifiers(t *testing.T) {
	// Test with real TOTP and SMS verifiers
	totpSecrets := map[string]TOTPConfig{
		"totp-user": {Secret: rfc6238TestSecret, Digits: 6},
	}

	phones := map[string]string{
		"sms-user": "+15551234567",
	}

	totpVerifier := NewTOTPVerifier(totpSecrets)
	smsVerifier := newSMSVerifierWithClient(&mockSMSAPI{}, phones)

	multi := NewMultiVerifier(totpVerifier, smsVerifier)

	t.Run("TOTP user gets TOTP challenge", func(t *testing.T) {
		challenge, err := multi.Challenge(context.Background(), "totp-user")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if challenge.Method != MethodTOTP {
			t.Errorf("Expected TOTP method, got %s", challenge.Method)
		}
	})

	t.Run("SMS user gets SMS challenge", func(t *testing.T) {
		challenge, err := multi.Challenge(context.Background(), "sms-user")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if challenge.Method != MethodSMS {
			t.Errorf("Expected SMS method, got %s", challenge.Method)
		}
	})

	t.Run("unknown user fails", func(t *testing.T) {
		_, err := multi.Challenge(context.Background(), "unknown-user")
		if err == nil {
			t.Error("Expected error for unknown user")
		}
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Expected ErrUserNotFound, got %v", err)
		}
	})

	t.Run("TOTP verification works", func(t *testing.T) {
		// For TOTP, challengeID is the userID
		code := GenerateTOTPAtTime(rfc6238TestSecret, time.Now(), 30, 6)
		valid, err := multi.Verify(context.Background(), "totp-user", code)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !valid {
			t.Error("Expected valid TOTP verification")
		}
	})
}
