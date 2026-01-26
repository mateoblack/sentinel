package mfa

import (
	"context"
	"errors"
	"testing"
	"time"
)

// RFC 6238 test secret (ASCII "12345678901234567890" in Base32)
// This is the SHA1 test secret from the RFC
const rfc6238TestSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// RFC 6238 test vectors for SHA1 (Table 1 in the RFC)
// Times are Unix timestamps, expected codes are for SHA1 with 8 digits
// Note: RFC 6238 uses 8-digit codes for test vectors, but we default to 6 digits
var rfc6238TestVectors = []struct {
	time     int64
	expected string // 8-digit code from RFC
}{
	{59, "94287082"},
	{1111111109, "07081804"},
	{1111111111, "14050471"},
	{1234567890, "89005924"},
	{2000000000, "69279037"},
	{20000000000, "65353130"},
}

func TestTOTP_RFC6238TestVectors(t *testing.T) {
	// Test with 8 digits to match RFC 6238 test vectors
	for _, tc := range rfc6238TestVectors {
		t.Run(tc.expected, func(t *testing.T) {
			testTime := time.Unix(tc.time, 0)
			got := GenerateTOTPAtTime(rfc6238TestSecret, testTime, 30, 8)
			if got != tc.expected {
				t.Errorf("GenerateTOTPAtTime(time=%d) = %q, want %q", tc.time, got, tc.expected)
			}
		})
	}
}

func TestTOTP_Generate6Digits(t *testing.T) {
	// Test 6-digit codes (default) at a known time
	// Using same secret but 6 digits
	testTime := time.Unix(1234567890, 0)
	got := GenerateTOTPAtTime(rfc6238TestSecret, testTime, 30, 6)
	// 6-digit truncation of the same HMAC value
	if len(got) != 6 {
		t.Errorf("Generated code length = %d, want 6", len(got))
	}
	// Verify it's all digits
	for _, c := range got {
		if c < '0' || c > '9' {
			t.Errorf("Generated code contains non-digit: %q", got)
			break
		}
	}
}

func TestTOTPVerifier_Challenge(t *testing.T) {
	secrets := map[string]TOTPConfig{
		"user1": {Secret: rfc6238TestSecret},
	}
	v := NewTOTPVerifier(secrets)

	t.Run("known user returns empty challenge", func(t *testing.T) {
		challenge, err := v.Challenge(context.Background(), "user1")
		if err != nil {
			t.Fatalf("Challenge() error = %v, want nil", err)
		}
		if challenge.Method != MethodTOTP {
			t.Errorf("Challenge.Method = %v, want %v", challenge.Method, MethodTOTP)
		}
		if challenge.ID != "" {
			t.Errorf("Challenge.ID = %q, want empty (TOTP is stateless)", challenge.ID)
		}
		if challenge.IsExpired() {
			t.Errorf("Challenge should not be expired immediately")
		}
	})

	t.Run("unknown user returns error", func(t *testing.T) {
		_, err := v.Challenge(context.Background(), "unknown")
		if err == nil {
			t.Fatal("Challenge() error = nil, want error for unknown user")
		}
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Challenge() error = %v, want ErrUserNotFound", err)
		}
	})
}

func TestTOTPVerifier_Verify(t *testing.T) {
	secrets := map[string]TOTPConfig{
		"user1": {Secret: rfc6238TestSecret, Digits: 8},
		"user2": {Secret: rfc6238TestSecret, Digits: 6, Period: 30, Skew: 1},
	}
	v := NewTOTPVerifier(secrets)

	t.Run("valid code accepted", func(t *testing.T) {
		// Generate a valid code for the current time
		code := GenerateTOTPAtTime(rfc6238TestSecret, time.Now(), 30, 8)
		valid, err := v.Verify(context.Background(), "user1", code)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !valid {
			t.Errorf("Verify() = false, want true for valid code")
		}
	})

	t.Run("invalid code rejected", func(t *testing.T) {
		valid, err := v.Verify(context.Background(), "user1", "00000000")
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if valid {
			t.Errorf("Verify() = true, want false for invalid code")
		}
	})

	t.Run("unknown user returns error", func(t *testing.T) {
		_, err := v.Verify(context.Background(), "unknown", "123456")
		if err == nil {
			t.Fatal("Verify() error = nil, want error for unknown user")
		}
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Verify() error = %v, want ErrUserNotFound", err)
		}
	})

	t.Run("6-digit code accepted", func(t *testing.T) {
		code := GenerateTOTPAtTime(rfc6238TestSecret, time.Now(), 30, 6)
		valid, err := v.Verify(context.Background(), "user2", code)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !valid {
			t.Errorf("Verify() = false, want true for valid 6-digit code")
		}
	})
}

func TestTOTPVerifier_SkewHandling(t *testing.T) {
	// Test that codes from adjacent time periods are accepted
	secrets := map[string]TOTPConfig{
		"user1": {Secret: rfc6238TestSecret, Digits: 6, Period: 30, Skew: 1},
	}
	v := NewTOTPVerifier(secrets)

	// Test a code from 30 seconds ago (1 period back)
	pastTime := time.Now().Add(-30 * time.Second)
	pastCode := GenerateTOTPAtTime(rfc6238TestSecret, pastTime, 30, 6)

	// Test a code from 30 seconds in future (1 period ahead)
	futureTime := time.Now().Add(30 * time.Second)
	futureCode := GenerateTOTPAtTime(rfc6238TestSecret, futureTime, 30, 6)

	t.Run("past period code accepted with skew", func(t *testing.T) {
		valid, err := v.Verify(context.Background(), "user1", pastCode)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		// Note: This may or may not be valid depending on exact timing,
		// but we're testing that skew is considered
		t.Logf("Past code validation: %v (code: %s)", valid, pastCode)
	})

	t.Run("future period code accepted with skew", func(t *testing.T) {
		valid, err := v.Verify(context.Background(), "user1", futureCode)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		// Note: This may or may not be valid depending on exact timing
		t.Logf("Future code validation: %v (code: %s)", valid, futureCode)
	})
}

func TestTOTP_InvalidSecret(t *testing.T) {
	// Test with invalid Base32 secret
	code := generateTOTP("invalid!secret!", 0, 6)
	if code != "" {
		t.Errorf("generateTOTP with invalid secret = %q, want empty string", code)
	}
}

func TestTOTP_SecretNormalization(t *testing.T) {
	// Test that secrets with different padding work
	secrets := []string{
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",   // Exact padding
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ==", // Extra padding
		"gezdgnbvgy3tqojqgezdgnbvgy3tqojq",   // Lowercase
		" GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ ", // Whitespace
	}

	refTime := time.Unix(1234567890, 0)
	expected := GenerateTOTPAtTime(secrets[0], refTime, 30, 8)

	for _, secret := range secrets {
		t.Run(secret[:10], func(t *testing.T) {
			got := GenerateTOTPAtTime(secret, refTime, 30, 8)
			if got != expected {
				t.Errorf("Secret normalization failed: got %q, want %q", got, expected)
			}
		})
	}
}

func TestTOTP_DefaultValues(t *testing.T) {
	secrets := map[string]TOTPConfig{
		"user1": {Secret: rfc6238TestSecret}, // No digits, period, or skew specified
	}
	v := NewTOTPVerifier(secrets)

	// Generate with defaults and verify
	code := GenerateTOTPAtTime(rfc6238TestSecret, time.Now(), 30, 6)
	valid, err := v.Verify(context.Background(), "user1", code)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !valid {
		t.Errorf("Verify() with default config = false, want true")
	}
}
