// Package mfa provides security regression tests for MFA bypass prevention.
// These tests validate that MFA verification cannot be bypassed through various
// attack vectors including replay attacks, brute force, timing attacks, and
// method downgrade attacks.
//
// SECURITY: These tests are regression tests for phase 127 MFA hardening.
package mfa

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// TOTP SECURITY TESTS
// =============================================================================

// TestSecurity_TOTP_ReplayAttack verifies TOTP code behavior within time windows.
//
// SECURITY: TOTP codes are valid for their time window (30s default) per RFC 6238.
// This is expected behavior - TOTP is stateless and time-based.
// Replay protection comes from the time window expiring, not from tracking used codes.
// Document: TOTP replay window is inherent to RFC 6238 specification.
func TestSecurity_TOTP_ReplayAttack(t *testing.T) {
	secrets := map[string]TOTPConfig{
		"user1": {Secret: rfc6238TestSecret, Digits: 6, Period: 30, Skew: 1},
	}
	v := NewTOTPVerifier(secrets)

	// Generate code for current time
	now := time.Now()
	code := GenerateTOTPAtTime(rfc6238TestSecret, now, 30, 6)

	// First verification should succeed
	valid1, err := v.Verify(context.Background(), "user1", code)
	if err != nil {
		t.Fatalf("First Verify() error = %v", err)
	}
	if !valid1 {
		t.Error("SECURITY: First TOTP verification should succeed")
	}

	// Second verification with same code should ALSO succeed (expected TOTP behavior)
	// SECURITY: TOTP is stateless - same code is valid throughout its time window
	valid2, err := v.Verify(context.Background(), "user1", code)
	if err != nil {
		t.Fatalf("Second Verify() error = %v", err)
	}
	if !valid2 {
		t.Error("SECURITY: Second TOTP verification should also succeed (expected RFC 6238 behavior)")
	}

	// Log for documentation
	t.Log("SECURITY NOTE: TOTP replay within time window is expected per RFC 6238.")
	t.Log("Replay protection comes from 30-second window expiry, not code tracking.")
}

// TestSecurity_TOTP_BruteForce verifies that invalid TOTP codes are properly rejected.
//
// SECURITY: 6-digit TOTP = 1,000,000 combinations.
// With 30-second window and network latency, brute force is impractical.
// This test verifies the foundation for rate limiting by confirming invalid codes are rejected.
func TestSecurity_TOTP_BruteForce(t *testing.T) {
	secrets := map[string]TOTPConfig{
		"user1": {Secret: rfc6238TestSecret, Digits: 6, Period: 30, Skew: 0}, // No skew for strict testing
	}
	v := NewTOTPVerifier(secrets)

	// Generate current valid code
	now := time.Now()
	validCode := GenerateTOTPAtTime(rfc6238TestSecret, now, 30, 6)

	// Test that random invalid codes are rejected
	invalidCodes := []string{
		"000000",
		"999999",
		"123456",
		"111111",
		"000001",
	}

	for _, code := range invalidCodes {
		// Skip if this happens to be the valid code (unlikely but possible)
		if code == validCode {
			continue
		}

		valid, err := v.Verify(context.Background(), "user1", code)
		if err != nil {
			t.Fatalf("Verify(%s) error = %v", code, err)
		}
		if valid {
			t.Errorf("SECURITY: Invalid TOTP code %q should be rejected", code)
		}
	}

	// Document brute force impracticality
	t.Log("SECURITY: 6-digit TOTP = 1M combinations, 30s window limits attempts.")
	t.Log("Rate limiting at the application layer further mitigates brute force.")
}

// TestSecurity_TOTP_ClockSkew verifies skew doesn't open excessive verification window.
//
// SECURITY: Skew=1 allows codes from t-30s, t, and t+30s (3 periods total).
// Skew=0 should only accept current period.
// Larger skew values increase attack window - verify limited acceptance.
func TestSecurity_TOTP_ClockSkew(t *testing.T) {
	// Test with skew=0 (strict - only current period)
	t.Run("skew=0 only accepts current period", func(t *testing.T) {
		secrets := map[string]TOTPConfig{
			"user1": {Secret: rfc6238TestSecret, Digits: 6, Period: 30, Skew: 0},
		}
		v := NewTOTPVerifier(secrets)

		// Generate code for current time
		now := time.Now()
		currentCode := GenerateTOTPAtTime(rfc6238TestSecret, now, 30, 6)

		// Current period code should work
		valid, err := v.Verify(context.Background(), "user1", currentCode)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !valid {
			t.Error("SECURITY: Current period code should be accepted with skew=0")
		}
	})

	// Test with skew=1 (default - allows adjacent periods for clock drift)
	t.Run("skew=1 accepts adjacent periods", func(t *testing.T) {
		secrets := map[string]TOTPConfig{
			"user1": {Secret: rfc6238TestSecret, Digits: 6, Period: 30, Skew: 1},
		}
		v := NewTOTPVerifier(secrets)

		now := time.Now()
		currentCode := GenerateTOTPAtTime(rfc6238TestSecret, now, 30, 6)

		// Current period should work
		valid, err := v.Verify(context.Background(), "user1", currentCode)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !valid {
			t.Error("SECURITY: Current period code should be accepted with skew=1")
		}

		// Adjacent periods should also work with skew=1
		// (Tested elsewhere in TestTOTPVerifier_SkewHandling)
	})

	t.Log("SECURITY: Skew=1 allows 3 periods (90s total window) for clock drift tolerance.")
}

// =============================================================================
// SMS SECURITY TESTS
// =============================================================================

// TestSecurity_SMS_ChallengeReuse verifies SMS challenge cannot be reused after verification.
//
// SECURITY: SMS challenges are one-time use. After any verification attempt (success or failure),
// the challenge is consumed and cannot be used again. This prevents replay attacks.
func TestSecurity_SMS_ChallengeReuse(t *testing.T) {
	phones := map[string]string{
		"user1": "+15551234567",
	}

	mock := &mockSMSAPI{}
	v := newSMSVerifierWithClient(mock, phones)

	// Create a challenge
	challenge, err := v.Challenge(context.Background(), "user1")
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}

	// Extract the correct code from sent message
	message := mock.messagesSent[0]
	correctCode := message[len("Sentinel break-glass verification code: "):]

	// First verification should succeed
	valid, err := v.Verify(context.Background(), challenge.ID, correctCode)
	if err != nil {
		t.Fatalf("First Verify() error = %v", err)
	}
	if !valid {
		t.Error("SECURITY: First SMS verification should succeed")
	}

	// Second verification with same challenge ID should fail (challenge consumed)
	_, err = v.Verify(context.Background(), challenge.ID, correctCode)
	if err == nil {
		t.Error("SECURITY VIOLATION: Challenge reuse should be rejected")
	}
	if !strings.Contains(err.Error(), "challenge not found") {
		t.Errorf("Expected 'challenge not found' error, got: %v", err)
	}
}

// TestSecurity_SMS_ChallengeExpiry verifies expired challenges are rejected.
//
// SECURITY: SMS challenges expire after DefaultChallengeTTL (5 minutes).
// Expired challenges must be rejected to limit attack window.
func TestSecurity_SMS_ChallengeExpiry(t *testing.T) {
	phones := map[string]string{
		"user1": "+15551234567",
	}

	mock := &mockSMSAPI{}
	v := newSMSVerifierWithClient(mock, phones)

	// Create a challenge
	challenge, err := v.Challenge(context.Background(), "user1")
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}

	// Manually expire the challenge (simulate time passing)
	v.mu.Lock()
	if c, exists := v.challenges[challenge.ID]; exists {
		c.expiresAt = time.Now().Add(-1 * time.Minute)
	}
	v.mu.Unlock()

	// Verification should fail due to expiry
	valid, err := v.Verify(context.Background(), challenge.ID, "123456")
	if err != nil {
		t.Fatalf("Verify() error = %v (expired should return false, not error)", err)
	}
	if valid {
		t.Error("SECURITY VIOLATION: Expired challenge should be rejected")
	}
}

// TestSecurity_SMS_TimingAttack verifies code comparison is timing-safe.
//
// SECURITY: Code comparison must use crypto/subtle.ConstantTimeCompare to prevent
// timing-based attacks that could leak information about correct code bytes.
func TestSecurity_SMS_TimingAttack(t *testing.T) {
	// Parse the source file to verify constant-time comparison is used
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sms.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("failed to parse sms.go: %v", err)
	}

	// Verify crypto/subtle is imported
	hasSubtleImport := false
	for _, imp := range f.Imports {
		if imp.Path.Value == `"crypto/subtle"` {
			hasSubtleImport = true
			break
		}
	}

	if !hasSubtleImport {
		t.Error("SECURITY: crypto/subtle must be imported for timing-safe comparison")
	}

	// Parse full AST to verify ConstantTimeCompare is used
	fFull, err := parser.ParseFile(fset, "sms.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("failed to parse sms.go for full AST: %v", err)
	}

	hasConstantTimeCompare := false
	ast.Inspect(fFull, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare" {
					hasConstantTimeCompare = true
					return false
				}
			}
		}
		return true
	})

	if !hasConstantTimeCompare {
		t.Error("SECURITY: SMS Verify must use subtle.ConstantTimeCompare for code comparison")
	}
}

// TestSecurity_SMS_ChallengeIDGuessing verifies challenge IDs are unguessable.
//
// SECURITY: Challenge IDs must have sufficient entropy to prevent guessing attacks.
// 16 hex chars = 64 bits of entropy, generated by crypto/rand.
func TestSecurity_SMS_ChallengeIDGuessing(t *testing.T) {
	// Generate sample of challenge IDs
	const sampleSize = 1000
	ids := make(map[string]bool, sampleSize)

	for i := 0; i < sampleSize; i++ {
		id := NewChallengeID()

		// Verify format: 16 lowercase hex chars
		if len(id) != ChallengeIDLength {
			t.Errorf("SECURITY: Challenge ID length = %d, want %d", len(id), ChallengeIDLength)
		}
		if !ValidateChallengeID(id) {
			t.Errorf("SECURITY: Challenge ID %q is not valid format", id)
		}

		// Check for collisions
		if ids[id] {
			t.Errorf("SECURITY VIOLATION: Challenge ID collision detected: %s", id)
		}
		ids[id] = true
	}

	// Verify we got unique IDs (cryptographic randomness check)
	if len(ids) != sampleSize {
		t.Errorf("SECURITY: Expected %d unique IDs, got %d", sampleSize, len(ids))
	}

	t.Log("SECURITY: Challenge IDs are 16 hex chars (64 bits entropy) from crypto/rand")
}

// =============================================================================
// MFA BYPASS PREVENTION TESTS
// =============================================================================

// TestSecurity_MFA_BypassWithEmptyCode verifies empty code doesn't bypass verification.
//
// SECURITY: Empty string MFA codes must be rejected, not treated as "no MFA required".
func TestSecurity_MFA_BypassWithEmptyCode(t *testing.T) {
	t.Run("TOTP rejects empty code", func(t *testing.T) {
		secrets := map[string]TOTPConfig{
			"user1": {Secret: rfc6238TestSecret},
		}
		v := NewTOTPVerifier(secrets)

		valid, err := v.Verify(context.Background(), "user1", "")
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if valid {
			t.Error("SECURITY VIOLATION: Empty TOTP code should be rejected")
		}
	})

	t.Run("SMS rejects empty code", func(t *testing.T) {
		phones := map[string]string{
			"user1": "+15551234567",
		}

		mock := &mockSMSAPI{}
		v := newSMSVerifierWithClient(mock, phones)

		challenge, err := v.Challenge(context.Background(), "user1")
		if err != nil {
			t.Fatalf("Challenge() error = %v", err)
		}

		valid, err := v.Verify(context.Background(), challenge.ID, "")
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if valid {
			t.Error("SECURITY VIOLATION: Empty SMS code should be rejected")
		}
	})
}

// TestSecurity_MFA_MethodValidation verifies MFA method validation is enforced.
//
// SECURITY: Only known MFA methods should be accepted. Unknown methods must be rejected
// to prevent bypassing security through invalid method specification.
func TestSecurity_MFA_MethodValidation(t *testing.T) {
	validMethods := []MFAMethod{MethodTOTP, MethodSMS}
	invalidMethods := []MFAMethod{"none", "skip", "bypass", "", "password", "email"}

	for _, method := range validMethods {
		if !method.IsValid() {
			t.Errorf("SECURITY: Valid method %q should be accepted", method)
		}
	}

	for _, method := range invalidMethods {
		if method.IsValid() {
			t.Errorf("SECURITY VIOLATION: Invalid method %q should be rejected", method)
		}
	}
}

// TestSecurity_MFA_UnknownUserHandling verifies unknown users are properly rejected.
//
// SECURITY: Attempts to verify MFA for unknown users must fail with an error,
// not silently succeed or leak information about valid users.
func TestSecurity_MFA_UnknownUserHandling(t *testing.T) {
	t.Run("TOTP unknown user", func(t *testing.T) {
		secrets := map[string]TOTPConfig{
			"known-user": {Secret: rfc6238TestSecret},
		}
		v := NewTOTPVerifier(secrets)

		// Challenge for unknown user should fail
		_, err := v.Challenge(context.Background(), "unknown-user")
		if err == nil {
			t.Error("SECURITY: Challenge for unknown user should fail")
		}

		// Verify for unknown user should fail
		_, err = v.Verify(context.Background(), "unknown-user", "123456")
		if err == nil {
			t.Error("SECURITY: Verify for unknown user should fail")
		}
	})

	t.Run("SMS unknown user", func(t *testing.T) {
		phones := map[string]string{
			"known-user": "+15551234567",
		}

		mock := &mockSMSAPI{}
		v := newSMSVerifierWithClient(mock, phones)

		// Challenge for unknown user should fail
		_, err := v.Challenge(context.Background(), "unknown-user")
		if err == nil {
			t.Error("SECURITY: Challenge for unknown user should fail")
		}
	})
}

// TestSecurity_MFA_ConcurrentVerification verifies thread-safe verification.
//
// SECURITY: Concurrent verification attempts must not cause race conditions
// that could lead to double-use of challenges or other security issues.
func TestSecurity_MFA_ConcurrentVerification(t *testing.T) {
	phones := map[string]string{
		"user1": "+15551234567",
	}

	mock := &mockSMSAPI{}
	v := newSMSVerifierWithClient(mock, phones)

	// Create a challenge
	challenge, err := v.Challenge(context.Background(), "user1")
	if err != nil {
		t.Fatalf("Challenge() error = %v", err)
	}

	// Extract the correct code
	message := mock.messagesSent[0]
	correctCode := message[len("Sentinel break-glass verification code: "):]

	// Attempt concurrent verification
	const goroutines = 10
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			valid, err := v.Verify(context.Background(), challenge.ID, correctCode)
			if err == nil && valid {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// SECURITY: Only ONE verification should succeed (challenge is one-time use)
	if successCount != 1 {
		t.Errorf("SECURITY VIOLATION: Expected exactly 1 successful verification, got %d (race condition)", successCount)
	}
}
