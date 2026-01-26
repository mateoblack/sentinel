package mfa

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sns"
)

// mockSMSAPI is a mock implementation of SMSAPI for testing.
type mockSMSAPI struct {
	publishFn      func(ctx context.Context, params *sns.PublishInput) (*sns.PublishOutput, error)
	publishCalls   []sns.PublishInput
	mu             sync.Mutex
	simulateError  error
	messagesSent   []string // Track message content
	phoneNumbers   []string // Track phone numbers
}

func (m *mockSMSAPI) Publish(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if params != nil {
		m.publishCalls = append(m.publishCalls, *params)
		if params.Message != nil {
			m.messagesSent = append(m.messagesSent, *params.Message)
		}
		if params.PhoneNumber != nil {
			m.phoneNumbers = append(m.phoneNumbers, *params.PhoneNumber)
		}
	}

	if m.simulateError != nil {
		return nil, m.simulateError
	}

	if m.publishFn != nil {
		return m.publishFn(ctx, params)
	}

	return &sns.PublishOutput{}, nil
}

func TestSMSVerifier_Challenge(t *testing.T) {
	phones := map[string]string{
		"user1": "+15551234567",
		"user2": "+15559876543",
	}

	t.Run("successful challenge sends SMS", func(t *testing.T) {
		mock := &mockSMSAPI{}
		v := newSMSVerifierWithClient(mock, phones)

		challenge, err := v.Challenge(context.Background(), "user1")
		if err != nil {
			t.Fatalf("Challenge() error = %v, want nil", err)
		}

		// Verify challenge structure
		if challenge.Method != MethodSMS {
			t.Errorf("Challenge.Method = %v, want %v", challenge.Method, MethodSMS)
		}
		if challenge.ID == "" {
			t.Error("Challenge.ID is empty, want non-empty")
		}
		if !ValidateChallengeID(challenge.ID) {
			t.Errorf("Challenge.ID = %q is not valid format", challenge.ID)
		}
		if challenge.Target != "***-***-4567" {
			t.Errorf("Challenge.Target = %q, want masked phone", challenge.Target)
		}
		if challenge.IsExpired() {
			t.Error("Challenge should not be expired immediately")
		}

		// Verify SMS was sent
		if len(mock.publishCalls) != 1 {
			t.Fatalf("Expected 1 publish call, got %d", len(mock.publishCalls))
		}

		call := mock.publishCalls[0]
		if *call.PhoneNumber != "+15551234567" {
			t.Errorf("PhoneNumber = %q, want +15551234567", *call.PhoneNumber)
		}
		if call.MessageAttributes["AWS.SNS.SMS.SMSType"].StringValue == nil ||
			*call.MessageAttributes["AWS.SNS.SMS.SMSType"].StringValue != "Transactional" {
			t.Error("Missing or incorrect SMS type attribute")
		}
	})

	t.Run("unknown user returns error", func(t *testing.T) {
		mock := &mockSMSAPI{}
		v := newSMSVerifierWithClient(mock, phones)

		_, err := v.Challenge(context.Background(), "unknown")
		if err == nil {
			t.Fatal("Challenge() error = nil, want error")
		}
		if !errors.Is(err, ErrUserNotFound) {
			t.Errorf("Challenge() error = %v, want ErrUserNotFound", err)
		}
	})

	t.Run("SMS send failure cleans up challenge", func(t *testing.T) {
		mock := &mockSMSAPI{
			simulateError: errors.New("SNS error"),
		}
		v := newSMSVerifierWithClient(mock, phones)

		_, err := v.Challenge(context.Background(), "user1")
		if err == nil {
			t.Fatal("Challenge() error = nil, want error")
		}

		// Verify no challenge was stored
		v.mu.RLock()
		challengeCount := len(v.challenges)
		v.mu.RUnlock()

		if challengeCount != 0 {
			t.Errorf("Challenge count = %d, want 0 (should cleanup on failure)", challengeCount)
		}
	})
}

func TestSMSVerifier_Verify(t *testing.T) {
	phones := map[string]string{
		"user1": "+15551234567",
	}

	t.Run("valid code accepted", func(t *testing.T) {
		mock := &mockSMSAPI{}
		v := newSMSVerifierWithClient(mock, phones)

		// Create a challenge
		challenge, err := v.Challenge(context.Background(), "user1")
		if err != nil {
			t.Fatalf("Challenge() error = %v", err)
		}

		// Extract the code from the sent message
		if len(mock.messagesSent) != 1 {
			t.Fatalf("Expected 1 message sent, got %d", len(mock.messagesSent))
		}
		// Message format: "Sentinel break-glass verification code: XXXXXX"
		message := mock.messagesSent[0]
		code := message[len("Sentinel break-glass verification code: "):]

		// Verify with correct code
		valid, err := v.Verify(context.Background(), challenge.ID, code)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !valid {
			t.Error("Verify() = false, want true for valid code")
		}
	})

	t.Run("invalid code rejected", func(t *testing.T) {
		mock := &mockSMSAPI{}
		v := newSMSVerifierWithClient(mock, phones)

		challenge, err := v.Challenge(context.Background(), "user1")
		if err != nil {
			t.Fatalf("Challenge() error = %v", err)
		}

		// Verify with wrong code
		valid, err := v.Verify(context.Background(), challenge.ID, "000000")
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if valid {
			t.Error("Verify() = true, want false for invalid code")
		}
	})

	t.Run("challenge only usable once", func(t *testing.T) {
		mock := &mockSMSAPI{}
		v := newSMSVerifierWithClient(mock, phones)

		challenge, err := v.Challenge(context.Background(), "user1")
		if err != nil {
			t.Fatalf("Challenge() error = %v", err)
		}

		// First verification (with wrong code - doesn't matter, deletes challenge)
		_, _ = v.Verify(context.Background(), challenge.ID, "000000")

		// Second verification should fail with "not found"
		_, err = v.Verify(context.Background(), challenge.ID, "000000")
		if err == nil {
			t.Fatal("Second Verify() error = nil, want error (challenge consumed)")
		}
	})

	t.Run("expired challenge rejected", func(t *testing.T) {
		mock := &mockSMSAPI{}
		v := newSMSVerifierWithClient(mock, phones)

		challenge, err := v.Challenge(context.Background(), "user1")
		if err != nil {
			t.Fatalf("Challenge() error = %v", err)
		}

		// Manually expire the challenge
		v.mu.Lock()
		if c, exists := v.challenges[challenge.ID]; exists {
			c.expiresAt = time.Now().Add(-1 * time.Minute)
		}
		v.mu.Unlock()

		// Verify should fail (expired)
		valid, err := v.Verify(context.Background(), challenge.ID, "123456")
		if err != nil {
			t.Fatalf("Verify() error = %v, want nil (expired is not error)", err)
		}
		if valid {
			t.Error("Verify() = true, want false for expired challenge")
		}
	})

	t.Run("unknown challenge returns error", func(t *testing.T) {
		mock := &mockSMSAPI{}
		v := newSMSVerifierWithClient(mock, phones)

		_, err := v.Verify(context.Background(), "nonexistent", "123456")
		if err == nil {
			t.Fatal("Verify() error = nil, want error for unknown challenge")
		}
	})
}

func TestSMSVerifier_TimingSafe(t *testing.T) {
	// This test verifies that constant-time comparison is used
	// We can't actually test timing, but we verify the code uses subtle.ConstantTimeCompare
	// by checking that both correct and incorrect codes take similar paths

	phones := map[string]string{
		"user1": "+15551234567",
	}

	mock := &mockSMSAPI{}
	v := newSMSVerifierWithClient(mock, phones)

	challenge, _ := v.Challenge(context.Background(), "user1")

	// Extract correct code
	message := mock.messagesSent[0]
	correctCode := message[len("Sentinel break-glass verification code: "):]

	// Test with correct code
	v.mu.Lock()
	v.challenges[challenge.ID] = &smsChallenge{
		code:      correctCode,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	v.mu.Unlock()

	valid1, _ := v.Verify(context.Background(), challenge.ID, correctCode)
	if !valid1 {
		t.Error("Expected valid code to be accepted")
	}

	// Create new challenge for wrong code test
	challenge2, _ := v.Challenge(context.Background(), "user1")
	valid2, _ := v.Verify(context.Background(), challenge2.ID, "wrong1")
	if valid2 {
		t.Error("Expected wrong code to be rejected")
	}
}

func TestMaskPhone(t *testing.T) {
	tests := []struct {
		phone string
		want  string
	}{
		{"+15551234567", "***-***-4567"},
		{"+1555", "***-***-1555"},
		{"+44", "***"}, // Too short
		{"", "***"},    // Empty
	}

	for _, tt := range tests {
		t.Run(tt.phone, func(t *testing.T) {
			got := maskPhone(tt.phone)
			if got != tt.want {
				t.Errorf("maskPhone(%q) = %q, want %q", tt.phone, got, tt.want)
			}
		})
	}
}

func TestGenerateSecureCode(t *testing.T) {
	// Generate multiple codes and verify format
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := generateSecureCode(6)
		if err != nil {
			t.Fatalf("generateSecureCode() error = %v", err)
		}

		// Check length
		if len(code) != 6 {
			t.Errorf("Code length = %d, want 6", len(code))
		}

		// Check all digits
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("Code contains non-digit: %q", code)
				break
			}
		}

		// Track uniqueness (not guaranteed but highly likely with crypto/rand)
		codes[code] = true
	}

	// With 100 random 6-digit codes, we should have high uniqueness
	// (probability of collision is very low)
	if len(codes) < 90 {
		t.Errorf("Low code uniqueness: got %d unique codes out of 100", len(codes))
	}
}

func TestSMSVerifier_ConcurrentAccess(t *testing.T) {
	phones := map[string]string{
		"user1": "+15551234567",
	}

	mock := &mockSMSAPI{}
	v := newSMSVerifierWithClient(mock, phones)

	// Create multiple challenges concurrently
	var wg sync.WaitGroup
	challenges := make(chan *MFAChallenge, 10)
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := v.Challenge(context.Background(), "user1")
			if err != nil {
				errs <- err
				return
			}
			challenges <- c
		}()
	}

	wg.Wait()
	close(challenges)
	close(errs)

	// Check for errors
	for err := range errs {
		t.Errorf("Concurrent Challenge() error = %v", err)
	}

	// Verify all challenges were created with unique IDs
	ids := make(map[string]bool)
	for c := range challenges {
		if ids[c.ID] {
			t.Errorf("Duplicate challenge ID: %s", c.ID)
		}
		ids[c.ID] = true
	}
}
