package mfa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sns/types"
)

// SMSAPI defines the SNS operations used by SMSVerifier.
// This interface enables testing with mock implementations.
type SMSAPI interface {
	Publish(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error)
}

// SMSConfig holds configuration for SMS-based MFA.
type SMSConfig struct {
	// PhoneNumbers maps userID to E.164 formatted phone number.
	PhoneNumbers map[string]string
}

// smsChallenge is the internal challenge state for SMS verification.
type smsChallenge struct {
	code      string
	expiresAt time.Time
}

// SMSVerifier implements the Verifier interface using SMS delivery.
// It sends verification codes via AWS SNS direct publish and stores
// challenges in memory for verification.
type SMSVerifier struct {
	client     SMSAPI
	phones     map[string]string      // userID -> phone number
	challenges map[string]*smsChallenge // challengeID -> challenge
	mu         sync.RWMutex
}

// NewSMSVerifier creates a new SMS verifier using the provided AWS configuration.
// The phones map associates user IDs with their E.164 formatted phone numbers.
func NewSMSVerifier(cfg aws.Config, phones map[string]string) *SMSVerifier {
	return &SMSVerifier{
		client:     sns.NewFromConfig(cfg),
		phones:     phones,
		challenges: make(map[string]*smsChallenge),
	}
}

// newSMSVerifierWithClient creates an SMSVerifier with a custom client.
// This is primarily used for testing with mock clients.
func newSMSVerifierWithClient(client SMSAPI, phones map[string]string) *SMSVerifier {
	return &SMSVerifier{
		client:     client,
		phones:     phones,
		challenges: make(map[string]*smsChallenge),
	}
}

// Challenge initiates SMS-based MFA for the given user.
// It generates a random 6-digit code, sends it via SNS, and returns
// a challenge with the ID needed for verification.
func (v *SMSVerifier) Challenge(ctx context.Context, userID string) (*MFAChallenge, error) {
	phone, exists := v.phones[userID]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
	}

	// Generate random 6-digit code using crypto/rand
	code, err := generateSecureCode(CodeLength)
	if err != nil {
		return nil, fmt.Errorf("generate code: %w", err)
	}

	// Generate challenge ID
	challengeID := NewChallengeID()

	// Store challenge
	expiresAt := time.Now().Add(DefaultChallengeTTL)
	v.mu.Lock()
	v.challenges[challengeID] = &smsChallenge{
		code:      code,
		expiresAt: expiresAt,
	}
	v.mu.Unlock()

	// Send SMS via SNS direct publish
	message := fmt.Sprintf("Sentinel break-glass verification code: %s", code)
	_, err = v.client.Publish(ctx, &sns.PublishInput{
		PhoneNumber: aws.String(phone),
		Message:     aws.String(message),
		MessageAttributes: map[string]types.MessageAttributeValue{
			"AWS.SNS.SMS.SMSType": {
				DataType:    aws.String("String"),
				StringValue: aws.String("Transactional"),
			},
		},
	})
	if err != nil {
		// Remove challenge on send failure
		v.mu.Lock()
		delete(v.challenges, challengeID)
		v.mu.Unlock()
		return nil, fmt.Errorf("send sms: %w", err)
	}

	return &MFAChallenge{
		ID:        challengeID,
		Method:    MethodSMS,
		Target:    maskPhone(phone),
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}, nil
}

// Verify checks if the provided code is valid for the given challenge.
// Uses timing-safe comparison to prevent timing attacks.
// Returns (true, nil) on success, (false, nil) on invalid code,
// (false, error) if challenge not found or expired.
func (v *SMSVerifier) Verify(ctx context.Context, challengeID string, code string) (bool, error) {
	v.mu.Lock()
	challenge, exists := v.challenges[challengeID]
	if !exists {
		v.mu.Unlock()
		return false, fmt.Errorf("challenge not found: %s", challengeID)
	}

	// Check expiry
	if time.Now().After(challenge.expiresAt) {
		delete(v.challenges, challengeID)
		v.mu.Unlock()
		return false, nil // Expired, not an error
	}

	// Delete challenge (one-time use) before comparison
	// to prevent timing-based information leakage about challenge validity
	storedCode := challenge.code
	delete(v.challenges, challengeID)
	v.mu.Unlock()

	// SECURITY: Use constant-time comparison to prevent timing attacks.
	// An attacker could otherwise measure response time to determine
	// how many characters of the code are correct.
	if subtle.ConstantTimeCompare([]byte(storedCode), []byte(code)) == 1 {
		return true, nil
	}

	return false, nil
}

// generateSecureCode generates a cryptographically random numeric code.
// Uses crypto/rand for secure random number generation.
func generateSecureCode(length int) (string, error) {
	// Calculate max value (10^length)
	max := big.NewInt(1)
	for i := 0; i < length; i++ {
		max.Mul(max, big.NewInt(10))
	}

	// Generate random number in [0, max)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	// Format with leading zeros
	return fmt.Sprintf("%0*d", length, n), nil
}

// maskPhone masks a phone number showing only the last 4 digits.
// Example: "+15551234567" -> "***-***-4567"
func maskPhone(phone string) string {
	if len(phone) < 4 {
		return "***"
	}
	last4 := phone[len(phone)-4:]
	return "***-***-" + last4
}
