package vault

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/byteness/keyring"
)

// mockKeyringCapture implements keyring.Keyring for testing.
// It captures the Item passed to Set() for security property verification.
type mockKeyringCapture struct {
	capturedItem keyring.Item
	setErr       error
	keys         []string
	items        map[string]keyring.Item
}

func (m *mockKeyringCapture) Get(key string) (keyring.Item, error) {
	if m.items != nil {
		if item, ok := m.items[key]; ok {
			return item, nil
		}
	}
	return keyring.Item{}, keyring.ErrKeyNotFound
}

func (m *mockKeyringCapture) Set(item keyring.Item) error {
	m.capturedItem = item
	if m.items == nil {
		m.items = make(map[string]keyring.Item)
	}
	m.items[item.Key] = item
	return m.setErr
}

func (m *mockKeyringCapture) Remove(key string) error {
	if m.items != nil {
		delete(m.items, key)
	}
	return nil
}

func (m *mockKeyringCapture) Keys() ([]string, error) {
	return m.keys, nil
}

// TestSecurityRegression_CredentialKeyring_NotTrustApplication verifies that
// credential storage prevents other applications from being trusted.
// THREAT: Malicious applications could be added to keychain ACL to steal credentials
func TestSecurityRegression_CredentialKeyring_NotTrustApplication(t *testing.T) {
	mock := &mockKeyringCapture{}
	ck := &CredentialKeyring{Keyring: mock}

	// Store a credential
	err := ck.Set("test-profile", aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// SECURITY CHECK: KeychainNotTrustApplication must be true
	if !mock.capturedItem.KeychainNotTrustApplication {
		t.Error("SECURITY VIOLATION: CredentialKeyring.Set must set KeychainNotTrustApplication: true")
	}
}

// TestSecurityRegression_CredentialKeyring_NoiCloudSync verifies that
// credential storage prevents iCloud synchronization.
// THREAT: Credentials synced to iCloud could be compromised via Apple account breach
func TestSecurityRegression_CredentialKeyring_NoiCloudSync(t *testing.T) {
	mock := &mockKeyringCapture{}
	ck := &CredentialKeyring{Keyring: mock}

	// Store a credential
	err := ck.Set("test-profile", aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// SECURITY CHECK: KeychainNotSynchronizable must be true
	if !mock.capturedItem.KeychainNotSynchronizable {
		t.Error("SECURITY VIOLATION: CredentialKeyring.Set must set KeychainNotSynchronizable: true")
	}
}

// TestSecurityRegression_SessionKeyring_NotTrustApplication verifies that
// session storage prevents other applications from being trusted.
// THREAT: Malicious applications could be added to keychain ACL to steal session tokens
func TestSecurityRegression_SessionKeyring_NotTrustApplication(t *testing.T) {
	mock := &mockKeyringCapture{}
	sk := &SessionKeyring{Keyring: mock}

	expiration := time.Now().Add(15 * time.Minute)
	creds := &ststypes.Credentials{
		AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
		SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		SessionToken:    aws.String("FwoGZXIvYXdzEBYaDH..."),
		Expiration:      &expiration,
	}

	key := SessionMetadata{
		Type:        "session",
		ProfileName: "test-profile",
		MfaSerial:   "",
		Expiration:  expiration,
	}

	err := sk.Set(key, creds)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// SECURITY CHECK: KeychainNotTrustApplication must be true
	if !mock.capturedItem.KeychainNotTrustApplication {
		t.Error("SECURITY VIOLATION: SessionKeyring.Set must set KeychainNotTrustApplication: true")
	}
}

// TestSecurityRegression_SessionKeyring_NoiCloudSync verifies that
// session storage prevents iCloud synchronization.
// THREAT: Session tokens synced to iCloud could be compromised via Apple account breach
func TestSecurityRegression_SessionKeyring_NoiCloudSync(t *testing.T) {
	mock := &mockKeyringCapture{}
	sk := &SessionKeyring{Keyring: mock}

	expiration := time.Now().Add(15 * time.Minute)
	creds := &ststypes.Credentials{
		AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
		SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		SessionToken:    aws.String("FwoGZXIvYXdzEBYaDH..."),
		Expiration:      &expiration,
	}

	key := SessionMetadata{
		Type:        "session",
		ProfileName: "test-profile",
		MfaSerial:   "",
		Expiration:  expiration,
	}

	err := sk.Set(key, creds)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// SECURITY CHECK: KeychainNotSynchronizable must be true
	if !mock.capturedItem.KeychainNotSynchronizable {
		t.Error("SECURITY VIOLATION: SessionKeyring.Set must set KeychainNotSynchronizable: true")
	}
}

// TestSecurityRegression_OIDCTokenKeyring_NotTrustApplication verifies that
// OIDC token storage prevents other applications from being trusted.
// THREAT: Malicious applications could be added to keychain ACL to steal OIDC tokens
func TestSecurityRegression_OIDCTokenKeyring_NotTrustApplication(t *testing.T) {
	mock := &mockKeyringCapture{}
	ok := &OIDCTokenKeyring{Keyring: mock}

	token := &ssooidc.CreateTokenOutput{
		AccessToken: aws.String("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."),
		ExpiresIn:   3600,
		TokenType:   aws.String("Bearer"),
	}

	err := ok.Set("https://example.awsapps.com/start", token)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// SECURITY CHECK: KeychainNotTrustApplication must be true
	if !mock.capturedItem.KeychainNotTrustApplication {
		t.Error("SECURITY VIOLATION: OIDCTokenKeyring.Set must set KeychainNotTrustApplication: true")
	}
}

// TestSecurityRegression_OIDCTokenKeyring_NoiCloudSync verifies that
// OIDC token storage prevents iCloud synchronization.
// THREAT: OIDC tokens synced to iCloud could be compromised via Apple account breach
func TestSecurityRegression_OIDCTokenKeyring_NoiCloudSync(t *testing.T) {
	mock := &mockKeyringCapture{}
	ok := &OIDCTokenKeyring{Keyring: mock}

	token := &ssooidc.CreateTokenOutput{
		AccessToken: aws.String("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."),
		ExpiresIn:   3600,
		TokenType:   aws.String("Bearer"),
	}

	err := ok.Set("https://example.awsapps.com/start", token)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// SECURITY CHECK: KeychainNotSynchronizable must be true
	if !mock.capturedItem.KeychainNotSynchronizable {
		t.Error("SECURITY VIOLATION: OIDCTokenKeyring.Set must set KeychainNotSynchronizable: true")
	}
}
