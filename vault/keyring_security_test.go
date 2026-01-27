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

// TestSecurityRegression_KeyringConfig_MacOSHardening_Documentation verifies that
// the expected macOS Keychain security settings are documented.
// THREAT: Credentials accessible when device locked or synced to iCloud
//
// This test documents the security requirements for cli/global.go keyringConfigDefaults:
// - KeychainAccessibleWhenUnlocked: false (credentials require unlocked device)
// - KeychainSynchronizable: false (credentials not synced to iCloud)
// - KeychainTrustApplication: true (at config level, but overridden by item-level NotTrustApplication)
//
// Note: The actual config is in cli package which we cannot import from vault.
// This test serves as documentation and validates our understanding of the security model.
func TestSecurityRegression_KeyringConfig_MacOSHardening_Documentation(t *testing.T) {
	t.Run("KeychainAccessibleWhenUnlocked_should_be_false", func(t *testing.T) {
		// When KeychainAccessibleWhenUnlocked is false, credentials require device to be unlocked.
		// This prevents access during sleep/screensaver/locked states.
		// The setting should be documented in keyring config (cli/global.go).
		//
		// Expected config value: KeychainAccessibleWhenUnlocked: false
		//
		// Security rationale:
		// - Default macOS behavior allows keychain access when device is unlocked only
		// - Setting this to false ensures we don't override to more permissive behavior
		// - This protects credentials when laptop is stolen in sleep mode
		t.Log("Documentation: KeychainAccessibleWhenUnlocked must be false in cli/global.go keyringConfigDefaults")
	})

	t.Run("KeychainSynchronizable_should_be_false", func(t *testing.T) {
		// When KeychainSynchronizable is false, credentials are not synced to iCloud.
		// This prevents credential exposure via Apple account compromise.
		//
		// Expected config value: KeychainSynchronizable: false
		// Plus item-level: KeychainNotSynchronizable: true (defense in depth)
		//
		// Security rationale:
		// - iCloud Keychain syncs items to all devices with same Apple ID
		// - Apple account compromise would expose all synced credentials
		// - AWS credentials should never leave the local machine
		t.Log("Documentation: KeychainSynchronizable must be false in cli/global.go keyringConfigDefaults")
	})

	t.Run("Defense_in_depth_config_plus_item_level", func(t *testing.T) {
		// We apply security settings at BOTH config level and item level.
		// This provides defense in depth:
		//
		// Config level (cli/global.go):
		// - KeychainSynchronizable: false (global default for all items)
		//
		// Item level (vault/*keyring.go):
		// - KeychainNotSynchronizable: true (explicit per-item setting)
		// - KeychainNotTrustApplication: true (prevents ACL expansion)
		//
		// Even if config is accidentally changed, item-level settings protect credentials.
		t.Log("Documentation: Security settings applied at both config and item level for defense in depth")
	})
}
