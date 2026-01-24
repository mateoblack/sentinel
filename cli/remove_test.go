package cli

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/byteness/keyring"
)

// makeRemoveSessionKey creates a properly formatted session key for testing
func makeRemoveSessionKey(sessionType, profileName, mfaSerial string, expiration time.Time) string {
	b64profile := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(profileName))
	b64mfa := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(mfaSerial))
	return fmt.Sprintf("%s,%s,%s,%d", sessionType, b64profile, b64mfa, expiration.Unix())
}

func TestRemoveCommand_SessionsOnly(t *testing.T) {
	futureTime := time.Now().Add(time.Hour)
	myprofileSessionKey := makeRemoveSessionKey("sts.GetSessionToken", "myprofile", "", futureTime)

	// Create keyring with credentials and sessions
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "myprofile", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
		{Key: myprofileSessionKey, Data: []byte(`{"AccessKeyId":"ASIA1","SecretAccessKey":"secret1","SessionToken":"token1","Expiration":"2099-01-01T00:00:00Z"}`)},
	})

	input := RemoveCommandInput{
		ProfileName:  "myprofile",
		SessionsOnly: true,
		Force:        true,
	}

	err := RemoveCommand(input, kr)
	if err != nil {
		t.Fatalf("RemoveCommand failed: %v", err)
	}

	// Verify credentials remain but sessions are removed
	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}

	hasCredentials := false
	hasSessions := false
	for _, key := range keys {
		if key == "myprofile" {
			hasCredentials = true
		}
		if key == myprofileSessionKey {
			hasSessions = true
		}
	}

	if !hasCredentials {
		t.Error("expected credentials to remain")
	}
	if hasSessions {
		t.Error("expected sessions to be removed")
	}
}

func TestRemoveCommand_CredentialsWithForce(t *testing.T) {
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "deleteMe", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
	})

	input := RemoveCommandInput{
		ProfileName: "deleteMe",
		Force:       true,
	}

	err := RemoveCommand(input, kr)
	if err != nil {
		t.Fatalf("RemoveCommand failed: %v", err)
	}

	// Verify credentials are removed
	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}

	for _, key := range keys {
		if key == "deleteMe" {
			t.Error("expected credentials to be removed")
		}
	}
}

func TestRemoveCommand_NonExistentCredentials(t *testing.T) {
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "existing", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
	})

	input := RemoveCommandInput{
		ProfileName: "nonexistent",
		Force:       true,
	}

	err := RemoveCommand(input, kr)
	// ArrayKeyring doesn't error for non-existent keys, so we just verify
	// the existing key wasn't affected
	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}

	found := false
	for _, key := range keys {
		if key == "existing" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'existing' credentials to remain")
	}
}

func TestRemoveCommand_SessionsOnlyNonExistent(t *testing.T) {
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "existing", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
	})

	input := RemoveCommandInput{
		ProfileName:  "nonexistent",
		SessionsOnly: true,
		Force:        true,
	}

	// Should succeed even if profile has no sessions
	err := RemoveCommand(input, kr)
	if err != nil {
		t.Fatalf("RemoveCommand should not error for non-existent sessions: %v", err)
	}
}

func TestRemoveCommand_MultipleSessionsForProfile(t *testing.T) {
	futureTime := time.Now().Add(time.Hour)
	multiSession1 := makeRemoveSessionKey("sts.GetSessionToken", "multi", "", futureTime)
	multiSession2 := makeRemoveSessionKey("sts.AssumeRole", "multi", "", futureTime.Add(time.Second)) // Different timestamp
	otherSessionKey := makeRemoveSessionKey("sts.GetSessionToken", "other", "", futureTime)

	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "multi", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
		{Key: multiSession1, Data: []byte(`{"AccessKeyId":"ASIA1","SecretAccessKey":"secret1","SessionToken":"token1","Expiration":"2099-01-01T00:00:00Z"}`)},
		{Key: multiSession2, Data: []byte(`{"AccessKeyId":"ASIA2","SecretAccessKey":"secret2","SessionToken":"token2","Expiration":"2099-01-01T00:00:00Z"}`)},
		{Key: otherSessionKey, Data: []byte(`{"AccessKeyId":"ASIA3","SecretAccessKey":"secret3","SessionToken":"token3","Expiration":"2099-01-01T00:00:00Z"}`)},
	})

	input := RemoveCommandInput{
		ProfileName:  "multi",
		SessionsOnly: true,
		Force:        true,
	}

	err := RemoveCommand(input, kr)
	if err != nil {
		t.Fatalf("RemoveCommand failed: %v", err)
	}

	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}

	// Should have credentials for 'multi' and 'other' session
	multiSessions := 0
	otherSession := false
	multiCreds := false

	for _, key := range keys {
		if key == "multi" {
			multiCreds = true
		}
		if key == otherSessionKey {
			otherSession = true
		}
		if key == multiSession1 || key == multiSession2 {
			multiSessions++
		}
	}

	if !multiCreds {
		t.Error("expected 'multi' credentials to remain")
	}
	if !otherSession {
		t.Error("expected 'other' session to remain")
	}
	if multiSessions > 0 {
		t.Errorf("expected 0 sessions for 'multi', found %d", multiSessions)
	}
}

func TestRemoveCommandInput_Defaults(t *testing.T) {
	input := RemoveCommandInput{}

	if input.ProfileName != "" {
		t.Errorf("expected empty ProfileName, got %q", input.ProfileName)
	}
	if input.SessionsOnly {
		t.Error("expected SessionsOnly to be false")
	}
	if input.Force {
		t.Error("expected Force to be false")
	}
}

func TestRemoveCommandInput_WithValues(t *testing.T) {
	input := RemoveCommandInput{
		ProfileName:  "test",
		SessionsOnly: true,
		Force:        true,
	}

	if input.ProfileName != "test" {
		t.Errorf("expected ProfileName 'test', got %q", input.ProfileName)
	}
	if !input.SessionsOnly {
		t.Error("expected SessionsOnly to be true")
	}
	if !input.Force {
		t.Error("expected Force to be true")
	}
}

func TestRemoveCommand_EmptyKeyring(t *testing.T) {
	kr := keyring.NewArrayKeyring([]keyring.Item{})

	input := RemoveCommandInput{
		ProfileName:  "nonexistent",
		SessionsOnly: true,
		Force:        true,
	}

	// Sessions only should succeed on empty keyring
	err := RemoveCommand(input, kr)
	if err != nil {
		t.Fatalf("RemoveCommand failed on empty keyring: %v", err)
	}
}

func TestRemoveCommand_RemoveCredentialsDoesNotRemoveSessions(t *testing.T) {
	futureTime := time.Now().Add(time.Hour)
	profileSessionKey := makeRemoveSessionKey("sts.GetSessionToken", "profile", "", futureTime)

	// When removing credentials (not sessions-only), sessions should remain
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "profile", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
		{Key: profileSessionKey, Data: []byte(`{"AccessKeyId":"ASIA1","SecretAccessKey":"secret1","SessionToken":"token1","Expiration":"2099-01-01T00:00:00Z"}`)},
	})

	input := RemoveCommandInput{
		ProfileName: "profile",
		Force:       true,
	}

	err := RemoveCommand(input, kr)
	if err != nil {
		t.Fatalf("RemoveCommand failed: %v", err)
	}

	keys, err := kr.Keys()
	if err != nil {
		t.Fatalf("failed to get keys: %v", err)
	}

	// Credentials should be removed
	hasCreds := false
	hasSession := false
	for _, key := range keys {
		if key == "profile" {
			hasCreds = true
		}
		if key == profileSessionKey {
			hasSession = true
		}
	}

	if hasCreds {
		t.Error("expected credentials to be removed")
	}
	// Sessions remain (they're managed separately)
	if !hasSession {
		t.Error("expected session to remain after credential removal")
	}
}
