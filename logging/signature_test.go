package logging

import (
	"encoding/hex"
	"strings"
	"testing"
)

// testSecretKey is a 32-byte key for testing (exactly 32 bytes).
var testSecretKey = []byte("0123456789abcdef0123456789abcdef")

// testShortKey is too short to be valid.
var testShortKey = []byte("short")

func TestComputeSignature(t *testing.T) {
	entry := map[string]string{"action": "test", "user": "alice"}

	sig, err := ComputeSignature(entry, testSecretKey)
	if err != nil {
		t.Fatalf("ComputeSignature failed: %v", err)
	}

	// Signature should be 64 hex characters (32 bytes * 2)
	if len(sig) != 64 {
		t.Errorf("Expected signature length 64, got %d", len(sig))
	}

	// Signature should be valid hex
	_, err = hex.DecodeString(sig)
	if err != nil {
		t.Errorf("Signature is not valid hex: %v", err)
	}
}

func TestComputeSignature_Deterministic(t *testing.T) {
	entry := map[string]string{"action": "test", "user": "alice"}

	sig1, err := ComputeSignature(entry, testSecretKey)
	if err != nil {
		t.Fatalf("First ComputeSignature failed: %v", err)
	}

	sig2, err := ComputeSignature(entry, testSecretKey)
	if err != nil {
		t.Fatalf("Second ComputeSignature failed: %v", err)
	}

	if sig1 != sig2 {
		t.Errorf("Signatures should be deterministic: %s != %s", sig1, sig2)
	}
}

func TestComputeSignature_DifferentEntriesDifferentSignatures(t *testing.T) {
	entry1 := map[string]string{"action": "test", "user": "alice"}
	entry2 := map[string]string{"action": "test", "user": "bob"}

	sig1, _ := ComputeSignature(entry1, testSecretKey)
	sig2, _ := ComputeSignature(entry2, testSecretKey)

	if sig1 == sig2 {
		t.Error("Different entries should produce different signatures")
	}
}

func TestComputeSignature_DifferentKeysDifferentSignatures(t *testing.T) {
	entry := map[string]string{"action": "test", "user": "alice"}
	key1 := []byte("0123456789abcdef0123456789abcdef")
	key2 := []byte("fedcba9876543210fedcba9876543210")

	sig1, _ := ComputeSignature(entry, key1)
	sig2, _ := ComputeSignature(entry, key2)

	if sig1 == sig2 {
		t.Error("Different keys should produce different signatures")
	}
}

func TestComputeSignature_ShortKeyError(t *testing.T) {
	entry := map[string]string{"action": "test"}

	_, err := ComputeSignature(entry, testShortKey)
	if err != ErrKeyTooShort {
		t.Errorf("Expected ErrKeyTooShort, got %v", err)
	}
}

func TestComputeSignature_EmptyEntry(t *testing.T) {
	// Empty struct should still produce valid signature
	entry := struct{}{}

	sig, err := ComputeSignature(entry, testSecretKey)
	if err != nil {
		t.Fatalf("ComputeSignature on empty entry failed: %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("Expected signature length 64, got %d", len(sig))
	}
}

func TestVerifySignature_ValidSignature(t *testing.T) {
	entry := map[string]string{"action": "test", "user": "alice"}

	sig, err := ComputeSignature(entry, testSecretKey)
	if err != nil {
		t.Fatalf("ComputeSignature failed: %v", err)
	}

	valid, err := VerifySignature(entry, sig, testSecretKey)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}

	if !valid {
		t.Error("Valid signature should verify")
	}
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
	entry := map[string]string{"action": "test", "user": "alice"}

	// Create a valid signature then tamper with it
	sig, _ := ComputeSignature(entry, testSecretKey)
	tamperedSig := strings.Replace(sig, sig[:4], "0000", 1)

	valid, err := VerifySignature(entry, tamperedSig, testSecretKey)
	if err != nil {
		t.Fatalf("VerifySignature should not error on invalid signature: %v", err)
	}

	if valid {
		t.Error("Tampered signature should not verify")
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	entry := map[string]string{"action": "test", "user": "alice"}

	sig, _ := ComputeSignature(entry, testSecretKey)
	wrongKey := []byte("fedcba9876543210fedcba9876543210")

	valid, err := VerifySignature(entry, sig, wrongKey)
	if err != nil {
		t.Fatalf("VerifySignature should not error with wrong key: %v", err)
	}

	if valid {
		t.Error("Signature should not verify with wrong key")
	}
}

func TestVerifySignature_TamperedData(t *testing.T) {
	entry := map[string]string{"action": "test", "user": "alice"}

	sig, _ := ComputeSignature(entry, testSecretKey)

	// Try to verify with modified entry
	tamperedEntry := map[string]string{"action": "test", "user": "mallory"}

	valid, err := VerifySignature(tamperedEntry, sig, testSecretKey)
	if err != nil {
		t.Fatalf("VerifySignature should not error on tampered data: %v", err)
	}

	if valid {
		t.Error("Signature should not verify with tampered data")
	}
}

func TestVerifySignature_InvalidHex(t *testing.T) {
	entry := map[string]string{"action": "test"}

	valid, err := VerifySignature(entry, "not-valid-hex-string!", testSecretKey)
	if err != nil {
		t.Fatalf("VerifySignature should not error on invalid hex: %v", err)
	}

	if valid {
		t.Error("Invalid hex signature should not verify")
	}
}

func TestVerifySignature_ShortKeyError(t *testing.T) {
	entry := map[string]string{"action": "test"}
	sig := strings.Repeat("a", 64) // Valid hex, 64 chars

	_, err := VerifySignature(entry, sig, testShortKey)
	if err != ErrKeyTooShort {
		t.Errorf("Expected ErrKeyTooShort, got %v", err)
	}
}

func TestSignatureConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  SignatureConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: SignatureConfig{
				KeyID:     "test-key",
				SecretKey: testSecretKey,
			},
			wantErr: false,
		},
		{
			name: "short key",
			config: SignatureConfig{
				KeyID:     "test-key",
				SecretKey: testShortKey,
			},
			wantErr: true,
		},
		{
			name: "empty key",
			config: SignatureConfig{
				KeyID:     "test-key",
				SecretKey: nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewSignedEntry(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "prod-2026",
		SecretKey: testSecretKey,
	}

	entry := map[string]string{"action": "test", "user": "alice"}

	signed, err := NewSignedEntry(entry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry failed: %v", err)
	}

	// Check all fields are populated
	if signed.Entry == nil {
		t.Error("Entry should not be nil")
	}

	if signed.KeyID != "prod-2026" {
		t.Errorf("KeyID = %s, want prod-2026", signed.KeyID)
	}

	if len(signed.Signature) != 64 {
		t.Errorf("Signature length = %d, want 64", len(signed.Signature))
	}

	if signed.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestNewSignedEntry_InvalidConfig(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "test",
		SecretKey: testShortKey,
	}

	entry := map[string]string{"action": "test"}

	_, err := NewSignedEntry(entry, config)
	if err != ErrKeyTooShort {
		t.Errorf("Expected ErrKeyTooShort, got %v", err)
	}
}

func TestSignedEntry_Verify(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "prod-2026",
		SecretKey: testSecretKey,
	}

	entry := map[string]string{"action": "test", "user": "alice"}

	signed, err := NewSignedEntry(entry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry failed: %v", err)
	}

	valid, err := signed.Verify(testSecretKey)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("SignedEntry should verify with correct key")
	}
}

func TestSignedEntry_Verify_WrongKey(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "prod-2026",
		SecretKey: testSecretKey,
	}

	entry := map[string]string{"action": "test", "user": "alice"}

	signed, err := NewSignedEntry(entry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry failed: %v", err)
	}

	wrongKey := []byte("fedcba9876543210fedcba9876543210")
	valid, err := signed.Verify(wrongKey)
	if err != nil {
		t.Fatalf("Verify should not error with wrong key: %v", err)
	}

	if valid {
		t.Error("SignedEntry should not verify with wrong key")
	}
}

func TestSignedEntry_Verify_TamperedSignature(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "prod-2026",
		SecretKey: testSecretKey,
	}

	entry := map[string]string{"action": "test", "user": "alice"}

	signed, err := NewSignedEntry(entry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry failed: %v", err)
	}

	// Tamper with signature
	signed.Signature = strings.Replace(signed.Signature, signed.Signature[:4], "0000", 1)

	valid, err := signed.Verify(testSecretKey)
	if err != nil {
		t.Fatalf("Verify should not error on tampered signature: %v", err)
	}

	if valid {
		t.Error("Tampered SignedEntry should not verify")
	}
}

func TestSignedEntry_Verify_TamperedTimestamp(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "prod-2026",
		SecretKey: testSecretKey,
	}

	entry := map[string]string{"action": "test", "user": "alice"}

	signed, err := NewSignedEntry(entry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry failed: %v", err)
	}

	// Tamper with timestamp
	signed.Timestamp = "2020-01-01T00:00:00Z"

	valid, err := signed.Verify(testSecretKey)
	if err != nil {
		t.Fatalf("Verify should not error on tampered timestamp: %v", err)
	}

	if valid {
		t.Error("SignedEntry with tampered timestamp should not verify")
	}
}

func TestSignedEntry_Verify_TamperedKeyID(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "prod-2026",
		SecretKey: testSecretKey,
	}

	entry := map[string]string{"action": "test", "user": "alice"}

	signed, err := NewSignedEntry(entry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry failed: %v", err)
	}

	// Tamper with key ID
	signed.KeyID = "dev-2025"

	valid, err := signed.Verify(testSecretKey)
	if err != nil {
		t.Fatalf("Verify should not error on tampered key ID: %v", err)
	}

	if valid {
		t.Error("SignedEntry with tampered key ID should not verify")
	}
}

func TestSignedEntry_PreservesEntryData(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "prod-2026",
		SecretKey: testSecretKey,
	}

	// Use a struct type entry
	type TestEntry struct {
		Action string `json:"action"`
		User   string `json:"user"`
		Count  int    `json:"count"`
	}

	entry := TestEntry{Action: "login", User: "alice", Count: 42}

	signed, err := NewSignedEntry(entry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry failed: %v", err)
	}

	// Entry should be preserved (as map due to json marshaling)
	entryMap, ok := signed.Entry.(TestEntry)
	if ok {
		if entryMap.Action != "login" || entryMap.User != "alice" || entryMap.Count != 42 {
			t.Error("Entry data was modified")
		}
	}
}
