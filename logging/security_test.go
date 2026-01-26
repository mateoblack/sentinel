// Package logging provides security regression tests for audit log integrity.
// These tests validate that log tampering is detected and signature verification
// cannot be bypassed through various attack vectors.
//
// SECURITY: These tests are regression tests for phase 128 audit log integrity.
package logging

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// =============================================================================
// SIGNATURE VERIFICATION SECURITY TESTS
// =============================================================================

// TestSecurity_SignatureDetectsTampering verifies that modifying a signed log entry
// is detected by signature verification.
//
// SECURITY: An attacker who gains access to log files cannot modify entries
// without detection if the signing key is protected. The HMAC signature covers
// the entire entry content, so any change invalidates the signature.
func TestSecurity_SignatureDetectsTampering(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "test-key-v1",
		SecretKey: make([]byte, 32),
	}
	for i := range config.SecretKey {
		config.SecretKey[i] = byte(i)
	}

	// Create a valid signed entry
	originalEntry := map[string]any{
		"action": "login",
		"user":   "alice",
		"role":   "admin",
	}

	signed, err := NewSignedEntry(originalEntry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry() error = %v", err)
	}

	// Verify original signature is valid
	valid, err := signed.Verify(config.SecretKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !valid {
		t.Fatal("SECURITY: Original signed entry should verify successfully")
	}

	// Tamper with the entry content by modifying the raw JSON
	tampered := &SignedEntry{
		Entry:     json.RawMessage(`{"action":"login","user":"ATTACKER","role":"admin"}`),
		Signature: signed.Signature,
		KeyID:     signed.KeyID,
		Timestamp: signed.Timestamp,
	}

	// Verification MUST fail for tampered entry
	valid, err = tampered.Verify(config.SecretKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if valid {
		t.Error("SECURITY VIOLATION: Tampered entry should NOT verify - signature must detect content changes")
	}
}

// TestSecurity_SignatureDetectsTruncation verifies that removing fields from a
// signed entry is detected.
//
// SECURITY: An attacker cannot selectively remove sensitive fields from log entries
// without invalidating the signature. This prevents sanitization attacks where
// an attacker removes evidence of their actions.
func TestSecurity_SignatureDetectsTruncation(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "test-key-v1",
		SecretKey: make([]byte, 32),
	}
	for i := range config.SecretKey {
		config.SecretKey[i] = byte(i)
	}

	// Create entry with multiple sensitive fields
	originalEntry := map[string]any{
		"action":    "delete_database",
		"user":      "attacker",
		"target":    "production-db",
		"timestamp": "2026-01-26T12:00:00Z",
	}

	signed, err := NewSignedEntry(originalEntry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry() error = %v", err)
	}

	// Verify original is valid
	valid, _ := signed.Verify(config.SecretKey)
	if !valid {
		t.Fatal("Original entry should verify")
	}

	// Truncate by removing the "user" field
	truncated := &SignedEntry{
		Entry:     json.RawMessage(`{"action":"delete_database","target":"production-db","timestamp":"2026-01-26T12:00:00Z"}`),
		Signature: signed.Signature,
		KeyID:     signed.KeyID,
		Timestamp: signed.Timestamp,
	}

	// Verification MUST fail for truncated entry
	valid, err = truncated.Verify(config.SecretKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if valid {
		t.Error("SECURITY VIOLATION: Truncated entry should NOT verify - removing fields must be detected")
	}
}

// TestSecurity_SignatureDetectsReplay verifies that signatures are entry-specific
// and cannot be reused across different entries.
//
// SECURITY: An attacker cannot take a valid signature from one entry and apply
// it to a different entry. The signature is bound to the specific content,
// timestamp, and key ID combination.
func TestSecurity_SignatureDetectsReplay(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "test-key-v1",
		SecretKey: make([]byte, 32),
	}
	for i := range config.SecretKey {
		config.SecretKey[i] = byte(i)
	}

	// Create two different entries
	entry1 := map[string]any{"action": "read", "user": "alice"}
	entry2 := map[string]any{"action": "delete", "user": "alice"}

	signed1, err := NewSignedEntry(entry1, config)
	if err != nil {
		t.Fatalf("NewSignedEntry(entry1) error = %v", err)
	}

	signed2, err := NewSignedEntry(entry2, config)
	if err != nil {
		t.Fatalf("NewSignedEntry(entry2) error = %v", err)
	}

	// Both should verify with their own signatures
	valid1, _ := signed1.Verify(config.SecretKey)
	valid2, _ := signed2.Verify(config.SecretKey)
	if !valid1 || !valid2 {
		t.Fatal("Both entries should verify with their own signatures")
	}

	// Attempt replay attack: use signature from entry1 on entry2's content
	replayed := &SignedEntry{
		Entry:     signed2.Entry,     // Content from entry2
		Signature: signed1.Signature, // Signature from entry1
		KeyID:     signed1.KeyID,
		Timestamp: signed1.Timestamp,
	}

	valid, err := replayed.Verify(config.SecretKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if valid {
		t.Error("SECURITY VIOLATION: Replayed signature should NOT verify - signatures must be entry-specific")
	}
}

// TestSecurity_WrongKeyRejected verifies that signatures cannot be verified
// with a different key.
//
// SECURITY: Even if an attacker obtains the signed entries, they cannot verify
// the signatures without the correct key. This ensures key confidentiality
// is critical for integrity verification.
func TestSecurity_WrongKeyRejected(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	for i := range keyA {
		keyA[i] = byte(i)
		keyB[i] = byte(255 - i) // Different key
	}

	configA := &SignatureConfig{
		KeyID:     "key-a",
		SecretKey: keyA,
	}

	entry := map[string]any{"action": "test"}
	signed, err := NewSignedEntry(entry, configA)
	if err != nil {
		t.Fatalf("NewSignedEntry() error = %v", err)
	}

	// Should verify with correct key
	valid, _ := signed.Verify(keyA)
	if !valid {
		t.Fatal("Entry should verify with correct key")
	}

	// Should NOT verify with wrong key
	valid, err = signed.Verify(keyB)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if valid {
		t.Error("SECURITY VIOLATION: Entry should NOT verify with wrong key")
	}
}

// TestSecurity_ConstantTimeComparison verifies that signature verification uses
// constant-time comparison to prevent timing attacks.
//
// SECURITY: Timing attacks can leak information about the correct signature
// by measuring response time. Using crypto/subtle.ConstantTimeCompare ensures
// the comparison takes the same time regardless of which byte differs.
func TestSecurity_ConstantTimeComparison(t *testing.T) {
	// Parse signature.go to verify it uses subtle.ConstantTimeCompare
	fset := token.NewFileSet()

	// First check for crypto/subtle import
	f, err := parser.ParseFile(fset, "signature.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("failed to parse signature.go: %v", err)
	}

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

	// Parse full AST to verify ConstantTimeCompare is actually used
	fFull, err := parser.ParseFile(fset, "signature.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("failed to parse signature.go for full AST: %v", err)
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
		t.Error("SECURITY: Verify function must use subtle.ConstantTimeCompare for signature comparison")
	}
}

// TestSecurity_MinimumKeyLength verifies that weak keys are rejected.
//
// SECURITY: HMAC-SHA256 with a key shorter than 32 bytes provides weaker
// security guarantees. Enforcing minimum key length ensures adequate entropy.
func TestSecurity_MinimumKeyLength(t *testing.T) {
	tests := []struct {
		name      string
		keyLength int
		wantError bool
	}{
		{"31 bytes - too short", 31, true},
		{"30 bytes - too short", 30, true},
		{"16 bytes - too short", 16, true},
		{"1 byte - too short", 1, true},
		{"0 bytes - empty", 0, true},
		{"32 bytes - minimum valid", 32, false},
		{"64 bytes - longer than minimum", 64, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SignatureConfig{
				KeyID:     "test-key",
				SecretKey: make([]byte, tt.keyLength),
			}

			err := config.Validate()
			if tt.wantError && err == nil {
				t.Errorf("SECURITY: Key length %d bytes should be rejected as too short", tt.keyLength)
			}
			if !tt.wantError && err != nil {
				t.Errorf("Key length %d bytes should be accepted, got error: %v", tt.keyLength, err)
			}
		})
	}
}

// TestSecurity_EmptySignatureRejected verifies that entries without signatures
// are properly rejected.
//
// SECURITY: An attacker cannot bypass verification by removing or emptying
// the signature field. Missing signatures must be explicitly rejected.
func TestSecurity_EmptySignatureRejected(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	tests := []struct {
		name      string
		signature string
	}{
		{"empty string", ""},
		{"whitespace only", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &SignedEntry{
				Entry:     json.RawMessage(`{"action":"test"}`),
				Signature: tt.signature,
				KeyID:     "test-key",
				Timestamp: "2026-01-26T12:00:00Z",
			}

			valid, err := entry.Verify(key)
			if err != nil {
				// Error is acceptable for empty signature
				return
			}
			if valid {
				t.Errorf("SECURITY VIOLATION: Entry with signature %q should NOT verify", tt.signature)
			}
		})
	}
}

// TestSecurity_MalformedSignatureRejected verifies that invalid hex signatures
// are properly rejected.
//
// SECURITY: An attacker cannot cause undefined behavior or bypass verification
// by providing malformed signature strings.
func TestSecurity_MalformedSignatureRejected(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	tests := []struct {
		name      string
		signature string
	}{
		{"non-hex characters", "not-valid-hex-signature"},
		{"odd length hex", "abc"},
		{"invalid chars in hex", "gg00ff"},
		{"truncated valid hex", "abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &SignedEntry{
				Entry:     json.RawMessage(`{"action":"test"}`),
				Signature: tt.signature,
				KeyID:     "test-key",
				Timestamp: "2026-01-26T12:00:00Z",
			}

			valid, err := entry.Verify(key)
			if err != nil {
				// Error is acceptable for malformed signature
				return
			}
			if valid {
				t.Errorf("SECURITY VIOLATION: Entry with malformed signature %q should NOT verify", tt.signature)
			}
		})
	}
}

// TestSecurity_TimestampIncludedInSignature verifies that the timestamp is
// included in the signed content to prevent timestamp manipulation.
//
// SECURITY: An attacker cannot change the timestamp of a log entry without
// invalidating the signature. This prevents backdating or forward-dating attacks.
func TestSecurity_TimestampIncludedInSignature(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "test-key-v1",
		SecretKey: make([]byte, 32),
	}
	for i := range config.SecretKey {
		config.SecretKey[i] = byte(i)
	}

	entry := map[string]any{"action": "test"}
	signed, err := NewSignedEntry(entry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry() error = %v", err)
	}

	// Verify original
	valid, _ := signed.Verify(config.SecretKey)
	if !valid {
		t.Fatal("Original should verify")
	}

	// Attempt to change timestamp
	manipulated := &SignedEntry{
		Entry:     signed.Entry,
		Signature: signed.Signature,
		KeyID:     signed.KeyID,
		Timestamp: "1999-01-01T00:00:00Z", // Changed timestamp
	}

	valid, err = manipulated.Verify(config.SecretKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if valid {
		t.Error("SECURITY VIOLATION: Entry with manipulated timestamp should NOT verify")
	}
}

// TestSecurity_KeyIDIncludedInSignature verifies that the key ID is included
// in the signed content to prevent key ID manipulation.
//
// SECURITY: An attacker cannot change the key ID field to impersonate a
// different signing key. The key ID is part of the signed content.
func TestSecurity_KeyIDIncludedInSignature(t *testing.T) {
	config := &SignatureConfig{
		KeyID:     "production-key-v1",
		SecretKey: make([]byte, 32),
	}
	for i := range config.SecretKey {
		config.SecretKey[i] = byte(i)
	}

	entry := map[string]any{"action": "test"}
	signed, err := NewSignedEntry(entry, config)
	if err != nil {
		t.Fatalf("NewSignedEntry() error = %v", err)
	}

	// Verify original
	valid, _ := signed.Verify(config.SecretKey)
	if !valid {
		t.Fatal("Original should verify")
	}

	// Attempt to change key ID
	manipulated := &SignedEntry{
		Entry:     signed.Entry,
		Signature: signed.Signature,
		KeyID:     "compromised-key", // Changed key ID
		Timestamp: signed.Timestamp,
	}

	valid, err = manipulated.Verify(config.SecretKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if valid {
		t.Error("SECURITY VIOLATION: Entry with manipulated key ID should NOT verify")
	}
}
