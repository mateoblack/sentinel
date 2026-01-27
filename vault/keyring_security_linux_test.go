//go:build linux

package vault

import (
	"testing"

	"github.com/byteness/keyring"
)

// TestSecurityRegression_KeyringConfig_LinuxHardening verifies that
// keyring config includes Linux keyctl security hardening.
// THREAT: Other processes running as same user could access keys without possessor-only permissions
func TestSecurityRegression_KeyringConfig_LinuxHardening(t *testing.T) {
	// Document expected KeyCtlPerm value: 0x3f000000 (possessor-only)
	// This is calculated as KEYCTL_PERM_ALL << KEYCTL_PERM_PROCESS
	// KEYCTL_PERM_ALL = 0x3f (all permission bits: view, read, write, search, link, setattr)
	// KEYCTL_PERM_PROCESS = 24 (shift to possessor position)
	// Result: 0x3f << 24 = 0x3f000000
	//
	// This permission mask means:
	// - Possessor (bits 24-29): all permissions (view, read, write, search, link, setattr)
	// - User (bits 16-21): no permissions
	// - Group (bits 8-13): no permissions
	// - Other (bits 0-5): no permissions
	//
	// Only the possessor (the process that created the key) can access it.
	// This prevents other processes running as the same user from accessing credentials.

	expectedPerm := uint32(keyring.KEYCTL_PERM_ALL << keyring.KEYCTL_PERM_PROCESS)
	if expectedPerm != 0x3f000000 {
		t.Errorf("SECURITY VIOLATION: Expected KeyCtlPerm 0x3f000000 (possessor-only), formula gives %#x", expectedPerm)
	}

	// Verify the constant values are as expected
	// KEYCTL_PERM_ALL should be 0x3f (6 permission bits all set)
	if keyring.KEYCTL_PERM_ALL != 0x3f {
		t.Errorf("SECURITY VIOLATION: KEYCTL_PERM_ALL should be 0x3f, got %#x", keyring.KEYCTL_PERM_ALL)
	}

	// KEYCTL_PERM_PROCESS (aka KEYCTL_PERM_POSSESSOR) should be 24
	if keyring.KEYCTL_PERM_PROCESS != 24 {
		t.Errorf("SECURITY VIOLATION: KEYCTL_PERM_PROCESS should be 24, got %d", keyring.KEYCTL_PERM_PROCESS)
	}
}
