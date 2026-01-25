// Package device provides device posture collection for Sentinel.

package device

import (
	"regexp"

	"github.com/denisbrodbeck/machineid"
)

// AppID is the application-specific key for HMAC hashing of machine IDs.
// This ensures the device ID is unique to Sentinel and cannot be correlated
// with other applications using the same machine ID library.
const AppID = "sentinel-device-posture"

// deviceIdentifierRegex matches valid device identifiers (64 lowercase hex chars).
// SHA256 output = 32 bytes = 64 hex characters.
var deviceIdentifierRegex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// GetDeviceID returns a stable, hashed device identifier for this machine.
//
// This function is for IDENTIFICATION only, not posture claims.
// The Lambda TVM uses this ID to query MDM/EDR APIs for actual device posture.
// This ensures clients cannot fake compliance - the server is the source of truth.
//
// Implementation:
//   - Uses machineid.ProtectedID(AppID) to get HMAC-SHA256 of the machine ID
//   - The raw machine ID is never exposed (security best practice per freedesktop.org)
//   - Returns 64-character lowercase hex string (SHA256 output)
//   - Application-specific hashing isolates Sentinel from other apps using machine IDs
//
// Why we hash:
//   - Prevents leaking raw machine ID to external services
//   - Provides app-specific isolation (different AppID = different device ID)
//   - Follows freedesktop.org machine-id security recommendations
//
// Returns:
//   - (deviceID string, error) - 64-char hex string on success, error on failure
//   - On error, returns empty string (do NOT generate random ID - defeats correlation)
func GetDeviceID() (string, error) {
	// ProtectedID returns HMAC-SHA256(AppID, machineID)
	// This hashes the raw machine ID with our app-specific key
	id, err := machineid.ProtectedID(AppID)
	if err != nil {
		return "", err
	}
	return id, nil
}

// ValidateDeviceIdentifier checks if the given string is a valid device identifier.
// A valid device identifier is exactly 64 lowercase hexadecimal characters (SHA256 output).
//
// This is used by the Lambda TVM to validate incoming device IDs before
// querying MDM/EDR APIs.
func ValidateDeviceIdentifier(id string) bool {
	return deviceIdentifierRegex.MatchString(id)
}
