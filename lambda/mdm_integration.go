// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/byteness/aws-vault/v7/device"
	"github.com/byteness/aws-vault/v7/mdm"
)

// MDMResult contains the result of an MDM device posture query.
type MDMResult struct {
	// DeviceID is the device identifier that was queried.
	DeviceID string

	// Posture is the device posture information from MDM.
	// nil if lookup failed or was skipped.
	Posture *device.DevicePosture

	// Error is the error from MDM lookup, if any.
	// nil if successful.
	Error error

	// Skipped is true if no MDM configured or no device_id provided.
	Skipped bool
}

// extractDeviceID extracts the device_id query parameter from an API Gateway request.
// Returns empty string if missing or invalid.
// The device_id is expected to be a 64-character lowercase hexadecimal string
// (HMAC-SHA256 hashed device identifier from GetDeviceID()).
func extractDeviceID(req events.APIGatewayV2HTTPRequest) string {
	deviceID := req.QueryStringParameters["device_id"]
	if deviceID == "" {
		return ""
	}

	// Validate format with device.ValidateDeviceIdentifier()
	// This expects 64 lowercase hex characters (SHA256 output)
	if !device.ValidateDeviceIdentifier(deviceID) {
		log.Printf("WARNING: Invalid device_id format: %s (expected 64 lowercase hex chars)", deviceID)
		return ""
	}

	return deviceID
}

// queryDevicePosture queries the MDM provider for device posture information.
// Returns a DevicePosture struct populated from MDMDeviceInfo, or an error.
//
// The mapping from MDMDeviceInfo to DevicePosture:
//   - DeviceID = the Sentinel device ID we looked up
//   - Status = compliant if MDMDeviceInfo.Compliant, else non_compliant
//   - MDMEnrolled = MDMDeviceInfo.Enrolled
//   - MDMCompliant = MDMDeviceInfo.Compliant
//   - OSVersion = MDMDeviceInfo.OSVersion
//   - CollectedAt = time.Now() (when TVM queried)
func queryDevicePosture(ctx context.Context, provider mdm.Provider, deviceID string) (*device.DevicePosture, error) {
	info, err := provider.LookupDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// Map MDMDeviceInfo to DevicePosture
	posture := &device.DevicePosture{
		DeviceID:    deviceID,
		CollectedAt: time.Now(),
	}

	// Set status based on compliance
	if info.Compliant {
		posture.Status = device.StatusCompliant
	} else {
		posture.Status = device.StatusNonCompliant
	}

	// Set MDM fields (non-pointer bools from MDM become pointer bools in DevicePosture)
	enrolled := info.Enrolled
	posture.MDMEnrolled = &enrolled

	compliant := info.Compliant
	posture.MDMCompliant = &compliant

	// Set optional fields
	posture.OSVersion = info.OSVersion

	return posture, nil
}

// logMDMResult logs the result of an MDM lookup operation.
// Uses appropriate log levels based on the outcome.
func logMDMResult(deviceID string, posture *device.DevicePosture, err error) {
	if err == nil && posture != nil {
		// Success - log INFO with posture summary
		log.Printf("INFO: MDM lookup success device_id=%s status=%s mdm_enrolled=%v mdm_compliant=%v",
			deviceID, posture.Status, posture.HasMDMEnrollment(), posture.HasMDMCompliance())
		return
	}

	// Log based on error type
	if err != nil {
		switch {
		case isDeviceNotFoundError(err):
			log.Printf("WARNING: Device not found in MDM device_id=%s", deviceID)
		case isMDMAuthError(err):
			log.Printf("ERROR: MDM authentication failed device_id=%s: %v", deviceID, err)
		case isMDMUnavailableError(err):
			log.Printf("ERROR: MDM service unavailable device_id=%s: %v", deviceID, err)
		default:
			log.Printf("ERROR: MDM lookup failed device_id=%s: %v", deviceID, err)
		}
	}
}

// Helper functions to check error types using errors.Is semantics.
// These check if the error or any wrapped error matches the sentinel errors.

func isDeviceNotFoundError(err error) bool {
	return containsError(err, mdm.ErrDeviceNotFound)
}

func isMDMAuthError(err error) bool {
	return containsError(err, mdm.ErrMDMAuthFailed)
}

func isMDMUnavailableError(err error) bool {
	return containsError(err, mdm.ErrMDMUnavailable)
}

// containsError checks if err contains target (using Unwrap for error chains).
func containsError(err, target error) bool {
	if err == nil {
		return false
	}
	if err == target {
		return true
	}
	// Check wrapped errors
	if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
		return containsError(unwrapper.Unwrap(), target)
	}
	// Check error chains (errors.Join)
	if joiner, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range joiner.Unwrap() {
			if containsError(e, target) {
				return true
			}
		}
	}
	return false
}
