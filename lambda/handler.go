// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// Duration validation constants (AWS STS limits).
const (
	// MinDurationSeconds is the minimum allowed session duration (15 minutes).
	MinDurationSeconds = 900
	// MaxDurationSeconds is the maximum allowed session duration (12 hours).
	MaxDurationSeconds = 43200
)

// Handler handles API Gateway v2 HTTP requests for credential vending.
type Handler struct {
	// Config contains all TVM configuration including policy, stores, and STS client.
	Config *TVMConfig
}

// NewHandler creates a new TVM handler.
// If cfg is nil, configuration will be loaded from environment on first request.
func NewHandler(cfg ...*TVMConfig) *Handler {
	if len(cfg) > 0 && cfg[0] != nil {
		return &Handler{Config: cfg[0]}
	}
	return &Handler{}
}

// HandleRequest processes an API Gateway v2 HTTP request.
// Returns credentials in AWS container credentials format.
func (h *Handler) HandleRequest(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Lazy-load config from environment if not provided
	if h.Config == nil {
		cfg, err := LoadConfigFromEnv(ctx)
		if err != nil {
			return errorResponse(http.StatusInternalServerError, "CONFIG_ERROR",
				"Failed to load configuration: "+err.Error())
		}
		h.Config = cfg
	}

	// Extract caller identity from IAM authorizer context
	caller, err := ExtractCallerIdentity(req)
	if err != nil {
		return errorResponse(http.StatusForbidden, "IAM_AUTH_REQUIRED",
			fmt.Sprintf("IAM authorization required: %v", err))
	}

	// Extract username from caller ARN for policy evaluation
	username, err := extractUsername(caller.UserARN)
	if err != nil {
		return errorResponse(http.StatusBadRequest, "INVALID_IDENTITY",
			fmt.Sprintf("Could not extract username: %v", err))
	}

	// Parse profile parameter (required)
	profile := req.QueryStringParameters["profile"]
	if profile == "" {
		return errorResponse(http.StatusBadRequest, "MISSING_PROFILE",
			"Missing required 'profile' query parameter")
	}

	// Create session context (after username and profile extraction)
	sessionCtx := CreateSessionContext(ctx, h.Config, username, profile)

	// Extract device ID from request (optional)
	deviceID := extractDeviceID(req)

	// Query MDM for device posture if configured and device ID provided
	var mdmResult *MDMResult
	if h.Config.MDMProvider != nil && deviceID != "" {
		posture, mdmErr := queryDevicePosture(ctx, h.Config.MDMProvider, deviceID)
		mdmResult = &MDMResult{
			DeviceID: deviceID,
			Posture:  posture,
			Error:    mdmErr,
		}
		logMDMResult(deviceID, posture, mdmErr)

		// If RequireDevicePosture and lookup failed, deny
		if h.Config.RequireDevicePosture && mdmErr != nil {
			return errorResponse(http.StatusForbidden, "DEVICE_VERIFICATION_FAILED",
				fmt.Sprintf("Device verification failed: %v", mdmErr))
		}
	} else if deviceID != "" && h.Config.MDMProvider == nil {
		log.Printf("INFO: Device ID provided but MDM not configured, skipping verification")
		mdmResult = &MDMResult{DeviceID: deviceID, Skipped: true}
	}

	// Parse optional duration parameter
	parsedDuration, err := parseDuration(req.QueryStringParameters["duration"])
	if err != nil {
		return errorResponse(http.StatusBadRequest, "INVALID_DURATION",
			fmt.Sprintf("Invalid duration: %v", err))
	}

	// Build policy request - Lambda TVM acts as server mode
	policyRequest := &policy.Request{
		User:             username,
		Profile:          profile,
		Time:             time.Now(),
		Mode:             policy.ModeServer, // TVM is server-side
		SessionTableName: h.Config.SessionTableName,
	}

	// Wire device posture into policy request for device condition evaluation
	// Policy rules with device conditions will use this posture for matching.
	// If MDM lookup succeeded, include the posture for policy evaluation.
	// If MDM lookup failed or was skipped, posture remains nil.
	if mdmResult != nil && mdmResult.Posture != nil {
		policyRequest.DevicePosture = mdmResult.Posture
	}

	// Load policy
	if h.Config.PolicyLoader == nil {
		return errorResponse(http.StatusInternalServerError, "CONFIG_ERROR",
			"Policy loader not configured")
	}

	loadedPolicy, err := h.Config.PolicyLoader.Load(ctx, h.Config.PolicyParameter)
	if err != nil {
		log.Printf("ERROR: Failed to load policy: %v", err)
		return errorResponse(http.StatusInternalServerError, "POLICY_ERROR",
			"Failed to load policy")
	}

	// Evaluate policy
	decision := policy.Evaluate(loadedPolicy, policyRequest)

	// Handle deny decision - check for approved request or break-glass first
	var approvedReq *request.Request
	var activeBreakGlass *breakglass.BreakGlassEvent

	if decision.Effect == policy.EffectDeny {
		// Check for approved request before denying
		if h.Config.ApprovalStore != nil {
			var storeErr error
			approvedReq, storeErr = request.FindApprovedRequest(ctx, h.Config.ApprovalStore, username, profile)
			if storeErr != nil {
				log.Printf("Warning: failed to check approved requests: %v", storeErr)
			}
		}

		// If no approved request, check for active break-glass
		if approvedReq == nil && h.Config.BreakGlassStore != nil {
			var bgErr error
			activeBreakGlass, bgErr = breakglass.FindActiveBreakGlass(ctx, h.Config.BreakGlassStore, username, profile)
			if bgErr != nil {
				log.Printf("Warning: failed to check break-glass: %v", bgErr)
			}
		}

		// If neither approved request nor break-glass, deny
		if approvedReq == nil && activeBreakGlass == nil {
			// Log deny decision with device posture context
			if h.Config.Logger != nil {
				// Use enhanced entry to include device posture in deny logs
				var denyCredFields *logging.CredentialIssuanceFields
				if mdmResult != nil && mdmResult.Posture != nil {
					denyCredFields = &logging.CredentialIssuanceFields{
						DevicePosture: mdmResult.Posture,
					}
				}
				entry := logging.NewEnhancedDecisionLogEntry(policyRequest, decision, h.Config.PolicyParameter, denyCredFields)
				h.Config.Logger.LogDecision(entry)
			}
			// Include device posture in console log for debugging
			if mdmResult != nil && mdmResult.Posture != nil {
				log.Printf("DENY: user=%s profile=%s rule=%s reason=%s device_id=%s device_status=%s mdm_enrolled=%v",
					username, profile, decision.MatchedRule, decision.Reason,
					mdmResult.Posture.DeviceID, mdmResult.Posture.Status, mdmResult.Posture.HasMDMEnrollment())
			} else {
				log.Printf("DENY: user=%s profile=%s rule=%s reason=%s device_status=not_provided",
					username, profile, decision.MatchedRule, decision.Reason)
			}
			return errorResponse(http.StatusForbidden, "POLICY_DENY",
				fmt.Sprintf("Policy denied: %s", decision.Reason))
		}
		// Approved request or active break-glass found - continue to credential issuance
	}

	// Apply duration from policy cap
	duration := parsedDuration
	if decision.MaxServerDuration > 0 {
		if duration == 0 || duration > decision.MaxServerDuration {
			duration = decision.MaxServerDuration
			log.Printf("INFO: Capping duration to policy max_server_duration: %v", duration)
		}
	}

	// Cap duration to break-glass remaining time if applicable
	if activeBreakGlass != nil {
		remainingTime := breakglass.RemainingDuration(activeBreakGlass)
		if duration == 0 || duration > remainingTime {
			duration = remainingTime
			log.Printf("INFO: Capping duration to break-glass remaining time: %v", duration)
		}
	}

	// Apply default duration if not specified
	if duration == 0 {
		duration = h.Config.DefaultDuration
		if duration == 0 {
			duration = DefaultTVMDuration
		}
	}

	// Check session revocation before credential issuance
	if sessionCtx.CheckRevocation(ctx) {
		return errorResponse(http.StatusForbidden, "SESSION_REVOKED",
			"Session has been revoked")
	}

	// Build RoleARN from profile
	// For now, use profile directly as RoleARN
	// Phase 100 will add profile lookup
	roleARN := profile

	// Build VendInput
	vendInput := &VendInput{
		Caller:          caller,
		RoleARN:         roleARN,
		SessionDuration: duration,
		Region:          h.Config.Region,
		SessionID:       sessionCtx.ID,
	}

	// Include approval ID for SourceIdentity stamping (if via approved request)
	if approvedReq != nil {
		vendInput.ApprovalID = approvedReq.ID
	}

	// Vend credentials
	var vendOutput *VendOutput
	if h.Config.STSClient != nil {
		// Use provided STS client (for testing)
		vendOutput, err = VendCredentialsWithClient(ctx, vendInput, h.Config.STSClient)
	} else {
		// Use default STS client (Lambda execution role)
		vendOutput, err = VendCredentials(ctx, vendInput)
	}
	if err != nil {
		// Log error details for debugging (CloudWatch)
		log.Printf("ERROR: VendCredentials failed for profile=%s account=%s: %v",
			profile, caller.AccountID, err)
		// Return generic error to client (don't leak details)
		return errorResponse(http.StatusInternalServerError, "CREDENTIAL_ERROR",
			"Failed to vend credentials")
	}

	// Touch session to update LastAccessAt
	sessionCtx.Touch(ctx)

	// Log decision with credential context
	if h.Config.Logger != nil {
		credFields := &logging.CredentialIssuanceFields{
			RequestID:       vendOutput.SourceIdentity.RequestID,
			SourceIdentity:  vendOutput.SourceIdentity.Format(),
			RoleARN:         roleARN,
			SessionDuration: duration,
		}

		// Include approved request ID if credentials were issued via approval override
		if approvedReq != nil {
			credFields.ApprovedRequestID = approvedReq.ID
		}

		// Include break-glass event ID if credentials were issued via break-glass override
		if activeBreakGlass != nil {
			credFields.BreakGlassEventID = activeBreakGlass.ID
		}

		// Include device posture if MDM lookup was successful
		if mdmResult != nil && mdmResult.Posture != nil {
			credFields.DevicePosture = mdmResult.Posture
		}

		entry := logging.NewEnhancedDecisionLogEntry(policyRequest, decision, h.Config.PolicyParameter, credFields)
		h.Config.Logger.LogDecision(entry)
	}

	// Log successful credential issuance (for audit/debugging)
	log.Printf("INFO: Credentials issued user=%s profile=%s account=%s source_identity_request_id=%s",
		username, profile, caller.AccountID, vendOutput.SourceIdentity.RequestID)

	return successResponse(vendOutput.Credentials)
}

// parseDuration parses and validates a duration string in seconds.
// Returns 0 for empty string (use default).
// Validates that duration is within AWS STS limits: 900-43200 seconds (15 min to 12 hours).
func parseDuration(durationStr string) (time.Duration, error) {
	if durationStr == "" {
		// Empty means use default
		return 0, nil
	}

	// Parse as integer seconds
	seconds, err := strconv.Atoi(durationStr)
	if err != nil {
		return 0, fmt.Errorf("duration must be an integer (seconds)")
	}

	// Validate AWS STS limits
	if seconds < MinDurationSeconds {
		return 0, fmt.Errorf("duration must be at least %d seconds (15 minutes)", MinDurationSeconds)
	}
	if seconds > MaxDurationSeconds {
		return 0, fmt.Errorf("duration must be at most %d seconds (12 hours)", MaxDurationSeconds)
	}

	return time.Duration(seconds) * time.Second, nil
}

// successResponse creates a successful credential response.
func successResponse(creds *TVMResponse) (events.APIGatewayV2HTTPResponse, error) {
	body, err := json.Marshal(creds)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "MARSHAL_ERROR",
			fmt.Sprintf("Failed to marshal credentials: %v", err))
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		Body: string(body),
	}, nil
}

// errorResponse creates an error response.
func errorResponse(statusCode int, code, message string) (events.APIGatewayV2HTTPResponse, error) {
	errResp := &TVMError{
		Code:    code,
		Message: message,
	}
	body, _ := json.Marshal(errResp)

	return events.APIGatewayV2HTTPResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		Body: string(body),
	}, nil
}

// ErrorResponse creates an error response (exported for main.go).
// This is a convenience wrapper around errorResponse.
func ErrorResponse(statusCode int, code, message string) (events.APIGatewayV2HTTPResponse, error) {
	return errorResponse(statusCode, code, message)
}

// Phase 100 placeholder
