// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
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
	// STSClient is an optional custom STS client for testing.
	// If nil, uses default credentials from Lambda execution role.
	STSClient STSClient

	// Region is the AWS region for STS endpoint.
	// Defaults to AWS_REGION environment variable.
	Region string
}

// HandlerConfig contains optional configuration for creating a Handler.
type HandlerConfig struct {
	// STSClient is an optional custom STS client for testing.
	STSClient STSClient

	// Region is the AWS region for STS endpoint (defaults to AWS_REGION).
	Region string
}

// NewHandler creates a new TVM handler with optional configuration.
func NewHandler(cfg *HandlerConfig) *Handler {
	h := &Handler{}
	if cfg != nil {
		h.STSClient = cfg.STSClient
		h.Region = cfg.Region
	}
	if h.Region == "" {
		h.Region = os.Getenv("AWS_REGION")
	}
	return h
}

// HandleRequest processes an API Gateway v2 HTTP request.
// Returns credentials in AWS container credentials format.
func (h *Handler) HandleRequest(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Extract caller identity from IAM authorizer context
	caller, err := ExtractCallerIdentity(req)
	if err != nil {
		return errorResponse(http.StatusForbidden, "IAM_AUTH_REQUIRED",
			fmt.Sprintf("IAM authorization required: %v", err))
	}

	// Parse profile parameter (required)
	profile := req.QueryStringParameters["profile"]
	if profile == "" {
		return errorResponse(http.StatusBadRequest, "MISSING_PROFILE",
			"Missing required 'profile' query parameter")
	}

	// Parse optional duration parameter
	duration, err := parseDuration(req.QueryStringParameters["duration"])
	if err != nil {
		return errorResponse(http.StatusBadRequest, "INVALID_DURATION",
			fmt.Sprintf("Invalid duration: %v", err))
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
		Region:          h.Region,
	}

	// Vend credentials
	var vendOutput *VendOutput
	if h.STSClient != nil {
		// Use provided STS client (for testing)
		vendOutput, err = VendCredentialsWithClient(ctx, vendInput, h.STSClient)
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

	// Log successful credential issuance (for audit/debugging)
	log.Printf("INFO: Credentials issued profile=%s account=%s source_identity_request_id=%s",
		profile, caller.AccountID, vendOutput.SourceIdentity.RequestID())

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
