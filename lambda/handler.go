// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// Handler handles API Gateway v2 HTTP requests for credential vending.
type Handler struct {
	// CredentialProvider will be added in Phase 98 for actual STS calls
	// For now, returns mock credentials for testing
}

// NewHandler creates a new TVM handler.
func NewHandler() *Handler {
	return &Handler{}
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

	// Parse request body for profile (optional query param: ?profile=xxx)
	profile := req.QueryStringParameters["profile"]
	if profile == "" {
		return errorResponse(http.StatusBadRequest, "MISSING_PROFILE",
			"Missing required 'profile' query parameter")
	}

	// TODO: Phase 98 will add actual STS AssumeRole call
	// For now, return mock response to validate request/response format
	_ = caller // Will be used for SourceIdentity in Phase 98

	// Return mock credentials (validates response format works with AWS SDKs)
	mockResponse := &TVMResponse{
		AccessKeyId:     "MOCK_ACCESS_KEY_ID",
		SecretAccessKey: "MOCK_SECRET_ACCESS_KEY",
		Token:           "MOCK_SESSION_TOKEN",
		Expiration:      time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339),
	}

	return successResponse(mockResponse)
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
