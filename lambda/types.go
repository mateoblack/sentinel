// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"errors"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// CallerIdentity represents the IAM identity of the API Gateway caller.
// Extracted from API Gateway v2 HTTP API IAM authorizer context.
type CallerIdentity struct {
	AccountID      string // AWS account ID of the caller
	UserARN        string // Full ARN of the calling IAM principal
	UserID         string // Unique ID of the calling principal
	AccessKey      string // Access key used to sign the request
	PrincipalOrgID string // AWS Organizations ID (if applicable)
}

// TVMRequest contains parameters for a credential vending request.
type TVMRequest struct {
	Profile         string        // Target profile/role to assume
	SessionDuration time.Duration // Requested credential duration (optional)
}

// TVMResponse contains credentials in AWS container credentials format.
// Compatible with AWS_CONTAINER_CREDENTIALS_FULL_URI.
type TVMResponse struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"` // RFC3339 format
}

// TVMError represents an error response from the TVM.
type TVMError struct {
	Message string `json:"Message"`
	Code    string `json:"Code,omitempty"`
}

// ErrMissingIAMContext is returned when IAM authorization context is missing from the request.
var ErrMissingIAMContext = errors.New("IAM authorization context is missing or incomplete")

// ExtractCallerIdentity extracts the IAM caller identity from an API Gateway v2 HTTP request.
// Returns an error if IAM authorization context is missing or incomplete.
func ExtractCallerIdentity(req events.APIGatewayV2HTTPRequest) (*CallerIdentity, error) {
	// Access the IAM authorization context from the request
	iam := req.RequestContext.Authorizer.IAM

	// Validate required fields are present
	if iam == nil {
		return nil, ErrMissingIAMContext
	}

	// Check for required fields
	if iam.AccountID == "" || iam.UserARN == "" {
		return nil, ErrMissingIAMContext
	}

	return &CallerIdentity{
		AccountID:      iam.AccountID,
		UserARN:        iam.UserARN,
		UserID:         iam.UserID,
		AccessKey:      iam.AccessKey,
		PrincipalOrgID: iam.PrincipalOrgID,
	}, nil
}
