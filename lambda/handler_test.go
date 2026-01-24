package lambda

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

func TestHandler_HandleRequest(t *testing.T) {
	handler := NewHandler()
	ctx := context.Background()

	tests := []struct {
		name           string
		req            events.APIGatewayV2HTTPRequest
		wantStatusCode int
		wantErrorCode  string
	}{
		{
			name: "successful request",
			req: events.APIGatewayV2HTTPRequest{
				QueryStringParameters: map[string]string{
					"profile": "prod",
				},
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
						IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
							AccountID: "123456789012",
							UserARN:   "arn:aws:iam::123456789012:user/testuser",
							UserID:    "AIDAEXAMPLE",
						},
					},
				},
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "missing IAM auth",
			req: events.APIGatewayV2HTTPRequest{
				QueryStringParameters: map[string]string{
					"profile": "prod",
				},
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					Authorizer: nil,
				},
			},
			wantStatusCode: http.StatusForbidden,
			wantErrorCode:  "IAM_AUTH_REQUIRED",
		},
		{
			name: "missing profile parameter",
			req: events.APIGatewayV2HTTPRequest{
				QueryStringParameters: map[string]string{},
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
						IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
							AccountID: "123456789012",
							UserARN:   "arn:aws:iam::123456789012:user/testuser",
						},
					},
				},
			},
			wantStatusCode: http.StatusBadRequest,
			wantErrorCode:  "MISSING_PROFILE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := handler.HandleRequest(ctx, tt.req)
			if err != nil {
				t.Fatalf("HandleRequest() unexpected error: %v", err)
			}
			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("HandleRequest() statusCode = %d, want %d", resp.StatusCode, tt.wantStatusCode)
			}

			if tt.wantErrorCode != "" {
				var errResp TVMError
				if err := json.Unmarshal([]byte(resp.Body), &errResp); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if errResp.Code != tt.wantErrorCode {
					t.Errorf("HandleRequest() error code = %s, want %s", errResp.Code, tt.wantErrorCode)
				}
			}

			if tt.wantStatusCode == http.StatusOK {
				var creds TVMResponse
				if err := json.Unmarshal([]byte(resp.Body), &creds); err != nil {
					t.Fatalf("Failed to unmarshal credentials response: %v", err)
				}
				// Verify response has required fields
				if creds.AccessKeyId == "" {
					t.Error("AccessKeyId should not be empty")
				}
				if creds.SecretAccessKey == "" {
					t.Error("SecretAccessKey should not be empty")
				}
				if creds.Token == "" {
					t.Error("Token should not be empty")
				}
				if creds.Expiration == "" {
					t.Error("Expiration should not be empty")
				}
				// Verify expiration is valid RFC3339
				_, err := time.Parse(time.RFC3339, creds.Expiration)
				if err != nil {
					t.Errorf("Expiration should be RFC3339 format: %v", err)
				}
			}
		})
	}
}

func TestCredentialResponseFormat(t *testing.T) {
	// Test that credential response matches AWS container credentials format
	handler := NewHandler()
	ctx := context.Background()

	req := events.APIGatewayV2HTTPRequest{
		QueryStringParameters: map[string]string{
			"profile": "test-profile",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
				IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
					AccountID: "123456789012",
					UserARN:   "arn:aws:iam::123456789012:user/testuser",
				},
			},
		},
	}

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("HandleRequest() error: %v", err)
	}

	// Verify Content-Type header
	if resp.Headers["Content-Type"] != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %s, want application/json; charset=utf-8", resp.Headers["Content-Type"])
	}

	// Verify JSON field names match AWS SDK expectations exactly
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(resp.Body), &raw); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// AWS SDKs expect these exact field names (case-sensitive)
	requiredFields := []string{"AccessKeyId", "SecretAccessKey", "Token", "Expiration"}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}
}
