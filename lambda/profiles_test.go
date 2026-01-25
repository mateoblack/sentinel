package lambda

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// mockSSMClient implements ssmAPI for testing.
type mockSSMClient struct {
	params []types.Parameter
	err    error
}

func (m *mockSSMClient) GetParametersByPath(ctx context.Context, input *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &ssm.GetParametersByPathOutput{
		Parameters: m.params,
	}, nil
}

func TestProfileDiscovery_HandleRequest_Success(t *testing.T) {
	client := &mockSSMClient{
		params: []types.Parameter{
			{Name: aws.String("/sentinel/policies/dev")},
			{Name: aws.String("/sentinel/policies/production")},
		},
	}

	profiler := NewProfileDiscovery(client, "/sentinel/policies")

	req := events.APIGatewayV2HTTPRequest{
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method: "GET",
			},
		},
	}

	resp, err := profiler.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result ProfileDiscoveryResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(result.Profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(result.Profiles))
	}

	if result.Profiles[0].Name != "dev" {
		t.Errorf("expected first profile 'dev', got %s", result.Profiles[0].Name)
	}

	if result.Root != "/sentinel/policies" {
		t.Errorf("expected root '/sentinel/policies', got %s", result.Root)
	}
}

func TestProfileDiscovery_HandleRequest_MethodNotAllowed(t *testing.T) {
	client := &mockSSMClient{}
	profiler := NewProfileDiscovery(client, "/sentinel/policies")

	req := events.APIGatewayV2HTTPRequest{
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method: "POST",
			},
		},
	}

	resp, _ := profiler.HandleRequest(context.Background(), req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestProfileDiscovery_HandleRequest_EmptyProfiles(t *testing.T) {
	client := &mockSSMClient{
		params: []types.Parameter{}, // No profiles
	}

	profiler := NewProfileDiscovery(client, "/sentinel/policies")

	req := events.APIGatewayV2HTTPRequest{
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
				Method: "GET",
			},
		},
	}

	resp, err := profiler.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result ProfileDiscoveryResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if result.Profiles == nil {
		// Profiles should be empty slice, not nil
		if len(result.Profiles) != 0 {
			t.Errorf("expected 0 profiles, got %d", len(result.Profiles))
		}
	}
}

func TestExtractProfileName(t *testing.T) {
	tests := []struct {
		root     string
		path     string
		expected string
	}{
		{"/sentinel/policies", "/sentinel/policies/dev", "dev"},
		{"/sentinel/policies/", "/sentinel/policies/production", "production"},
		{"/custom/path", "/custom/path/test-profile", "test-profile"},
		{"/sentinel/policies", "/sentinel/policies/multi-part-name", "multi-part-name"},
	}

	for _, tt := range tests {
		result := extractProfileName(tt.root, tt.path)
		if result != tt.expected {
			t.Errorf("extractProfileName(%q, %q) = %q, want %q",
				tt.root, tt.path, result, tt.expected)
		}
	}
}
