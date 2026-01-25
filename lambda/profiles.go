// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// ProfileInfo holds information about a discoverable Sentinel profile.
type ProfileInfo struct {
	Name       string `json:"name"`        // Profile name (e.g., "production")
	PolicyPath string `json:"policy_path"` // Full SSM path (e.g., "/sentinel/policies/production")
}

// ProfileDiscoveryResponse is the response format for /profiles endpoint.
type ProfileDiscoveryResponse struct {
	Profiles []ProfileInfo `json:"profiles"`
	Root     string        `json:"root"` // Policy root path used for discovery
}

// ssmAPI defines the SSM operations used by ProfileDiscovery.
// This interface enables testing with mock implementations.
type ssmAPI interface {
	GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
}

// ProfileDiscovery handles the /profiles endpoint for discovering available Sentinel profiles.
type ProfileDiscovery struct {
	ssm        ssmAPI
	policyRoot string // SSM path root for policies (e.g., "/sentinel/policies")
}

// NewProfileDiscovery creates a new ProfileDiscovery with the given SSM client and policy root.
func NewProfileDiscovery(client ssmAPI, policyRoot string) *ProfileDiscovery {
	return &ProfileDiscovery{
		ssm:        client,
		policyRoot: policyRoot,
	}
}

// HandleRequest handles a profile discovery request.
// Returns a list of available profiles from SSM.
func (p *ProfileDiscovery) HandleRequest(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Only GET method allowed
	if req.RequestContext.HTTP.Method != "GET" {
		return errorResponse(http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"Only GET method is allowed for /profiles")
	}

	// Discover profiles from SSM
	profiles, err := p.discoverProfiles(ctx)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "SSM_ERROR",
			"Failed to discover profiles: "+err.Error())
	}

	// Build response
	resp := &ProfileDiscoveryResponse{
		Profiles: profiles,
		Root:     p.policyRoot,
	}

	body, err := json.Marshal(resp)
	if err != nil {
		return errorResponse(http.StatusInternalServerError, "MARSHAL_ERROR",
			"Failed to marshal response")
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		Body: string(body),
	}, nil
}

// discoverProfiles queries SSM for all policy parameters under the root path.
// This is similar to shell.ShellGenerator.GetProfiles but returns simplified info.
func (p *ProfileDiscovery) discoverProfiles(ctx context.Context) ([]ProfileInfo, error) {
	var profiles []ProfileInfo
	var nextToken *string

	for {
		input := &ssm.GetParametersByPathInput{
			Path:      aws.String(p.policyRoot),
			Recursive: aws.Bool(false), // Only direct children (profiles are at top level)
			NextToken: nextToken,
		}

		output, err := p.ssm.GetParametersByPath(ctx, input)
		if err != nil {
			return nil, err
		}

		// Process parameters from this page
		for _, param := range output.Parameters {
			path := aws.ToString(param.Name)
			name := extractProfileName(p.policyRoot, path)

			profiles = append(profiles, ProfileInfo{
				Name:       name,
				PolicyPath: path,
			})
		}

		// Check for more pages
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return profiles, nil
}

// extractProfileName extracts the profile name from a full parameter path.
// For example, "/sentinel/policies/production" -> "production".
func extractProfileName(policyRoot, paramPath string) string {
	// Remove trailing slash from policyRoot if present
	policyRoot = strings.TrimSuffix(policyRoot, "/")

	// Remove the policy root prefix and leading slash
	name := strings.TrimPrefix(paramPath, policyRoot)
	name = strings.TrimPrefix(name, "/")

	return name
}
