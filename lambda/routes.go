// Package lambda provides the Lambda handler for the Token Vending Machine (TVM).
package lambda

import (
	"context"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// Router dispatches API Gateway requests to appropriate handlers based on path.
// Supports:
//   - GET /           -> credential vending (profile query param required)
//   - POST /          -> credential vending (profile query param required)
//   - GET /profiles   -> profile discovery
type Router struct {
	handler  *Handler
	profiler *ProfileDiscovery
}

// NewRouter creates a new Router with the given handler and profiler.
func NewRouter(handler *Handler, profiler *ProfileDiscovery) *Router {
	return &Router{
		handler:  handler,
		profiler: profiler,
	}
}

// Route handles an API Gateway v2 HTTP request and routes to appropriate handler.
func (r *Router) Route(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Normalize path (remove trailing slash)
	path := strings.TrimSuffix(req.RawPath, "/")
	if path == "" {
		path = "/"
	}

	// Route based on path
	switch path {
	case "/", "":
		// Credential vending endpoint
		return r.handler.HandleRequest(ctx, req)
	case "/profiles":
		// Profile discovery endpoint
		if r.profiler == nil {
			return errorResponse(http.StatusNotImplemented, "NOT_IMPLEMENTED",
				"Profile discovery is not configured")
		}
		return r.profiler.HandleRequest(ctx, req)
	default:
		return errorResponse(http.StatusNotFound, "NOT_FOUND",
			"Unknown path: "+path)
	}
}
