package lambda

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestRouter_Route_RootPath(t *testing.T) {
	// Create mock handler that returns success
	handler := &Handler{Config: &TVMConfig{}}
	router := NewRouter(handler, nil)

	tests := []struct {
		name string
		path string
	}{
		{"root with slash", "/"},
		{"root empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := events.APIGatewayV2HTTPRequest{
				RawPath: tt.path,
			}
			// Handler will fail due to missing config, but route is correct
			resp, _ := router.Route(context.Background(), req)
			// Verify it didn't return 404 (route was found)
			if resp.StatusCode == http.StatusNotFound {
				t.Errorf("expected route to be found for path %q", tt.path)
			}
		})
	}
}

func TestRouter_Route_ProfilesPath(t *testing.T) {
	handler := &Handler{Config: &TVMConfig{}}

	// Without profiler
	router := NewRouter(handler, nil)
	req := events.APIGatewayV2HTTPRequest{
		RawPath: "/profiles",
	}
	resp, _ := router.Route(context.Background(), req)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("expected 501 when profiler is nil, got %d", resp.StatusCode)
	}
}

func TestRouter_Route_UnknownPath(t *testing.T) {
	handler := &Handler{Config: &TVMConfig{}}
	router := NewRouter(handler, nil)

	req := events.APIGatewayV2HTTPRequest{
		RawPath: "/unknown",
	}
	resp, _ := router.Route(context.Background(), req)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown path, got %d", resp.StatusCode)
	}
}

func TestRouter_Route_TrailingSlash(t *testing.T) {
	handler := &Handler{Config: &TVMConfig{}}
	router := NewRouter(handler, nil)

	// /profiles/ should route to profiles (trailing slash removed)
	req := events.APIGatewayV2HTTPRequest{
		RawPath: "/profiles/",
	}
	resp, _ := router.Route(context.Background(), req)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("expected 501 for /profiles/ when profiler is nil, got %d", resp.StatusCode)
	}
}
