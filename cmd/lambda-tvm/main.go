// Package main is the entry point for the Lambda TVM.
package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	tvmhandler "github.com/byteness/aws-vault/v7/lambda"
)

// Version is set at build time via ldflags
var Version = "dev"

// Global router (initialized lazily)
var router *tvmhandler.Router

func main() {
	lambda.Start(handleRequest)
}

// handleRequest routes API Gateway requests to appropriate handlers.
// Router is initialized lazily on first request for cold start optimization.
func handleRequest(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// Lazy-initialize router on first request
	if router == nil {
		var err error
		router, err = initRouter(ctx)
		if err != nil {
			log.Printf("ERROR: Failed to initialize router: %v", err)
			return tvmhandler.ErrorResponse(500, "INIT_ERROR", "Failed to initialize handler")
		}
	}

	return router.Route(ctx, req)
}

// initRouter creates the Router with handler and profile discovery.
func initRouter(ctx context.Context) (*tvmhandler.Router, error) {
	// Load config from environment
	cfg, err := tvmhandler.LoadConfigFromEnv(ctx)
	if err != nil {
		return nil, err
	}

	// Create credential handler
	handler := tvmhandler.NewHandler(cfg)

	// Create profile discovery if policy root is configured
	var profiler *tvmhandler.ProfileDiscovery
	if cfg.PolicyRoot != "" {
		awsCfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			log.Printf("Warning: failed to create SSM client for profile discovery: %v", err)
		} else {
			ssmClient := ssm.NewFromConfig(awsCfg)
			profiler = tvmhandler.NewProfileDiscovery(ssmClient, cfg.PolicyRoot)
		}
	}

	return tvmhandler.NewRouter(handler, profiler), nil
}
