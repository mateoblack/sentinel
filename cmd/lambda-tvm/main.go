// Package main is the entry point for the Lambda TVM.
package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	tvmhandler "github.com/byteness/aws-vault/v7/lambda"
)

// Version is set at build time via ldflags
var Version = "dev"

func main() {
	handler := tvmhandler.NewHandler()
	lambda.Start(handler.HandleRequest)
}
