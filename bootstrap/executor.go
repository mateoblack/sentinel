package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ssmWriterAPI defines the SSM write operations used by Executor.
// This interface enables testing with mock implementations.
type ssmWriterAPI interface {
	PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// Executor applies a BootstrapPlan by creating or updating SSM parameters.
// It provides terraform apply-style execution after planning.
type Executor struct {
	ssm ssmWriterAPI
}

// NewExecutor creates a new Executor using the provided AWS configuration.
func NewExecutor(cfg aws.Config) *Executor {
	return &Executor{
		ssm: ssm.NewFromConfig(cfg),
	}
}

// newExecutorWithClient creates an Executor with a custom SSM client.
// This is primarily used for testing with mock clients.
func newExecutorWithClient(client ssmWriterAPI) *Executor {
	return &Executor{
		ssm: client,
	}
}

// ApplyError represents a failed parameter operation.
type ApplyError struct {
	// Name is the parameter name that failed.
	Name string `json:"name"`
	// Error is the error message.
	Error string `json:"error"`
}

// ApplyResult contains the results of applying a bootstrap plan.
type ApplyResult struct {
	// Created contains names of successfully created parameters.
	Created []string `json:"created"`
	// Updated contains names of successfully updated parameters.
	Updated []string `json:"updated"`
	// Skipped contains names of skipped parameters.
	Skipped []string `json:"skipped"`
	// Failed contains parameters that failed to create or update.
	Failed []ApplyError `json:"failed"`
}

// Apply executes a BootstrapPlan, creating or updating SSM parameters.
// It continues processing on individual failures, collecting all errors in the result.
func (e *Executor) Apply(ctx context.Context, plan *BootstrapPlan) (*ApplyResult, error) {
	result := &ApplyResult{
		Created: []string{},
		Updated: []string{},
		Skipped: []string{},
		Failed:  []ApplyError{},
	}

	for _, resource := range plan.Resources {
		// Skip non-SSM resources (IAM policies are not created via SSM)
		if resource.Type != ResourceTypeSSMParameter {
			result.Skipped = append(result.Skipped, resource.Name)
			continue
		}

		switch resource.State {
		case StateExists, StateSkip:
			result.Skipped = append(result.Skipped, resource.Name)

		case StateCreate:
			err := e.putParameter(ctx, resource.Name, "", false)
			if err != nil {
				result.Failed = append(result.Failed, ApplyError{
					Name:  resource.Name,
					Error: err.Error(),
				})
			} else {
				result.Created = append(result.Created, resource.Name)
			}

		case StateUpdate:
			err := e.putParameter(ctx, resource.Name, "", true)
			if err != nil {
				result.Failed = append(result.Failed, ApplyError{
					Name:  resource.Name,
					Error: err.Error(),
				})
			} else {
				result.Updated = append(result.Updated, resource.Name)
			}
		}
	}

	return result, nil
}

// putParameter creates or updates an SSM parameter.
func (e *Executor) putParameter(ctx context.Context, name, value string, overwrite bool) error {
	// Use empty policy placeholder if no value provided
	if value == "" {
		value = "# Sentinel policy placeholder\nversion: \"1\"\nrules: []\n"
	}

	_, err := e.ssm.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(name),
		Value:     aws.String(value),
		Type:      types.ParameterTypeString,
		Overwrite: aws.Bool(overwrite),
	})

	if err != nil {
		var alreadyExists *types.ParameterAlreadyExists
		if errors.As(err, &alreadyExists) {
			return fmt.Errorf("parameter already exists (possible race condition): %s", name)
		}
		return fmt.Errorf("SSM PutParameter failed: %w", err)
	}

	return nil
}
