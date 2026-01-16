package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ssmAPI defines the SSM operations used by Planner.
// This interface enables testing with mock implementations.
type ssmAPI interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// Planner checks AWS SSM for existing parameters and produces a BootstrapPlan.
// It enables dry-run workflow (terraform plan-style) before making changes.
type Planner struct {
	ssm ssmAPI
}

// NewPlanner creates a new Planner using the provided AWS configuration.
func NewPlanner(cfg aws.Config) *Planner {
	return &Planner{
		ssm: ssm.NewFromConfig(cfg),
	}
}

// newPlannerWithClient creates a Planner with a custom SSM client.
// This is primarily used for testing with mock clients.
func newPlannerWithClient(client ssmAPI) *Planner {
	return &Planner{
		ssm: client,
	}
}

// Plan checks SSM for existing parameters and produces a BootstrapPlan.
// It validates the config first, then checks each profile's parameter existence.
func (p *Planner) Plan(ctx context.Context, config *BootstrapConfig) (*BootstrapPlan, error) {
	// Validate config first
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	var resources []ResourceSpec

	// Check each profile's SSM parameter
	for _, profile := range config.Profiles {
		// Determine parameter name
		paramName := profile.PolicyParameterName
		if paramName == "" {
			paramName = DefaultPolicyParameterName(config.PolicyRoot, profile.Name)
		}

		// Check if parameter exists
		exists, version, err := p.checkSSMParameter(ctx, paramName)
		if err != nil {
			return nil, fmt.Errorf("check parameter %s: %w", paramName, err)
		}

		// Build resource spec
		spec := ResourceSpec{
			Type:        ResourceTypeSSMParameter,
			Name:        paramName,
			Description: fmt.Sprintf("Policy parameter for profile %s", profile.Name),
		}

		if exists {
			spec.State = StateExists
			spec.CurrentVersion = version
		} else {
			spec.State = StateCreate
		}

		resources = append(resources, spec)
	}

	// Add IAM policy document specs if requested
	if config.GenerateIAMPolicies {
		resources = append(resources,
			ResourceSpec{
				Type:        ResourceTypeIAMPolicy,
				Name:        IAMPolicyName("Policy", "Reader"),
				State:       StateCreate,
				Description: "IAM policy document for read-only access to Sentinel policies",
			},
			ResourceSpec{
				Type:        ResourceTypeIAMPolicy,
				Name:        IAMPolicyName("Policy", "Admin"),
				State:       StateCreate,
				Description: "IAM policy document for administrative access to Sentinel policies",
			},
		)
	}

	// Build plan
	plan := &BootstrapPlan{
		Config:      *config,
		Resources:   resources,
		GeneratedAt: time.Now(),
	}

	// Compute summary
	plan.Summary.Compute(resources)

	return plan, nil
}

// checkSSMParameter checks if an SSM parameter exists.
// Returns (exists, version, error).
func (p *Planner) checkSSMParameter(ctx context.Context, paramName string) (bool, string, error) {
	output, err := p.ssm.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(paramName),
	})
	if err != nil {
		var notFound *types.ParameterNotFound
		if errors.As(err, &notFound) {
			return false, "", nil
		}
		return false, "", err
	}

	// Extract version from response
	version := ""
	if output.Parameter != nil && output.Parameter.Version != 0 {
		version = fmt.Sprintf("%d", output.Parameter.Version)
	}

	return true, version, nil
}
