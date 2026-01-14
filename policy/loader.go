// Package policy provides SSM-based policy loading for Sentinel.
// Policies are stored in AWS Systems Manager Parameter Store and
// fetched on demand using the Loader type.
package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ErrPolicyNotFound is returned when the requested policy parameter
// does not exist in SSM Parameter Store.
var ErrPolicyNotFound = errors.New("policy not found")

// Loader fetches policies from AWS SSM Parameter Store.
type Loader struct {
	client *ssm.Client
}

// NewLoader creates a new Loader using the provided AWS configuration.
// The caller is responsible for providing a properly configured aws.Config
// (typically via config.LoadDefaultConfig).
func NewLoader(cfg aws.Config) *Loader {
	return &Loader{
		client: ssm.NewFromConfig(cfg),
	}
}

// Load fetches a policy from SSM Parameter Store by parameter name.
// It returns ErrPolicyNotFound (wrapped) if the parameter does not exist.
// The parameter is fetched with decryption enabled to support SecureString parameters.
func (l *Loader) Load(ctx context.Context, parameterName string) (*Policy, error) {
	output, err := l.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(parameterName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		var notFound *types.ParameterNotFound
		if errors.As(err, &notFound) {
			return nil, fmt.Errorf("%s: %w", parameterName, ErrPolicyNotFound)
		}
		return nil, fmt.Errorf("ssm GetParameter: %w", err)
	}

	return ParsePolicy([]byte(*output.Parameter.Value))
}
