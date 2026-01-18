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
	sentinelerrors "github.com/byteness/aws-vault/v7/errors"
)

// ErrPolicyNotFound is returned when the requested policy parameter
// does not exist in SSM Parameter Store.
var ErrPolicyNotFound = errors.New("policy not found")

// SSMAPI defines the SSM operations used by Loader.
// This interface enables testing with mock implementations.
type SSMAPI interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// Loader fetches policies from AWS SSM Parameter Store.
type Loader struct {
	client SSMAPI
}

// NewLoader creates a new Loader using the provided AWS configuration.
// The caller is responsible for providing a properly configured aws.Config
// (typically via config.LoadDefaultConfig).
func NewLoader(cfg aws.Config) *Loader {
	return &Loader{
		client: ssm.NewFromConfig(cfg),
	}
}

// NewLoaderWithClient creates a Loader with a custom SSM client.
// This is primarily used for testing with mock clients.
func NewLoaderWithClient(client SSMAPI) *Loader {
	return &Loader{
		client: client,
	}
}

// Load fetches a policy from SSM Parameter Store by parameter name.
// It returns ErrPolicyNotFound (wrapped) if the parameter does not exist.
// The parameter is fetched with decryption enabled to support SecureString parameters.
// Returns a SentinelError with actionable suggestions for common SSM failures.
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
		// Wrap SSM error with context and actionable suggestion
		return nil, sentinelerrors.WrapSSMError(err, parameterName)
	}

	return ParsePolicy([]byte(*output.Parameter.Value))
}
