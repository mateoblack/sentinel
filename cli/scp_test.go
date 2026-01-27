package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/byteness/aws-vault/v7/deploy"
)

// ============================================================================
// Mock Client for SCP Deploy Tests
// ============================================================================

// mockSCPDeployClient implements organizationsDeployAPI for testing.
type mockSCPDeployClient struct {
	ListPoliciesFunc                     func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
	DescribePolicyFunc                   func(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
	ListTargetsForPolicyFunc             func(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error)
	CreatePolicyFunc                     func(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error)
	AttachPolicyFunc                     func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error)
	UpdatePolicyFunc                     func(ctx context.Context, params *organizations.UpdatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error)
	ListRootsFunc                        func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParentFunc func(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
}

func (m *mockSCPDeployClient) ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if m.ListPoliciesFunc != nil {
		return m.ListPoliciesFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListPolicies not implemented")
}

func (m *mockSCPDeployClient) DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if m.DescribePolicyFunc != nil {
		return m.DescribePolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribePolicy not implemented")
}

func (m *mockSCPDeployClient) ListTargetsForPolicy(ctx context.Context, params *organizations.ListTargetsForPolicyInput, optFns ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	if m.ListTargetsForPolicyFunc != nil {
		return m.ListTargetsForPolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListTargetsForPolicy not implemented")
}

func (m *mockSCPDeployClient) CreatePolicy(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error) {
	if m.CreatePolicyFunc != nil {
		return m.CreatePolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("CreatePolicy not implemented")
}

func (m *mockSCPDeployClient) AttachPolicy(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
	if m.AttachPolicyFunc != nil {
		return m.AttachPolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("AttachPolicy not implemented")
}

func (m *mockSCPDeployClient) UpdatePolicy(ctx context.Context, params *organizations.UpdatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error) {
	if m.UpdatePolicyFunc != nil {
		return m.UpdatePolicyFunc(ctx, params, optFns...)
	}
	return nil, errors.New("UpdatePolicy not implemented")
}

func (m *mockSCPDeployClient) ListRoots(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	if m.ListRootsFunc != nil {
		return m.ListRootsFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListRoots not implemented")
}

func (m *mockSCPDeployClient) ListOrganizationalUnitsForParent(ctx context.Context, params *organizations.ListOrganizationalUnitsForParentInput, optFns ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	if m.ListOrganizationalUnitsForParentFunc != nil {
		return m.ListOrganizationalUnitsForParentFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListOrganizationalUnitsForParent not implemented")
}

// createMockDeployer creates a deployer with mock client for testing.
func createMockDeployer(client *mockSCPDeployClient) *deploy.SCPDeployer {
	return deploy.NewSCPDeployerWithClient(client)
}

// ============================================================================
// SCP Deploy CLI Tests
// ============================================================================

func TestSCPDeployCommand_DryRun(t *testing.T) {
	ctx := context.Background()

	client := &mockSCPDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-abcd")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{},
			}, nil
		},
	}

	deployer := createMockDeployer(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPDeployCommandInput{
		DryRun:   true,
		Deployer: deployer,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SCPDeployCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0 for dry-run, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Dry Run") {
		t.Error("expected output to contain 'Dry Run'")
	}
	if !strings.Contains(output, deploy.SentinelSCPName) {
		t.Error("expected output to contain policy name")
	}
	if !strings.Contains(output, "sts:SourceIdentity") {
		t.Error("expected output to contain policy content with SourceIdentity")
	}
	if !strings.Contains(output, "Would create new policy") {
		t.Error("expected output to indicate policy would be created")
	}
}

func TestSCPDeployCommand_DryRunExistingPolicy(t *testing.T) {
	ctx := context.Background()

	client := &mockSCPDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-abcd")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{Id: aws.String("p-existing123"), Name: aws.String(deploy.SentinelSCPName)},
				},
			}, nil
		},
	}

	deployer := createMockDeployer(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPDeployCommandInput{
		DryRun:   true,
		Deployer: deployer,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SCPDeployCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 for dry-run, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Would update existing policy") {
		t.Error("expected output to indicate policy would be updated")
	}
}

func TestSCPDeployCommand_ConfirmationPrompt(t *testing.T) {
	ctx := context.Background()

	client := &mockSCPDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-abcd")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{}}, nil
		},
	}

	deployer := createMockDeployer(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	stdin, _ := os.CreateTemp("", "stdin")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())
	defer os.Remove(stdin.Name())

	// Simulate user typing "n" (cancel)
	stdin.WriteString("n\n")
	stdin.Seek(0, 0)

	input := SCPDeployCommandInput{
		Deployer: deployer,
		Stdout:   stdout,
		Stderr:   stderr,
		Stdin:    stdin,
	}

	exitCode := SCPDeployCommand(ctx, input)

	if exitCode != 2 {
		t.Errorf("expected exit code 2 for user cancel, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Cancelled") {
		t.Error("expected output to contain 'Cancelled'")
	}
}

func TestSCPDeployCommand_ForceBypassesConfirmation(t *testing.T) {
	ctx := context.Background()

	deployed := false
	client := &mockSCPDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-abcd")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{}}, nil
		},
		CreatePolicyFunc: func(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error) {
			deployed = true
			return &organizations.CreatePolicyOutput{
				Policy: &orgtypes.Policy{
					PolicySummary: &orgtypes.PolicySummary{
						Id:  aws.String("p-new123"),
						Arn: aws.String("arn:aws:organizations::123456789012:policy/o-xxxxx/service_control_policy/p-new123"),
					},
				},
			}, nil
		},
		AttachPolicyFunc: func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
			return &organizations.AttachPolicyOutput{}, nil
		},
	}

	deployer := createMockDeployer(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPDeployCommandInput{
		Force:    true, // Skip confirmation
		Deployer: deployer,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SCPDeployCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if !deployed {
		t.Error("expected policy to be deployed with --force")
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "SCP deployed successfully") {
		t.Error("expected success message")
	}
	if !strings.Contains(output, "p-new123") {
		t.Error("expected output to contain policy ID")
	}
}

func TestSCPDeployCommand_SuccessfulDeployToRoot(t *testing.T) {
	ctx := context.Background()

	attachedTo := ""
	client := &mockSCPDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-xyz789")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{}}, nil
		},
		CreatePolicyFunc: func(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error) {
			return &organizations.CreatePolicyOutput{
				Policy: &orgtypes.Policy{
					PolicySummary: &orgtypes.PolicySummary{
						Id:  aws.String("p-created"),
						Arn: aws.String("arn:aws:organizations::123456789012:policy/o-xxxxx/service_control_policy/p-created"),
					},
				},
			}, nil
		},
		AttachPolicyFunc: func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
			attachedTo = *params.TargetId
			return &organizations.AttachPolicyOutput{}, nil
		},
	}

	deployer := createMockDeployer(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPDeployCommandInput{
		Force:    true,
		Deployer: deployer,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SCPDeployCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if attachedTo != "r-xyz789" {
		t.Errorf("expected attachment to root r-xyz789, got %s", attachedTo)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "created new policy") {
		t.Error("expected output to mention created new policy")
	}
}

func TestSCPDeployCommand_SuccessfulDeployToOU(t *testing.T) {
	ctx := context.Background()

	attachedTo := ""
	client := &mockSCPDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-xyz789")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{Policies: []orgtypes.PolicySummary{}}, nil
		},
		CreatePolicyFunc: func(ctx context.Context, params *organizations.CreatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.CreatePolicyOutput, error) {
			return &organizations.CreatePolicyOutput{
				Policy: &orgtypes.Policy{
					PolicySummary: &orgtypes.PolicySummary{
						Id:  aws.String("p-created"),
						Arn: aws.String("arn:aws:organizations::123456789012:policy/o-xxxxx/service_control_policy/p-created"),
					},
				},
			}, nil
		},
		AttachPolicyFunc: func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
			attachedTo = *params.TargetId
			return &organizations.AttachPolicyOutput{}, nil
		},
	}

	deployer := createMockDeployer(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPDeployCommandInput{
		Force:    true,
		TargetOU: "ou-production-123",
		Deployer: deployer,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SCPDeployCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if attachedTo != "ou-production-123" {
		t.Errorf("expected attachment to ou-production-123, got %s", attachedTo)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "ou-production-123") {
		t.Error("expected output to show target OU")
	}
}

func TestSCPDeployCommand_PermissionValidationFailure(t *testing.T) {
	ctx := context.Background()

	client := &mockSCPDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return nil, errors.New("AccessDeniedException: User not authorized to perform organizations:ListRoots")
		},
	}

	deployer := createMockDeployer(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPDeployCommandInput{
		Force:    true,
		Deployer: deployer,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SCPDeployCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for permission failure, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	output := buf.String()

	if !strings.Contains(output, "Permission denied") && !strings.Contains(output, "management account") {
		t.Error("expected error message about permissions or management account")
	}
}

func TestSCPDeployCommand_NotInOrganization(t *testing.T) {
	ctx := context.Background()

	client := &mockSCPDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return nil, errors.New("AWSOrganizationsNotInUseException: Account is not a member of an organization")
		},
	}

	deployer := createMockDeployer(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPDeployCommandInput{
		Force:    true,
		Deployer: deployer,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SCPDeployCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for not in organization, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	output := buf.String()

	if !strings.Contains(output, "not part of an AWS Organization") {
		t.Error("expected error message about not being in organization")
	}
}

func TestSCPDeployCommand_UpdateExistingPolicy(t *testing.T) {
	ctx := context.Background()

	updated := false
	client := &mockSCPDeployClient{
		ListRootsFunc: func(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
			return &organizations.ListRootsOutput{
				Roots: []orgtypes.Root{
					{Id: aws.String("r-xyz789")},
				},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{Id: aws.String("p-existing456"), Name: aws.String(deploy.SentinelSCPName)},
				},
			}, nil
		},
		UpdatePolicyFunc: func(ctx context.Context, params *organizations.UpdatePolicyInput, optFns ...func(*organizations.Options)) (*organizations.UpdatePolicyOutput, error) {
			updated = true
			return &organizations.UpdatePolicyOutput{
				Policy: &orgtypes.Policy{
					PolicySummary: &orgtypes.PolicySummary{
						Id:  aws.String("p-existing456"),
						Arn: aws.String("arn:aws:organizations::123456789012:policy/o-xxxxx/service_control_policy/p-existing456"),
					},
				},
			}, nil
		},
		AttachPolicyFunc: func(ctx context.Context, params *organizations.AttachPolicyInput, optFns ...func(*organizations.Options)) (*organizations.AttachPolicyOutput, error) {
			return &organizations.AttachPolicyOutput{}, nil
		},
	}

	deployer := createMockDeployer(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := SCPDeployCommandInput{
		Force:    true,
		Deployer: deployer,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := SCPDeployCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if !updated {
		t.Error("expected UpdatePolicy to be called for existing policy")
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "updated existing policy") {
		t.Error("expected output to mention updated existing policy")
	}
}
