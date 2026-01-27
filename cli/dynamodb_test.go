package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/byteness/aws-vault/v7/deploy"
)

// ============================================================================
// Mock Client for DynamoDB Harden CLI Tests
// ============================================================================

// mockDynamoDBHardenCLIClient implements dynamodbHardenAPI for testing.
type mockDynamoDBHardenCLIClient struct {
	DescribeTableFunc             func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	DescribeContinuousBackupsFunc func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error)
	ListTablesFunc                func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	UpdateTableFunc               func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error)
	UpdateContinuousBackupsFunc   func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error)
}

func (m *mockDynamoDBHardenCLIClient) DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if m.DescribeTableFunc != nil {
		return m.DescribeTableFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribeTable not implemented")
}

func (m *mockDynamoDBHardenCLIClient) DescribeContinuousBackups(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	if m.DescribeContinuousBackupsFunc != nil {
		return m.DescribeContinuousBackupsFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DescribeContinuousBackups not implemented")
}

func (m *mockDynamoDBHardenCLIClient) ListTables(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	if m.ListTablesFunc != nil {
		return m.ListTablesFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ListTables not implemented")
}

func (m *mockDynamoDBHardenCLIClient) UpdateTable(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
	if m.UpdateTableFunc != nil {
		return m.UpdateTableFunc(ctx, params, optFns...)
	}
	return nil, errors.New("UpdateTable not implemented")
}

func (m *mockDynamoDBHardenCLIClient) UpdateContinuousBackups(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
	if m.UpdateContinuousBackupsFunc != nil {
		return m.UpdateContinuousBackupsFunc(ctx, params, optFns...)
	}
	return nil, errors.New("UpdateContinuousBackups not implemented")
}

// createMockHardener creates a hardener with mock client for testing.
func createMockHardener(client *mockDynamoDBHardenCLIClient) *deploy.DynamoDBHardener {
	return deploy.NewDynamoDBHardenerWithClient(client)
}

// ============================================================================
// DynamoDB Harden CLI Tests
// ============================================================================

func TestDynamoDBHardenCommand_AutoDiscovery(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{
					"sentinel-requests",
					"sentinel-sessions",
					"other-table",
				},
			}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Force:    true,
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Should only show sentinel- prefixed tables
	if !strings.Contains(output, "sentinel-requests") {
		t.Error("expected output to contain sentinel-requests")
	}
	if !strings.Contains(output, "sentinel-sessions") {
		t.Error("expected output to contain sentinel-sessions")
	}
	if strings.Contains(output, "other-table") {
		t.Error("expected output NOT to contain other-table")
	}
	if !strings.Contains(output, "2/2 tables hardened") {
		t.Error("expected output to show 2/2 success")
	}
}

func TestDynamoDBHardenCommand_ExplicitTables(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenCLIClient{
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Tables:   []string{"my-custom-table", "another-table"},
		Force:    true,
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "my-custom-table") {
		t.Error("expected output to contain my-custom-table")
	}
	if !strings.Contains(output, "another-table") {
		t.Error("expected output to contain another-table")
	}
}

func TestDynamoDBHardenCommand_ConfirmationPrompt(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"sentinel-requests"},
			}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	stdin, _ := os.CreateTemp("", "stdin")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())
	defer os.Remove(stdin.Name())

	// Simulate user typing "n" (cancel)
	stdin.WriteString("n\n")
	stdin.Seek(0, 0)

	input := DynamoDBHardenCommandInput{
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
		Stdin:    stdin,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

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

func TestDynamoDBHardenCommand_ForceBypassesConfirmation(t *testing.T) {
	ctx := context.Background()

	hardened := false
	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"sentinel-requests"},
			}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			hardened = true
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Force:    true, // Skip confirmation
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if !hardened {
		t.Error("expected table to be hardened with --force")
	}
}

func TestDynamoDBHardenCommand_NoPITR(t *testing.T) {
	ctx := context.Background()

	pitrCalled := false
	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"sentinel-requests"},
			}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			pitrCalled = true
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Force:    true,
		NoPITR:   true, // Skip PITR
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if pitrCalled {
		t.Error("expected PITR NOT to be enabled with --no-pitr")
	}
}

func TestDynamoDBHardenCommand_JSONOutput(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"sentinel-requests"},
			}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Force:      true,
		JSONOutput: true,
		Hardener:   hardener,
		Stdout:     stdout,
		Stderr:     stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Check JSON structure
	if !strings.Contains(output, `"tables"`) {
		t.Error("expected JSON output to contain 'tables' field")
	}
	if !strings.Contains(output, `"total"`) {
		t.Error("expected JSON output to contain 'total' field")
	}
	if !strings.Contains(output, `"succeeded"`) {
		t.Error("expected JSON output to contain 'succeeded' field")
	}
	if !strings.Contains(output, `"deletion_protection_changed": true`) {
		t.Error("expected JSON output to show deletion_protection_changed: true")
	}
	if !strings.Contains(output, `"pitr_changed": true`) {
		t.Error("expected JSON output to show pitr_changed: true")
	}
}

func TestDynamoDBHardenCommand_AllTablesAlreadyProtected(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"sentinel-requests", "sentinel-sessions"},
			}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(true), // Already enabled
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusEnabled, // Already enabled
					},
				},
			}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Force:    true,
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "already fully protected") {
		t.Error("expected output to indicate tables are already protected")
	}
}

func TestDynamoDBHardenCommand_PartialFailure(t *testing.T) {
	ctx := context.Background()

	callCount := 0
	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"sentinel-good", "sentinel-bad"},
			}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			callCount++
			if *params.TableName == "sentinel-bad" {
				return nil, errors.New("ValidationException: Table is in a state that does not allow update")
			}
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Force:    true,
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	// Should return 1 for partial failure
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for partial failure, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "1/2 tables hardened") {
		t.Error("expected output to show 1/2 success")
	}
}

func TestDynamoDBHardenCommand_NoTablesFound(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{}, // No tables
			}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Force:    true,
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 when no tables found, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "No Sentinel tables found") {
		t.Error("expected output to indicate no tables found")
	}
}

func TestDynamoDBHardenCommand_AccessDenied(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return nil, errors.New("AccessDeniedException: User not authorized to perform dynamodb:ListTables")
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Force:    true,
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for access denied, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	output := buf.String()

	if !strings.Contains(output, "Permission denied") {
		t.Error("expected error message about permission denied")
	}
}

func TestDynamoDBHardenCommand_CustomPrefix(t *testing.T) {
	ctx := context.Background()

	client := &mockDynamoDBHardenCLIClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{
					"myorg-sentinel-requests",
					"myorg-sentinel-sessions",
					"sentinel-requests", // Should not be included
				},
			}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &dbtypes.TableDescription{
					TableName:                 params.TableName,
					TableArn:                  aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/" + *params.TableName),
					DeletionProtectionEnabled: aws.Bool(false),
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &dbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &dbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: dbtypes.PointInTimeRecoveryStatusDisabled,
					},
				},
			}, nil
		},
		UpdateTableFunc: func(ctx context.Context, params *dynamodb.UpdateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateTableOutput, error) {
			return &dynamodb.UpdateTableOutput{}, nil
		},
		UpdateContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.UpdateContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateContinuousBackupsOutput, error) {
			return &dynamodb.UpdateContinuousBackupsOutput{}, nil
		},
	}

	hardener := createMockHardener(client)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := DynamoDBHardenCommandInput{
		Prefix:   "myorg-sentinel-",
		Force:    true,
		Hardener: hardener,
		Stdout:   stdout,
		Stderr:   stderr,
	}

	exitCode := DynamoDBHardenCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Should include myorg-sentinel- prefixed tables
	if !strings.Contains(output, "myorg-sentinel-requests") {
		t.Error("expected output to contain myorg-sentinel-requests")
	}
	// Should show 2/2 (only the myorg-sentinel- tables)
	if !strings.Contains(output, "2/2 tables hardened") {
		t.Error("expected output to show 2/2 success")
	}
}
