package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/byteness/aws-vault/v7/deploy"
)

// ============================================================================
// Mock Clients for Monitoring CLI Tests
// ============================================================================

// mockCloudWatchAlarmsClientCLI implements cloudwatchAlarmsAPI for testing.
type mockCloudWatchAlarmsClientCLI struct {
	PutMetricAlarmFunc func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error)
	DescribeAlarmsFunc func(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

func (m *mockCloudWatchAlarmsClientCLI) PutMetricAlarm(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
	if m.PutMetricAlarmFunc != nil {
		return m.PutMetricAlarmFunc(ctx, params, optFns...)
	}
	return &cloudwatch.PutMetricAlarmOutput{}, nil
}

func (m *mockCloudWatchAlarmsClientCLI) DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	if m.DescribeAlarmsFunc != nil {
		return m.DescribeAlarmsFunc(ctx, params, optFns...)
	}
	return &cloudwatch.DescribeAlarmsOutput{}, nil
}

// mockSNSClientCLI implements snsAPI for testing.
type mockSNSClientCLI struct {
	CreateTopicFunc func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error)
	SubscribeFunc   func(ctx context.Context, params *sns.SubscribeInput, optFns ...func(*sns.Options)) (*sns.SubscribeOutput, error)
}

func (m *mockSNSClientCLI) CreateTopic(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
	if m.CreateTopicFunc != nil {
		return m.CreateTopicFunc(ctx, params, optFns...)
	}
	return &sns.CreateTopicOutput{
		TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts"),
	}, nil
}

func (m *mockSNSClientCLI) Subscribe(ctx context.Context, params *sns.SubscribeInput, optFns ...func(*sns.Options)) (*sns.SubscribeOutput, error) {
	if m.SubscribeFunc != nil {
		return m.SubscribeFunc(ctx, params, optFns...)
	}
	return &sns.SubscribeOutput{
		SubscriptionArn: aws.String("pending confirmation"),
	}, nil
}

// mockCloudWatchLogsClientCLI implements cloudwatchLogsMonitorAPI for testing.
type mockCloudWatchLogsClientCLI struct {
	PutMetricFilterFunc       func(ctx context.Context, params *cloudwatchlogs.PutMetricFilterInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutMetricFilterOutput, error)
	DescribeMetricFiltersFunc func(ctx context.Context, params *cloudwatchlogs.DescribeMetricFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error)
}

func (m *mockCloudWatchLogsClientCLI) PutMetricFilter(ctx context.Context, params *cloudwatchlogs.PutMetricFilterInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutMetricFilterOutput, error) {
	if m.PutMetricFilterFunc != nil {
		return m.PutMetricFilterFunc(ctx, params, optFns...)
	}
	return &cloudwatchlogs.PutMetricFilterOutput{}, nil
}

func (m *mockCloudWatchLogsClientCLI) DescribeMetricFilters(ctx context.Context, params *cloudwatchlogs.DescribeMetricFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error) {
	if m.DescribeMetricFiltersFunc != nil {
		return m.DescribeMetricFiltersFunc(ctx, params, optFns...)
	}
	return &cloudwatchlogs.DescribeMetricFiltersOutput{}, nil
}

// createMockMonitoringSetup creates a MonitoringSetup with mock clients for testing.
func createMockMonitoringSetup(cw *mockCloudWatchAlarmsClientCLI, snsClient *mockSNSClientCLI, cwLogs *mockCloudWatchLogsClientCLI) *deploy.MonitoringSetup {
	return deploy.NewMonitoringSetupWithClients(cw, snsClient, cwLogs)
}

// ============================================================================
// Monitoring Setup CLI Tests
// ============================================================================

func TestMonitoringSetupCommand_AllDefaultAlarms(t *testing.T) {
	ctx := context.Background()

	alarmsCreated := []string{}
	filtersCreated := []string{}

	cwClient := &mockCloudWatchAlarmsClientCLI{
		PutMetricAlarmFunc: func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
			alarmsCreated = append(alarmsCreated, *params.AlarmName)
			return &cloudwatch.PutMetricAlarmOutput{}, nil
		},
	}

	snsClient := &mockSNSClientCLI{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			return &sns.CreateTopicOutput{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts"),
			}, nil
		},
	}

	cwLogsClient := &mockCloudWatchLogsClientCLI{
		PutMetricFilterFunc: func(ctx context.Context, params *cloudwatchlogs.PutMetricFilterInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutMetricFilterOutput, error) {
			filtersCreated = append(filtersCreated, *params.FilterName)
			return &cloudwatchlogs.PutMetricFilterOutput{}, nil
		},
	}

	setup := createMockMonitoringSetup(cwClient, snsClient, cwLogsClient)

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := MonitoringSetupCommandInput{
		CloudTrailLogGroup: "aws-cloudtrail-logs",
		SNSTopicName:       "sentinel-security-alerts",
		Force:              true,
		Setup:              setup,
		Stdout:             stdout,
		Stderr:             stderr,
	}

	exitCode := MonitoringSetupCommand(ctx, input)

	if exitCode != 0 {
		stderr.Seek(0, 0)
		var buf bytes.Buffer
		buf.ReadFrom(stderr)
		t.Logf("stderr: %s", buf.String())
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Should create all 4 alarms
	if len(alarmsCreated) != 4 {
		t.Errorf("expected 4 alarms created, got %d: %v", len(alarmsCreated), alarmsCreated)
	}

	// Should create all 4 filters
	if len(filtersCreated) != 4 {
		t.Errorf("expected 4 filters created, got %d: %v", len(filtersCreated), filtersCreated)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Check output contains key information
	if !strings.Contains(output, "SNS topic created") {
		t.Error("expected output to show SNS topic creation")
	}
	if !strings.Contains(output, "4 alarms created") {
		t.Error("expected output to show 4 alarms created")
	}
}

func TestMonitoringSetupCommand_SpecificAlarmSelection(t *testing.T) {
	ctx := context.Background()

	alarmsCreated := []string{}

	cwClient := &mockCloudWatchAlarmsClientCLI{
		PutMetricAlarmFunc: func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
			alarmsCreated = append(alarmsCreated, *params.AlarmName)
			return &cloudwatch.PutMetricAlarmOutput{}, nil
		},
	}

	setup := createMockMonitoringSetup(cwClient, &mockSNSClientCLI{}, &mockCloudWatchLogsClientCLI{})

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := MonitoringSetupCommandInput{
		CloudTrailLogGroup: "aws-cloudtrail-logs",
		Alarms:             []string{"kms", "dynamodb"}, // Only 2 alarms
		Force:              true,
		Setup:              setup,
		Stdout:             stdout,
		Stderr:             stderr,
	}

	exitCode := MonitoringSetupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Should only create 2 alarms
	if len(alarmsCreated) != 2 {
		t.Errorf("expected 2 alarms created, got %d: %v", len(alarmsCreated), alarmsCreated)
	}

	// Check that correct alarms were created
	hasKMS := false
	hasDynamoDB := false
	for _, name := range alarmsCreated {
		if name == "sentinel-kms-key-changes" {
			hasKMS = true
		}
		if name == "sentinel-dynamodb-delete" {
			hasDynamoDB = true
		}
	}
	if !hasKMS {
		t.Error("expected kms alarm to be created")
	}
	if !hasDynamoDB {
		t.Error("expected dynamodb alarm to be created")
	}
}

func TestMonitoringSetupCommand_WithEmailSubscription(t *testing.T) {
	ctx := context.Background()

	emailSubscribed := ""

	snsClient := &mockSNSClientCLI{
		SubscribeFunc: func(ctx context.Context, params *sns.SubscribeInput, optFns ...func(*sns.Options)) (*sns.SubscribeOutput, error) {
			emailSubscribed = *params.Endpoint
			return &sns.SubscribeOutput{}, nil
		},
	}

	setup := createMockMonitoringSetup(&mockCloudWatchAlarmsClientCLI{}, snsClient, &mockCloudWatchLogsClientCLI{})

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := MonitoringSetupCommandInput{
		CloudTrailLogGroup: "aws-cloudtrail-logs",
		Email:              "security@example.com",
		Force:              true,
		Setup:              setup,
		Stdout:             stdout,
		Stderr:             stderr,
	}

	exitCode := MonitoringSetupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if emailSubscribed != "security@example.com" {
		t.Errorf("expected email subscription for security@example.com, got %s", emailSubscribed)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Email subscription requested") {
		t.Error("expected output to mention email subscription")
	}
	if !strings.Contains(output, "Check inbox and confirm subscription") {
		t.Error("expected output to mention confirmation requirement")
	}
}

func TestMonitoringSetupCommand_DryRun(t *testing.T) {
	ctx := context.Background()

	alarmsCreated := []string{}

	cwClient := &mockCloudWatchAlarmsClientCLI{
		PutMetricAlarmFunc: func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
			alarmsCreated = append(alarmsCreated, *params.AlarmName)
			return &cloudwatch.PutMetricAlarmOutput{}, nil
		},
	}

	setup := createMockMonitoringSetup(cwClient, &mockSNSClientCLI{}, &mockCloudWatchLogsClientCLI{})

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := MonitoringSetupCommandInput{
		CloudTrailLogGroup: "aws-cloudtrail-logs",
		DryRun:             true,
		Setup:              setup,
		Stdout:             stdout,
		Stderr:             stderr,
	}

	exitCode := MonitoringSetupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 for dry-run, got %d", exitCode)
	}

	// Should NOT create any alarms in dry-run mode
	if len(alarmsCreated) != 0 {
		t.Errorf("expected 0 alarms created in dry-run, got %d", len(alarmsCreated))
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Dry-run") || !strings.Contains(output, "no resources created") {
		t.Error("expected output to indicate dry-run mode")
	}
}

func TestMonitoringSetupCommand_ConfirmationPrompt(t *testing.T) {
	ctx := context.Background()

	alarmsCreated := false

	cwClient := &mockCloudWatchAlarmsClientCLI{
		PutMetricAlarmFunc: func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
			alarmsCreated = true
			return &cloudwatch.PutMetricAlarmOutput{}, nil
		},
	}

	setup := createMockMonitoringSetup(cwClient, &mockSNSClientCLI{}, &mockCloudWatchLogsClientCLI{})

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	stdin, _ := os.CreateTemp("", "stdin")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())
	defer os.Remove(stdin.Name())

	// Simulate user typing "n" (cancel)
	stdin.WriteString("n\n")
	stdin.Seek(0, 0)

	input := MonitoringSetupCommandInput{
		CloudTrailLogGroup: "aws-cloudtrail-logs",
		Setup:              setup,
		Stdout:             stdout,
		Stderr:             stderr,
		Stdin:              stdin,
	}

	exitCode := MonitoringSetupCommand(ctx, input)

	if exitCode != 2 {
		t.Errorf("expected exit code 2 for user cancel, got %d", exitCode)
	}

	if alarmsCreated {
		t.Error("expected no alarms created when user cancels")
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	if !strings.Contains(output, "Cancelled") {
		t.Error("expected output to contain 'Cancelled'")
	}
}

func TestMonitoringSetupCommand_ForceBypassesConfirmation(t *testing.T) {
	ctx := context.Background()

	alarmsCreated := false

	cwClient := &mockCloudWatchAlarmsClientCLI{
		PutMetricAlarmFunc: func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
			alarmsCreated = true
			return &cloudwatch.PutMetricAlarmOutput{}, nil
		},
	}

	setup := createMockMonitoringSetup(cwClient, &mockSNSClientCLI{}, &mockCloudWatchLogsClientCLI{})

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := MonitoringSetupCommandInput{
		CloudTrailLogGroup: "aws-cloudtrail-logs",
		Force:              true, // Skip confirmation
		Setup:              setup,
		Stdout:             stdout,
		Stderr:             stderr,
	}

	exitCode := MonitoringSetupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if !alarmsCreated {
		t.Error("expected alarms to be created with --force")
	}
}

func TestMonitoringSetupCommand_JSONOutput(t *testing.T) {
	ctx := context.Background()

	setup := createMockMonitoringSetup(&mockCloudWatchAlarmsClientCLI{}, &mockSNSClientCLI{}, &mockCloudWatchLogsClientCLI{})

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := MonitoringSetupCommandInput{
		CloudTrailLogGroup: "aws-cloudtrail-logs",
		Email:              "security@example.com",
		Force:              true,
		JSONOutput:         true,
		Setup:              setup,
		Stdout:             stdout,
		Stderr:             stderr,
	}

	exitCode := MonitoringSetupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Check JSON structure
	if !strings.Contains(output, `"sns_topic_arn"`) {
		t.Error("expected JSON output to contain 'sns_topic_arn' field")
	}
	if !strings.Contains(output, `"alarms_created"`) {
		t.Error("expected JSON output to contain 'alarms_created' field")
	}
	if !strings.Contains(output, `"filters_created"`) {
		t.Error("expected JSON output to contain 'filters_created' field")
	}
	if !strings.Contains(output, `"email_subscribed"`) {
		t.Error("expected JSON output to contain 'email_subscribed' field")
	}
	if !strings.Contains(output, "security@example.com") {
		t.Error("expected JSON output to contain email address")
	}
}

func TestMonitoringSetupCommand_AccessDenied(t *testing.T) {
	ctx := context.Background()

	snsClient := &mockSNSClientCLI{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			return nil, errors.New("AccessDeniedException: User is not authorized to perform sns:CreateTopic")
		},
	}

	setup := createMockMonitoringSetup(&mockCloudWatchAlarmsClientCLI{}, snsClient, &mockCloudWatchLogsClientCLI{})

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := MonitoringSetupCommandInput{
		CloudTrailLogGroup: "aws-cloudtrail-logs",
		Force:              true,
		Setup:              setup,
		Stdout:             stdout,
		Stderr:             stderr,
	}

	exitCode := MonitoringSetupCommand(ctx, input)

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for access denied, got %d", exitCode)
	}

	stderr.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stderr)
	output := buf.String()

	if !strings.Contains(output, "Permission denied") || !strings.Contains(output, "Error") {
		t.Error("expected error message about permission denied")
	}
}

func TestMonitoringSetupCommand_PreviewShowsCorrectInfo(t *testing.T) {
	ctx := context.Background()

	setup := createMockMonitoringSetup(&mockCloudWatchAlarmsClientCLI{}, &mockSNSClientCLI{}, &mockCloudWatchLogsClientCLI{})

	stdout, _ := os.CreateTemp("", "stdout")
	stderr, _ := os.CreateTemp("", "stderr")
	defer os.Remove(stdout.Name())
	defer os.Remove(stderr.Name())

	input := MonitoringSetupCommandInput{
		CloudTrailLogGroup: "my-cloudtrail-logs",
		SNSTopicName:       "my-alerts-topic",
		Email:              "admin@example.com",
		DryRun:             true,
		Setup:              setup,
		Stdout:             stdout,
		Stderr:             stderr,
	}

	exitCode := MonitoringSetupCommand(ctx, input)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	stdout.Seek(0, 0)
	var buf bytes.Buffer
	buf.ReadFrom(stdout)
	output := buf.String()

	// Check preview contains all expected information
	if !strings.Contains(output, "my-cloudtrail-logs") {
		t.Error("expected preview to show CloudTrail log group name")
	}
	if !strings.Contains(output, "my-alerts-topic") {
		t.Error("expected preview to show SNS topic name")
	}
	if !strings.Contains(output, "admin@example.com") {
		t.Error("expected preview to show email address")
	}
	if !strings.Contains(output, "Alarms to create (4)") {
		t.Error("expected preview to show alarm count")
	}
	if !strings.Contains(output, "sentinel-kms-key-changes") {
		t.Error("expected preview to show KMS alarm name")
	}
	if !strings.Contains(output, "KMS DisableKey/Delete") {
		t.Error("expected preview to show alarm event type")
	}
}

// ============================================================================
// Alarm Name Resolution Tests
// ============================================================================

func TestResolveAlarmNames_EmptyReturnsAll(t *testing.T) {
	names := resolveAlarmNames([]string{})

	if len(names) != 4 {
		t.Errorf("expected 4 alarm names for empty input, got %d", len(names))
	}
}

func TestResolveAlarmNames_ShortNames(t *testing.T) {
	names := resolveAlarmNames([]string{"kms", "ssm"})

	if len(names) != 2 {
		t.Errorf("expected 2 alarm names, got %d", len(names))
	}

	hasKMS := false
	hasSSM := false
	for _, name := range names {
		if name == "sentinel-kms-key-changes" {
			hasKMS = true
		}
		if name == "sentinel-ssm-delete" {
			hasSSM = true
		}
	}

	if !hasKMS {
		t.Error("expected KMS alarm name to be resolved")
	}
	if !hasSSM {
		t.Error("expected SSM alarm name to be resolved")
	}
}

func TestResolveAlarmNames_FullNames(t *testing.T) {
	names := resolveAlarmNames([]string{"sentinel-kms-key-changes", "sentinel-dynamodb-delete"})

	if len(names) != 2 {
		t.Errorf("expected 2 alarm names, got %d", len(names))
	}

	// Full names should pass through unchanged
	if names[0] != "sentinel-kms-key-changes" {
		t.Errorf("expected sentinel-kms-key-changes, got %s", names[0])
	}
	if names[1] != "sentinel-dynamodb-delete" {
		t.Errorf("expected sentinel-dynamodb-delete, got %s", names[1])
	}
}
