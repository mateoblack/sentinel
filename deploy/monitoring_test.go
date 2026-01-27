package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

// ============================================================================
// Mock Clients for Monitoring
// ============================================================================

// mockCloudWatchAlarmsClient implements cloudwatchAlarmsAPI for testing.
type mockCloudWatchAlarmsClient struct {
	PutMetricAlarmFunc func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error)
	DescribeAlarmsFunc func(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

func (m *mockCloudWatchAlarmsClient) PutMetricAlarm(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
	if m.PutMetricAlarmFunc != nil {
		return m.PutMetricAlarmFunc(ctx, params, optFns...)
	}
	return &cloudwatch.PutMetricAlarmOutput{}, nil
}

func (m *mockCloudWatchAlarmsClient) DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	if m.DescribeAlarmsFunc != nil {
		return m.DescribeAlarmsFunc(ctx, params, optFns...)
	}
	return &cloudwatch.DescribeAlarmsOutput{}, nil
}

// mockSNSClient implements snsAPI for testing.
type mockSNSClient struct {
	CreateTopicFunc func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error)
	SubscribeFunc   func(ctx context.Context, params *sns.SubscribeInput, optFns ...func(*sns.Options)) (*sns.SubscribeOutput, error)
}

func (m *mockSNSClient) CreateTopic(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
	if m.CreateTopicFunc != nil {
		return m.CreateTopicFunc(ctx, params, optFns...)
	}
	return &sns.CreateTopicOutput{
		TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts"),
	}, nil
}

func (m *mockSNSClient) Subscribe(ctx context.Context, params *sns.SubscribeInput, optFns ...func(*sns.Options)) (*sns.SubscribeOutput, error) {
	if m.SubscribeFunc != nil {
		return m.SubscribeFunc(ctx, params, optFns...)
	}
	return &sns.SubscribeOutput{
		SubscriptionArn: aws.String("pending confirmation"),
	}, nil
}

// mockCloudWatchLogsClient implements cloudwatchLogsMonitorAPI for testing.
type mockCloudWatchLogsClient struct {
	PutMetricFilterFunc       func(ctx context.Context, params *cloudwatchlogs.PutMetricFilterInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutMetricFilterOutput, error)
	DescribeMetricFiltersFunc func(ctx context.Context, params *cloudwatchlogs.DescribeMetricFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error)
}

func (m *mockCloudWatchLogsClient) PutMetricFilter(ctx context.Context, params *cloudwatchlogs.PutMetricFilterInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutMetricFilterOutput, error) {
	if m.PutMetricFilterFunc != nil {
		return m.PutMetricFilterFunc(ctx, params, optFns...)
	}
	return &cloudwatchlogs.PutMetricFilterOutput{}, nil
}

func (m *mockCloudWatchLogsClient) DescribeMetricFilters(ctx context.Context, params *cloudwatchlogs.DescribeMetricFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error) {
	if m.DescribeMetricFiltersFunc != nil {
		return m.DescribeMetricFiltersFunc(ctx, params, optFns...)
	}
	return &cloudwatchlogs.DescribeMetricFiltersOutput{}, nil
}

// ============================================================================
// CreateOrGetSNSTopic Tests
// ============================================================================

func TestMonitoringSetup_CreateOrGetSNSTopic_CreatesNewTopic(t *testing.T) {
	ctx := context.Background()

	snsClient := &mockSNSClient{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			if *params.Name != "sentinel-security-alerts" {
				t.Errorf("expected topic name 'sentinel-security-alerts', got %s", *params.Name)
			}
			return &sns.CreateTopicOutput{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts"),
			}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(&mockCloudWatchAlarmsClient{}, snsClient, &mockCloudWatchLogsClient{})
	topicARN, err := setup.CreateOrGetSNSTopic(ctx, "sentinel-security-alerts")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if topicARN != "arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts" {
		t.Errorf("unexpected topic ARN: %s", topicARN)
	}
}

func TestMonitoringSetup_CreateOrGetSNSTopic_DefaultTopicName(t *testing.T) {
	ctx := context.Background()

	createdName := ""
	snsClient := &mockSNSClient{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			createdName = *params.Name
			return &sns.CreateTopicOutput{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:" + createdName),
			}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(&mockCloudWatchAlarmsClient{}, snsClient, &mockCloudWatchLogsClient{})
	_, err := setup.CreateOrGetSNSTopic(ctx, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if createdName != DefaultSNSTopicName {
		t.Errorf("expected default topic name %s, got %s", DefaultSNSTopicName, createdName)
	}
}

func TestMonitoringSetup_CreateOrGetSNSTopic_ExistingTopic(t *testing.T) {
	ctx := context.Background()

	// SNS CreateTopic is idempotent - returns existing topic ARN
	snsClient := &mockSNSClient{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			return &sns.CreateTopicOutput{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:existing-topic"),
			}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(&mockCloudWatchAlarmsClient{}, snsClient, &mockCloudWatchLogsClient{})
	topicARN, err := setup.CreateOrGetSNSTopic(ctx, "existing-topic")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if topicARN != "arn:aws:sns:us-east-1:123456789012:existing-topic" {
		t.Errorf("unexpected topic ARN: %s", topicARN)
	}
}

func TestMonitoringSetup_CreateOrGetSNSTopic_AccessDenied(t *testing.T) {
	ctx := context.Background()

	snsClient := &mockSNSClient{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			return nil, errors.New("AccessDeniedException: User is not authorized to perform sns:CreateTopic")
		},
	}

	setup := NewMonitoringSetupWithClients(&mockCloudWatchAlarmsClient{}, snsClient, &mockCloudWatchLogsClient{})
	_, err := setup.CreateOrGetSNSTopic(ctx, "sentinel-security-alerts")

	if err == nil {
		t.Fatal("expected error for access denied")
	}
}

// ============================================================================
// SubscribeEmail Tests
// ============================================================================

func TestMonitoringSetup_SubscribeEmail_CreatesSubscription(t *testing.T) {
	ctx := context.Background()

	subscribeCalled := false
	snsClient := &mockSNSClient{
		SubscribeFunc: func(ctx context.Context, params *sns.SubscribeInput, optFns ...func(*sns.Options)) (*sns.SubscribeOutput, error) {
			subscribeCalled = true
			if *params.Protocol != "email" {
				t.Errorf("expected protocol 'email', got %s", *params.Protocol)
			}
			if *params.Endpoint != "security@example.com" {
				t.Errorf("expected endpoint 'security@example.com', got %s", *params.Endpoint)
			}
			return &sns.SubscribeOutput{
				SubscriptionArn: aws.String("pending confirmation"),
			}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(&mockCloudWatchAlarmsClient{}, snsClient, &mockCloudWatchLogsClient{})
	err := setup.SubscribeEmail(ctx, "arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts", "security@example.com")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !subscribeCalled {
		t.Error("expected Subscribe to be called")
	}
}

// ============================================================================
// CreateMetricFilter Tests
// ============================================================================

func TestMonitoringSetup_CreateMetricFilter_CreatesFilter(t *testing.T) {
	ctx := context.Background()

	filterCalled := false
	cwLogsClient := &mockCloudWatchLogsClient{
		PutMetricFilterFunc: func(ctx context.Context, params *cloudwatchlogs.PutMetricFilterInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutMetricFilterOutput, error) {
			filterCalled = true
			if *params.FilterName != "sentinel-kms-key-changes" {
				t.Errorf("expected filter name 'sentinel-kms-key-changes', got %s", *params.FilterName)
			}
			if *params.LogGroupName != "aws-cloudtrail-logs" {
				t.Errorf("expected log group 'aws-cloudtrail-logs', got %s", *params.LogGroupName)
			}
			if len(params.MetricTransformations) != 1 {
				t.Errorf("expected 1 metric transformation, got %d", len(params.MetricTransformations))
			}
			if *params.MetricTransformations[0].MetricNamespace != DefaultMetricNamespace {
				t.Errorf("expected namespace %s, got %s", DefaultMetricNamespace, *params.MetricTransformations[0].MetricNamespace)
			}
			return &cloudwatchlogs.PutMetricFilterOutput{}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(&mockCloudWatchAlarmsClient{}, &mockSNSClient{}, cwLogsClient)
	config := MetricFilterConfig{
		Name:          "sentinel-kms-key-changes",
		LogGroupName:  "aws-cloudtrail-logs",
		FilterPattern: `{ ($.eventName = "DisableKey") }`,
		MetricName:    "KMSKeyChanges",
		Namespace:     DefaultMetricNamespace,
	}

	err := setup.CreateMetricFilter(ctx, config)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !filterCalled {
		t.Error("expected PutMetricFilter to be called")
	}
}

// ============================================================================
// CreateAlarm Tests
// ============================================================================

func TestMonitoringSetup_CreateAlarm_CreatesAlarmWithSNSAction(t *testing.T) {
	ctx := context.Background()

	alarmCalled := false
	cwClient := &mockCloudWatchAlarmsClient{
		PutMetricAlarmFunc: func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
			alarmCalled = true
			if *params.AlarmName != "sentinel-kms-key-changes" {
				t.Errorf("expected alarm name 'sentinel-kms-key-changes', got %s", *params.AlarmName)
			}
			if len(params.AlarmActions) != 1 {
				t.Errorf("expected 1 alarm action, got %d", len(params.AlarmActions))
			}
			if params.AlarmActions[0] != "arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts" {
				t.Errorf("unexpected alarm action: %s", params.AlarmActions[0])
			}
			if *params.Threshold != 1 {
				t.Errorf("expected threshold 1, got %f", *params.Threshold)
			}
			if *params.Period != 300 {
				t.Errorf("expected period 300, got %d", *params.Period)
			}
			return &cloudwatch.PutMetricAlarmOutput{}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(cwClient, &mockSNSClient{}, &mockCloudWatchLogsClient{})
	config := AlarmConfig{
		Name:              "sentinel-kms-key-changes",
		Description:       "Alert on KMS key changes",
		MetricName:        "KMSKeyChanges",
		Namespace:         DefaultMetricNamespace,
		Statistic:         "Sum",
		Period:            300,
		EvaluationPeriods: 1,
		Threshold:         1,
		ComparisonOp:      "GreaterThanOrEqualToThreshold",
	}

	err := setup.CreateAlarm(ctx, config, "arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !alarmCalled {
		t.Error("expected PutMetricAlarm to be called")
	}
}

// ============================================================================
// SetupSentinelMonitoring Tests
// ============================================================================

func TestMonitoringSetup_SetupSentinelMonitoring_CreatesAllResources(t *testing.T) {
	ctx := context.Background()

	filtersCreated := []string{}
	alarmsCreated := []string{}

	cwClient := &mockCloudWatchAlarmsClient{
		PutMetricAlarmFunc: func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
			alarmsCreated = append(alarmsCreated, *params.AlarmName)
			return &cloudwatch.PutMetricAlarmOutput{}, nil
		},
	}

	snsClient := &mockSNSClient{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			return &sns.CreateTopicOutput{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts"),
			}, nil
		},
	}

	cwLogsClient := &mockCloudWatchLogsClient{
		PutMetricFilterFunc: func(ctx context.Context, params *cloudwatchlogs.PutMetricFilterInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutMetricFilterOutput, error) {
			filtersCreated = append(filtersCreated, *params.FilterName)
			return &cloudwatchlogs.PutMetricFilterOutput{}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(cwClient, snsClient, cwLogsClient)
	result, err := setup.SetupSentinelMonitoring(ctx, "aws-cloudtrail-logs", "sentinel-security-alerts", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check SNS topic created
	if result.SNSTopicARN != "arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts" {
		t.Errorf("unexpected SNS topic ARN: %s", result.SNSTopicARN)
	}

	// Check all 4 filters created
	if len(filtersCreated) != 4 {
		t.Errorf("expected 4 filters created, got %d", len(filtersCreated))
	}

	// Check all 4 alarms created
	if len(alarmsCreated) != 4 {
		t.Errorf("expected 4 alarms created, got %d", len(alarmsCreated))
	}

	// Check result tracking
	if len(result.FiltersCreated) != 4 {
		t.Errorf("expected 4 filters in result, got %d", len(result.FiltersCreated))
	}
	if len(result.AlarmsCreated) != 4 {
		t.Errorf("expected 4 alarms in result, got %d", len(result.AlarmsCreated))
	}
}

func TestMonitoringSetup_SetupSentinelMonitoring_WithEmailSubscription(t *testing.T) {
	ctx := context.Background()

	emailSubscribed := false

	snsClient := &mockSNSClient{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			return &sns.CreateTopicOutput{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts"),
			}, nil
		},
		SubscribeFunc: func(ctx context.Context, params *sns.SubscribeInput, optFns ...func(*sns.Options)) (*sns.SubscribeOutput, error) {
			emailSubscribed = true
			if *params.Endpoint != "security@example.com" {
				t.Errorf("expected email 'security@example.com', got %s", *params.Endpoint)
			}
			return &sns.SubscribeOutput{}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(&mockCloudWatchAlarmsClient{}, snsClient, &mockCloudWatchLogsClient{})
	_, err := setup.SetupSentinelMonitoring(ctx, "aws-cloudtrail-logs", "sentinel-security-alerts", "security@example.com")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !emailSubscribed {
		t.Error("expected email subscription to be created")
	}
}

func TestMonitoringSetup_SetupSentinelMonitoring_AccessDeniedPartialFailure(t *testing.T) {
	ctx := context.Background()

	cwClient := &mockCloudWatchAlarmsClient{
		PutMetricAlarmFunc: func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
			if *params.AlarmName == "sentinel-kms-key-changes" {
				return nil, errors.New("AccessDeniedException: User is not authorized")
			}
			return &cloudwatch.PutMetricAlarmOutput{}, nil
		},
	}

	snsClient := &mockSNSClient{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			return &sns.CreateTopicOutput{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts"),
			}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(cwClient, snsClient, &mockCloudWatchLogsClient{})
	result, err := setup.SetupSentinelMonitoring(ctx, "aws-cloudtrail-logs", "sentinel-security-alerts", "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should continue and create other alarms
	if len(result.AlarmsCreated) != 3 {
		t.Errorf("expected 3 alarms created (1 failed), got %d", len(result.AlarmsCreated))
	}

	// Should have 1 error recorded
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestMonitoringSetup_SetupSelectedAlarms_CreatesOnlyRequested(t *testing.T) {
	ctx := context.Background()

	alarmsCreated := []string{}
	filtersCreated := []string{}

	cwClient := &mockCloudWatchAlarmsClient{
		PutMetricAlarmFunc: func(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error) {
			alarmsCreated = append(alarmsCreated, *params.AlarmName)
			return &cloudwatch.PutMetricAlarmOutput{}, nil
		},
	}

	snsClient := &mockSNSClient{
		CreateTopicFunc: func(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error) {
			return &sns.CreateTopicOutput{
				TopicArn: aws.String("arn:aws:sns:us-east-1:123456789012:sentinel-security-alerts"),
			}, nil
		},
	}

	cwLogsClient := &mockCloudWatchLogsClient{
		PutMetricFilterFunc: func(ctx context.Context, params *cloudwatchlogs.PutMetricFilterInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutMetricFilterOutput, error) {
			filtersCreated = append(filtersCreated, *params.FilterName)
			return &cloudwatchlogs.PutMetricFilterOutput{}, nil
		},
	}

	setup := NewMonitoringSetupWithClients(cwClient, snsClient, cwLogsClient)

	// Only request 2 of 4 alarms
	selectedAlarms := []string{"sentinel-kms-key-changes", "sentinel-dynamodb-delete"}
	result, err := setup.SetupSelectedAlarms(ctx, "aws-cloudtrail-logs", "sentinel-security-alerts", "", selectedAlarms)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only create 2 alarms
	if len(alarmsCreated) != 2 {
		t.Errorf("expected 2 alarms created, got %d: %v", len(alarmsCreated), alarmsCreated)
	}

	// Should only create 2 filters
	if len(filtersCreated) != 2 {
		t.Errorf("expected 2 filters created, got %d: %v", len(filtersCreated), filtersCreated)
	}

	// Result should show 2 created and 2 skipped
	if len(result.AlarmsCreated) != 2 {
		t.Errorf("expected 2 alarms in result, got %d", len(result.AlarmsCreated))
	}
	if len(result.AlarmsSkipped) != 2 {
		t.Errorf("expected 2 alarms skipped, got %d", len(result.AlarmsSkipped))
	}
}

// ============================================================================
// GetDefaultMetricFilters Tests
// ============================================================================

func TestGetDefaultMetricFilters_ReturnsCorrectFilters(t *testing.T) {
	filters := GetDefaultMetricFilters("aws-cloudtrail-logs")

	if len(filters) != 4 {
		t.Fatalf("expected 4 filters, got %d", len(filters))
	}

	// Check filter names
	expectedNames := map[string]bool{
		"sentinel-kms-key-changes":       true,
		"sentinel-dynamodb-delete":       true,
		"sentinel-ssm-delete":            true,
		"sentinel-unmanaged-assume-role": true,
	}

	for _, filter := range filters {
		if !expectedNames[filter.Name] {
			t.Errorf("unexpected filter name: %s", filter.Name)
		}
		if filter.LogGroupName != "aws-cloudtrail-logs" {
			t.Errorf("expected log group 'aws-cloudtrail-logs', got %s", filter.LogGroupName)
		}
		if filter.Namespace != DefaultMetricNamespace {
			t.Errorf("expected namespace %s, got %s", DefaultMetricNamespace, filter.Namespace)
		}
	}
}

// ============================================================================
// GetDefaultAlarms Tests
// ============================================================================

func TestGetDefaultAlarms_ReturnsCorrectAlarms(t *testing.T) {
	alarms := GetDefaultAlarms()

	if len(alarms) != 4 {
		t.Fatalf("expected 4 alarms, got %d", len(alarms))
	}

	for _, alarm := range alarms {
		// All alarms should trigger on single occurrence
		if alarm.Threshold != 1 {
			t.Errorf("alarm %s: expected threshold 1, got %f", alarm.Name, alarm.Threshold)
		}
		// All alarms should have 5 minute period
		if alarm.Period != 300 {
			t.Errorf("alarm %s: expected period 300, got %d", alarm.Name, alarm.Period)
		}
		// All alarms should evaluate 1 period
		if alarm.EvaluationPeriods != 1 {
			t.Errorf("alarm %s: expected evaluation periods 1, got %d", alarm.Name, alarm.EvaluationPeriods)
		}
	}
}
