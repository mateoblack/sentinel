package deploy

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

// DefaultSNSTopicName is the default topic name for Sentinel security alerts.
const DefaultSNSTopicName = "sentinel-security-alerts"

// DefaultMetricNamespace is the namespace for Sentinel CloudWatch metrics.
const DefaultMetricNamespace = "Sentinel/Security"

// cloudwatchAlarmsAPI defines CloudWatch operations for alarm management.
type cloudwatchAlarmsAPI interface {
	PutMetricAlarm(ctx context.Context, params *cloudwatch.PutMetricAlarmInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.PutMetricAlarmOutput, error)
	DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

// snsAPI defines SNS operations for topic management.
type snsAPI interface {
	CreateTopic(ctx context.Context, params *sns.CreateTopicInput, optFns ...func(*sns.Options)) (*sns.CreateTopicOutput, error)
	Subscribe(ctx context.Context, params *sns.SubscribeInput, optFns ...func(*sns.Options)) (*sns.SubscribeOutput, error)
}

// cloudwatchLogsMonitorAPI defines CloudWatch Logs operations for metric filters.
type cloudwatchLogsMonitorAPI interface {
	PutMetricFilter(ctx context.Context, params *cloudwatchlogs.PutMetricFilterInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutMetricFilterOutput, error)
	DescribeMetricFilters(ctx context.Context, params *cloudwatchlogs.DescribeMetricFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error)
}

// MonitoringSetup creates CloudWatch alarms for Sentinel security event monitoring.
type MonitoringSetup struct {
	cloudwatch     cloudwatchAlarmsAPI
	sns            snsAPI
	cloudwatchLogs cloudwatchLogsMonitorAPI
}

// AlarmConfig describes a CloudWatch alarm to create.
type AlarmConfig struct {
	Name              string  `json:"name"`
	Description       string  `json:"description"`
	MetricName        string  `json:"metric_name"`
	Namespace         string  `json:"namespace"`
	Statistic         string  `json:"statistic"`
	Period            int32   `json:"period"`
	EvaluationPeriods int32   `json:"evaluation_periods"`
	Threshold         float64 `json:"threshold"`
	ComparisonOp      string  `json:"comparison_operator"`
}

// MetricFilterConfig describes a CloudWatch Logs metric filter.
type MetricFilterConfig struct {
	Name          string `json:"name"`
	LogGroupName  string `json:"log_group_name"`
	FilterPattern string `json:"filter_pattern"`
	MetricName    string `json:"metric_name"`
	Namespace     string `json:"namespace"`
}

// MonitoringResult contains the result of setting up monitoring.
type MonitoringResult struct {
	SNSTopicARN    string   `json:"sns_topic_arn"`
	AlarmsCreated  []string `json:"alarms_created"`
	FiltersCreated []string `json:"filters_created"`
	AlarmsSkipped  []string `json:"alarms_skipped,omitempty"`
	Errors         []string `json:"errors,omitempty"`
}

// NewMonitoringSetup creates a new MonitoringSetup using the provided AWS configuration.
func NewMonitoringSetup(cfg aws.Config) *MonitoringSetup {
	return &MonitoringSetup{
		cloudwatch:     cloudwatch.NewFromConfig(cfg),
		sns:            sns.NewFromConfig(cfg),
		cloudwatchLogs: cloudwatchlogs.NewFromConfig(cfg),
	}
}

// NewMonitoringSetupWithClients creates a MonitoringSetup with custom clients for testing.
func NewMonitoringSetupWithClients(cw cloudwatchAlarmsAPI, snsClient snsAPI, cwLogs cloudwatchLogsMonitorAPI) *MonitoringSetup {
	return &MonitoringSetup{
		cloudwatch:     cw,
		sns:            snsClient,
		cloudwatchLogs: cwLogs,
	}
}

// CreateOrGetSNSTopic creates an SNS topic for alarm notifications or returns existing ARN.
// SNS CreateTopic is idempotent - returns existing topic ARN if topic already exists.
func (m *MonitoringSetup) CreateOrGetSNSTopic(ctx context.Context, topicName string) (string, error) {
	if topicName == "" {
		topicName = DefaultSNSTopicName
	}

	output, err := m.sns.CreateTopic(ctx, &sns.CreateTopicInput{
		Name: aws.String(topicName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create SNS topic: %w", err)
	}

	if output.TopicArn == nil {
		return "", fmt.Errorf("SNS topic created but no ARN returned")
	}

	return *output.TopicArn, nil
}

// SubscribeEmail adds an email subscription to the SNS topic.
// The subscription will be pending until the email is confirmed.
func (m *MonitoringSetup) SubscribeEmail(ctx context.Context, topicARN, email string) error {
	_, err := m.sns.Subscribe(ctx, &sns.SubscribeInput{
		TopicArn: aws.String(topicARN),
		Protocol: aws.String("email"),
		Endpoint: aws.String(email),
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe email: %w", err)
	}

	return nil
}

// CreateMetricFilter creates a CloudWatch Logs metric filter for CloudTrail events.
func (m *MonitoringSetup) CreateMetricFilter(ctx context.Context, config MetricFilterConfig) error {
	_, err := m.cloudwatchLogs.PutMetricFilter(ctx, &cloudwatchlogs.PutMetricFilterInput{
		LogGroupName:  aws.String(config.LogGroupName),
		FilterName:    aws.String(config.Name),
		FilterPattern: aws.String(config.FilterPattern),
		MetricTransformations: []cwltypes.MetricTransformation{
			{
				MetricName:      aws.String(config.MetricName),
				MetricNamespace: aws.String(config.Namespace),
				MetricValue:     aws.String("1"),
				DefaultValue:    aws.Float64(0),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create metric filter %s: %w", config.Name, err)
	}

	return nil
}

// CreateAlarm creates a CloudWatch alarm for a metric.
func (m *MonitoringSetup) CreateAlarm(ctx context.Context, config AlarmConfig, snsTopicARN string) error {
	var comparisonOp cwtypes.ComparisonOperator
	switch config.ComparisonOp {
	case "GreaterThanOrEqualToThreshold":
		comparisonOp = cwtypes.ComparisonOperatorGreaterThanOrEqualToThreshold
	case "GreaterThanThreshold":
		comparisonOp = cwtypes.ComparisonOperatorGreaterThanThreshold
	case "LessThanThreshold":
		comparisonOp = cwtypes.ComparisonOperatorLessThanThreshold
	case "LessThanOrEqualToThreshold":
		comparisonOp = cwtypes.ComparisonOperatorLessThanOrEqualToThreshold
	default:
		comparisonOp = cwtypes.ComparisonOperatorGreaterThanOrEqualToThreshold
	}

	var statistic cwtypes.Statistic
	switch config.Statistic {
	case "Sum":
		statistic = cwtypes.StatisticSum
	case "Average":
		statistic = cwtypes.StatisticAverage
	case "Maximum":
		statistic = cwtypes.StatisticMaximum
	case "Minimum":
		statistic = cwtypes.StatisticMinimum
	case "SampleCount":
		statistic = cwtypes.StatisticSampleCount
	default:
		statistic = cwtypes.StatisticSum
	}

	input := &cloudwatch.PutMetricAlarmInput{
		AlarmName:          aws.String(config.Name),
		AlarmDescription:   aws.String(config.Description),
		MetricName:         aws.String(config.MetricName),
		Namespace:          aws.String(config.Namespace),
		Statistic:          statistic,
		Period:             aws.Int32(config.Period),
		EvaluationPeriods:  aws.Int32(config.EvaluationPeriods),
		Threshold:          aws.Float64(config.Threshold),
		ComparisonOperator: comparisonOp,
		TreatMissingData:   aws.String("notBreaching"),
	}

	// Add SNS action if topic ARN provided
	if snsTopicARN != "" {
		input.AlarmActions = []string{snsTopicARN}
	}

	_, err := m.cloudwatch.PutMetricAlarm(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create alarm %s: %w", config.Name, err)
	}

	return nil
}

// GetDefaultMetricFilters returns the standard metric filter configurations for Sentinel monitoring.
// These filters detect security-critical CloudTrail events.
func GetDefaultMetricFilters(logGroupName string) []MetricFilterConfig {
	return []MetricFilterConfig{
		{
			Name:          "sentinel-kms-key-changes",
			LogGroupName:  logGroupName,
			FilterPattern: `{ ($.eventName = "DisableKey") || ($.eventName = "ScheduleKeyDeletion") }`,
			MetricName:    "KMSKeyChanges",
			Namespace:     DefaultMetricNamespace,
		},
		{
			Name:          "sentinel-dynamodb-delete",
			LogGroupName:  logGroupName,
			FilterPattern: `{ ($.eventName = "DeleteTable") && ($.requestParameters.tableName = "sentinel-*") }`,
			MetricName:    "DynamoDBTableDelete",
			Namespace:     DefaultMetricNamespace,
		},
		{
			Name:          "sentinel-ssm-delete",
			LogGroupName:  logGroupName,
			FilterPattern: `{ ($.eventName = "DeleteParameter") && ($.requestParameters.name = "/sentinel/*") }`,
			MetricName:    "SSMParameterDelete",
			Namespace:     DefaultMetricNamespace,
		},
		{
			Name:          "sentinel-unmanaged-assume-role",
			LogGroupName:  logGroupName,
			FilterPattern: `{ ($.eventName = "AssumeRole") && NOT ($.requestParameters.sourceIdentity = *) }`,
			MetricName:    "UnmanagedAssumeRole",
			Namespace:     DefaultMetricNamespace,
		},
	}
}

// GetDefaultAlarms returns the standard alarm configurations for Sentinel monitoring.
// All alarms trigger on a single occurrence (threshold=1).
func GetDefaultAlarms() []AlarmConfig {
	return []AlarmConfig{
		{
			Name:              "sentinel-kms-key-changes",
			Description:       "Alert when KMS keys used by Sentinel are disabled or scheduled for deletion",
			MetricName:        "KMSKeyChanges",
			Namespace:         DefaultMetricNamespace,
			Statistic:         "Sum",
			Period:            300, // 5 minutes
			EvaluationPeriods: 1,
			Threshold:         1,
			ComparisonOp:      "GreaterThanOrEqualToThreshold",
		},
		{
			Name:              "sentinel-dynamodb-delete",
			Description:       "Alert when Sentinel DynamoDB tables are deleted",
			MetricName:        "DynamoDBTableDelete",
			Namespace:         DefaultMetricNamespace,
			Statistic:         "Sum",
			Period:            300,
			EvaluationPeriods: 1,
			Threshold:         1,
			ComparisonOp:      "GreaterThanOrEqualToThreshold",
		},
		{
			Name:              "sentinel-ssm-delete",
			Description:       "Alert when Sentinel SSM parameters are deleted",
			MetricName:        "SSMParameterDelete",
			Namespace:         DefaultMetricNamespace,
			Statistic:         "Sum",
			Period:            300,
			EvaluationPeriods: 1,
			Threshold:         1,
			ComparisonOp:      "GreaterThanOrEqualToThreshold",
		},
		{
			Name:              "sentinel-unmanaged-assume-role",
			Description:       "Alert when AssumeRole calls lack sourceIdentity (unmanaged access)",
			MetricName:        "UnmanagedAssumeRole",
			Namespace:         DefaultMetricNamespace,
			Statistic:         "Sum",
			Period:            300,
			EvaluationPeriods: 1,
			Threshold:         1,
			ComparisonOp:      "GreaterThanOrEqualToThreshold",
		},
	}
}

// GetAlarmNames returns the list of default alarm names for filtering.
func GetAlarmNames() []string {
	return []string{
		"sentinel-kms-key-changes",
		"sentinel-dynamodb-delete",
		"sentinel-ssm-delete",
		"sentinel-unmanaged-assume-role",
	}
}

// SetupSentinelMonitoring creates all recommended alarms for Sentinel infrastructure.
// Requires CloudTrail log group name where CloudTrail events are delivered.
func (m *MonitoringSetup) SetupSentinelMonitoring(ctx context.Context, cloudTrailLogGroup string, snsTopicName string, email string) (*MonitoringResult, error) {
	result := &MonitoringResult{
		AlarmsCreated:  []string{},
		FiltersCreated: []string{},
		AlarmsSkipped:  []string{},
		Errors:         []string{},
	}

	// Create SNS topic
	topicARN, err := m.CreateOrGetSNSTopic(ctx, snsTopicName)
	if err != nil {
		return nil, fmt.Errorf("failed to create SNS topic: %w", err)
	}
	result.SNSTopicARN = topicARN

	// Subscribe email if provided
	if email != "" {
		if err := m.SubscribeEmail(ctx, topicARN, email); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("email subscription failed: %v", err))
		}
	}

	// Create metric filters
	filters := GetDefaultMetricFilters(cloudTrailLogGroup)
	for _, filter := range filters {
		if err := m.CreateMetricFilter(ctx, filter); err != nil {
			if isAccessDenied(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("access denied creating filter %s", filter.Name))
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("failed to create filter %s: %v", filter.Name, err))
			continue
		}
		result.FiltersCreated = append(result.FiltersCreated, filter.Name)
	}

	// Create alarms
	alarms := GetDefaultAlarms()
	for _, alarm := range alarms {
		if err := m.CreateAlarm(ctx, alarm, topicARN); err != nil {
			if isAccessDenied(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("access denied creating alarm %s", alarm.Name))
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("failed to create alarm %s: %v", alarm.Name, err))
			continue
		}
		result.AlarmsCreated = append(result.AlarmsCreated, alarm.Name)
	}

	return result, nil
}

// SetupSelectedAlarms creates only the specified alarms (by name).
// alarmNames should be a subset of GetAlarmNames().
func (m *MonitoringSetup) SetupSelectedAlarms(ctx context.Context, cloudTrailLogGroup string, snsTopicName string, email string, alarmNames []string) (*MonitoringResult, error) {
	result := &MonitoringResult{
		AlarmsCreated:  []string{},
		FiltersCreated: []string{},
		AlarmsSkipped:  []string{},
		Errors:         []string{},
	}

	// Create SNS topic
	topicARN, err := m.CreateOrGetSNSTopic(ctx, snsTopicName)
	if err != nil {
		return nil, fmt.Errorf("failed to create SNS topic: %w", err)
	}
	result.SNSTopicARN = topicARN

	// Subscribe email if provided
	if email != "" {
		if err := m.SubscribeEmail(ctx, topicARN, email); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("email subscription failed: %v", err))
		}
	}

	// Build set of requested alarm names
	requested := make(map[string]bool)
	for _, name := range alarmNames {
		requested[name] = true
	}

	// Create metric filters for requested alarms only
	filters := GetDefaultMetricFilters(cloudTrailLogGroup)
	for _, filter := range filters {
		if !requested[filter.Name] {
			continue
		}
		if err := m.CreateMetricFilter(ctx, filter); err != nil {
			if isAccessDenied(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("access denied creating filter %s", filter.Name))
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("failed to create filter %s: %v", filter.Name, err))
			continue
		}
		result.FiltersCreated = append(result.FiltersCreated, filter.Name)
	}

	// Create alarms for requested alarms only
	alarms := GetDefaultAlarms()
	for _, alarm := range alarms {
		if !requested[alarm.Name] {
			result.AlarmsSkipped = append(result.AlarmsSkipped, alarm.Name)
			continue
		}
		if err := m.CreateAlarm(ctx, alarm, topicARN); err != nil {
			if isAccessDenied(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("access denied creating alarm %s", alarm.Name))
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("failed to create alarm %s: %v", alarm.Name, err))
			continue
		}
		result.AlarmsCreated = append(result.AlarmsCreated, alarm.Name)
	}

	return result, nil
}
