package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// CloudWatchConfig holds configuration for CloudWatch log forwarding.
type CloudWatchConfig struct {
	LogGroupName  string           // CloudWatch log group name
	LogStreamName string           // CloudWatch log stream name (typically instance/function ID)
	SignConfig    *SignatureConfig // Signature config for signing entries (nil to disable)
}

// CloudWatchAPI defines the CloudWatch Logs operations used.
// This interface enables testing with mock implementations.
type CloudWatchAPI interface {
	PutLogEvents(ctx context.Context, params *cloudwatchlogs.PutLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error)
}

// CloudWatchLogger implements Logger by forwarding to CloudWatch Logs.
type CloudWatchLogger struct {
	client        CloudWatchAPI
	config        *CloudWatchConfig
	sequenceToken *string // For PutLogEvents sequencing
	mu            sync.Mutex
}

// NewCloudWatchLogger creates a CloudWatch logger from AWS config.
func NewCloudWatchLogger(awsCfg aws.Config, config *CloudWatchConfig) *CloudWatchLogger {
	client := cloudwatchlogs.NewFromConfig(awsCfg)
	return &CloudWatchLogger{
		client: client,
		config: config,
	}
}

// NewCloudWatchLoggerWithClient creates a CloudWatch logger with a custom client (for testing).
func NewCloudWatchLoggerWithClient(client CloudWatchAPI, config *CloudWatchConfig) *CloudWatchLogger {
	return &CloudWatchLogger{
		client: client,
		config: config,
	}
}

// LogDecision signs (if configured) and forwards a decision log entry to CloudWatch.
func (l *CloudWatchLogger) LogDecision(entry DecisionLogEntry) {
	l.writeEntry(entry)
}

// LogApproval signs (if configured) and forwards an approval log entry to CloudWatch.
func (l *CloudWatchLogger) LogApproval(entry ApprovalLogEntry) {
	l.writeEntry(entry)
}

// LogBreakGlass signs (if configured) and forwards a break-glass log entry to CloudWatch.
func (l *CloudWatchLogger) LogBreakGlass(entry BreakGlassLogEntry) {
	l.writeEntry(entry)
}

// writeEntry marshals and writes an entry to CloudWatch Logs.
// If SignConfig is set, the entry is signed before sending.
// Errors are logged to stderr but don't block (fail-open pattern).
func (l *CloudWatchLogger) writeEntry(entry any) {
	var message []byte
	var err error

	if l.config.SignConfig != nil {
		// Sign the entry
		signed, signErr := NewSignedEntry(entry, l.config.SignConfig)
		if signErr != nil {
			// Fail-open: log error to stderr but continue with unsigned entry
			fmt.Fprintf(os.Stderr, "cloudwatch signing error: %v\n", signErr)
			message, err = json.Marshal(entry)
		} else {
			message, err = json.Marshal(signed)
		}
	} else {
		// No signing configured
		message, err = json.Marshal(entry)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "cloudwatch marshal error: %v\n", err)
		return
	}

	l.putLogEvent(string(message))
}

// putLogEvent sends a single log event to CloudWatch Logs.
// It handles sequence token management and errors gracefully.
func (l *CloudWatchLogger) putLogEvent(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Use current time in milliseconds since epoch
	timestamp := time.Now().UnixMilli()

	input := &cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  aws.String(l.config.LogGroupName),
		LogStreamName: aws.String(l.config.LogStreamName),
		LogEvents: []types.InputLogEvent{
			{
				Message:   aws.String(message),
				Timestamp: aws.Int64(timestamp),
			},
		},
	}

	// Include sequence token if we have one from a previous call
	if l.sequenceToken != nil {
		input.SequenceToken = l.sequenceToken
	}

	// Send to CloudWatch - use background context since Lambda context may be short
	ctx := context.Background()
	output, err := l.client.PutLogEvents(ctx, input)
	if err != nil {
		// Fail-open: log error to stderr but don't fail
		// This matches the rate limiter pattern from Phase 116 - availability over security
		fmt.Fprintf(os.Stderr, "cloudwatch PutLogEvents error: %v\n", err)
		return
	}

	// Update sequence token for next call
	if output != nil && output.NextSequenceToken != nil {
		l.sequenceToken = output.NextSequenceToken
	}
}
