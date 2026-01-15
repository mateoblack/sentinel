package notification

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sns/types"
)

// snsAPI defines the SNS operations used by SNSNotifier.
// This interface enables testing with mock implementations.
type snsAPI interface {
	Publish(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error)
}

// SNSNotifier publishes notification events to an AWS SNS topic.
// It implements the Notifier interface for AWS-native notification delivery.
//
// Messages are published as JSON with a MessageAttribute "event_type" for
// subscription filtering. Subscribers can filter by event type (e.g., only
// receive "request.approved" events).
type SNSNotifier struct {
	client   snsAPI
	topicARN string
}

// NewSNSNotifier creates a new SNSNotifier using the provided AWS configuration.
// The topicARN specifies the SNS topic to publish events to.
func NewSNSNotifier(cfg aws.Config, topicARN string) *SNSNotifier {
	return &SNSNotifier{
		client:   sns.NewFromConfig(cfg),
		topicARN: topicARN,
	}
}

// newSNSNotifierWithClient creates an SNSNotifier with a custom client.
// This is primarily used for testing with mock clients.
func newSNSNotifierWithClient(client snsAPI, topicARN string) *SNSNotifier {
	return &SNSNotifier{
		client:   client,
		topicARN: topicARN,
	}
}

// Notify publishes the event to the configured SNS topic.
// The event is serialized as JSON and includes a "event_type" message attribute
// for subscription filtering.
func (n *SNSNotifier) Notify(ctx context.Context, event *Event) error {
	// Marshal event to JSON
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	// Publish to SNS with event_type attribute for filtering
	_, err = n.client.Publish(ctx, &sns.PublishInput{
		TopicArn: aws.String(n.topicARN),
		Message:  aws.String(string(payload)),
		MessageAttributes: map[string]types.MessageAttributeValue{
			"event_type": {
				DataType:    aws.String("String"),
				StringValue: aws.String(event.Type.String()),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("sns publish: %w", err)
	}

	return nil
}
