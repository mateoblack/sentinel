package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sns/types"
)

// BreakGlassNotifier defines the interface for break-glass notification delivery.
// Implementations send notifications to specific backends when break-glass events occur.
type BreakGlassNotifier interface {
	// NotifyBreakGlass sends a notification for the given break-glass event.
	// Returns an error if delivery fails.
	NotifyBreakGlass(ctx context.Context, event *BreakGlassEvent) error
}

// SNSBreakGlassNotifier publishes break-glass notification events to an AWS SNS topic.
// It implements the BreakGlassNotifier interface for AWS-native notification delivery.
//
// Messages are published as JSON with a MessageAttribute "event_type" for
// subscription filtering. Subscribers can filter by event type (e.g., only
// receive "breakglass.invoked" events).
type SNSBreakGlassNotifier struct {
	client   snsAPI
	topicARN string
}

// NewSNSBreakGlassNotifier creates a new SNSBreakGlassNotifier using the provided AWS configuration.
// The topicARN specifies the SNS topic to publish events to.
func NewSNSBreakGlassNotifier(cfg aws.Config, topicARN string) *SNSBreakGlassNotifier {
	return &SNSBreakGlassNotifier{
		client:   sns.NewFromConfig(cfg),
		topicARN: topicARN,
	}
}

// newSNSBreakGlassNotifierWithClient creates an SNSBreakGlassNotifier with a custom client.
// This is primarily used for testing with mock clients.
func newSNSBreakGlassNotifierWithClient(client snsAPI, topicARN string) *SNSBreakGlassNotifier {
	return &SNSBreakGlassNotifier{
		client:   client,
		topicARN: topicARN,
	}
}

// NotifyBreakGlass publishes the break-glass event to the configured SNS topic.
// The event is serialized as JSON and includes a "event_type" message attribute
// for subscription filtering.
func (n *SNSBreakGlassNotifier) NotifyBreakGlass(ctx context.Context, event *BreakGlassEvent) error {
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

// WebhookBreakGlassNotifier sends break-glass notifications to an HTTP webhook endpoint.
// It implements the BreakGlassNotifier interface.
type WebhookBreakGlassNotifier struct {
	url        string
	client     *http.Client
	maxRetries int
	retryDelay time.Duration
}

// NewWebhookBreakGlassNotifier creates a new WebhookBreakGlassNotifier with the given configuration.
// Returns an error if the URL is empty or invalid.
func NewWebhookBreakGlassNotifier(config WebhookConfig) (*WebhookBreakGlassNotifier, error) {
	if config.URL == "" {
		return nil, errors.New("webhook URL is required")
	}

	// Validate URL format
	if _, err := url.ParseRequestURI(config.URL); err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}

	// Apply defaults for zero values
	timeout := config.TimeoutSeconds
	if timeout == 0 {
		timeout = 10
	}

	maxRetries := config.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	retryDelay := config.RetryDelaySeconds
	if retryDelay == 0 {
		retryDelay = 1
	}

	return &WebhookBreakGlassNotifier{
		url: config.URL,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		maxRetries: maxRetries,
		retryDelay: time.Duration(retryDelay) * time.Second,
	}, nil
}

// NotifyBreakGlass sends the break-glass event to the configured webhook URL.
// It retries on 5xx errors or network errors with exponential backoff.
// Returns an error if all retries are exhausted.
func (w *WebhookBreakGlassNotifier) NotifyBreakGlass(ctx context.Context, event *BreakGlassEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= w.maxRetries; attempt++ {
		// Check context before each attempt
		if err := ctx.Err(); err != nil {
			return err
		}

		// Wait before retry (skip on first attempt)
		if attempt > 0 {
			delay := w.retryDelay * (1 << (attempt - 1)) // exponential backoff
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		// Create request
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Sentinel-Event", string(event.Type))

		// Execute request
		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue // Retry on network errors
		}
		resp.Body.Close()

		// Success on 2xx
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		// Retry on 5xx server errors
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error: status %d", resp.StatusCode)
			continue
		}

		// Don't retry on 4xx client errors
		return fmt.Errorf("webhook request failed: status %d", resp.StatusCode)
	}

	return fmt.Errorf("webhook delivery failed after %d retries: %w", w.maxRetries, lastErr)
}

// MultiBreakGlassNotifier composes multiple break-glass notifiers and sends to all of them.
// It implements the BreakGlassNotifier interface for consistent usage.
type MultiBreakGlassNotifier struct {
	notifiers []BreakGlassNotifier
}

// NewMultiBreakGlassNotifier creates a new MultiBreakGlassNotifier with the given notifiers.
// Nil notifiers are filtered out for convenience.
func NewMultiBreakGlassNotifier(notifiers ...BreakGlassNotifier) *MultiBreakGlassNotifier {
	filtered := make([]BreakGlassNotifier, 0, len(notifiers))
	for _, n := range notifiers {
		if n != nil {
			filtered = append(filtered, n)
		}
	}
	return &MultiBreakGlassNotifier{notifiers: filtered}
}

// NotifyBreakGlass sends the break-glass event to all configured notifiers.
// Returns a joined error if any notifiers fail.
func (m *MultiBreakGlassNotifier) NotifyBreakGlass(ctx context.Context, event *BreakGlassEvent) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.NotifyBreakGlass(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// NoopBreakGlassNotifier is a no-op break-glass notifier that does nothing.
// Useful for testing or when notifications are disabled.
type NoopBreakGlassNotifier struct{}

// NotifyBreakGlass does nothing and returns nil.
func (n *NoopBreakGlassNotifier) NotifyBreakGlass(_ context.Context, _ *BreakGlassEvent) error {
	return nil
}
