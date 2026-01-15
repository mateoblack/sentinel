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
)

// WebhookConfig contains configuration for the webhook notifier.
type WebhookConfig struct {
	// URL is the webhook endpoint to POST events to.
	URL string

	// TimeoutSeconds is the HTTP client timeout. Default: 10.
	TimeoutSeconds int

	// MaxRetries is the maximum number of retry attempts. Default: 3.
	MaxRetries int

	// RetryDelaySeconds is the base delay between retries. Default: 1.
	// Uses exponential backoff: delay * 2^attempt.
	RetryDelaySeconds int
}

// WebhookNotifier sends notifications to an HTTP webhook endpoint.
// It implements the Notifier interface.
type WebhookNotifier struct {
	url        string
	client     *http.Client
	maxRetries int
	retryDelay time.Duration
}

// NewWebhookNotifier creates a new WebhookNotifier with the given configuration.
// Returns an error if the URL is empty or invalid.
func NewWebhookNotifier(config WebhookConfig) (*WebhookNotifier, error) {
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

	return &WebhookNotifier{
		url: config.URL,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		maxRetries: maxRetries,
		retryDelay: time.Duration(retryDelay) * time.Second,
	}, nil
}

// Notify sends the event to the configured webhook URL.
// It retries on 5xx errors or network errors with exponential backoff.
// Returns an error if all retries are exhausted.
func (w *WebhookNotifier) Notify(ctx context.Context, event *Event) error {
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
