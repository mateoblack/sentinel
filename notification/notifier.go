package notification

import (
	"context"
	"errors"
)

// Notifier defines the interface for notification delivery.
// Implementations send notifications to specific backends (Slack, email, webhook, etc.).
type Notifier interface {
	// Notify sends a notification for the given event.
	// Returns an error if delivery fails.
	Notify(ctx context.Context, event *Event) error
}

// MultiNotifier composes multiple notifiers and sends to all of them.
// It implements the Notifier interface for consistent usage.
type MultiNotifier struct {
	notifiers []Notifier
}

// NewMultiNotifier creates a new MultiNotifier with the given notifiers.
// Nil notifiers are filtered out for convenience.
func NewMultiNotifier(notifiers ...Notifier) *MultiNotifier {
	filtered := make([]Notifier, 0, len(notifiers))
	for _, n := range notifiers {
		if n != nil {
			filtered = append(filtered, n)
		}
	}
	return &MultiNotifier{notifiers: filtered}
}

// Notify sends the event to all configured notifiers.
// Returns a joined error if any notifiers fail.
func (m *MultiNotifier) Notify(ctx context.Context, event *Event) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Notify(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// NoopNotifier is a no-op notifier that does nothing.
// Useful for testing or when notifications are disabled.
type NoopNotifier struct{}

// Notify does nothing and returns nil.
func (n *NoopNotifier) Notify(_ context.Context, _ *Event) error {
	return nil
}
