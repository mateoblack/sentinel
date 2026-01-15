package notification

import (
	"context"
	"log"

	"github.com/byteness/aws-vault/v7/request"
)

// NotifyStore wraps a request.Store and fires notifications on state transitions.
// It implements the request.Store interface, delegating operations to the wrapped
// store and firing appropriate events after successful mutations.
type NotifyStore struct {
	store    request.Store
	notifier Notifier
}

// NewNotifyStore creates a new NotifyStore wrapping the given store.
// If notifier is nil, a NoopNotifier is used (no notifications fired).
func NewNotifyStore(store request.Store, notifier Notifier) *NotifyStore {
	if notifier == nil {
		notifier = &NoopNotifier{}
	}
	return &NotifyStore{
		store:    store,
		notifier: notifier,
	}
}

// Create stores a new request and fires EventRequestCreated on success.
// The actor for the event is the request's Requester.
func (s *NotifyStore) Create(ctx context.Context, req *request.Request) error {
	if err := s.store.Create(ctx, req); err != nil {
		return err
	}

	// Fire notification asynchronously
	go s.notify(ctx, EventRequestCreated, req, req.Requester)

	return nil
}

// Get retrieves a request by ID. No notification is fired.
func (s *NotifyStore) Get(ctx context.Context, id string) (*request.Request, error) {
	return s.store.Get(ctx, id)
}

// Update modifies an existing request and fires notifications on state transitions.
// It detects status changes and fires the appropriate event type:
//   - pending -> approved: EventRequestApproved (actor: Approver)
//   - pending -> denied: EventRequestDenied (actor: Approver)
//   - pending -> cancelled: EventRequestCancelled (actor: Requester)
//   - pending -> expired: EventRequestExpired (actor: "system")
func (s *NotifyStore) Update(ctx context.Context, req *request.Request) error {
	// Get current request to detect status transition
	oldReq, err := s.store.Get(ctx, req.ID)
	if err != nil {
		// If we can't get the old request, still try the update
		// but we won't be able to detect the transition
		return s.store.Update(ctx, req)
	}

	// Perform the update
	if err := s.store.Update(ctx, req); err != nil {
		return err
	}

	// Check for status transition and fire notification
	if oldReq.Status == request.StatusPending && req.Status != request.StatusPending {
		var eventType EventType
		var actor string

		switch req.Status {
		case request.StatusApproved:
			eventType = EventRequestApproved
			actor = req.Approver
		case request.StatusDenied:
			eventType = EventRequestDenied
			actor = req.Approver
		case request.StatusCancelled:
			eventType = EventRequestCancelled
			actor = req.Requester
		case request.StatusExpired:
			eventType = EventRequestExpired
			actor = "system"
		}

		if eventType != "" {
			go s.notify(ctx, eventType, req, actor)
		}
	}

	return nil
}

// Delete removes a request by ID. No notification is fired.
func (s *NotifyStore) Delete(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

// ListByRequester returns all requests from a specific user.
func (s *NotifyStore) ListByRequester(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
	return s.store.ListByRequester(ctx, requester, limit)
}

// ListByStatus returns all requests with a specific status.
func (s *NotifyStore) ListByStatus(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error) {
	return s.store.ListByStatus(ctx, status, limit)
}

// ListByProfile returns all requests for a specific AWS profile.
func (s *NotifyStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
	return s.store.ListByProfile(ctx, profile, limit)
}

// notify sends a notification asynchronously.
// Errors are logged but do not fail the operation.
func (s *NotifyStore) notify(ctx context.Context, eventType EventType, req *request.Request, actor string) {
	event := NewEvent(eventType, req, actor)
	if err := s.notifier.Notify(ctx, event); err != nil {
		log.Printf("notification error (%s): %v", eventType, err)
	}
}
