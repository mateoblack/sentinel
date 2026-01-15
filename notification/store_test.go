package notification

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/request"
)

// storeTestMock is a test double for request.Store
type storeTestMock struct {
	createFn          func(ctx context.Context, req *request.Request) error
	getFn             func(ctx context.Context, id string) (*request.Request, error)
	updateFn          func(ctx context.Context, req *request.Request) error
	deleteFn          func(ctx context.Context, id string) error
	listByRequesterFn func(ctx context.Context, requester string, limit int) ([]*request.Request, error)
	listByStatusFn    func(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error)
	listByProfileFn   func(ctx context.Context, profile string, limit int) ([]*request.Request, error)
}

func (m *storeTestMock) Create(ctx context.Context, req *request.Request) error {
	if m.createFn != nil {
		return m.createFn(ctx, req)
	}
	return nil
}

func (m *storeTestMock) Get(ctx context.Context, id string) (*request.Request, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id)
	}
	return nil, nil
}

func (m *storeTestMock) Update(ctx context.Context, req *request.Request) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, req)
	}
	return nil
}

func (m *storeTestMock) Delete(ctx context.Context, id string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

func (m *storeTestMock) ListByRequester(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
	if m.listByRequesterFn != nil {
		return m.listByRequesterFn(ctx, requester, limit)
	}
	return nil, nil
}

func (m *storeTestMock) ListByStatus(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error) {
	if m.listByStatusFn != nil {
		return m.listByStatusFn(ctx, status, limit)
	}
	return nil, nil
}

func (m *storeTestMock) ListByProfile(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
	if m.listByProfileFn != nil {
		return m.listByProfileFn(ctx, profile, limit)
	}
	return nil, nil
}

// notifyTestMock captures notifications for verification
type notifyTestMock struct {
	mu     sync.Mutex
	events []*Event
	err    error
}

func (m *notifyTestMock) Notify(ctx context.Context, event *Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return m.err
}

func (m *notifyTestMock) getEvents() []*Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*Event(nil), m.events...)
}

func (m *notifyTestMock) waitForEvents(count int, timeout time.Duration) []*Event {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		events := m.getEvents()
		if len(events) >= count {
			return events
		}
		time.Sleep(10 * time.Millisecond)
	}
	return m.getEvents()
}

// testRequest creates a test request with the given status
func testRequest(status request.RequestStatus) *request.Request {
	now := time.Now()
	return &request.Request{
		ID:            "1234567890abcdef",
		Requester:     "testuser",
		Profile:       "production",
		Justification: "Need access for deployment",
		Duration:      time.Hour,
		Status:        status,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
		Approver:      "approver",
	}
}

func TestNotifyStore_Create(t *testing.T) {
	store := &storeTestMock{}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	req := testRequest(request.StatusPending)

	err := ns.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Wait for async notification
	events := notifier.waitForEvents(1, 100*time.Millisecond)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.Type != EventRequestCreated {
		t.Errorf("expected EventRequestCreated, got %s", event.Type)
	}
	if event.Actor != req.Requester {
		t.Errorf("expected actor %q, got %q", req.Requester, event.Actor)
	}
	if event.Request.ID != req.ID {
		t.Errorf("expected request ID %q, got %q", req.ID, event.Request.ID)
	}
}

func TestNotifyStore_Create_Error(t *testing.T) {
	expectedErr := errors.New("create failed")
	store := &storeTestMock{
		createFn: func(ctx context.Context, req *request.Request) error {
			return expectedErr
		},
	}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	req := testRequest(request.StatusPending)

	err := ns.Create(context.Background(), req)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}

	// No notification should be fired on error
	time.Sleep(50 * time.Millisecond)
	events := notifier.getEvents()
	if len(events) != 0 {
		t.Errorf("expected 0 events on error, got %d", len(events))
	}
}

func TestNotifyStore_Update_Approved(t *testing.T) {
	pendingReq := testRequest(request.StatusPending)
	approvedReq := testRequest(request.StatusApproved)
	approvedReq.Approver = "approver-user"

	store := &storeTestMock{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
	}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	err := ns.Update(context.Background(), approvedReq)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	events := notifier.waitForEvents(1, 100*time.Millisecond)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.Type != EventRequestApproved {
		t.Errorf("expected EventRequestApproved, got %s", event.Type)
	}
	if event.Actor != approvedReq.Approver {
		t.Errorf("expected actor %q, got %q", approvedReq.Approver, event.Actor)
	}
}

func TestNotifyStore_Update_Denied(t *testing.T) {
	pendingReq := testRequest(request.StatusPending)
	deniedReq := testRequest(request.StatusDenied)
	deniedReq.Approver = "approver-user"

	store := &storeTestMock{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
	}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	err := ns.Update(context.Background(), deniedReq)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	events := notifier.waitForEvents(1, 100*time.Millisecond)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.Type != EventRequestDenied {
		t.Errorf("expected EventRequestDenied, got %s", event.Type)
	}
	if event.Actor != deniedReq.Approver {
		t.Errorf("expected actor %q, got %q", deniedReq.Approver, event.Actor)
	}
}

func TestNotifyStore_Update_Cancelled(t *testing.T) {
	pendingReq := testRequest(request.StatusPending)
	cancelledReq := testRequest(request.StatusCancelled)

	store := &storeTestMock{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
	}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	err := ns.Update(context.Background(), cancelledReq)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	events := notifier.waitForEvents(1, 100*time.Millisecond)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.Type != EventRequestCancelled {
		t.Errorf("expected EventRequestCancelled, got %s", event.Type)
	}
	if event.Actor != cancelledReq.Requester {
		t.Errorf("expected actor %q, got %q", cancelledReq.Requester, event.Actor)
	}
}

func TestNotifyStore_Update_Expired(t *testing.T) {
	pendingReq := testRequest(request.StatusPending)
	expiredReq := testRequest(request.StatusExpired)

	store := &storeTestMock{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
	}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	err := ns.Update(context.Background(), expiredReq)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	events := notifier.waitForEvents(1, 100*time.Millisecond)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.Type != EventRequestExpired {
		t.Errorf("expected EventRequestExpired, got %s", event.Type)
	}
	if event.Actor != "system" {
		t.Errorf("expected actor 'system', got %q", event.Actor)
	}
}

func TestNotifyStore_Update_NoTransition(t *testing.T) {
	// Update without status change (e.g., updating justification)
	pendingReq := testRequest(request.StatusPending)
	updatedReq := testRequest(request.StatusPending)
	updatedReq.Justification = "Updated justification text"

	store := &storeTestMock{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return pendingReq, nil
		},
	}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	err := ns.Update(context.Background(), updatedReq)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// No notification should be fired for non-transition updates
	time.Sleep(50 * time.Millisecond)
	events := notifier.getEvents()
	if len(events) != 0 {
		t.Errorf("expected 0 events for non-transition update, got %d", len(events))
	}
}

func TestNotifyStore_Update_FromTerminalState(t *testing.T) {
	// Starting from terminal state should not fire notification
	approvedReq := testRequest(request.StatusApproved)
	updatedReq := testRequest(request.StatusApproved)
	updatedReq.ApproverComment = "Additional comment"

	store := &storeTestMock{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return approvedReq, nil
		},
	}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	err := ns.Update(context.Background(), updatedReq)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// No notification - not a pending -> terminal transition
	time.Sleep(50 * time.Millisecond)
	events := notifier.getEvents()
	if len(events) != 0 {
		t.Errorf("expected 0 events for terminal state update, got %d", len(events))
	}
}

func TestNotifyStore_Get_NoNotification(t *testing.T) {
	expectedReq := testRequest(request.StatusPending)

	store := &storeTestMock{
		getFn: func(ctx context.Context, id string) (*request.Request, error) {
			return expectedReq, nil
		},
	}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	req, err := ns.Get(context.Background(), expectedReq.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if req.ID != expectedReq.ID {
		t.Errorf("expected request ID %q, got %q", expectedReq.ID, req.ID)
	}

	// No notification should be fired for Get
	time.Sleep(50 * time.Millisecond)
	events := notifier.getEvents()
	if len(events) != 0 {
		t.Errorf("expected 0 events for Get, got %d", len(events))
	}
}

func TestNotifyStore_Delete_NoNotification(t *testing.T) {
	store := &storeTestMock{}
	notifier := &notifyTestMock{}
	ns := NewNotifyStore(store, notifier)

	err := ns.Delete(context.Background(), "1234567890abcdef")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// No notification should be fired for Delete
	time.Sleep(50 * time.Millisecond)
	events := notifier.getEvents()
	if len(events) != 0 {
		t.Errorf("expected 0 events for Delete, got %d", len(events))
	}
}

func TestNotifyStore_NilNotifier(t *testing.T) {
	store := &storeTestMock{}
	ns := NewNotifyStore(store, nil)

	req := testRequest(request.StatusPending)

	// Should not panic with nil notifier (uses NoopNotifier)
	err := ns.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create with nil notifier failed: %v", err)
	}
}

func TestNotifyStore_NotifierError(t *testing.T) {
	store := &storeTestMock{}
	notifier := &notifyTestMock{
		err: errors.New("notification failed"),
	}
	ns := NewNotifyStore(store, notifier)

	req := testRequest(request.StatusPending)

	// Operation should succeed even if notification fails
	err := ns.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create should succeed despite notification error: %v", err)
	}

	// Notification was still attempted
	events := notifier.waitForEvents(1, 100*time.Millisecond)
	if len(events) != 1 {
		t.Errorf("expected 1 event attempt, got %d", len(events))
	}
}
