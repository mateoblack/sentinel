// Package request_test contains integration tests for the request package.
// These tests verify the interaction between request lifecycle, notification system,
// and finder functions in cross-service scenarios.
package request_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/request"
	"github.com/byteness/aws-vault/v7/testutil"
)

// ============================================================================
// Request Lifecycle Notification Integration Tests
// ============================================================================

func TestIntegration_RequestLifecycleNotifications(t *testing.T) {
	// Test that request state transitions trigger correct notifications

	t.Run("create_triggers_notification", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		notifier := testutil.NewMockNotifier()
		notifyStore := notification.NewNotifyStore(store, notifier)

		ctx := context.Background()
		now := time.Now()

		req := &request.Request{
			ID:            "c1d2e3f4a5b6c7d8",
			Requester:     "alice",
			Profile:       "prod",
			Justification: "Testing notification on create",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}

		err := notifyStore.Create(ctx, req)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		// Give async notification time to fire
		time.Sleep(50 * time.Millisecond)

		if notifier.NotifyCallCount() != 1 {
			t.Errorf("expected 1 notification, got %d", notifier.NotifyCallCount())
		}

		event := notifier.LastNotification()
		if event == nil {
			t.Fatal("expected notification event")
		}
		if event.Type != notification.EventRequestCreated {
			t.Errorf("expected EventRequestCreated, got %s", event.Type)
		}
		if event.Actor != "alice" {
			t.Errorf("expected actor 'alice', got %s", event.Actor)
		}
		if event.Request.ID != req.ID {
			t.Errorf("expected request ID %s, got %s", req.ID, event.Request.ID)
		}
	})

	t.Run("approve_triggers_notification", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		notifier := testutil.NewMockNotifier()
		notifyStore := notification.NewNotifyStore(store, notifier)

		ctx := context.Background()
		now := time.Now()

		// Create pending request via NotifyStore to track it properly
		req := &request.Request{
			ID:            "d2e3f4a5b6c7d8e9",
			Requester:     "bob",
			Profile:       "prod",
			Justification: "Testing approval notification",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}
		_ = notifyStore.Create(ctx, req)
		time.Sleep(50 * time.Millisecond) // Wait for create notification
		notifier.Reset()                  // Clear create notification

		// Create a new request object with approved status (don't modify in place)
		// This ensures the underlying store.Get() returns the old (pending) status
		approvedReq := &request.Request{
			ID:              "d2e3f4a5b6c7d8e9",
			Requester:       "bob",
			Profile:         "prod",
			Justification:   "Testing approval notification",
			Duration:        1 * time.Hour,
			Status:          request.StatusApproved,
			CreatedAt:       now,
			UpdatedAt:       time.Now(),
			ExpiresAt:       now.Add(request.DefaultRequestTTL),
			Approver:        "manager",
			ApproverComment: "Approved for deployment",
		}

		err := notifyStore.Update(ctx, approvedReq)
		if err != nil {
			t.Fatalf("failed to update request: %v", err)
		}

		// Give async notification time to fire
		time.Sleep(50 * time.Millisecond)

		if notifier.NotifyCallCount() != 1 {
			t.Errorf("expected 1 notification, got %d", notifier.NotifyCallCount())
		}

		event := notifier.LastNotification()
		if event == nil {
			t.Fatal("expected notification event")
		}
		if event.Type != notification.EventRequestApproved {
			t.Errorf("expected EventRequestApproved, got %s", event.Type)
		}
		if event.Actor != "manager" {
			t.Errorf("expected actor 'manager', got %s", event.Actor)
		}
	})

	t.Run("deny_triggers_notification", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		notifier := testutil.NewMockNotifier()
		notifyStore := notification.NewNotifyStore(store, notifier)

		ctx := context.Background()
		now := time.Now()

		req := &request.Request{
			ID:            "e3f4a5b6c7d8e9f0",
			Requester:     "charlie",
			Profile:       "prod",
			Justification: "Testing denial notification",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}
		_ = notifyStore.Create(ctx, req)
		time.Sleep(50 * time.Millisecond)
		notifier.Reset()

		// Create new request object with denied status
		deniedReq := &request.Request{
			ID:              "e3f4a5b6c7d8e9f0",
			Requester:       "charlie",
			Profile:         "prod",
			Justification:   "Testing denial notification",
			Duration:        1 * time.Hour,
			Status:          request.StatusDenied,
			CreatedAt:       now,
			UpdatedAt:       time.Now(),
			ExpiresAt:       now.Add(request.DefaultRequestTTL),
			Approver:        "security-lead",
			ApproverComment: "Denied - insufficient justification",
		}

		err := notifyStore.Update(ctx, deniedReq)
		if err != nil {
			t.Fatalf("failed to update request: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		event := notifier.LastNotification()
		if event == nil {
			t.Fatal("expected notification event")
		}
		if event.Type != notification.EventRequestDenied {
			t.Errorf("expected EventRequestDenied, got %s", event.Type)
		}
		if event.Actor != "security-lead" {
			t.Errorf("expected actor 'security-lead', got %s", event.Actor)
		}
	})

	t.Run("cancel_triggers_notification", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		notifier := testutil.NewMockNotifier()
		notifyStore := notification.NewNotifyStore(store, notifier)

		ctx := context.Background()
		now := time.Now()

		req := &request.Request{
			ID:            "f4a5b6c7d8e9f0a1",
			Requester:     "dave",
			Profile:       "staging",
			Justification: "Testing cancellation notification",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}
		_ = notifyStore.Create(ctx, req)
		time.Sleep(50 * time.Millisecond)
		notifier.Reset()

		// Create new request object with cancelled status
		cancelledReq := &request.Request{
			ID:            "f4a5b6c7d8e9f0a1",
			Requester:     "dave",
			Profile:       "staging",
			Justification: "Testing cancellation notification",
			Duration:      1 * time.Hour,
			Status:        request.StatusCancelled,
			CreatedAt:     now,
			UpdatedAt:     time.Now(),
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}

		err := notifyStore.Update(ctx, cancelledReq)
		if err != nil {
			t.Fatalf("failed to update request: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		event := notifier.LastNotification()
		if event == nil {
			t.Fatal("expected notification event")
		}
		if event.Type != notification.EventRequestCancelled {
			t.Errorf("expected EventRequestCancelled, got %s", event.Type)
		}
		if event.Actor != "dave" {
			t.Errorf("expected actor 'dave' (requester cancels own request), got %s", event.Actor)
		}
	})

	t.Run("expire_triggers_system_notification", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		notifier := testutil.NewMockNotifier()
		notifyStore := notification.NewNotifyStore(store, notifier)

		ctx := context.Background()
		now := time.Now()

		req := &request.Request{
			ID:            "a5b6c7d8e9f0a1b2",
			Requester:     "eve",
			Profile:       "prod",
			Justification: "Testing expiration notification",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}
		_ = notifyStore.Create(ctx, req)
		time.Sleep(50 * time.Millisecond)
		notifier.Reset()

		// Create new request object with expired status (by system)
		expiredReq := &request.Request{
			ID:            "a5b6c7d8e9f0a1b2",
			Requester:     "eve",
			Profile:       "prod",
			Justification: "Testing expiration notification",
			Duration:      1 * time.Hour,
			Status:        request.StatusExpired,
			CreatedAt:     now,
			UpdatedAt:     time.Now(),
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}

		err := notifyStore.Update(ctx, expiredReq)
		if err != nil {
			t.Fatalf("failed to update request: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		event := notifier.LastNotification()
		if event == nil {
			t.Fatal("expected notification event")
		}
		if event.Type != notification.EventRequestExpired {
			t.Errorf("expected EventRequestExpired, got %s", event.Type)
		}
		if event.Actor != "system" {
			t.Errorf("expected actor 'system', got %s", event.Actor)
		}
	})
}

// ============================================================================
// NotifyStore Wrapper Integration Tests
// ============================================================================

func TestIntegration_NotifyStoreWrapper(t *testing.T) {
	t.Run("notification_contains_request_details", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		notifier := testutil.NewMockNotifier()
		notifyStore := notification.NewNotifyStore(store, notifier)

		ctx := context.Background()
		now := time.Now()

		req := &request.Request{
			ID:            "b6c7d8e9f0a1b2c3",
			Requester:     "frank",
			Profile:       "admin-prod",
			Justification: "Detailed justification for audit purposes",
			Duration:      2 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}

		err := notifyStore.Create(ctx, req)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		event := notifier.LastNotification()
		if event == nil {
			t.Fatal("expected notification event")
		}

		// Verify notification contains correct request details
		if event.Request.Profile != "admin-prod" {
			t.Errorf("expected profile 'admin-prod', got %s", event.Request.Profile)
		}
		if event.Request.Justification != "Detailed justification for audit purposes" {
			t.Errorf("expected full justification in notification")
		}
		if event.Request.Duration != 2*time.Hour {
			t.Errorf("expected duration 2h, got %v", event.Request.Duration)
		}
	})

	t.Run("store_errors_propagate_without_notification", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		notifier := testutil.NewMockNotifier()
		notifyStore := notification.NewNotifyStore(store, notifier)

		ctx := context.Background()

		// Set store to return error
		expectedErr := errors.New("database connection failed")
		store.CreateErr = expectedErr

		req := &request.Request{
			ID:        "c7d8e9f0a1b2c3d4",
			Requester: "grace",
			Profile:   "prod",
			Status:    request.StatusPending,
		}

		err := notifyStore.Create(ctx, req)
		if err == nil {
			t.Fatal("expected error from store")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}

		// No notification should be sent on error
		if notifier.NotifyCallCount() != 0 {
			t.Error("no notification should be sent when store returns error")
		}
	})

	t.Run("nil_notifier_uses_noop", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		// Pass nil notifier - should use NoopNotifier
		notifyStore := notification.NewNotifyStore(store, nil)

		ctx := context.Background()
		now := time.Now()

		req := &request.Request{
			ID:            "d8e9f0a1b2c3d4e5",
			Requester:     "henry",
			Profile:       "prod",
			Justification: "Testing nil notifier",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}

		// Should not panic with nil notifier
		err := notifyStore.Create(ctx, req)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		// Verify request was stored
		got, err := notifyStore.Get(ctx, req.ID)
		if err != nil {
			t.Fatalf("failed to get request: %v", err)
		}
		if got.Requester != "henry" {
			t.Errorf("expected requester 'henry', got %s", got.Requester)
		}
	})
}

// ============================================================================
// Multiple Notifier Integration Tests
// ============================================================================

func TestIntegration_MultipleNotifiers(t *testing.T) {
	t.Run("all_notifiers_receive_notification", func(t *testing.T) {
		store := testutil.NewMockRequestStore()

		// Create multiple notifiers (simulating SNS + Webhook pattern)
		notifier1 := testutil.NewMockNotifier()
		notifier2 := testutil.NewMockNotifier()
		notifier3 := testutil.NewMockNotifier()

		multiNotifier := notification.NewMultiNotifier(notifier1, notifier2, notifier3)
		notifyStore := notification.NewNotifyStore(store, multiNotifier)

		ctx := context.Background()
		now := time.Now()

		req := &request.Request{
			ID:            "e9f0a1b2c3d4e5f6",
			Requester:     "ivy",
			Profile:       "prod",
			Justification: "Testing multi-notifier",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}

		err := notifyStore.Create(ctx, req)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		// All notifiers should receive the notification
		if notifier1.NotifyCallCount() != 1 {
			t.Errorf("notifier1 expected 1 call, got %d", notifier1.NotifyCallCount())
		}
		if notifier2.NotifyCallCount() != 1 {
			t.Errorf("notifier2 expected 1 call, got %d", notifier2.NotifyCallCount())
		}
		if notifier3.NotifyCallCount() != 1 {
			t.Errorf("notifier3 expected 1 call, got %d", notifier3.NotifyCallCount())
		}
	})

	t.Run("one_notifier_failure_does_not_block_others", func(t *testing.T) {
		// This tests fire-and-forget semantics
		store := testutil.NewMockRequestStore()

		notifier1 := testutil.NewMockNotifier()
		notifier2 := testutil.NewMockNotifier()
		notifier3 := testutil.NewMockNotifier()

		// Configure notifier2 to fail
		notifier2.NotifyErr = errors.New("webhook unavailable")

		multiNotifier := notification.NewMultiNotifier(notifier1, notifier2, notifier3)
		notifyStore := notification.NewNotifyStore(store, multiNotifier)

		ctx := context.Background()
		now := time.Now()

		req := &request.Request{
			ID:            "f0a1b2c3d4e5f6a7",
			Requester:     "jack",
			Profile:       "prod",
			Justification: "Testing notifier failure isolation",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}

		// Create should still succeed even if one notifier fails
		err := notifyStore.Create(ctx, req)
		if err != nil {
			t.Fatalf("store operation should succeed despite notification failure: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		// All notifiers should have been called
		if notifier1.NotifyCallCount() != 1 {
			t.Errorf("notifier1 should have been called")
		}
		if notifier2.NotifyCallCount() != 1 {
			t.Errorf("notifier2 should have been called (even though it fails)")
		}
		if notifier3.NotifyCallCount() != 1 {
			t.Errorf("notifier3 should have been called after notifier2 failed")
		}
	})

	t.Run("nil_notifiers_filtered", func(t *testing.T) {
		notifier1 := testutil.NewMockNotifier()
		// Pass nil notifiers mixed with valid ones
		multiNotifier := notification.NewMultiNotifier(notifier1, nil, nil)

		ctx := context.Background()
		event := notification.NewEvent(notification.EventRequestCreated, &request.Request{
			ID:        "test-id",
			Requester: "test-user",
		}, "test-user")

		// Should not panic
		err := multiNotifier.Notify(ctx, event)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Only valid notifier should have been called
		if notifier1.NotifyCallCount() != 1 {
			t.Errorf("expected 1 call, got %d", notifier1.NotifyCallCount())
		}
	})
}

// ============================================================================
// Concurrent Notification Tests
// ============================================================================

func TestIntegration_ConcurrentNotifications(t *testing.T) {
	t.Run("concurrent_creates_all_notify", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		notifier := testutil.NewMockNotifier()
		notifyStore := notification.NewNotifyStore(store, notifier)

		ctx := context.Background()
		now := time.Now()

		var wg sync.WaitGroup
		numRequests := 10

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				req := &request.Request{
					ID:            request.NewRequestID(),
					Requester:     "concurrent-user",
					Profile:       "prod",
					Justification: "Testing concurrent notifications",
					Duration:      1 * time.Hour,
					Status:        request.StatusPending,
					CreatedAt:     now,
					UpdatedAt:     now,
					ExpiresAt:     now.Add(request.DefaultRequestTTL),
				}
				_ = notifyStore.Create(ctx, req)
			}(i)
		}

		wg.Wait()
		time.Sleep(100 * time.Millisecond) // Give async notifications time to complete

		// All requests should have triggered notifications
		if notifier.NotifyCallCount() != numRequests {
			t.Errorf("expected %d notifications, got %d", numRequests, notifier.NotifyCallCount())
		}
	})

	t.Run("concurrent_transitions_notify_correctly", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		notifier := testutil.NewMockNotifier()
		notifyStore := notification.NewNotifyStore(store, notifier)

		ctx := context.Background()
		now := time.Now()

		// Create multiple pending requests first via NotifyStore
		type reqInfo struct {
			id        string
			requester string
		}
		var requests []reqInfo
		for i := 0; i < 5; i++ {
			req := &request.Request{
				ID:            request.NewRequestID(),
				Requester:     "user",
				Profile:       "prod",
				Justification: "Concurrent transition test",
				Duration:      1 * time.Hour,
				Status:        request.StatusPending,
				CreatedAt:     now,
				UpdatedAt:     now,
				ExpiresAt:     now.Add(request.DefaultRequestTTL),
			}
			_ = notifyStore.Create(ctx, req)
			requests = append(requests, reqInfo{id: req.ID, requester: req.Requester})
		}
		time.Sleep(100 * time.Millisecond) // Wait for create notifications
		notifier.Reset()

		// Concurrently transition all requests by creating new request objects
		var wg sync.WaitGroup
		var approved int32
		var denied int32

		for i, ri := range requests {
			wg.Add(1)
			go func(idx int, info reqInfo) {
				defer wg.Done()
				// Create new request object with new status (don't modify in place)
				newReq := &request.Request{
					ID:            info.id,
					Requester:     info.requester,
					Profile:       "prod",
					Justification: "Concurrent transition test",
					Duration:      1 * time.Hour,
					CreatedAt:     now,
					UpdatedAt:     time.Now(),
					ExpiresAt:     now.Add(request.DefaultRequestTTL),
					Approver:      "manager",
				}
				if idx%2 == 0 {
					newReq.Status = request.StatusApproved
					atomic.AddInt32(&approved, 1)
				} else {
					newReq.Status = request.StatusDenied
					atomic.AddInt32(&denied, 1)
				}
				_ = notifyStore.Update(ctx, newReq)
			}(i, ri)
		}

		wg.Wait()
		time.Sleep(100 * time.Millisecond)

		// All transitions should have triggered notifications
		if notifier.NotifyCallCount() != 5 {
			t.Errorf("expected 5 notifications, got %d", notifier.NotifyCallCount())
		}
	})
}
