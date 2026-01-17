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

	"github.com/byteness/aws-vault/v7/breakglass"
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

// ============================================================================
// FindApprovedRequest Integration Tests
// ============================================================================

func TestIntegration_FindApprovedRequest(t *testing.T) {
	t.Run("returns_valid_approved_request", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()
		now := time.Now()

		// Create approved request with valid time window
		approvedReq := &request.Request{
			ID:            "a1a2a3a4a5a6a7a8",
			Requester:     "alice",
			Profile:       "prod",
			Justification: "Approved request test",
			Duration:      2 * time.Hour,
			Status:        request.StatusApproved,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
			Approver:      "manager",
		}
		_ = store.Create(ctx, approvedReq)

		found, err := request.FindApprovedRequest(ctx, store, "alice", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found == nil {
			t.Fatal("expected to find approved request")
		}
		if found.ID != "a1a2a3a4a5a6a7a8" {
			t.Errorf("expected ID 'a1a2a3a4a5a6a7a8', got %s", found.ID)
		}
	})

	t.Run("filters_out_pending_requests", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()
		now := time.Now()

		// Create multiple requests with different statuses
		pendingReq := &request.Request{
			ID:            "b1b2b3b4b5b6b7b8",
			Requester:     "bob",
			Profile:       "prod",
			Justification: "Pending request",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}
		_ = store.Create(ctx, pendingReq)

		found, err := request.FindApprovedRequest(ctx, store, "bob", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("pending request should not be returned as approved")
		}
	})

	t.Run("filters_out_expired_approved_requests", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()
		past := time.Now().Add(-2 * time.Hour)

		// Create approved request that has expired
		expiredReq := &request.Request{
			ID:            "c1c2c3c4c5c6c7c8",
			Requester:     "charlie",
			Profile:       "prod",
			Justification: "Expired approved request",
			Duration:      1 * time.Hour,
			Status:        request.StatusApproved,
			CreatedAt:     past,
			UpdatedAt:     past,
			ExpiresAt:     past.Add(1 * time.Hour), // Already expired
			Approver:      "manager",
		}
		_ = store.Create(ctx, expiredReq)

		found, err := request.FindApprovedRequest(ctx, store, "charlie", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("expired approved request should not be returned")
		}
	})

	t.Run("filters_by_profile", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()
		now := time.Now()

		// Create approved request for different profile
		approvedReq := &request.Request{
			ID:            "d1d2d3d4d5d6d7d8",
			Requester:     "dave",
			Profile:       "staging",
			Justification: "Wrong profile",
			Duration:      2 * time.Hour,
			Status:        request.StatusApproved,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
			Approver:      "manager",
		}
		_ = store.Create(ctx, approvedReq)

		// Search for different profile
		found, err := request.FindApprovedRequest(ctx, store, "dave", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("approved request for different profile should not be returned")
		}
	})

	t.Run("returns_first_valid_of_multiple", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()
		now := time.Now()
		past := now.Add(-2 * time.Hour)

		// Create multiple requests for same user
		expiredReq := &request.Request{
			ID:            "e1e2e3e4e5e6e7e8",
			Requester:     "eve",
			Profile:       "prod",
			Justification: "Expired",
			Duration:      1 * time.Hour,
			Status:        request.StatusApproved,
			CreatedAt:     past,
			UpdatedAt:     past,
			ExpiresAt:     past.Add(30 * time.Minute), // Expired
			Approver:      "manager",
		}
		pendingReq := &request.Request{
			ID:            "f1f2f3f4f5f6f7f8",
			Requester:     "eve",
			Profile:       "prod",
			Justification: "Still pending",
			Duration:      1 * time.Hour,
			Status:        request.StatusPending,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
		}
		validReq := &request.Request{
			ID:            "a1b2c3d4e5f6a7b8",
			Requester:     "eve",
			Profile:       "prod",
			Justification: "Valid approved",
			Duration:      2 * time.Hour,
			Status:        request.StatusApproved,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
			Approver:      "manager",
		}

		_ = store.Create(ctx, expiredReq)
		_ = store.Create(ctx, pendingReq)
		_ = store.Create(ctx, validReq)

		found, err := request.FindApprovedRequest(ctx, store, "eve", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found == nil {
			t.Fatal("expected to find valid approved request")
		}
		if found.ID != "a1b2c3d4e5f6a7b8" {
			t.Errorf("expected valid request ID 'a1b2c3d4e5f6a7b8', got %s", found.ID)
		}
	})

	t.Run("filters_out_access_window_closed", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()
		past := time.Now().Add(-3 * time.Hour)

		// Create approved request where access window has closed
		// (ExpiresAt not yet reached, but CreatedAt + Duration has passed)
		closedWindowReq := &request.Request{
			ID:            "g1g2g3g4g5g6g7g8",
			Requester:     "grace",
			Profile:       "prod",
			Justification: "Access window closed",
			Duration:      1 * time.Hour, // Access for 1 hour
			Status:        request.StatusApproved,
			CreatedAt:     past,                                 // Created 3 hours ago
			UpdatedAt:     past,                                 // Duration was 1 hour
			ExpiresAt:     time.Now().Add(request.DefaultRequestTTL), // Still "valid" by TTL
			Approver:      "manager",
		}
		_ = store.Create(ctx, closedWindowReq)

		found, err := request.FindApprovedRequest(ctx, store, "grace", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("request with closed access window should not be returned")
		}
	})

	t.Run("returns_nil_for_empty_store", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()

		found, err := request.FindApprovedRequest(ctx, store, "nobody", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("expected nil for empty store")
		}
	})

	t.Run("handles_store_error", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		expectedErr := errors.New("database connection failed")
		store.ListByRequesterErr = expectedErr

		ctx := context.Background()

		_, err := request.FindApprovedRequest(ctx, store, "alice", "prod")
		if err == nil {
			t.Fatal("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})
}

// ============================================================================
// FindActiveBreakGlass Integration Tests
// ============================================================================

func TestIntegration_FindActiveBreakGlass(t *testing.T) {
	t.Run("returns_active_break_glass_event", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()
		configureListByInvoker(store)

		ctx := context.Background()
		now := time.Now()

		activeEvent := &breakglass.BreakGlassEvent{
			ID:            "b1b2b3b4b5b6b7b8",
			Invoker:       "alice",
			Profile:       "prod",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Active break-glass",
			Duration:      2 * time.Hour,
			Status:        breakglass.StatusActive,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(2 * time.Hour),
		}
		_ = store.Create(ctx, activeEvent)

		found, err := breakglass.FindActiveBreakGlass(ctx, store, "alice", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found == nil {
			t.Fatal("expected to find active break-glass event")
		}
		if found.ID != "b1b2b3b4b5b6b7b8" {
			t.Errorf("expected ID 'b1b2b3b4b5b6b7b8', got %s", found.ID)
		}
	})

	t.Run("filters_out_closed_events", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()
		configureListByInvoker(store)

		ctx := context.Background()
		now := time.Now()

		closedEvent := &breakglass.BreakGlassEvent{
			ID:            "c1c2c3c4c5c6c7c8",
			Invoker:       "bob",
			Profile:       "prod",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Closed break-glass",
			Duration:      2 * time.Hour,
			Status:        breakglass.StatusClosed,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(2 * time.Hour),
			ClosedBy:      "bob",
			ClosedReason:  "Incident resolved",
		}
		_ = store.Create(ctx, closedEvent)

		found, err := breakglass.FindActiveBreakGlass(ctx, store, "bob", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("closed event should not be returned")
		}
	})

	t.Run("filters_out_expired_events", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()
		configureListByInvoker(store)

		ctx := context.Background()
		past := time.Now().Add(-2 * time.Hour)

		expiredEvent := &breakglass.BreakGlassEvent{
			ID:            "d1d2d3d4d5d6d7d8",
			Invoker:       "charlie",
			Profile:       "prod",
			ReasonCode:    breakglass.ReasonMaintenance,
			Justification: "Expired break-glass",
			Duration:      1 * time.Hour,
			Status:        breakglass.StatusActive, // Still active but expired
			CreatedAt:     past,
			UpdatedAt:     past,
			ExpiresAt:     past.Add(1 * time.Hour), // Expired
		}
		_ = store.Create(ctx, expiredEvent)

		found, err := breakglass.FindActiveBreakGlass(ctx, store, "charlie", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("expired event should not be returned even if status is active")
		}
	})

	t.Run("filters_by_profile", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()
		configureListByInvoker(store)

		ctx := context.Background()
		now := time.Now()

		activeEvent := &breakglass.BreakGlassEvent{
			ID:            "e1e2e3e4e5e6e7e8",
			Invoker:       "dave",
			Profile:       "staging",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Wrong profile",
			Duration:      2 * time.Hour,
			Status:        breakglass.StatusActive,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(2 * time.Hour),
		}
		_ = store.Create(ctx, activeEvent)

		// Search for different profile
		found, err := breakglass.FindActiveBreakGlass(ctx, store, "dave", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("event for different profile should not be returned")
		}
	})

	t.Run("returns_nil_for_empty_store", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()
		configureListByInvoker(store)

		ctx := context.Background()

		found, err := breakglass.FindActiveBreakGlass(ctx, store, "nobody", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("expected nil for empty store")
		}
	})

	t.Run("handles_store_error", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()
		expectedErr := errors.New("database connection failed")
		store.ListByInvokerErr = expectedErr

		ctx := context.Background()

		_, err := breakglass.FindActiveBreakGlass(ctx, store, "alice", "prod")
		if err == nil {
			t.Fatal("expected error")
		}
		if err != expectedErr {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})
}

// ============================================================================
// Concurrent Finder Tests
// ============================================================================

func TestIntegration_ConcurrentFinders(t *testing.T) {
	t.Run("concurrent_find_approved_request", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()
		now := time.Now()

		// Create approved request
		approvedReq := &request.Request{
			ID:            "a1a2a3a4a5a6a7a8",
			Requester:     "alice",
			Profile:       "prod",
			Justification: "Concurrent test",
			Duration:      2 * time.Hour,
			Status:        request.StatusApproved,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
			Approver:      "manager",
		}
		_ = store.Create(ctx, approvedReq)

		var wg sync.WaitGroup
		var found int32
		numGoroutines := 10

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				result, err := request.FindApprovedRequest(ctx, store, "alice", "prod")
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != nil {
					atomic.AddInt32(&found, 1)
				}
			}()
		}

		wg.Wait()

		if found != int32(numGoroutines) {
			t.Errorf("expected all %d goroutines to find request, got %d", numGoroutines, found)
		}
	})

	t.Run("concurrent_find_active_break_glass", func(t *testing.T) {
		store := testutil.NewMockBreakGlassStore()
		configureListByInvoker(store)

		ctx := context.Background()
		now := time.Now()

		activeEvent := &breakglass.BreakGlassEvent{
			ID:            "b1b2b3b4b5b6b7b8",
			Invoker:       "bob",
			Profile:       "prod",
			ReasonCode:    breakglass.ReasonIncident,
			Justification: "Concurrent test",
			Duration:      2 * time.Hour,
			Status:        breakglass.StatusActive,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(2 * time.Hour),
		}
		_ = store.Create(ctx, activeEvent)

		var wg sync.WaitGroup
		var found int32
		numGoroutines := 10

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				result, err := breakglass.FindActiveBreakGlass(ctx, store, "bob", "prod")
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if result != nil {
					atomic.AddInt32(&found, 1)
				}
			}()
		}

		wg.Wait()

		if found != int32(numGoroutines) {
			t.Errorf("expected all %d goroutines to find event, got %d", numGoroutines, found)
		}
	})

	t.Run("concurrent_find_with_store_mutations", func(t *testing.T) {
		// This test verifies that finder functions work correctly when
		// the store is being mutated concurrently.
		// Note: The mock store's map iteration is not thread-safe, so we use
		// thread-safe ListByRequester that returns a fixed snapshot.

		store := testutil.NewMockRequestStore()

		ctx := context.Background()
		now := time.Now()

		// Pre-create some requests
		for i := 0; i < 5; i++ {
			req := &request.Request{
				ID:            request.NewRequestID(),
				Requester:     "user",
				Profile:       "prod",
				Justification: "Pre-created request",
				Duration:      2 * time.Hour,
				Status:        request.StatusApproved,
				CreatedAt:     now,
				UpdatedAt:     now,
				ExpiresAt:     now.Add(request.DefaultRequestTTL),
				Approver:      "manager",
			}
			_ = store.Create(ctx, req)
		}

		// Use a mutex-protected list for concurrent access
		var requestsMu sync.Mutex
		var requestsList []*request.Request
		for _, req := range store.Requests {
			requestsList = append(requestsList, req)
		}

		// Configure ListByRequester to use thread-safe snapshot
		store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
			requestsMu.Lock()
			defer requestsMu.Unlock()
			var results []*request.Request
			for _, req := range requestsList {
				if req.Requester == requester {
					results = append(results, req)
				}
			}
			return results, nil
		}

		var wg sync.WaitGroup
		numGoroutines := 10

		// Concurrent creates and finds
		for i := 0; i < numGoroutines; i++ {
			wg.Add(2)

			// Creator goroutine - adds to thread-safe list
			go func(idx int) {
				defer wg.Done()
				req := &request.Request{
					ID:            request.NewRequestID(),
					Requester:     "user",
					Profile:       "prod",
					Justification: "Concurrent mutation test",
					Duration:      2 * time.Hour,
					Status:        request.StatusApproved,
					CreatedAt:     now,
					UpdatedAt:     now,
					ExpiresAt:     now.Add(request.DefaultRequestTTL),
					Approver:      "manager",
				}
				requestsMu.Lock()
				requestsList = append(requestsList, req)
				requestsMu.Unlock()
			}(i)

			// Finder goroutine
			go func() {
				defer wg.Done()
				// Should not panic even with concurrent mutations
				_, _ = request.FindApprovedRequest(ctx, store, "user", "prod")
			}()
		}

		wg.Wait()
		// Test passes if no panics occurred
	})
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestIntegration_FinderEdgeCases(t *testing.T) {
	t.Run("nil_store_for_approved_request", func(t *testing.T) {
		ctx := context.Background()

		// FindApprovedRequest with nil store
		// This will panic since store.ListByRequester will be called on nil
		// Test documents behavior: nil store is a programming error
		defer func() {
			if r := recover(); r == nil {
				t.Log("Note: FindApprovedRequest with nil store panics (programming error)")
			}
		}()

		_, _ = request.FindApprovedRequest(ctx, nil, "alice", "prod")
	})

	t.Run("empty_requester", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()

		// Empty requester should return nil (no requests match)
		found, err := request.FindApprovedRequest(ctx, store, "", "prod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("expected nil for empty requester")
		}
	})

	t.Run("empty_profile", func(t *testing.T) {
		store := testutil.NewMockRequestStore()
		configureListByRequester(store)

		ctx := context.Background()
		now := time.Now()

		// Create request with non-empty profile
		req := &request.Request{
			ID:            "a1a2a3a4a5a6a7a8",
			Requester:     "alice",
			Profile:       "prod",
			Justification: "Test",
			Duration:      2 * time.Hour,
			Status:        request.StatusApproved,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     now.Add(request.DefaultRequestTTL),
			Approver:      "manager",
		}
		_ = store.Create(ctx, req)

		// Search with empty profile should not match
		found, err := request.FindApprovedRequest(ctx, store, "alice", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found != nil {
			t.Error("expected nil for empty profile search")
		}
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

// configureListByRequester sets up the mock to query in-memory storage
func configureListByRequester(store *testutil.MockRequestStore) {
	store.ListByRequesterFunc = func(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
		var results []*request.Request
		for _, req := range store.Requests {
			if req.Requester == requester {
				results = append(results, req)
			}
		}
		return results, nil
	}
}

// configureListByInvoker sets up the mock to query in-memory storage
func configureListByInvoker(store *testutil.MockBreakGlassStore) {
	store.ListByInvokerFunc = func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
		var results []*breakglass.BreakGlassEvent
		for _, event := range store.Events {
			if event.Invoker == invoker {
				results = append(results, event)
			}
		}
		return results, nil
	}
}
