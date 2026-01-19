package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/identity"
)

// testableBreakGlassListCommand is a testable version that uses mock STS client.
func testableBreakGlassListCommand(ctx context.Context, input BreakGlassListCommandInput) ([]BreakGlassEventSummary, error) {
	// 1. Get invoker (use STSClient if no invoker filter and no other filter)
	invoker := input.Invoker
	if invoker == "" && input.Status == "" && input.Profile == "" {
		stsClient := input.STSClient
		if stsClient == nil {
			return nil, errors.New("STSClient is required for testing when no filter is provided")
		}
		var err error
		invoker, err = identity.GetAWSUsername(ctx, stsClient)
		if err != nil {
			return nil, err
		}
	}

	// 2. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 3. Query based on flags (priority: status > profile > invoker)
	var events []*breakglass.BreakGlassEvent
	var err error
	limit := input.Limit
	if limit == 0 {
		limit = 100
	}

	if input.Status != "" {
		// Query by status
		status := breakglass.BreakGlassStatus(input.Status)
		if !status.IsValid() {
			return nil, errors.New("invalid status: " + input.Status)
		}
		events, err = store.ListByStatus(ctx, status, limit)
	} else if input.Profile != "" {
		// Query by profile
		events, err = store.ListByProfile(ctx, input.Profile, limit)
	} else {
		// Query by invoker (default to mock username)
		events, err = store.ListByInvoker(ctx, invoker, limit)
	}

	if err != nil {
		return nil, err
	}

	// 4. Filter by invoker if specified AND query was not by invoker
	if input.Invoker != "" && (input.Status != "" || input.Profile != "") {
		filtered := make([]*breakglass.BreakGlassEvent, 0, len(events))
		for _, event := range events {
			if event.Invoker == input.Invoker {
				filtered = append(filtered, event)
			}
		}
		events = filtered
	}

	// 5. Format results
	summaries := make([]BreakGlassEventSummary, 0, len(events))
	for _, event := range events {
		summaries = append(summaries, BreakGlassEventSummary{
			ID:         event.ID,
			Profile:    event.Profile,
			Status:     string(event.Status),
			Invoker:    event.Invoker,
			ReasonCode: string(event.ReasonCode),
			CreatedAt:  event.CreatedAt,
			ExpiresAt:  event.ExpiresAt,
		})
	}

	return summaries, nil
}

func TestBreakGlassListCommand_DefaultListsCurrentUserEvents(t *testing.T) {
	now := time.Now()
	expectedEvents := []*breakglass.BreakGlassEvent{
		{
			ID:         "abc123def4567890",
			Invoker:    defaultMockUsername,
			Profile:    "dev",
			Status:     breakglass.StatusActive,
			ReasonCode: breakglass.ReasonIncident,
			CreatedAt:  now,
			ExpiresAt:  now.Add(4 * time.Hour),
		},
		{
			ID:         "def456ghi7890123",
			Invoker:    defaultMockUsername,
			Profile:    "prod",
			Status:     breakglass.StatusClosed,
			ReasonCode: breakglass.ReasonMaintenance,
			CreatedAt:  now.Add(-1 * time.Hour),
			ExpiresAt:  now.Add(3 * time.Hour),
		},
	}

	var calledInvoker string
	store := &mockBreakGlassStore{
		listByInvokerFn: func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			calledInvoker = invoker
			return expectedEvents, nil
		},
	}

	input := BreakGlassListCommandInput{
		Store:     store,
		Limit:     100,
		STSClient: defaultMockSTSClient(),
	}

	summaries, err := testableBreakGlassListCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByInvoker was called with AWS identity (mock username)
	if calledInvoker != defaultMockUsername {
		t.Errorf("expected invoker %q, got %q", defaultMockUsername, calledInvoker)
	}

	// Verify results
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}

	if summaries[0].ID != "abc123def4567890" {
		t.Errorf("unexpected first event ID: %s", summaries[0].ID)
	}
	if summaries[0].Profile != "dev" {
		t.Errorf("unexpected first event profile: %s", summaries[0].Profile)
	}
	if summaries[0].ReasonCode != "incident" {
		t.Errorf("unexpected first event reason code: %s", summaries[0].ReasonCode)
	}
}

func TestBreakGlassListCommand_FilterByStatus(t *testing.T) {
	now := time.Now()
	expectedEvents := []*breakglass.BreakGlassEvent{
		{
			ID:         "abc123def4567890",
			Invoker:    "alice",
			Profile:    "dev",
			Status:     breakglass.StatusActive,
			ReasonCode: breakglass.ReasonIncident,
			CreatedAt:  now,
			ExpiresAt:  now.Add(4 * time.Hour),
		},
		{
			ID:         "def456ghi7890123",
			Invoker:    "bob",
			Profile:    "staging",
			Status:     breakglass.StatusActive,
			ReasonCode: breakglass.ReasonSecurity,
			CreatedAt:  now.Add(-30 * time.Minute),
			ExpiresAt:  now.Add(3 * time.Hour),
		},
	}

	var calledStatus breakglass.BreakGlassStatus
	store := &mockBreakGlassStore{
		listByStatusFn: func(ctx context.Context, status breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error) {
			calledStatus = status
			return expectedEvents, nil
		},
	}

	input := BreakGlassListCommandInput{
		Status: "active",
		Store:  store,
		Limit:  100,
	}

	summaries, err := testableBreakGlassListCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByStatus was called with correct status
	if calledStatus != breakglass.StatusActive {
		t.Errorf("expected status %q, got %q", breakglass.StatusActive, calledStatus)
	}

	// Verify results include both invokers (no filtering by current user)
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}

	if summaries[0].Invoker != "alice" {
		t.Errorf("unexpected first invoker: %s", summaries[0].Invoker)
	}
	if summaries[1].Invoker != "bob" {
		t.Errorf("unexpected second invoker: %s", summaries[1].Invoker)
	}
}

func TestBreakGlassListCommand_FilterByProfile(t *testing.T) {
	now := time.Now()
	expectedEvents := []*breakglass.BreakGlassEvent{
		{
			ID:         "abc123def4567890",
			Invoker:    "alice",
			Profile:    "prod",
			Status:     breakglass.StatusActive,
			ReasonCode: breakglass.ReasonIncident,
			CreatedAt:  now,
			ExpiresAt:  now.Add(4 * time.Hour),
		},
	}

	var calledProfile string
	store := &mockBreakGlassStore{
		listByProfileFn: func(ctx context.Context, profile string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			calledProfile = profile
			return expectedEvents, nil
		},
	}

	input := BreakGlassListCommandInput{
		Profile: "prod",
		Store:   store,
		Limit:   100,
	}

	summaries, err := testableBreakGlassListCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByProfile was called with correct profile
	if calledProfile != "prod" {
		t.Errorf("expected profile %q, got %q", "prod", calledProfile)
	}

	// Verify results
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	if summaries[0].Profile != "prod" {
		t.Errorf("unexpected profile: %s", summaries[0].Profile)
	}
}

func TestBreakGlassListCommand_FilterByInvoker(t *testing.T) {
	now := time.Now()
	expectedEvents := []*breakglass.BreakGlassEvent{
		{
			ID:         "abc123def4567890",
			Invoker:    "other-user",
			Profile:    "dev",
			Status:     breakglass.StatusActive,
			ReasonCode: breakglass.ReasonRecovery,
			CreatedAt:  now,
			ExpiresAt:  now.Add(4 * time.Hour),
		},
	}

	var calledInvoker string
	store := &mockBreakGlassStore{
		listByInvokerFn: func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			calledInvoker = invoker
			return expectedEvents, nil
		},
	}

	input := BreakGlassListCommandInput{
		Invoker: "other-user",
		Store:   store,
		Limit:   100,
	}

	summaries, err := testableBreakGlassListCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByInvoker was called with specified user (not current user)
	if calledInvoker != "other-user" {
		t.Errorf("expected invoker %q, got %q", "other-user", calledInvoker)
	}

	// Verify results
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	if summaries[0].Invoker != "other-user" {
		t.Errorf("unexpected invoker: %s", summaries[0].Invoker)
	}
}

func TestBreakGlassListCommand_EmptyResults(t *testing.T) {
	store := &mockBreakGlassStore{
		listByInvokerFn: func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			return []*breakglass.BreakGlassEvent{}, nil
		},
	}

	input := BreakGlassListCommandInput{
		Store: store,
		Limit: 100,
	}

	summaries, err := testableBreakGlassListCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify empty results
	if len(summaries) != 0 {
		t.Fatalf("expected 0 summaries, got %d", len(summaries))
	}
}

func TestBreakGlassListCommand_StoreError(t *testing.T) {
	store := &mockBreakGlassStore{
		listByInvokerFn: func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			return nil, errors.New("network error: connection refused")
		},
	}

	input := BreakGlassListCommandInput{
		Store: store,
		Limit: 100,
	}

	_, err := testableBreakGlassListCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when store fails")
	}

	if err.Error() != "network error: connection refused" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassListCommand_InvalidStatus(t *testing.T) {
	store := &mockBreakGlassStore{}

	input := BreakGlassListCommandInput{
		Status: "invalid-status",
		Store:  store,
		Limit:  100,
	}

	_, err := testableBreakGlassListCommand(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid status")
	}

	if err.Error() != "invalid status: invalid-status" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBreakGlassListCommand_FilterByStatusAndInvoker(t *testing.T) {
	now := time.Now()
	// Store returns events from multiple users
	allEvents := []*breakglass.BreakGlassEvent{
		{
			ID:         "abc123def4567890",
			Invoker:    "alice",
			Profile:    "dev",
			Status:     breakglass.StatusActive,
			ReasonCode: breakglass.ReasonIncident,
			CreatedAt:  now,
			ExpiresAt:  now.Add(4 * time.Hour),
		},
		{
			ID:         "def456ghi7890123",
			Invoker:    "bob",
			Profile:    "staging",
			Status:     breakglass.StatusActive,
			ReasonCode: breakglass.ReasonMaintenance,
			CreatedAt:  now.Add(-30 * time.Minute),
			ExpiresAt:  now.Add(3 * time.Hour),
		},
	}

	store := &mockBreakGlassStore{
		listByStatusFn: func(ctx context.Context, status breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error) {
			return allEvents, nil
		},
	}

	// Filter by status=active AND invoker=alice
	input := BreakGlassListCommandInput{
		Status:  "active",
		Invoker: "alice",
		Store:   store,
		Limit:   100,
	}

	summaries, err := testableBreakGlassListCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should filter to only alice's events
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary (filtered), got %d", len(summaries))
	}

	if summaries[0].Invoker != "alice" {
		t.Errorf("expected invoker 'alice', got %s", summaries[0].Invoker)
	}
}

func TestBreakGlassListCommand_AllStatusValues(t *testing.T) {
	statuses := []string{"active", "closed", "expired"}

	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			now := time.Now()
			expectedEvents := []*breakglass.BreakGlassEvent{
				{
					ID:         "abc123def4567890",
					Invoker:    "testuser",
					Profile:    "test-profile",
					Status:     breakglass.BreakGlassStatus(status),
					ReasonCode: breakglass.ReasonIncident,
					CreatedAt:  now,
					ExpiresAt:  now.Add(4 * time.Hour),
				},
			}

			var calledStatus breakglass.BreakGlassStatus
			store := &mockBreakGlassStore{
				listByStatusFn: func(ctx context.Context, s breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error) {
					calledStatus = s
					return expectedEvents, nil
				},
			}

			input := BreakGlassListCommandInput{
				Status: status,
				Store:  store,
				Limit:  100,
			}

			summaries, err := testableBreakGlassListCommand(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error for status %s: %v", status, err)
			}

			// Verify correct status was queried
			if calledStatus != breakglass.BreakGlassStatus(status) {
				t.Errorf("expected status %q, got %q", status, calledStatus)
			}

			// Verify results
			if len(summaries) != 1 {
				t.Fatalf("expected 1 summary, got %d", len(summaries))
			}

			if summaries[0].Status != status {
				t.Errorf("expected status %q in output, got %q", status, summaries[0].Status)
			}
		})
	}
}

func TestBreakGlassListCommand_OutputContainsReasonCode(t *testing.T) {
	now := time.Now()
	expectedEvents := []*breakglass.BreakGlassEvent{
		{
			ID:         "abc123def4567890",
			Invoker:    "testuser",
			Profile:    "production",
			Status:     breakglass.StatusActive,
			ReasonCode: breakglass.ReasonSecurity,
			CreatedAt:  now,
			ExpiresAt:  now.Add(4 * time.Hour),
		},
	}

	store := &mockBreakGlassStore{
		listByInvokerFn: func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
			return expectedEvents, nil
		},
	}

	input := BreakGlassListCommandInput{
		Store: store,
		Limit: 100,
	}

	summaries, err := testableBreakGlassListCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	// Verify reason_code is included in output
	if summaries[0].ReasonCode != "security" {
		t.Errorf("expected reason_code 'security', got %q", summaries[0].ReasonCode)
	}
}
