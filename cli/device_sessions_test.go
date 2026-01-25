package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/byteness/aws-vault/v7/session"
)

// Test device IDs (64-char lowercase hex - SHA256 output format)
const (
	testDeviceID1 = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
	testDeviceID2 = "f9e8d7c6b5a4321098765432109876543210fedcba0987654321fedcba098765"
	testDeviceID3 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
)

// testableDeviceSessionsCommand is a testable version that uses mock store.
func testableDeviceSessionsCommand(ctx context.Context, input DeviceSessionsCommandInput) ([]DeviceSessionSummary, error) {
	// 1. Validate device ID format
	if len(input.DeviceID) != 64 {
		return nil, errors.New("invalid device ID format: " + input.DeviceID)
	}
	for _, c := range input.DeviceID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, errors.New("invalid device ID format: " + input.DeviceID)
		}
	}

	// 2. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 3. Query sessions by device ID
	limit := input.Limit
	if limit == 0 {
		limit = 100
	}
	sessions, err := store.ListByDeviceID(ctx, input.DeviceID, limit)
	if err != nil {
		return nil, err
	}

	// 4. Apply optional status filter
	if input.Status != "" {
		status := session.SessionStatus(input.Status)
		if !status.IsValid() {
			return nil, errors.New("invalid status: " + input.Status)
		}
		filtered := make([]*session.ServerSession, 0, len(sessions))
		for _, sess := range sessions {
			if sess.Status == status {
				filtered = append(filtered, sess)
			}
		}
		sessions = filtered
	}

	// 5. Format results
	summaries := make([]DeviceSessionSummary, 0, len(sessions))
	for _, sess := range sessions {
		summaries = append(summaries, DeviceSessionSummary{
			ID:               sess.ID,
			User:             sess.User,
			Profile:          sess.Profile,
			Status:           string(sess.Status),
			StartedAt:        sess.StartedAt,
			LastAccessAt:     sess.LastAccessAt,
			ExpiresAt:        sess.ExpiresAt,
			RequestCount:     sess.RequestCount,
			ServerInstanceID: sess.ServerInstanceID,
			SourceIdentity:   sess.SourceIdentity,
			DeviceID:         sess.DeviceID,
		})
	}

	return summaries, nil
}

// testableDevicesCommand is a testable version that uses mock store.
func testableDevicesCommand(ctx context.Context, input DevicesCommandInput) ([]DeviceAggregation, error) {
	// 1. Get store (must be provided for testing)
	store := input.Store
	if store == nil {
		return nil, errors.New("store is required for testing")
	}

	// 2. Query sessions based on --since flag or default to active
	var sessions []*session.ServerSession
	var err error
	limit := input.Limit
	if limit == 0 {
		limit = 1000
	}

	if input.Since != "" {
		// Parse --since duration
		sinceDuration, err := ParseDuration(input.Since)
		if err != nil {
			return nil, errors.New("invalid --since duration: " + err.Error())
		}
		sinceTime := time.Now().Add(-sinceDuration)

		// Query by time range
		sessions, err = store.ListByTimeRange(ctx, sinceTime, time.Now(), limit)
		if err != nil {
			return nil, err
		}
	} else {
		// Default to active sessions
		sessions, err = store.ListByStatus(ctx, session.StatusActive, limit)
		if err != nil {
			return nil, err
		}
	}

	// 3. Aggregate by device ID
	deviceMap := make(map[string]*deviceAggregator)
	for _, sess := range sessions {
		// Skip sessions without device ID
		if sess.DeviceID == "" {
			continue
		}

		agg, exists := deviceMap[sess.DeviceID]
		if !exists {
			agg = &deviceAggregator{
				deviceID:     sess.DeviceID,
				users:        make(map[string]bool),
				profiles:     make(map[string]bool),
				latestTime:   sess.StartedAt,
				sessionCount: 0,
			}
			deviceMap[sess.DeviceID] = agg
		}

		agg.sessionCount++
		agg.users[sess.User] = true
		agg.profiles[sess.Profile] = true
		if sess.StartedAt.After(agg.latestTime) {
			agg.latestTime = sess.StartedAt
		}
	}

	// 4. Convert to output format with anomaly detection
	profileThreshold := input.ProfileThreshold
	if profileThreshold == 0 {
		profileThreshold = 5
	}

	devices := make([]DeviceAggregation, 0, len(deviceMap))
	for deviceID, agg := range deviceMap {
		users := make([]string, 0, len(agg.users))
		for u := range agg.users {
			users = append(users, u)
		}

		profiles := make([]string, 0, len(agg.profiles))
		for p := range agg.profiles {
			profiles = append(profiles, p)
		}

		// Detect anomalies
		var anomalies []string
		if len(users) > 1 {
			anomalies = append(anomalies, "MULTI_USER")
		}
		if len(profiles) > profileThreshold {
			anomalies = append(anomalies, "HIGH_PROFILE_COUNT")
		}

		devices = append(devices, DeviceAggregation{
			DeviceID:         deviceID,
			SessionCount:     agg.sessionCount,
			UniqueUsers:      users,
			ProfilesAccessed: profiles,
			LatestSession:    agg.latestTime,
			Anomalies:        anomalies,
		})
	}

	return devices, nil
}

// TestDeviceSessionsCommand_Success tests valid device ID returns sessions.
func TestDeviceSessionsCommand_Success(t *testing.T) {
	now := time.Now()
	expectedSessions := []*session.ServerSession{
		{
			ID:               "abc123def4567890",
			User:             "alice",
			Profile:          "dev",
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now.Add(10 * time.Minute),
			ExpiresAt:        now.Add(30 * time.Minute),
			RequestCount:     42,
			ServerInstanceID: "server-1",
			DeviceID:         testDeviceID1,
		},
		{
			ID:               "def456ghi7890123",
			User:             "alice",
			Profile:          "staging",
			Status:           session.StatusActive,
			StartedAt:        now.Add(-1 * time.Hour),
			LastAccessAt:     now.Add(-30 * time.Minute),
			ExpiresAt:        now.Add(1 * time.Hour),
			RequestCount:     100,
			ServerInstanceID: "server-2",
			DeviceID:         testDeviceID1,
		},
	}

	var calledDeviceID string
	store := &mockSessionStore{
		listByDeviceIDFn: func(ctx context.Context, deviceID string, limit int) ([]*session.ServerSession, error) {
			calledDeviceID = deviceID
			return expectedSessions, nil
		},
	}

	input := DeviceSessionsCommandInput{
		DeviceID: testDeviceID1,
		Store:    store,
		Limit:    100,
	}

	summaries, err := testableDeviceSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByDeviceID was called with correct device ID
	if calledDeviceID != testDeviceID1 {
		t.Errorf("expected device ID %q, got %q", testDeviceID1, calledDeviceID)
	}

	// Verify results
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}

	if summaries[0].DeviceID != testDeviceID1 {
		t.Errorf("expected device ID %q in output, got %q", testDeviceID1, summaries[0].DeviceID)
	}
	if summaries[0].User != "alice" {
		t.Errorf("unexpected user: %s", summaries[0].User)
	}
	if summaries[0].RequestCount != 42 {
		t.Errorf("unexpected request count: %d", summaries[0].RequestCount)
	}
}

// TestDeviceSessionsCommand_InvalidDeviceID tests rejection of invalid format.
func TestDeviceSessionsCommand_InvalidDeviceID(t *testing.T) {
	invalidIDs := []string{
		"",    // empty
		"abc", // too short
		"ABCDEF1234567890" +
			"ABCDEF1234567890" +
			"ABCDEF1234567890" +
			"ABCDEF1234567890", // uppercase
		"a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345g",  // invalid hex char
		"a1b2c3d4e5f67890123456789012345",                                   // 31 chars (too short)
		"a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567", // 65 chars (too long)
	}

	store := &mockSessionStore{}

	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			input := DeviceSessionsCommandInput{
				DeviceID: id,
				Store:    store,
				Limit:    100,
			}

			_, err := testableDeviceSessionsCommand(context.Background(), input)
			if err == nil {
				t.Fatalf("expected error for invalid device ID %q", id)
			}
			if err.Error() != "invalid device ID format: "+id {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestDeviceSessionsCommand_NoSessions tests empty result handling.
func TestDeviceSessionsCommand_NoSessions(t *testing.T) {
	store := &mockSessionStore{
		listByDeviceIDFn: func(ctx context.Context, deviceID string, limit int) ([]*session.ServerSession, error) {
			return []*session.ServerSession{}, nil
		},
	}

	input := DeviceSessionsCommandInput{
		DeviceID: testDeviceID1,
		Store:    store,
		Limit:    100,
	}

	summaries, err := testableDeviceSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(summaries) != 0 {
		t.Fatalf("expected 0 summaries, got %d", len(summaries))
	}
}

// TestDeviceSessionsCommand_StatusFilter tests filtering by status.
func TestDeviceSessionsCommand_StatusFilter(t *testing.T) {
	now := time.Now()
	allSessions := []*session.ServerSession{
		{
			ID:       "abc123def4567890",
			User:     "alice",
			Profile:  "dev",
			Status:   session.StatusActive,
			DeviceID: testDeviceID1,
		},
		{
			ID:       "def456ghi7890123",
			User:     "alice",
			Profile:  "staging",
			Status:   session.StatusRevoked,
			DeviceID: testDeviceID1,
		},
		{
			ID:        "hij789klm0123456",
			User:      "alice",
			Profile:   "prod",
			Status:    session.StatusExpired,
			StartedAt: now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(-1 * time.Hour),
			DeviceID:  testDeviceID1,
		},
	}

	store := &mockSessionStore{
		listByDeviceIDFn: func(ctx context.Context, deviceID string, limit int) ([]*session.ServerSession, error) {
			return allSessions, nil
		},
	}

	// Filter to active only
	input := DeviceSessionsCommandInput{
		DeviceID: testDeviceID1,
		Status:   "active",
		Store:    store,
		Limit:    100,
	}

	summaries, err := testableDeviceSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should filter to only active sessions
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary (filtered to active), got %d", len(summaries))
	}

	if summaries[0].Status != "active" {
		t.Errorf("expected active status, got %s", summaries[0].Status)
	}
}

// TestDeviceSessionsCommand_JSONOutput tests JSON format output data.
func TestDeviceSessionsCommand_JSONOutput(t *testing.T) {
	now := time.Now()
	expectedSessions := []*session.ServerSession{
		{
			ID:               "abc123def4567890",
			User:             "alice",
			Profile:          "production",
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now.Add(5 * time.Minute),
			ExpiresAt:        now.Add(30 * time.Minute),
			RequestCount:     25,
			ServerInstanceID: "server-xyz",
			SourceIdentity:   "sentinel:alice:req123",
			DeviceID:         testDeviceID1,
		},
	}

	store := &mockSessionStore{
		listByDeviceIDFn: func(ctx context.Context, deviceID string, limit int) ([]*session.ServerSession, error) {
			return expectedSessions, nil
		},
	}

	input := DeviceSessionsCommandInput{
		DeviceID:     testDeviceID1,
		OutputFormat: "json",
		Store:        store,
		Limit:        100,
	}

	summaries, err := testableDeviceSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	// Verify all fields that would be in JSON output
	s := summaries[0]
	if s.ID != "abc123def4567890" {
		t.Errorf("unexpected ID: %s", s.ID)
	}
	if s.User != "alice" {
		t.Errorf("unexpected user: %s", s.User)
	}
	if s.Profile != "production" {
		t.Errorf("unexpected profile: %s", s.Profile)
	}
	if s.DeviceID != testDeviceID1 {
		t.Errorf("unexpected device ID: %s", s.DeviceID)
	}
	if s.SourceIdentity != "sentinel:alice:req123" {
		t.Errorf("unexpected source identity: %s", s.SourceIdentity)
	}
}

// TestDeviceSessionsCommand_CSVOutput tests CSV format includes device ID.
func TestDeviceSessionsCommand_CSVOutput(t *testing.T) {
	now := time.Now()
	expectedSessions := []*session.ServerSession{
		{
			ID:               "abc123def4567890",
			User:             "alice",
			Profile:          "production",
			Status:           session.StatusActive,
			StartedAt:        now,
			LastAccessAt:     now.Add(5 * time.Minute),
			ExpiresAt:        now.Add(30 * time.Minute),
			RequestCount:     25,
			ServerInstanceID: "server-xyz",
			DeviceID:         testDeviceID1,
		},
	}

	store := &mockSessionStore{
		listByDeviceIDFn: func(ctx context.Context, deviceID string, limit int) ([]*session.ServerSession, error) {
			return expectedSessions, nil
		},
	}

	input := DeviceSessionsCommandInput{
		DeviceID:     testDeviceID1,
		OutputFormat: "csv",
		Store:        store,
		Limit:        100,
	}

	summaries, err := testableDeviceSessionsCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify DeviceID field is populated for CSV output
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}

	if summaries[0].DeviceID != testDeviceID1 {
		t.Errorf("expected device ID %q, got %q", testDeviceID1, summaries[0].DeviceID)
	}
}

// TestDevicesCommand_Success tests listing unique devices.
func TestDevicesCommand_Success(t *testing.T) {
	now := time.Now()
	sessions := []*session.ServerSession{
		{
			ID:        "abc123def4567890",
			User:      "alice",
			Profile:   "dev",
			Status:    session.StatusActive,
			StartedAt: now,
			DeviceID:  testDeviceID1,
		},
		{
			ID:        "def456ghi7890123",
			User:      "alice",
			Profile:   "staging",
			Status:    session.StatusActive,
			StartedAt: now.Add(-1 * time.Hour),
			DeviceID:  testDeviceID1,
		},
		{
			ID:        "ghi789jkl0123456",
			User:      "bob",
			Profile:   "dev",
			Status:    session.StatusActive,
			StartedAt: now.Add(-30 * time.Minute),
			DeviceID:  testDeviceID2,
		},
	}

	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return sessions, nil
		},
	}

	input := DevicesCommandInput{
		Store: store,
		Limit: 1000,
	}

	devices, err := testableDevicesCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 2 unique devices
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}

	// Find device1 (alice's device with 2 sessions)
	var device1 *DeviceAggregation
	for i := range devices {
		if devices[i].DeviceID == testDeviceID1 {
			device1 = &devices[i]
			break
		}
	}

	if device1 == nil {
		t.Fatal("device1 not found in results")
	}

	if device1.SessionCount != 2 {
		t.Errorf("expected 2 sessions for device1, got %d", device1.SessionCount)
	}
	if len(device1.UniqueUsers) != 1 {
		t.Errorf("expected 1 unique user for device1, got %d", len(device1.UniqueUsers))
	}
	if len(device1.ProfilesAccessed) != 2 {
		t.Errorf("expected 2 profiles for device1, got %d", len(device1.ProfilesAccessed))
	}
}

// TestDevicesCommand_MultiUserAnomaly tests detection of multiple users from same device.
func TestDevicesCommand_MultiUserAnomaly(t *testing.T) {
	now := time.Now()
	sessions := []*session.ServerSession{
		{
			ID:        "abc123def4567890",
			User:      "alice",
			Profile:   "dev",
			Status:    session.StatusActive,
			StartedAt: now,
			DeviceID:  testDeviceID1,
		},
		{
			ID:        "def456ghi7890123",
			User:      "bob",
			Profile:   "staging",
			Status:    session.StatusActive,
			StartedAt: now.Add(-1 * time.Hour),
			DeviceID:  testDeviceID1,
		},
		{
			ID:        "ghi789jkl0123456",
			User:      "charlie",
			Profile:   "prod",
			Status:    session.StatusActive,
			StartedAt: now.Add(-2 * time.Hour),
			DeviceID:  testDeviceID1,
		},
	}

	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return sessions, nil
		},
	}

	input := DevicesCommandInput{
		Store: store,
		Limit: 1000,
	}

	devices, err := testableDevicesCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}

	device := devices[0]
	if len(device.UniqueUsers) != 3 {
		t.Errorf("expected 3 unique users, got %d", len(device.UniqueUsers))
	}

	// Should have MULTI_USER anomaly flag
	hasMultiUser := false
	for _, anomaly := range device.Anomalies {
		if anomaly == "MULTI_USER" {
			hasMultiUser = true
			break
		}
	}
	if !hasMultiUser {
		t.Errorf("expected MULTI_USER anomaly flag, got: %v", device.Anomalies)
	}
}

// TestDevicesCommand_HighProfileAnomaly tests detection of many profiles from single device.
func TestDevicesCommand_HighProfileAnomaly(t *testing.T) {
	now := time.Now()
	// Create sessions with 6 different profiles (threshold is 5)
	sessions := []*session.ServerSession{
		{ID: "a1", User: "alice", Profile: "profile1", Status: session.StatusActive, StartedAt: now, DeviceID: testDeviceID1},
		{ID: "a2", User: "alice", Profile: "profile2", Status: session.StatusActive, StartedAt: now, DeviceID: testDeviceID1},
		{ID: "a3", User: "alice", Profile: "profile3", Status: session.StatusActive, StartedAt: now, DeviceID: testDeviceID1},
		{ID: "a4", User: "alice", Profile: "profile4", Status: session.StatusActive, StartedAt: now, DeviceID: testDeviceID1},
		{ID: "a5", User: "alice", Profile: "profile5", Status: session.StatusActive, StartedAt: now, DeviceID: testDeviceID1},
		{ID: "a6", User: "alice", Profile: "profile6", Status: session.StatusActive, StartedAt: now, DeviceID: testDeviceID1},
	}

	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return sessions, nil
		},
	}

	input := DevicesCommandInput{
		Store:            store,
		ProfileThreshold: 5,
		Limit:            1000,
	}

	devices, err := testableDevicesCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}

	device := devices[0]
	if len(device.ProfilesAccessed) != 6 {
		t.Errorf("expected 6 profiles, got %d", len(device.ProfilesAccessed))
	}

	// Should have HIGH_PROFILE_COUNT anomaly flag
	hasHighProfile := false
	for _, anomaly := range device.Anomalies {
		if anomaly == "HIGH_PROFILE_COUNT" {
			hasHighProfile = true
			break
		}
	}
	if !hasHighProfile {
		t.Errorf("expected HIGH_PROFILE_COUNT anomaly flag, got: %v", device.Anomalies)
	}
}

// TestDevicesCommand_SinceFilter tests time-based filtering.
func TestDevicesCommand_SinceFilter(t *testing.T) {
	now := time.Now()
	sessions := []*session.ServerSession{
		{
			ID:        "abc123def4567890",
			User:      "alice",
			Profile:   "dev",
			Status:    session.StatusActive,
			StartedAt: now.Add(-2 * time.Hour),
			DeviceID:  testDeviceID1,
		},
	}

	var calledStartTime, calledEndTime time.Time
	store := &mockSessionStore{
		listByTimeRangeFn: func(ctx context.Context, startTime, endTime time.Time, limit int) ([]*session.ServerSession, error) {
			calledStartTime = startTime
			calledEndTime = endTime
			return sessions, nil
		},
	}

	input := DevicesCommandInput{
		Since: "24h",
		Store: store,
		Limit: 1000,
	}

	devices, err := testableDevicesCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ListByTimeRange was called
	expectedStart := now.Add(-24 * time.Hour)
	if calledStartTime.Before(expectedStart.Add(-2*time.Second)) || calledStartTime.After(expectedStart.Add(2*time.Second)) {
		t.Errorf("expected start time around %v, got %v", expectedStart, calledStartTime)
	}
	if calledEndTime.Before(now.Add(-2*time.Second)) || calledEndTime.After(now.Add(2*time.Second)) {
		t.Errorf("expected end time around %v, got %v", now, calledEndTime)
	}

	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
}

// TestDevicesCommand_JSONOutput tests JSON format output.
func TestDevicesCommand_JSONOutput(t *testing.T) {
	now := time.Now()
	sessions := []*session.ServerSession{
		{
			ID:        "abc123def4567890",
			User:      "alice",
			Profile:   "dev",
			Status:    session.StatusActive,
			StartedAt: now,
			DeviceID:  testDeviceID1,
		},
		{
			ID:        "def456ghi7890123",
			User:      "bob",
			Profile:   "staging",
			Status:    session.StatusActive,
			StartedAt: now.Add(-1 * time.Hour),
			DeviceID:  testDeviceID1,
		},
	}

	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return sessions, nil
		},
	}

	input := DevicesCommandInput{
		OutputFormat: "json",
		Store:        store,
		Limit:        1000,
	}

	devices, err := testableDevicesCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}

	device := devices[0]
	if device.DeviceID != testDeviceID1 {
		t.Errorf("expected device ID %q, got %q", testDeviceID1, device.DeviceID)
	}
	if device.SessionCount != 2 {
		t.Errorf("expected 2 sessions, got %d", device.SessionCount)
	}
	if len(device.UniqueUsers) != 2 {
		t.Errorf("expected 2 unique users, got %d", len(device.UniqueUsers))
	}
	// Should have MULTI_USER anomaly since alice and bob both used same device
	hasMultiUser := false
	for _, a := range device.Anomalies {
		if a == "MULTI_USER" {
			hasMultiUser = true
			break
		}
	}
	if !hasMultiUser {
		t.Errorf("expected MULTI_USER anomaly, got: %v", device.Anomalies)
	}
}

// TestDevicesCommand_NoDevices tests empty sessions handling.
func TestDevicesCommand_NoDevices(t *testing.T) {
	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return []*session.ServerSession{}, nil
		},
	}

	input := DevicesCommandInput{
		Store: store,
		Limit: 1000,
	}

	devices, err := testableDevicesCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(devices) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(devices))
	}
}

// TestDevicesCommand_SessionsWithoutDeviceID tests that sessions without device ID are skipped.
func TestDevicesCommand_SessionsWithoutDeviceID(t *testing.T) {
	now := time.Now()
	sessions := []*session.ServerSession{
		{
			ID:        "abc123def4567890",
			User:      "alice",
			Profile:   "dev",
			Status:    session.StatusActive,
			StartedAt: now,
			DeviceID:  testDeviceID1,
		},
		{
			ID:        "def456ghi7890123",
			User:      "bob",
			Profile:   "staging",
			Status:    session.StatusActive,
			StartedAt: now.Add(-1 * time.Hour),
			DeviceID:  "", // No device ID
		},
	}

	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return sessions, nil
		},
	}

	input := DevicesCommandInput{
		Store: store,
		Limit: 1000,
	}

	devices, err := testableDevicesCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have 1 device (the one with device ID)
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}

	if devices[0].DeviceID != testDeviceID1 {
		t.Errorf("expected device ID %q, got %q", testDeviceID1, devices[0].DeviceID)
	}
}

// TestDevicesCommand_NoAnomaliesWhenSingleUser tests no anomaly for single user.
func TestDevicesCommand_NoAnomaliesWhenSingleUser(t *testing.T) {
	now := time.Now()
	sessions := []*session.ServerSession{
		{
			ID:        "abc123def4567890",
			User:      "alice",
			Profile:   "dev",
			Status:    session.StatusActive,
			StartedAt: now,
			DeviceID:  testDeviceID1,
		},
		{
			ID:        "def456ghi7890123",
			User:      "alice",
			Profile:   "staging",
			Status:    session.StatusActive,
			StartedAt: now.Add(-1 * time.Hour),
			DeviceID:  testDeviceID1,
		},
	}

	store := &mockSessionStore{
		listByStatusFn: func(ctx context.Context, status session.SessionStatus, limit int) ([]*session.ServerSession, error) {
			return sessions, nil
		},
	}

	input := DevicesCommandInput{
		Store:            store,
		ProfileThreshold: 5,
		Limit:            1000,
	}

	devices, err := testableDevicesCommand(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}

	device := devices[0]
	// Single user with 2 profiles should have no anomalies
	if len(device.Anomalies) != 0 {
		t.Errorf("expected no anomalies for single user with few profiles, got: %v", device.Anomalies)
	}
}
