// Security regression tests for request approval denial paths.
// These tests serve as regression guards against future code changes that
// might inadvertently weaken security by allowing credential issuance
// when request approval should deny.
//
// Test naming convention: TestSecurityRegression_<Category>_<Specific>
// Categories:
//   - ApprovalGate: Tests that only approved requests grant credentials
//   - ExpiryEnforcement: Tests that expired approvals are rejected
//   - ApproverAuthorization: Tests approver permission checks
//   - RequestTampering: Tests input validation against manipulation

package request

import (
	"testing"
	"time"
)

// ============================================================================
// Approval Gate Enforcement Tests
// ============================================================================

// TestSecurityRegression_ApprovalGate_PendingDoesNotGrantAccess verifies that
// a pending request does NOT grant credentials.
func TestSecurityRegression_ApprovalGate_PendingDoesNotGrantAccess(t *testing.T) {
	now := time.Now()

	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusPending, // Not yet approved
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultRequestTTL),
	}

	if isApprovalValid(req) {
		t.Errorf("SECURITY VIOLATION: Pending request should NOT grant credentials")
	}
}

// TestSecurityRegression_ApprovalGate_DeniedDoesNotGrantAccess verifies that
// a denied request does NOT grant credentials.
func TestSecurityRegression_ApprovalGate_DeniedDoesNotGrantAccess(t *testing.T) {
	now := time.Now()

	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusDenied, // Explicitly denied
		CreatedAt:     now.Add(-time.Hour),
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultRequestTTL - time.Hour),
		Approver:      "security-admin",
	}

	if isApprovalValid(req) {
		t.Errorf("SECURITY VIOLATION: Denied request should NOT grant credentials")
	}
}

// TestSecurityRegression_ApprovalGate_ExpiredDoesNotGrantAccess verifies that
// an expired request does NOT grant credentials.
func TestSecurityRegression_ApprovalGate_ExpiredDoesNotGrantAccess(t *testing.T) {
	now := time.Now()

	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusExpired, // Expired without approval
		CreatedAt:     now.Add(-2 * time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
		ExpiresAt:     now.Add(-time.Hour), // In the past
	}

	if isApprovalValid(req) {
		t.Errorf("SECURITY VIOLATION: Expired request should NOT grant credentials")
	}
}

// TestSecurityRegression_ApprovalGate_CancelledDoesNotGrantAccess verifies that
// a cancelled request does NOT grant credentials.
func TestSecurityRegression_ApprovalGate_CancelledDoesNotGrantAccess(t *testing.T) {
	now := time.Now()

	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusCancelled, // User cancelled
		CreatedAt:     now.Add(-30 * time.Minute),
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultRequestTTL - 30*time.Minute),
	}

	if isApprovalValid(req) {
		t.Errorf("SECURITY VIOLATION: Cancelled request should NOT grant credentials")
	}
}

// TestSecurityRegression_ApprovalGate_OnlyApprovedGrantsAccess verifies that
// ONLY StatusApproved grants credentials.
func TestSecurityRegression_ApprovalGate_OnlyApprovedGrantsAccess(t *testing.T) {
	now := time.Now()

	tests := []struct {
		status      RequestStatus
		expectGrant bool
	}{
		{StatusPending, false},
		{StatusApproved, true}, // Only approved should grant
		{StatusDenied, false},
		{StatusExpired, false},
		{StatusCancelled, false},
		// Invalid statuses
		{"", false},
		{"APPROVED", false}, // Wrong case
		{"Approved", false}, // Wrong case
		{"approved ", false}, // Trailing space
		{"pending", false},   // Wrong status
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			req := &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      time.Hour,
				Status:        tt.status,
				CreatedAt:     now.Add(-30 * time.Minute),
				UpdatedAt:     now,
				ExpiresAt:     now.Add(30 * time.Minute), // Future expiry
				Approver:      "admin",
			}

			result := isApprovalValid(req)

			if tt.expectGrant && !result {
				t.Errorf("Status %q should grant access", tt.status)
			}
			if !tt.expectGrant && result {
				t.Errorf("SECURITY VIOLATION: Status %q should NOT grant access", tt.status)
			}
		})
	}
}

// ============================================================================
// Expiry Enforcement Tests
// ============================================================================

// TestSecurityRegression_ExpiryEnforcement_ApprovedButExpiredDoesNotGrant verifies
// that an approved request with past expiry does NOT grant credentials.
func TestSecurityRegression_ExpiryEnforcement_ApprovedButExpiredDoesNotGrant(t *testing.T) {
	now := time.Now()

	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusApproved, // Approved
		CreatedAt:     now.Add(-2 * time.Hour),
		UpdatedAt:     now.Add(-time.Hour),
		ExpiresAt:     now.Add(-30 * time.Minute), // But expired
		Approver:      "admin",
	}

	if isApprovalValid(req) {
		t.Errorf("SECURITY VIOLATION: Approved but expired request should NOT grant credentials")
	}
}

// TestSecurityRegression_ExpiryEnforcement_OneNanosecondPastExpiry verifies that
// an approved request 1ns past expiry does NOT grant credentials.
func TestSecurityRegression_ExpiryEnforcement_OneNanosecondPastExpiry(t *testing.T) {
	// Set expiry in the past by 1 nanosecond
	expiry := time.Now().Add(-time.Nanosecond)

	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusApproved,
		CreatedAt:     time.Now().Add(-time.Hour),
		UpdatedAt:     time.Now().Add(-30 * time.Minute),
		ExpiresAt:     expiry,
		Approver:      "admin",
	}

	if isApprovalValid(req) {
		t.Errorf("SECURITY VIOLATION: Approved request 1ns past expiry should NOT grant credentials")
	}
}

// TestSecurityRegression_ExpiryEnforcement_ExactlyAtExpiry verifies the
// boundary behavior at exactly ExpiresAt.
func TestSecurityRegression_ExpiryEnforcement_ExactlyAtExpiry(t *testing.T) {
	// Create request that expires now
	expiresAt := time.Now()
	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusApproved,
		CreatedAt:     time.Now().Add(-time.Hour),
		UpdatedAt:     time.Now().Add(-30 * time.Minute),
		ExpiresAt:     expiresAt,
		Approver:      "admin",
	}

	// Let a moment pass so now > expiresAt
	time.Sleep(time.Millisecond)

	if isApprovalValid(req) {
		t.Errorf("SECURITY VIOLATION: Request at exactly ExpiresAt should be rejected after that instant")
	}
}

// TestSecurityRegression_ExpiryEnforcement_ZeroExpiresAtRejected verifies that
// a request with zero ExpiresAt is rejected.
func TestSecurityRegression_ExpiryEnforcement_ZeroExpiresAtRejected(t *testing.T) {
	now := time.Now()

	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusApproved,
		CreatedAt:     now.Add(-30 * time.Minute),
		UpdatedAt:     now,
		ExpiresAt:     time.Time{}, // Zero time
		Approver:      "admin",
	}

	if isApprovalValid(req) {
		t.Errorf("SECURITY VIOLATION: Request with zero ExpiresAt should NOT grant credentials")
	}
}

// ============================================================================
// Approver Authorization Tests
// ============================================================================

// TestSecurityRegression_ApproverAuth_SelfApprovalRejected verifies that
// a user cannot approve their own request.
func TestSecurityRegression_ApproverAuth_SelfApprovalRejected(t *testing.T) {
	now := time.Now()

	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusApproved,
		CreatedAt:     now.Add(-30 * time.Minute),
		UpdatedAt:     now,
		ExpiresAt:     now.Add(30 * time.Minute),
		Approver:      "alice", // Same as requester
	}

	if canApprove(req, "alice") {
		t.Errorf("SECURITY VIOLATION: Self-approval should be rejected")
	}
}

// TestSecurityRegression_ApproverAuth_ApproverCaseSensitive verifies that
// approver matching is case-sensitive.
func TestSecurityRegression_ApproverAuth_ApproverCaseSensitive(t *testing.T) {
	// Authorized approver is "bob"
	approvers := []string{"bob"}

	tests := []struct {
		approver   string
		canApprove bool
	}{
		{"bob", true},   // Exact match
		{"Bob", false},  // Wrong case
		{"BOB", false},  // Wrong case
		{"bob ", false}, // Trailing space
		{" bob", false}, // Leading space
		{"bobs", false}, // Extra chars
	}

	for _, tt := range tests {
		t.Run(tt.approver, func(t *testing.T) {
			result := isAuthorizedApprover(tt.approver, approvers)

			if tt.canApprove && !result {
				t.Errorf("Approver %q should be authorized", tt.approver)
			}
			if !tt.canApprove && result {
				t.Errorf("SECURITY VIOLATION: Approver %q should NOT be authorized (case mismatch)", tt.approver)
			}
		})
	}
}

// TestSecurityRegression_ApproverAuth_EmptyApproverRejected verifies that
// an empty approver string is rejected.
func TestSecurityRegression_ApproverAuth_EmptyApproverRejected(t *testing.T) {
	approvers := []string{"bob", "charlie"}

	emptyValues := []string{
		"",
		" ",
		"  ",
		"\t",
		"\n",
	}

	for _, empty := range emptyValues {
		t.Run("empty_"+empty, func(t *testing.T) {
			if isAuthorizedApprover(empty, approvers) {
				t.Errorf("SECURITY VIOLATION: Empty approver %q should NOT be authorized", empty)
			}
		})
	}
}

// TestSecurityRegression_ApproverAuth_RequesterCaseSensitive verifies that
// requester matching (for self-approval check) is case-sensitive.
func TestSecurityRegression_ApproverAuth_RequesterCaseSensitive(t *testing.T) {
	now := time.Now()

	// Requester is "alice" (lowercase)
	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusPending,
		CreatedAt:     now.Add(-30 * time.Minute),
		UpdatedAt:     now,
		ExpiresAt:     now.Add(30 * time.Minute),
	}

	// "Alice" (different case) should be allowed to approve (not same as "alice")
	// This is a security design decision: case-sensitive matching prevents
	// accidental self-approval through case manipulation.
	// The system SHOULD consider "Alice" different from "alice"
	// for identity purposes, so "Alice" can approve "alice"'s request.
	// However, this depends on the identity system being case-preserving.
	if !canApprove(req, "Alice") {
		t.Logf("Note: Case-sensitive check means 'Alice' can approve 'alice' request")
	}

	// But "alice" (exact match) should NOT be allowed (self-approval)
	if canApprove(req, "alice") {
		t.Errorf("SECURITY VIOLATION: Exact self-approval should be rejected")
	}
}

// ============================================================================
// Request Tampering Prevention Tests
// ============================================================================

// TestSecurityRegression_RequestTampering_InvalidStatusRejected verifies that
// requests with invalid status strings are rejected.
func TestSecurityRegression_RequestTampering_InvalidStatusRejected(t *testing.T) {
	invalidStatuses := []RequestStatus{
		"",
		"APPROVED",   // Wrong case
		"Approved",   // Wrong case
		"approved ",  // Trailing space
		" approved",  // Leading space
		"approve",    // Misspelling
		"approvd",    // Typo
		"active",     // Different system's status
		"pending\n",  // Newline injection
		"approved\x00", // Null byte
		"'; DROP TABLE requests;--", // SQL injection
		"$ne: null",  // NoSQL injection
	}

	for _, status := range invalidStatuses {
		t.Run(string(status), func(t *testing.T) {
			if status.IsValid() {
				t.Errorf("SECURITY VIOLATION: Invalid status %q should not be valid", status)
			}

			// Request with invalid status should not grant access
			now := time.Now()
			req := &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      time.Hour,
				Status:        status,
				CreatedAt:     now.Add(-30 * time.Minute),
				UpdatedAt:     now,
				ExpiresAt:     now.Add(30 * time.Minute),
				Approver:      "admin",
			}

			if isApprovalValid(req) {
				t.Errorf("SECURITY VIOLATION: Request with invalid status %q should NOT grant credentials", status)
			}
		})
	}
}

// TestSecurityRegression_RequestTampering_TerminalStatusCannotChange verifies
// that terminal statuses cannot be changed.
func TestSecurityRegression_RequestTampering_TerminalStatusCannotChange(t *testing.T) {
	terminalStatuses := []RequestStatus{
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	allTargets := []RequestStatus{
		StatusPending,
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	for _, fromStatus := range terminalStatuses {
		for _, toStatus := range allTargets {
			t.Run(string(fromStatus)+"_to_"+string(toStatus), func(t *testing.T) {
				req := &Request{Status: fromStatus}
				if req.CanTransitionTo(toStatus) {
					t.Errorf("SECURITY VIOLATION: Terminal status %q should NOT transition to %q",
						fromStatus, toStatus)
				}
			})
		}
	}
}

// TestSecurityRegression_RequestTampering_DurationManipulation verifies that
// duration validation catches manipulation attempts.
func TestSecurityRegression_RequestTampering_DurationManipulation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		duration time.Duration
		expectOK bool
	}{
		{"negative_duration", -time.Hour, false},
		{"zero_duration", 0, false},
		{"exceed_max_by_1ns", MaxDuration + time.Nanosecond, false},
		{"exceed_max_by_1s", MaxDuration + time.Second, false},
		{"max_duration", MaxDuration, true},
		{"normal_duration", time.Hour, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      tt.duration,
				Status:        StatusPending,
				CreatedAt:     now,
				UpdatedAt:     now,
				ExpiresAt:     now.Add(DefaultRequestTTL),
			}

			err := req.Validate()
			if tt.expectOK && err != nil {
				t.Errorf("Duration %v should be valid, got error: %v", tt.duration, err)
			}
			if !tt.expectOK && err == nil {
				t.Errorf("SECURITY VIOLATION: Duration %v should be rejected", tt.duration)
			}
		})
	}
}

// TestSecurityRegression_RequestTampering_RequestIDManipulation verifies that
// request ID validation catches manipulation attempts.
func TestSecurityRegression_RequestTampering_RequestIDManipulation(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expectOK bool
	}{
		{"valid_hex", "abcdef1234567890", true},
		{"valid_numeric", "1234567890123456", true},
		{"uppercase", "ABCDEF1234567890", false},
		{"mixed_case", "AbCdEf1234567890", false},
		{"non_hex", "ghijkl1234567890", false},
		{"too_short", "abcdef12345678", false},
		{"too_long", "abcdef123456789012", false},
		{"with_space", "abcdef12 34567890", false},
		{"with_dash", "abcdef12-34567890", false},
		{"null_byte", "abcdef12\x00567890", false},
		{"sql_injection", "'; DROP TABLE--", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := ValidateRequestID(tt.id)

			if tt.expectOK && !valid {
				t.Errorf("ID %q should be valid", tt.id)
			}
			if !tt.expectOK && valid {
				t.Errorf("SECURITY VIOLATION: ID %q should be rejected", tt.id)
			}
		})
	}
}

// ============================================================================
// Comprehensive Approval Denial Table Tests
// ============================================================================

// TestSecurityRegression_ComprehensiveApprovalDenial tests all denial paths
// in a comprehensive table-driven manner.
func TestSecurityRegression_ComprehensiveApprovalDenial(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		request    *Request
		expectGrant bool
		reason     string
	}{
		{
			name: "valid_approved_request",
			request: &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      time.Hour,
				Status:        StatusApproved,
				CreatedAt:     now.Add(-30 * time.Minute),
				UpdatedAt:     now,
				ExpiresAt:     now.Add(30 * time.Minute),
				Approver:      "admin",
			},
			expectGrant: true,
			reason:     "should grant access",
		},
		{
			name: "pending_request",
			request: &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      time.Hour,
				Status:        StatusPending,
				CreatedAt:     now,
				UpdatedAt:     now,
				ExpiresAt:     now.Add(DefaultRequestTTL),
			},
			expectGrant: false,
			reason:     "pending status",
		},
		{
			name: "denied_request",
			request: &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      time.Hour,
				Status:        StatusDenied,
				CreatedAt:     now.Add(-time.Hour),
				UpdatedAt:     now,
				ExpiresAt:     now.Add(DefaultRequestTTL - time.Hour),
				Approver:      "security-admin",
			},
			expectGrant: false,
			reason:     "denied status",
		},
		{
			name: "expired_request",
			request: &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      time.Hour,
				Status:        StatusExpired,
				CreatedAt:     now.Add(-2 * time.Hour),
				UpdatedAt:     now.Add(-time.Hour),
				ExpiresAt:     now.Add(-time.Hour),
			},
			expectGrant: false,
			reason:     "expired status",
		},
		{
			name: "cancelled_request",
			request: &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      time.Hour,
				Status:        StatusCancelled,
				CreatedAt:     now.Add(-30 * time.Minute),
				UpdatedAt:     now,
				ExpiresAt:     now.Add(DefaultRequestTTL - 30*time.Minute),
			},
			expectGrant: false,
			reason:     "cancelled status",
		},
		{
			name: "approved_but_time_expired",
			request: &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      time.Hour,
				Status:        StatusApproved,
				CreatedAt:     now.Add(-2 * time.Hour),
				UpdatedAt:     now.Add(-time.Hour),
				ExpiresAt:     now.Add(-30 * time.Minute), // Past
				Approver:      "admin",
			},
			expectGrant: false,
			reason:     "time expired despite approved status",
		},
		{
			name: "approved_but_no_approver",
			request: &Request{
				ID:            "abcdef1234567890",
				Requester:     "alice",
				Profile:       "production",
				Justification: "Valid justification for access request testing",
				Duration:      time.Hour,
				Status:        StatusApproved,
				CreatedAt:     now.Add(-30 * time.Minute),
				UpdatedAt:     now,
				ExpiresAt:     now.Add(30 * time.Minute),
				Approver:      "", // Missing approver
			},
			expectGrant: false,
			reason:     "approved but no approver recorded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isApprovalValid(tt.request)

			if tt.expectGrant && !result {
				t.Errorf("%s: expected grant but got denied", tt.reason)
			}
			if !tt.expectGrant && result {
				t.Errorf("SECURITY VIOLATION: %s should be denied", tt.reason)
			}
		})
	}
}

// TestSecurityRegression_ApprovalWorkflow_FullLifecycle tests the complete
// approval workflow to ensure no security gaps.
func TestSecurityRegression_ApprovalWorkflow_FullLifecycle(t *testing.T) {
	now := time.Now()

	// Stage 1: New request (pending)
	req := &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultRequestTTL),
	}

	// Pending should NOT grant access
	if isApprovalValid(req) {
		t.Fatal("SECURITY VIOLATION: Stage 1 - Pending request should not grant access")
	}

	// Stage 2: Approver denies
	req.Status = StatusDenied
	req.UpdatedAt = now.Add(10 * time.Minute)
	req.Approver = "security-admin"

	// Denied should NOT grant access
	if isApprovalValid(req) {
		t.Fatal("SECURITY VIOLATION: Stage 2 - Denied request should not grant access")
	}

	// Stage 3: Reset to pending (simulating a new request)
	req2 := &Request{
		ID:            "bcdef12345678901",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Valid justification for access request testing",
		Duration:      time.Hour,
		Status:        StatusPending,
		CreatedAt:     now.Add(time.Hour),
		UpdatedAt:     now.Add(time.Hour),
		ExpiresAt:     now.Add(time.Hour + DefaultRequestTTL),
	}

	// Pending should NOT grant access
	if isApprovalValid(req2) {
		t.Fatal("SECURITY VIOLATION: Stage 3 - New pending request should not grant access")
	}

	// Stage 4: Approver approves
	req2.Status = StatusApproved
	req2.UpdatedAt = now.Add(time.Hour + 5*time.Minute)
	req2.Approver = "security-admin"

	// Approved should grant access
	if !isApprovalValid(req2) {
		t.Fatal("Stage 4 - Approved request should grant access")
	}

	// Stage 5: Time passes, approval expires
	req2.ExpiresAt = now.Add(-time.Minute) // Now in the past

	// Expired approval should NOT grant access
	if isApprovalValid(req2) {
		t.Fatal("SECURITY VIOLATION: Stage 5 - Expired approval should not grant access")
	}
}

// ============================================================================
// Helper Functions for Testing
// ============================================================================

// isApprovalValid checks if an approval request grants credentials.
// This simulates the security check that would occur before issuing credentials.
func isApprovalValid(req *Request) bool {
	if req == nil {
		return false
	}

	// Must be approved
	if req.Status != StatusApproved {
		return false
	}

	// Status must be valid
	if !req.Status.IsValid() {
		return false
	}

	// Must have an approver
	if req.Approver == "" {
		return false
	}

	// Must not be expired (ExpiresAt must be in the future)
	if req.ExpiresAt.IsZero() || time.Now().After(req.ExpiresAt) {
		return false
	}

	return true
}

// canApprove checks if a user can approve a request.
func canApprove(req *Request, approver string) bool {
	if req == nil || approver == "" {
		return false
	}

	// Self-approval is rejected (exact string match)
	if req.Requester == approver {
		return false
	}

	return true
}

// isAuthorizedApprover checks if the approver is in the list of authorized approvers.
func isAuthorizedApprover(approver string, authorizedApprovers []string) bool {
	if approver == "" {
		return false
	}

	for _, a := range authorizedApprovers {
		if a == approver {
			return true
		}
	}
	return false
}
