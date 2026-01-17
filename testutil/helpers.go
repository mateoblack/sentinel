package testutil

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// ============================================================================
// Time helpers
// ============================================================================

// MustParseTime parses a time string using the given layout and panics on error.
// Useful for test data initialization where parse errors indicate a test bug.
//
// Example:
//
//	t := MustParseTime(time.RFC3339, "2024-01-15T10:00:00Z")
func MustParseTime(layout, value string) time.Time {
	t, err := time.Parse(layout, value)
	if err != nil {
		panic("testutil.MustParseTime: " + err.Error())
	}
	return t
}

// FixedClock returns a function that always returns the given time.
// Useful for testing time-dependent logic with deterministic values.
//
// Example:
//
//	now := time.Now()
//	clock := FixedClock(now)
//	// clock() always returns now
func FixedClock(t time.Time) func() time.Time {
	return func() time.Time {
		return t
	}
}

// ============================================================================
// Policy helpers
// ============================================================================

// MakeAllowPolicy creates a simple allow policy for the given profile.
// The policy allows any user to access the profile at any time.
//
// Example:
//
//	pol := MakeAllowPolicy("production")
func MakeAllowPolicy(profile string) *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-" + profile,
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{profile},
				},
			},
		},
	}
}

// MakeDenyPolicy creates a simple deny policy for the given profile.
// The policy denies any user access to the profile at any time.
//
// Example:
//
//	pol := MakeDenyPolicy("production")
func MakeDenyPolicy(profile string) *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "deny-" + profile,
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Profiles: []string{profile},
				},
				Reason: "Access denied by test policy",
			},
		},
	}
}

// MakeRequireApprovalPolicy creates a require-approval policy for the given profile.
// The policy requires approval for any user accessing the profile.
//
// Example:
//
//	pol := MakeRequireApprovalPolicy("production")
func MakeRequireApprovalPolicy(profile string) *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "require-approval-" + profile,
				Effect: policy.EffectRequireApproval,
				Conditions: policy.Condition{
					Profiles: []string{profile},
				},
			},
		},
	}
}

// MakeUserAllowPolicy creates an allow policy for a specific user and profile.
//
// Example:
//
//	pol := MakeUserAllowPolicy("alice", "production")
func MakeUserAllowPolicy(user, profile string) *policy.Policy {
	return &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-" + user + "-" + profile,
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: []string{profile},
					Users:    []string{user},
				},
			},
		},
	}
}

// ============================================================================
// Request helpers
// ============================================================================

// MakeRequest creates a test request with sensible defaults.
// The request is in pending status with a 1-hour duration.
//
// Example:
//
//	req := MakeRequest("alice", "production")
func MakeRequest(user, profile string) *request.Request {
	now := time.Now()
	return &request.Request{
		ID:            request.NewRequestID(),
		Requester:     user,
		Profile:       profile,
		Justification: "Test request for " + profile + " access",
		Duration:      1 * time.Hour,
		Status:        request.StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(request.DefaultRequestTTL),
	}
}

// MakeApprovedRequest creates a test request in approved status.
// The request includes an approver and approval comment.
//
// Example:
//
//	req := MakeApprovedRequest("alice", "production")
func MakeApprovedRequest(user, profile string) *request.Request {
	now := time.Now()
	return &request.Request{
		ID:              request.NewRequestID(),
		Requester:       user,
		Profile:         profile,
		Justification:   "Test request for " + profile + " access",
		Duration:        1 * time.Hour,
		Status:          request.StatusApproved,
		CreatedAt:       now.Add(-10 * time.Minute),
		UpdatedAt:       now,
		ExpiresAt:       now.Add(request.DefaultRequestTTL - 10*time.Minute),
		Approver:        "test-approver",
		ApproverComment: "Approved for testing",
	}
}

// MakeRequestWithDuration creates a test request with a specific duration.
//
// Example:
//
//	req := MakeRequestWithDuration("alice", "production", 4*time.Hour)
func MakeRequestWithDuration(user, profile string, duration time.Duration) *request.Request {
	req := MakeRequest(user, profile)
	req.Duration = duration
	return req
}

// MakeRequestWithJustification creates a test request with a specific justification.
//
// Example:
//
//	req := MakeRequestWithJustification("alice", "production", "Emergency fix for TICKET-123")
func MakeRequestWithJustification(user, profile, justification string) *request.Request {
	req := MakeRequest(user, profile)
	req.Justification = justification
	return req
}

// MakeDeniedRequest creates a test request in denied status.
//
// Example:
//
//	req := MakeDeniedRequest("alice", "production")
func MakeDeniedRequest(user, profile string) *request.Request {
	now := time.Now()
	return &request.Request{
		ID:              request.NewRequestID(),
		Requester:       user,
		Profile:         profile,
		Justification:   "Test request for " + profile + " access",
		Duration:        1 * time.Hour,
		Status:          request.StatusDenied,
		CreatedAt:       now.Add(-10 * time.Minute),
		UpdatedAt:       now,
		ExpiresAt:       now.Add(request.DefaultRequestTTL - 10*time.Minute),
		Approver:        "test-approver",
		ApproverComment: "Denied for testing",
	}
}

// MakeExpiredRequest creates a test request in expired status.
//
// Example:
//
//	req := MakeExpiredRequest("alice", "production")
func MakeExpiredRequest(user, profile string) *request.Request {
	now := time.Now()
	createdAt := now.Add(-48 * time.Hour)
	return &request.Request{
		ID:            request.NewRequestID(),
		Requester:     user,
		Profile:       profile,
		Justification: "Test request for " + profile + " access",
		Duration:      1 * time.Hour,
		Status:        request.StatusExpired,
		CreatedAt:     createdAt,
		UpdatedAt:     createdAt.Add(request.DefaultRequestTTL),
		ExpiresAt:     createdAt.Add(request.DefaultRequestTTL),
	}
}

// ============================================================================
// Credential helpers
// ============================================================================

// MakeCredentials creates test AWS credentials with reasonable defaults.
// The credentials are valid for 1 hour from now.
//
// Example:
//
//	creds := MakeCredentials()
func MakeCredentials() aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
		CanExpire:       true,
		Expires:         time.Now().Add(1 * time.Hour),
	}
}

// MakeExpiredCredentials creates test AWS credentials that have already expired.
// Useful for testing credential refresh logic.
//
// Example:
//
//	creds := MakeExpiredCredentials()
func MakeExpiredCredentials() aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     "TEST-ACCESS-KEY-EXPIRED",
		SecretAccessKey: "TEST-SECRET-KEY-EXPIRED",
		SessionToken:    "AQoDYXdzEJr...(expired)",
		CanExpire:       true,
		Expires:         time.Now().Add(-1 * time.Hour),
	}
}

// MakeCredentialsExpiring creates test AWS credentials that expire at a specific time.
//
// Example:
//
//	creds := MakeCredentialsExpiring(time.Now().Add(5 * time.Minute))
func MakeCredentialsExpiring(expiresAt time.Time) aws.Credentials {
	return aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr...",
		CanExpire:       true,
		Expires:         expiresAt,
	}
}

// ============================================================================
// Assertion helpers
// ============================================================================

// AssertErrorIs checks if got error matches want error using errors.Is.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertErrorIs(t, err, request.ErrRequestNotFound)
func AssertErrorIs(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Errorf("error mismatch:\n  got:  %v\n  want: %v", got, want)
	}
}

// AssertNoError fails the test if err is not nil.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertNoError(t, err)
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// AssertError fails the test if err is nil.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertError(t, err)
func AssertError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// AssertContains checks if got string contains substr.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertContains(t, err.Error(), "not found")
func AssertContains(t *testing.T, got, substr string) {
	t.Helper()
	if !strings.Contains(got, substr) {
		t.Errorf("string does not contain expected substring:\n  got:    %q\n  substr: %q", got, substr)
	}
}

// AssertNotContains checks if got string does not contain substr.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertNotContains(t, output, "error")
func AssertNotContains(t *testing.T, got, substr string) {
	t.Helper()
	if strings.Contains(got, substr) {
		t.Errorf("string contains unexpected substring:\n  got:    %q\n  substr: %q", got, substr)
	}
}

// AssertEqual checks if got equals want.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertEqual(t, result.Status, request.StatusApproved)
func AssertEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("value mismatch:\n  got:  %v\n  want: %v", got, want)
	}
}

// AssertNotEqual checks if got does not equal want.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertNotEqual(t, result.ID, "")
func AssertNotEqual[T comparable](t *testing.T, got, notWant T) {
	t.Helper()
	if got == notWant {
		t.Errorf("value should not be: %v", got)
	}
}

// AssertTrue fails if condition is false.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertTrue(t, result.HasIssues())
func AssertTrue(t *testing.T, condition bool, msg ...string) {
	t.Helper()
	if !condition {
		if len(msg) > 0 {
			t.Errorf("expected true: %s", msg[0])
		} else {
			t.Error("expected true, got false")
		}
	}
}

// AssertFalse fails if condition is true.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertFalse(t, result.HasIssues())
func AssertFalse(t *testing.T, condition bool, msg ...string) {
	t.Helper()
	if condition {
		if len(msg) > 0 {
			t.Errorf("expected false: %s", msg[0])
		} else {
			t.Error("expected false, got true")
		}
	}
}

// AssertNil fails if value is not nil.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertNil(t, result.Error)
func AssertNil(t *testing.T, value interface{}) {
	t.Helper()
	if value != nil {
		t.Errorf("expected nil, got: %v", value)
	}
}

// AssertNotNil fails if value is nil.
// Uses t.Helper() for correct line number reporting.
//
// Example:
//
//	AssertNotNil(t, result.Request)
func AssertNotNil(t *testing.T, value interface{}) {
	t.Helper()
	if value == nil {
		t.Error("expected non-nil value, got nil")
	}
}

// ============================================================================
// String helpers
// ============================================================================

// Ptr returns a pointer to the given value.
// Useful for constructing test data with pointer fields.
//
// Example:
//
//	input := &ssm.GetParameterInput{Name: testutil.Ptr("my-param")}
func Ptr[T any](v T) *T {
	return &v
}
