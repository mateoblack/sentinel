package testutil

import (
	"testing"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/request"
)

// Compile-time interface verification for store mocks
var (
	_ request.Store    = (*MockRequestStore)(nil)
	_ breakglass.Store = (*MockBreakGlassStore)(nil)
)

// Compile-time interface verification for service mocks
var (
	_ notification.Notifier = (*MockNotifier)(nil)
	_ logging.Logger        = (*MockLogger)(nil)
)

func TestMockRequestStore_ImplementsInterface(t *testing.T) {
	store := NewMockRequestStore()
	var _ request.Store = store // Compile-time check
	if store == nil {
		t.Fatal("NewMockRequestStore returned nil")
	}
}

func TestMockBreakGlassStore_ImplementsInterface(t *testing.T) {
	store := NewMockBreakGlassStore()
	var _ breakglass.Store = store // Compile-time check
	if store == nil {
		t.Fatal("NewMockBreakGlassStore returned nil")
	}
}

func TestMockNotifier_ImplementsInterface(t *testing.T) {
	notifier := NewMockNotifier()
	var _ notification.Notifier = notifier // Compile-time check
	if notifier == nil {
		t.Fatal("NewMockNotifier returned nil")
	}
}

func TestMockLogger_ImplementsInterface(t *testing.T) {
	logger := NewMockLogger()
	var _ logging.Logger = logger // Compile-time check
	if logger == nil {
		t.Fatal("NewMockLogger returned nil")
	}
}

func TestMockPolicyLoader_Load(t *testing.T) {
	loader := NewMockPolicyLoader()
	if loader == nil {
		t.Fatal("NewMockPolicyLoader returned nil")
	}
}

func TestHelperFunctions(t *testing.T) {
	// Test MakeRequest
	req := MakeRequest("alice", "production")
	if req.Requester != "alice" {
		t.Errorf("MakeRequest: expected requester 'alice', got '%s'", req.Requester)
	}
	if req.Profile != "production" {
		t.Errorf("MakeRequest: expected profile 'production', got '%s'", req.Profile)
	}
	if req.Status != request.StatusPending {
		t.Errorf("MakeRequest: expected status pending, got '%s'", req.Status)
	}

	// Test MakeApprovedRequest
	approved := MakeApprovedRequest("bob", "staging")
	if approved.Status != request.StatusApproved {
		t.Errorf("MakeApprovedRequest: expected status approved, got '%s'", approved.Status)
	}
	if approved.Approver == "" {
		t.Error("MakeApprovedRequest: expected approver to be set")
	}

	// Test MakeAllowPolicy
	pol := MakeAllowPolicy("test-profile")
	if pol == nil {
		t.Fatal("MakeAllowPolicy returned nil")
	}
	if len(pol.Rules) != 1 {
		t.Fatalf("MakeAllowPolicy: expected 1 rule, got %d", len(pol.Rules))
	}

	// Test MakeCredentials
	creds := MakeCredentials()
	if creds.AccessKeyID == "" {
		t.Error("MakeCredentials: expected AccessKeyID to be set")
	}
	if !creds.CanExpire {
		t.Error("MakeCredentials: expected CanExpire to be true")
	}

	// Test Ptr helper
	strPtr := Ptr("hello")
	if *strPtr != "hello" {
		t.Errorf("Ptr: expected 'hello', got '%s'", *strPtr)
	}
}
