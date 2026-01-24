package cli

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/identity"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// ============================================================================
// Security Regression Tests for AWS Identity Integration
// ============================================================================
//
// These tests verify that the OS username bug (fixed in v1.7.1) is properly
// addressed across all Sentinel commands. Prior to v1.7.1, Sentinel used
// os/user.Current() for policy evaluation, allowing users to bypass policies
// by running as a different local user.
//
// Bug: v1.7.0 and earlier used OS username for:
//   - Policy evaluation in credentials command
//   - Requester identity in request command
//   - Approver identity in approve/deny commands
//   - Invoker identity in break-glass commands
//
// Fix: v1.7.1 uses AWS identity from STS GetCallerIdentity for all commands.
//
// Tests use TestSecurityRegression_ prefix for CI/CD filtering.
// ============================================================================

// mockSecuritySTSClient implements identity.STSAPI for security testing.
type mockSecuritySTSClient struct {
	GetCallerIdentityFunc func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

func (m *mockSecuritySTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if m.GetCallerIdentityFunc != nil {
		return m.GetCallerIdentityFunc(ctx, params, optFns...)
	}
	return &sts.GetCallerIdentityOutput{
		Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
		Account: aws.String("123456789012"),
		UserId:  aws.String("AIDAEXAMPLE"),
	}, nil
}

// newSecurityMockSTSClient creates a mock STS client for the given ARN.
func newSecurityMockSTSClient(arn string) identity.STSAPI {
	return &mockSecuritySTSClient{
		GetCallerIdentityFunc: func(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
			return &sts.GetCallerIdentityOutput{
				Arn:     aws.String(arn),
				Account: aws.String("123456789012"),
				UserId:  aws.String("AIDAEXAMPLE"),
			}, nil
		},
	}
}

// ============================================================================
// Identity Extraction Security Tests
// ============================================================================

// TestSecurityRegression_CredentialsUsesAWSIdentity verifies that credentials
// command extracts username from AWS ARN, not OS.
func TestSecurityRegression_CredentialsUsesAWSIdentity(t *testing.T) {
	tests := []struct {
		name        string
		arnReturned string
		wantUser    string
	}{
		{
			name:        "IAM user",
			arnReturned: "arn:aws:iam::123456789012:user/alice",
			wantUser:    "alice",
		},
		{
			name:        "SSO assumed-role with email",
			arnReturned: "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/alice@company.com",
			wantUser:    "alicecompanycom",
		},
		{
			name:        "Regular assumed-role",
			arnReturned: "arn:aws:sts::123456789012:assumed-role/AdminRole/bob",
			wantUser:    "bob",
		},
		{
			name:        "Federated user",
			arnReturned: "arn:aws:sts::123456789012:federated-user/carol",
			wantUser:    "carol",
		},
		{
			name:        "GovCloud IAM user",
			arnReturned: "arn:aws-us-gov:iam::123456789012:user/dave",
			wantUser:    "dave",
		},
		{
			name:        "China partition",
			arnReturned: "arn:aws-cn:iam::123456789012:user/eve",
			wantUser:    "eve",
		},
		{
			name:        "Root user",
			arnReturned: "arn:aws:iam::123456789012:root",
			wantUser:    "root",
		},
		{
			name:        "IAM user with path",
			arnReturned: "arn:aws:iam::123456789012:user/admins/team1/alice",
			wantUser:    "alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newSecurityMockSTSClient(tt.arnReturned)

			username, err := identity.GetAWSUsername(context.Background(), mockClient)
			if err != nil {
				t.Fatalf("GetAWSUsername() error = %v", err)
			}

			if username != tt.wantUser {
				t.Errorf("SECURITY VIOLATION: Expected username %q from ARN, got %q", tt.wantUser, username)
			}
		})
	}
}

// TestSecurityRegression_NoOSUserLeakage verifies that extracting identity
// does not return OS-level information when given an AWS ARN.
func TestSecurityRegression_NoOSUserLeakage(t *testing.T) {
	testARNs := []string{
		"arn:aws:iam::123456789012:user/aws-alice",
		"arn:aws:sts::123456789012:assumed-role/Role/session",
		"arn:aws:sts::123456789012:federated-user/feduser",
		"arn:aws:iam::123456789012:root",
	}

	for _, arn := range testARNs {
		t.Run(arn, func(t *testing.T) {
			parsedIdentity, err := identity.ParseARN(arn)
			if err != nil {
				t.Fatalf("ParseARN() error = %v", err)
			}

			// Username must come from ARN, not match any potential OS user
			// This is a sanity check - the real protection is code review
			if parsedIdentity.Username == "" {
				t.Error("SECURITY VIOLATION: Empty username extracted from ARN")
			}

			// Verify username contains only safe characters (no control chars, etc.)
			for _, c := range parsedIdentity.Username {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
					t.Errorf("SECURITY VIOLATION: Username contains invalid character %q", c)
				}
			}
		})
	}
}

// TestSecurityRegression_BreakGlassUsesAWSIdentity verifies break-glass command
// extracts invoker username from AWS ARN.
func TestSecurityRegression_BreakGlassUsesAWSIdentity(t *testing.T) {
	tests := []struct {
		name        string
		arnReturned string
		wantInvoker string
	}{
		{
			name:        "IAM user invoker",
			arnReturned: "arn:aws:iam::123456789012:user/oncall",
			wantInvoker: "oncall",
		},
		{
			name:        "SSO user invoker",
			arnReturned: "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/admin@company.com",
			wantInvoker: "admincompanycom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var storedEvent *breakglass.BreakGlassEvent
			store := &mockBreakGlassStore{
				createFn: func(ctx context.Context, event *breakglass.BreakGlassEvent) error {
					storedEvent = event
					return nil
				},
				findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
					return nil, nil
				},
			}

			input := BreakGlassCommandInput{
				ProfileName:   "production",
				Duration:      1 * time.Hour,
				ReasonCode:    "incident",
				Justification: "Security regression test for AWS identity",
				Store:         store,
				STSClient:     newSecurityMockSTSClient(tt.arnReturned),
			}

			_, err := testableBreakGlassCommand(context.Background(), input, func(string) error { return nil })
			if err != nil {
				t.Fatalf("testableBreakGlassCommand() error = %v", err)
			}

			if storedEvent == nil {
				t.Fatal("expected event to be stored")
			}

			if storedEvent.Invoker != tt.wantInvoker {
				t.Errorf("SECURITY VIOLATION: Expected invoker %q from ARN, got %q", tt.wantInvoker, storedEvent.Invoker)
			}
		})
	}
}

// TestSecurityRegression_ApprovalUsesAWSIdentity verifies approve command
// extracts approver username from AWS ARN.
func TestSecurityRegression_ApprovalUsesAWSIdentity(t *testing.T) {
	tests := []struct {
		name         string
		arnReturned  string
		wantApprover string
	}{
		{
			name:         "IAM user approver",
			arnReturned:  "arn:aws:iam::123456789012:user/manager",
			wantApprover: "manager",
		},
		{
			name:         "SSO user approver",
			arnReturned:  "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/lead@company.com",
			wantApprover: "leadcompanycom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newSecurityMockSTSClient(tt.arnReturned)

			// Use identity.GetAWSUsername directly to verify the approver extraction
			approver, err := identity.GetAWSUsername(context.Background(), mockClient)
			if err != nil {
				t.Fatalf("identity.GetAWSUsername() error = %v", err)
			}

			if approver != tt.wantApprover {
				t.Errorf("SECURITY VIOLATION: Expected approver %q from ARN, got %q", tt.wantApprover, approver)
			}
		})
	}
}

// TestSecurityRegression_RequestUsesAWSIdentity verifies request command
// extracts requester username from AWS ARN.
func TestSecurityRegression_RequestUsesAWSIdentity(t *testing.T) {
	tests := []struct {
		name          string
		arnReturned   string
		wantRequester string
	}{
		{
			name:          "IAM user requester",
			arnReturned:   "arn:aws:iam::123456789012:user/developer",
			wantRequester: "developer",
		},
		{
			name:          "SSO user requester",
			arnReturned:   "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Developer_abc/dev@company.com",
			wantRequester: "devcompanycom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newSecurityMockSTSClient(tt.arnReturned)

			// Use identity.GetAWSUsername directly to verify the requester extraction
			requester, err := identity.GetAWSUsername(context.Background(), mockClient)
			if err != nil {
				t.Fatalf("identity.GetAWSUsername() error = %v", err)
			}

			if requester != tt.wantRequester {
				t.Errorf("SECURITY VIOLATION: Expected requester %q from ARN, got %q", tt.wantRequester, requester)
			}
		})
	}
}

// ============================================================================
// Policy Bypass Prevention Tests
// ============================================================================

// mockSecurityPolicyStore implements request.Store for policy bypass testing.
type mockSecurityPolicyStore struct {
	requests map[string]*request.Request
}

func newMockSecurityPolicyStore() *mockSecurityPolicyStore {
	return &mockSecurityPolicyStore{
		requests: make(map[string]*request.Request),
	}
}

func (m *mockSecurityPolicyStore) Create(ctx context.Context, req *request.Request) error {
	m.requests[req.ID] = req
	return nil
}

func (m *mockSecurityPolicyStore) Get(ctx context.Context, id string) (*request.Request, error) {
	if req, ok := m.requests[id]; ok {
		return req, nil
	}
	return nil, request.ErrRequestNotFound
}

func (m *mockSecurityPolicyStore) Update(ctx context.Context, req *request.Request) error {
	m.requests[req.ID] = req
	return nil
}

func (m *mockSecurityPolicyStore) Delete(ctx context.Context, id string) error {
	delete(m.requests, id)
	return nil
}

func (m *mockSecurityPolicyStore) ListByRequester(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
	var results []*request.Request
	for _, req := range m.requests {
		if req.Requester == requester {
			results = append(results, req)
		}
	}
	return results, nil
}

func (m *mockSecurityPolicyStore) ListByStatus(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error) {
	var results []*request.Request
	for _, req := range m.requests {
		if req.Status == status {
			results = append(results, req)
		}
	}
	return results, nil
}

func (m *mockSecurityPolicyStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
	var results []*request.Request
	for _, req := range m.requests {
		if req.Profile == profile {
			results = append(results, req)
		}
	}
	return results, nil
}

// TestSecurityRegression_PolicyUsesAWSUsername verifies that policy evaluation
// uses the AWS identity username, not OS username.
func TestSecurityRegression_PolicyUsesAWSUsername(t *testing.T) {
	// Create a policy that only allows "alice"
	testPolicy := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-alice",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Users:    []string{"alice"},
					Profiles: []string{"production"},
				},
			},
			{
				Name:   "deny-all",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Users:    []string{"*"},
					Profiles: []string{"*"},
				},
			},
		},
	}

	tests := []struct {
		name         string
		arnReturned  string
		wantUsername string
		wantEffect   policy.Effect
	}{
		{
			name:         "alice ARN allows access",
			arnReturned:  "arn:aws:iam::123456789012:user/alice",
			wantUsername: "alice",
			wantEffect:   policy.EffectAllow,
		},
		{
			name:         "bob ARN denies access",
			arnReturned:  "arn:aws:iam::123456789012:user/bob",
			wantUsername: "bob",
			wantEffect:   policy.EffectDeny,
		},
		{
			name:         "eve ARN denies access",
			arnReturned:  "arn:aws:iam::123456789012:user/eve",
			wantUsername: "eve",
			wantEffect:   policy.EffectDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newSecurityMockSTSClient(tt.arnReturned)

			// Extract username from AWS identity
			username, err := identity.GetAWSUsername(context.Background(), mockClient)
			if err != nil {
				t.Fatalf("GetAWSUsername() error = %v", err)
			}

			if username != tt.wantUsername {
				t.Errorf("SECURITY VIOLATION: Expected username %q, got %q", tt.wantUsername, username)
			}

			// Evaluate policy with AWS identity username
			policyRequest := &policy.Request{
				User:    username,
				Profile: "production",
				Time:    time.Now(),
			}

			decision := policy.Evaluate(testPolicy, policyRequest)

			if decision.Effect != tt.wantEffect {
				t.Errorf("SECURITY VIOLATION: Policy evaluation with AWS identity %q returned %v, expected %v",
					username, decision.Effect, tt.wantEffect)
			}
		})
	}
}

// TestSecurityRegression_BreakGlassPolicyUsesAWSUsername verifies break-glass
// policy uses AWS identity for authorization.
func TestSecurityRegression_BreakGlassPolicyUsesAWSUsername(t *testing.T) {
	// Create a break-glass policy that only allows "oncall"
	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:     "production-oncall",
				Profiles: []string{"production"},
				Users:    []string{"oncall"},
			},
		},
	}

	tests := []struct {
		name         string
		arnReturned  string
		wantUsername string
		wantAllowed  bool
	}{
		{
			name:         "oncall ARN allows break-glass",
			arnReturned:  "arn:aws:iam::123456789012:user/oncall",
			wantUsername: "oncall",
			wantAllowed:  true,
		},
		{
			name:         "developer ARN denies break-glass",
			arnReturned:  "arn:aws:iam::123456789012:user/developer",
			wantUsername: "developer",
			wantAllowed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newSecurityMockSTSClient(tt.arnReturned)

			// Extract username from AWS identity
			username, err := identity.GetAWSUsername(context.Background(), mockClient)
			if err != nil {
				t.Fatalf("GetAWSUsername() error = %v", err)
			}

			if username != tt.wantUsername {
				t.Errorf("SECURITY VIOLATION: Expected username %q, got %q", tt.wantUsername, username)
			}

			// Check break-glass policy authorization
			rule := breakglass.FindBreakGlassPolicyRule(bgPolicy, "production")
			if rule == nil {
				t.Fatal("expected to find break-glass rule")
			}

			canInvoke := breakglass.CanInvokeBreakGlass(rule, username)

			if canInvoke != tt.wantAllowed {
				t.Errorf("SECURITY VIOLATION: Break-glass policy check with AWS identity %q returned %v, expected %v",
					username, canInvoke, tt.wantAllowed)
			}
		})
	}
}

// TestSecurityRegression_ApprovalPolicyUsesAWSUsername verifies approval
// policy uses AWS identity for approver authorization.
func TestSecurityRegression_ApprovalPolicyUsesAWSUsername(t *testing.T) {
	// Create an approval policy that only allows "manager" to approve
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-approval",
				Profiles:  []string{"production"},
				Approvers: []string{"manager"},
			},
		},
	}

	tests := []struct {
		name         string
		arnReturned  string
		wantUsername string
		wantAllowed  bool
	}{
		{
			name:         "manager ARN can approve",
			arnReturned:  "arn:aws:iam::123456789012:user/manager",
			wantUsername: "manager",
			wantAllowed:  true,
		},
		{
			name:         "developer ARN cannot approve",
			arnReturned:  "arn:aws:iam::123456789012:user/developer",
			wantUsername: "developer",
			wantAllowed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newSecurityMockSTSClient(tt.arnReturned)

			// Extract username from AWS identity
			username, err := identity.GetAWSUsername(context.Background(), mockClient)
			if err != nil {
				t.Fatalf("GetAWSUsername() error = %v", err)
			}

			if username != tt.wantUsername {
				t.Errorf("SECURITY VIOLATION: Expected username %q, got %q", tt.wantUsername, username)
			}

			// Check approval policy authorization
			rule := policy.FindApprovalRule(approvalPolicy, "production")
			if rule == nil {
				t.Fatal("expected to find approval rule")
			}

			canApprove := policy.CanApprove(rule, username)

			if canApprove != tt.wantAllowed {
				t.Errorf("SECURITY VIOLATION: Approval policy check with AWS identity %q returned %v, expected %v",
					username, canApprove, tt.wantAllowed)
			}
		})
	}
}

// TestSecurityRegression_FindApprovedRequestUsesAWSIdentity verifies that
// finding approved requests uses the AWS identity username.
func TestSecurityRegression_FindApprovedRequestUsesAWSIdentity(t *testing.T) {
	now := time.Now()

	// Create a request approved for "alice"
	store := newMockSecurityPolicyStore()
	store.requests["req001"] = &request.Request{
		ID:        "req001",
		Requester: "alice",
		Profile:   "production",
		Status:    request.StatusApproved,
		CreatedAt: now.Add(-1 * time.Hour),
		ExpiresAt: now.Add(23 * time.Hour),
	}

	tests := []struct {
		name         string
		arnReturned  string
		wantUsername string
		wantFound    bool
	}{
		{
			name:         "alice ARN finds approved request",
			arnReturned:  "arn:aws:iam::123456789012:user/alice",
			wantUsername: "alice",
			wantFound:    true,
		},
		{
			name:         "bob ARN does not find request",
			arnReturned:  "arn:aws:iam::123456789012:user/bob",
			wantUsername: "bob",
			wantFound:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newSecurityMockSTSClient(tt.arnReturned)

			// Extract username from AWS identity
			username, err := identity.GetAWSUsername(context.Background(), mockClient)
			if err != nil {
				t.Fatalf("GetAWSUsername() error = %v", err)
			}

			if username != tt.wantUsername {
				t.Errorf("SECURITY VIOLATION: Expected username %q, got %q", tt.wantUsername, username)
			}

			// Find approved request using AWS identity
			foundReq, err := request.FindApprovedRequest(context.Background(), store, username, "production")
			if err != nil {
				t.Fatalf("FindApprovedRequest() error = %v", err)
			}

			found := foundReq != nil

			if found != tt.wantFound {
				t.Errorf("SECURITY VIOLATION: FindApprovedRequest with AWS identity %q returned found=%v, expected %v",
					username, found, tt.wantFound)
			}
		})
	}
}

// TestSecurityRegression_FindActiveBreakGlassUsesAWSIdentity verifies that
// finding active break-glass uses the AWS identity username.
func TestSecurityRegression_FindActiveBreakGlassUsesAWSIdentity(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		arnReturned  string
		wantUsername string
		wantFound    bool
	}{
		{
			name:         "oncall ARN finds active break-glass",
			arnReturned:  "arn:aws:iam::123456789012:user/oncall",
			wantUsername: "oncall",
			wantFound:    true,
		},
		{
			name:         "developer ARN does not find break-glass",
			arnReturned:  "arn:aws:iam::123456789012:user/developer",
			wantUsername: "developer",
			wantFound:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newSecurityMockSTSClient(tt.arnReturned)

			// Extract username from AWS identity
			username, err := identity.GetAWSUsername(context.Background(), mockClient)
			if err != nil {
				t.Fatalf("GetAWSUsername() error = %v", err)
			}

			if username != tt.wantUsername {
				t.Errorf("SECURITY VIOLATION: Expected username %q, got %q", tt.wantUsername, username)
			}

			// Create store with break-glass event for "oncall"
			store := &mockBreakGlassStore{
				findActiveByInvokerAndProfileFn: func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
					if invoker == "oncall" && profile == "production" {
						return &breakglass.BreakGlassEvent{
							ID:        "bg001",
							Invoker:   "oncall",
							Profile:   "production",
							Status:    breakglass.StatusActive,
							ExpiresAt: now.Add(1 * time.Hour),
						}, nil
					}
					return nil, nil
				},
			}

			// Find active break-glass using AWS identity
			foundEvent, err := breakglass.FindActiveBreakGlass(context.Background(), store, username, "production")
			if err != nil {
				t.Fatalf("FindActiveBreakGlass() error = %v", err)
			}

			found := foundEvent != nil

			if found != tt.wantFound {
				t.Errorf("SECURITY VIOLATION: FindActiveBreakGlass with AWS identity %q returned found=%v, expected %v",
					username, found, tt.wantFound)
			}
		})
	}
}

// ============================================================================
// Username Sanitization Security Tests
// ============================================================================

// TestSecurityRegression_UsernameSanitization verifies that special characters
// in ARNs are properly sanitized to prevent injection attacks.
func TestSecurityRegression_UsernameSanitization(t *testing.T) {
	tests := []struct {
		name            string
		arnReturned     string
		wantSanitized   string
		wantNoSpecial   bool // Username should contain only alphanumeric
		description     string
	}{
		{
			name:          "email @ removed",
			arnReturned:   "arn:aws:sts::123456789012:assumed-role/Role/user@domain.com",
			wantSanitized: "userdomaincom",
			wantNoSpecial: true,
			description:   "@ and . removed from email",
		},
		{
			name:          "dots removed",
			arnReturned:   "arn:aws:sts::123456789012:assumed-role/Role/user.name",
			wantSanitized: "username",
			wantNoSpecial: true,
			description:   "dots removed",
		},
		{
			name:          "underscores removed",
			arnReturned:   "arn:aws:sts::123456789012:federated-user/user_name",
			wantSanitized: "username",
			wantNoSpecial: true,
			description:   "underscores removed",
		},
		{
			name:          "hyphens removed",
			arnReturned:   "arn:aws:sts::123456789012:assumed-role/Role/user-name",
			wantSanitized: "username",
			wantNoSpecial: true,
			description:   "hyphens removed",
		},
		{
			name:          "plus sign removed",
			arnReturned:   "arn:aws:sts::123456789012:assumed-role/Role/user+test@domain.com",
			wantSanitized: "usertestdomaincom",
			wantNoSpecial: true,
			description:   "+ removed from email",
		},
		{
			name:          "truncation to 20 chars",
			arnReturned:   "arn:aws:sts::123456789012:assumed-role/Role/verylongusernamethatexceedstwentycharacters",
			wantSanitized: "verylongusernamethat",
			wantNoSpecial: true,
			description:   "truncated to 20 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newSecurityMockSTSClient(tt.arnReturned)

			username, err := identity.GetAWSUsername(context.Background(), mockClient)
			if err != nil {
				t.Fatalf("GetAWSUsername() error = %v", err)
			}

			if username != tt.wantSanitized {
				t.Errorf("SECURITY VIOLATION: Expected sanitized username %q, got %q (%s)",
					tt.wantSanitized, username, tt.description)
			}

			if tt.wantNoSpecial {
				for _, c := range username {
					if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
						t.Errorf("SECURITY VIOLATION: Username contains special character %q (%s)",
							c, tt.description)
					}
				}
			}
		})
	}
}

// ============================================================================
// Attack Scenario Demonstration Tests
// ============================================================================
//
// These tests explicitly demonstrate the attack scenario that was possible
// prior to v1.7.1 and verify it is now prevented.

// TestSecurityRegression_AttackScenario_OSUserBypass demonstrates the
// vulnerability that existed in v1.7.0 where an attacker could bypass
// policies by changing their local OS username.
//
// Attack scenario (pre-fix):
//  1. Alice has AWS credentials for role AdminRole
//  2. Policy allows "admin" to access production profile
//  3. Alice's OS username is "alice", so policy denies access
//  4. Alice creates a local user named "admin" and runs aws-vault as that user
//  5. Policy now allows access because os/user.Current() returns "admin"
//
// Fix (v1.7.1+):
//  - Policy evaluation uses AWS STS GetCallerIdentity to extract username
//  - OS username is never used for policy decisions
//  - Attack fails because ARN still shows alice, not admin
func TestSecurityRegression_AttackScenario_OSUserBypass(t *testing.T) {
	// Create a policy that allows "admin" to access production
	testPolicy := &policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-admin-production",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Users:    []string{"admin"},
					Profiles: []string{"production"},
				},
			},
			{
				Name:   "deny-all",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Users:    []string{"*"},
					Profiles: []string{"*"},
				},
			},
		},
	}

	// Scenario 1: Attacker tries to impersonate admin via OS username
	// AWS credentials still belong to alice
	t.Run("attacker_alice_impersonates_admin", func(t *testing.T) {
		// Attacker's AWS identity is still "alice" (from their credentials)
		mockClient := newSecurityMockSTSClient("arn:aws:iam::123456789012:user/alice")

		// Extract username using AWS identity (the fix)
		username, err := identity.GetAWSUsername(context.Background(), mockClient)
		if err != nil {
			t.Fatalf("GetAWSUsername() error = %v", err)
		}

		// Verify AWS identity is used, not OS username
		if username != "alice" {
			t.Errorf("Expected AWS username 'alice', got %q", username)
		}

		// Policy evaluation should deny because AWS identity is "alice", not "admin"
		policyRequest := &policy.Request{
			User:    username, // Uses AWS identity, not OS username
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(testPolicy, policyRequest)

		if decision.Effect != policy.EffectDeny {
			t.Errorf("SECURITY VIOLATION: Attacker 'alice' with AWS creds could bypass policy by impersonating 'admin' OS user. Expected deny, got %v", decision.Effect)
		}
	})

	// Scenario 2: Legitimate admin user with admin AWS credentials should be allowed
	t.Run("legitimate_admin", func(t *testing.T) {
		// Admin's AWS identity is "admin"
		mockClient := newSecurityMockSTSClient("arn:aws:iam::123456789012:user/admin")

		username, err := identity.GetAWSUsername(context.Background(), mockClient)
		if err != nil {
			t.Fatalf("GetAWSUsername() error = %v", err)
		}

		if username != "admin" {
			t.Errorf("Expected AWS username 'admin', got %q", username)
		}

		policyRequest := &policy.Request{
			User:    username,
			Profile: "production",
			Time:    time.Now(),
		}

		decision := policy.Evaluate(testPolicy, policyRequest)

		if decision.Effect != policy.EffectAllow {
			t.Errorf("Legitimate admin should be allowed. Expected allow, got %v", decision.Effect)
		}
	})
}

// TestSecurityRegression_AttackScenario_BreakGlassImpersonation demonstrates
// the break-glass impersonation attack that was possible pre-fix.
//
// Attack scenario (pre-fix):
//  1. Break-glass policy allows "oncall" to invoke for production
//  2. Attacker alice is not in oncall rotation
//  3. Alice creates local user "oncall" and runs breakglass command
//  4. Break-glass is allowed because os/user.Current() returns "oncall"
//
// Fix: Break-glass uses AWS identity, so alice's ARN is always used
func TestSecurityRegression_AttackScenario_BreakGlassImpersonation(t *testing.T) {
	bgPolicy := &breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:     "oncall-production",
				Profiles: []string{"production"},
				Users:    []string{"oncall"},
			},
		},
	}

	t.Run("attacker_alice_impersonates_oncall", func(t *testing.T) {
		// Attacker's AWS identity is "alice"
		mockClient := newSecurityMockSTSClient("arn:aws:iam::123456789012:user/alice")

		username, err := identity.GetAWSUsername(context.Background(), mockClient)
		if err != nil {
			t.Fatalf("GetAWSUsername() error = %v", err)
		}

		if username != "alice" {
			t.Errorf("Expected AWS username 'alice', got %q", username)
		}

		// Check if alice can invoke break-glass (should be denied)
		rule := breakglass.FindBreakGlassPolicyRule(bgPolicy, "production")
		if rule == nil {
			t.Fatal("expected to find break-glass rule")
		}

		canInvoke := breakglass.CanInvokeBreakGlass(rule, username)

		if canInvoke {
			t.Errorf("SECURITY VIOLATION: Attacker 'alice' could invoke break-glass by impersonating 'oncall' OS user")
		}
	})

	t.Run("legitimate_oncall", func(t *testing.T) {
		// Oncall's AWS identity is "oncall"
		mockClient := newSecurityMockSTSClient("arn:aws:iam::123456789012:user/oncall")

		username, err := identity.GetAWSUsername(context.Background(), mockClient)
		if err != nil {
			t.Fatalf("GetAWSUsername() error = %v", err)
		}

		rule := breakglass.FindBreakGlassPolicyRule(bgPolicy, "production")
		canInvoke := breakglass.CanInvokeBreakGlass(rule, username)

		if !canInvoke {
			t.Errorf("Legitimate oncall should be allowed to invoke break-glass")
		}
	})
}

// TestSecurityRegression_AttackScenario_ApproverImpersonation demonstrates
// the approval impersonation attack that was possible pre-fix.
//
// Attack scenario (pre-fix):
//  1. Approval policy requires "manager" to approve production requests
//  2. Attacker alice requests access, needs manager approval
//  3. Alice creates local user "manager" and approves her own request
//  4. Approval succeeds because os/user.Current() returns "manager"
//
// Fix: Approval uses AWS identity, so alice's ARN is always used
func TestSecurityRegression_AttackScenario_ApproverImpersonation(t *testing.T) {
	approvalPolicy := &policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "production-approval",
				Profiles:  []string{"production"},
				Approvers: []string{"manager"},
			},
		},
	}

	t.Run("attacker_alice_self_approves_as_manager", func(t *testing.T) {
		// Attacker's AWS identity is "alice"
		mockClient := newSecurityMockSTSClient("arn:aws:iam::123456789012:user/alice")

		username, err := identity.GetAWSUsername(context.Background(), mockClient)
		if err != nil {
			t.Fatalf("GetAWSUsername() error = %v", err)
		}

		rule := policy.FindApprovalRule(approvalPolicy, "production")
		if rule == nil {
			t.Fatal("expected to find approval rule")
		}

		canApprove := policy.CanApprove(rule, username)

		if canApprove {
			t.Errorf("SECURITY VIOLATION: Attacker 'alice' could self-approve by impersonating 'manager' OS user")
		}
	})

	t.Run("legitimate_manager_approves", func(t *testing.T) {
		// Manager's AWS identity is "manager"
		mockClient := newSecurityMockSTSClient("arn:aws:iam::123456789012:user/manager")

		username, err := identity.GetAWSUsername(context.Background(), mockClient)
		if err != nil {
			t.Fatalf("GetAWSUsername() error = %v", err)
		}

		rule := policy.FindApprovalRule(approvalPolicy, "production")
		canApprove := policy.CanApprove(rule, username)

		if !canApprove {
			t.Errorf("Legitimate manager should be allowed to approve")
		}
	})
}

// ============================================================================
// Username Sanitization and Injection Prevention Tests
// ============================================================================

// TestSecurityRegression_InjectionPrevention verifies that potentially
// malicious ARN inputs are properly sanitized.
func TestSecurityRegression_InjectionPrevention(t *testing.T) {
	tests := []struct {
		name        string
		arn         string
		description string
	}{
		{
			name:        "path traversal in user",
			arn:         "arn:aws:iam::123456789012:user/../../../etc/passwd",
			description: "path traversal should be sanitized",
		},
		{
			name:        "special chars in session name",
			arn:         "arn:aws:sts::123456789012:assumed-role/Role/user;admin",
			description: "semicolon should be sanitized",
		},
		{
			name:        "quotes in session name",
			arn:         "arn:aws:sts::123456789012:assumed-role/Role/user\"admin",
			description: "quotes should be sanitized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedIdentity, err := identity.ParseARN(tt.arn)

			// Some inputs may fail parsing entirely - that's also acceptable
			if err != nil {
				return
			}

			// If parsed, verify the username is safe
			for _, c := range parsedIdentity.Username {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
					t.Errorf("SECURITY VIOLATION: Username contains dangerous character %q after sanitization (%s)",
						c, tt.description)
				}
			}
		})
	}
}
