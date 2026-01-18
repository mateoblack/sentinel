package permissions

import (
	"testing"
)

func TestRegistry_AllFeaturesRegistered(t *testing.T) {
	// Verify every feature has a registry entry
	allFeatures := AllFeatures()

	for _, f := range allFeatures {
		fp, ok := GetFeaturePermissions(f)
		if !ok {
			t.Errorf("Feature %s is not registered", f)
			continue
		}
		if fp.Feature != f {
			t.Errorf("GetFeaturePermissions(%s).Feature = %s, want %s", f, fp.Feature, f)
		}
	}
}

func TestRegistry_FeatureCount(t *testing.T) {
	// Verify registry has exactly 10 features
	allPerms := GetAllPermissions()
	if len(allPerms) != 10 {
		t.Errorf("Registry has %d features, want 10", len(allPerms))
	}
}

func TestGetFeaturePermissions(t *testing.T) {
	tests := []struct {
		name    string
		feature Feature
		wantOK  bool
	}{
		{"policy_load exists", FeaturePolicyLoad, true},
		{"credential_issue exists", FeatureCredentialIssue, true},
		{"approval_workflow exists", FeatureApprovalWorkflow, true},
		{"breakglass exists", FeatureBreakGlass, true},
		{"notify_sns exists", FeatureNotifySNS, true},
		{"notify_webhook exists", FeatureNotifyWebhook, true},
		{"audit_verify exists", FeatureAuditVerify, true},
		{"enforce_analyze exists", FeatureEnforceAnalyze, true},
		{"bootstrap_plan exists", FeatureBootstrapPlan, true},
		{"bootstrap_apply exists", FeatureBootstrapApply, true},
		{"unknown feature", Feature("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := GetFeaturePermissions(tt.feature)
			if ok != tt.wantOK {
				t.Errorf("GetFeaturePermissions(%s) ok = %v, want %v", tt.feature, ok, tt.wantOK)
			}
		})
	}
}

func TestGetFeaturePermissions_CorrectSubsystem(t *testing.T) {
	tests := []struct {
		feature   Feature
		subsystem Subsystem
	}{
		{FeaturePolicyLoad, SubsystemCore},
		{FeatureCredentialIssue, SubsystemCredentials},
		{FeatureApprovalWorkflow, SubsystemApprovals},
		{FeatureBreakGlass, SubsystemBreakGlass},
		{FeatureNotifySNS, SubsystemNotifications},
		{FeatureNotifyWebhook, SubsystemNotifications},
		{FeatureAuditVerify, SubsystemAudit},
		{FeatureEnforceAnalyze, SubsystemEnforce},
		{FeatureBootstrapPlan, SubsystemBootstrap},
		{FeatureBootstrapApply, SubsystemBootstrap},
	}

	for _, tt := range tests {
		t.Run(tt.feature.String(), func(t *testing.T) {
			fp, ok := GetFeaturePermissions(tt.feature)
			if !ok {
				t.Fatalf("Feature %s not found", tt.feature)
			}
			if fp.Subsystem != tt.subsystem {
				t.Errorf("Feature %s has subsystem %s, want %s", tt.feature, fp.Subsystem, tt.subsystem)
			}
		})
	}
}

func TestGetSubsystemPermissions(t *testing.T) {
	tests := []struct {
		subsystem     Subsystem
		wantFeatures  []Feature
		wantMinPerms  int
	}{
		{SubsystemCore, []Feature{FeaturePolicyLoad}, 1},
		{SubsystemCredentials, []Feature{FeatureCredentialIssue}, 1},
		{SubsystemApprovals, []Feature{FeatureApprovalWorkflow}, 1},
		{SubsystemBreakGlass, []Feature{FeatureBreakGlass}, 1},
		{SubsystemNotifications, []Feature{FeatureNotifySNS, FeatureNotifyWebhook}, 1},
		{SubsystemAudit, []Feature{FeatureAuditVerify}, 1},
		{SubsystemEnforce, []Feature{FeatureEnforceAnalyze}, 1},
		{SubsystemBootstrap, []Feature{FeatureBootstrapPlan, FeatureBootstrapApply}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.subsystem.String(), func(t *testing.T) {
			perms := GetSubsystemPermissions(tt.subsystem)

			if len(perms) != len(tt.wantFeatures) {
				t.Errorf("GetSubsystemPermissions(%s) returned %d features, want %d",
					tt.subsystem, len(perms), len(tt.wantFeatures))
			}

			// Check all expected features are present
			featureSet := make(map[Feature]bool)
			for _, fp := range perms {
				featureSet[fp.Feature] = true
			}

			for _, wantF := range tt.wantFeatures {
				if !featureSet[wantF] {
					t.Errorf("GetSubsystemPermissions(%s) missing feature %s", tt.subsystem, wantF)
				}
			}
		})
	}
}

func TestGetAllPermissions(t *testing.T) {
	perms := GetAllPermissions()

	if len(perms) != 10 {
		t.Errorf("GetAllPermissions() returned %d permissions, want 10", len(perms))
	}

	// Verify all features are present
	featureSet := make(map[Feature]bool)
	for _, fp := range perms {
		featureSet[fp.Feature] = true
	}

	for _, f := range AllFeatures() {
		if !featureSet[f] {
			t.Errorf("GetAllPermissions() missing feature %s", f)
		}
	}
}

func TestGetRequiredPermissions(t *testing.T) {
	perms := GetRequiredPermissions()

	// Should exclude optional features (notify_sns, notify_webhook)
	for _, fp := range perms {
		if fp.Optional {
			t.Errorf("GetRequiredPermissions() included optional feature %s", fp.Feature)
		}
	}

	// Count: 10 total - 2 optional = 8 required
	if len(perms) != 8 {
		t.Errorf("GetRequiredPermissions() returned %d features, want 8", len(perms))
	}

	// Verify required features are present
	requiredFeatures := map[Feature]bool{
		FeaturePolicyLoad:       false,
		FeatureCredentialIssue:  false,
		FeatureApprovalWorkflow: false,
		FeatureBreakGlass:       false,
		FeatureAuditVerify:      false,
		FeatureEnforceAnalyze:   false,
		FeatureBootstrapPlan:    false,
		FeatureBootstrapApply:   false,
	}

	for _, fp := range perms {
		requiredFeatures[fp.Feature] = true
	}

	for f, found := range requiredFeatures {
		if !found {
			t.Errorf("GetRequiredPermissions() missing required feature %s", f)
		}
	}
}

func TestOptionalFeatures(t *testing.T) {
	optionalFeatures := []Feature{FeatureNotifySNS, FeatureNotifyWebhook}

	for _, f := range optionalFeatures {
		fp, ok := GetFeaturePermissions(f)
		if !ok {
			t.Fatalf("Feature %s not found", f)
		}
		if !fp.Optional {
			t.Errorf("Feature %s should be optional", f)
		}
	}
}

func TestFeaturePermissions_HasCorrectActions(t *testing.T) {
	tests := []struct {
		feature     Feature
		wantService string
		wantActions []string
	}{
		{
			feature:     FeaturePolicyLoad,
			wantService: "ssm",
			wantActions: []string{"ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"},
		},
		{
			feature:     FeatureCredentialIssue,
			wantService: "sts",
			wantActions: []string{"sts:AssumeRole"},
		},
		{
			feature:     FeatureNotifySNS,
			wantService: "sns",
			wantActions: []string{"sns:Publish"},
		},
		{
			feature:     FeatureAuditVerify,
			wantService: "cloudtrail",
			wantActions: []string{"cloudtrail:LookupEvents"},
		},
		{
			feature:     FeatureEnforceAnalyze,
			wantService: "iam",
			wantActions: []string{"iam:GetRole"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.feature.String(), func(t *testing.T) {
			fp, ok := GetFeaturePermissions(tt.feature)
			if !ok {
				t.Fatalf("Feature %s not found", tt.feature)
			}

			// Find permission with expected service
			var found *Permission
			for _, p := range fp.Permissions {
				if p.Service == tt.wantService {
					found = &p
					break
				}
			}

			if found == nil {
				t.Fatalf("Feature %s missing permission for service %s", tt.feature, tt.wantService)
			}

			// Verify actions match
			if len(found.Actions) != len(tt.wantActions) {
				t.Errorf("Feature %s has %d actions, want %d", tt.feature, len(found.Actions), len(tt.wantActions))
			}

			actionSet := make(map[string]bool)
			for _, a := range found.Actions {
				actionSet[a] = true
			}

			for _, wantAction := range tt.wantActions {
				if !actionSet[wantAction] {
					t.Errorf("Feature %s missing action %s", tt.feature, wantAction)
				}
			}
		})
	}
}

func TestFeaturePermissions_DynamoDB(t *testing.T) {
	// Test DynamoDB features have correct table and index permissions
	dynamoFeatures := []Feature{FeatureApprovalWorkflow, FeatureBreakGlass}

	for _, f := range dynamoFeatures {
		t.Run(f.String(), func(t *testing.T) {
			fp, ok := GetFeaturePermissions(f)
			if !ok {
				t.Fatalf("Feature %s not found", f)
			}

			if len(fp.Permissions) < 2 {
				t.Errorf("Feature %s should have at least 2 permission entries (table + index), got %d",
					f, len(fp.Permissions))
			}

			// Verify has both table and index permissions
			hasTable := false
			hasIndex := false
			for _, p := range fp.Permissions {
				if p.Service == "dynamodb" {
					if !hasTable && !contains(p.Resource, "/index/") {
						hasTable = true
					}
					if contains(p.Resource, "/index/*") {
						hasIndex = true
					}
				}
			}

			if !hasTable {
				t.Errorf("Feature %s missing DynamoDB table permission", f)
			}
			if !hasIndex {
				t.Errorf("Feature %s missing DynamoDB index permission", f)
			}
		})
	}
}

func TestFeaturePermissions_Bootstrap(t *testing.T) {
	// Bootstrap plan should have read-only SSM actions
	planFP, ok := GetFeaturePermissions(FeatureBootstrapPlan)
	if !ok {
		t.Fatal("FeatureBootstrapPlan not found")
	}

	// Verify no write actions in plan
	for _, p := range planFP.Permissions {
		for _, a := range p.Actions {
			if a == "ssm:PutParameter" || a == "ssm:DeleteParameter" {
				t.Errorf("FeatureBootstrapPlan should not have write action %s", a)
			}
		}
	}

	// Bootstrap apply should have write SSM actions
	applyFP, ok := GetFeaturePermissions(FeatureBootstrapApply)
	if !ok {
		t.Fatal("FeatureBootstrapApply not found")
	}

	hasWrite := false
	for _, p := range applyFP.Permissions {
		for _, a := range p.Actions {
			if a == "ssm:PutParameter" {
				hasWrite = true
				break
			}
		}
	}

	if !hasWrite {
		t.Error("FeatureBootstrapApply should have ssm:PutParameter action")
	}
}

func TestUniqueActions(t *testing.T) {
	tests := []struct {
		name        string
		perms       []FeaturePermissions
		wantActions []string
	}{
		{
			name:        "empty input",
			perms:       []FeaturePermissions{},
			wantActions: nil,
		},
		{
			name: "single feature",
			perms: []FeaturePermissions{
				{
					Permissions: []Permission{
						{Actions: []string{"ssm:GetParameter", "ssm:GetParameters"}},
					},
				},
			},
			wantActions: []string{"ssm:GetParameter", "ssm:GetParameters"},
		},
		{
			name: "deduplication",
			perms: []FeaturePermissions{
				{
					Permissions: []Permission{
						{Actions: []string{"ssm:GetParameter"}},
					},
				},
				{
					Permissions: []Permission{
						{Actions: []string{"ssm:GetParameter", "ssm:PutParameter"}},
					},
				},
			},
			wantActions: []string{"ssm:GetParameter", "ssm:PutParameter"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UniqueActions(tt.perms)

			if len(got) != len(tt.wantActions) {
				t.Errorf("UniqueActions() returned %d actions, want %d", len(got), len(tt.wantActions))
			}

			// Verify all expected actions present
			gotSet := make(map[string]bool)
			for _, a := range got {
				gotSet[a] = true
			}

			for _, want := range tt.wantActions {
				if !gotSet[want] {
					t.Errorf("UniqueActions() missing action %s", want)
				}
			}
		})
	}
}

func TestUniqueActions_AllPermissions(t *testing.T) {
	// Test with all permissions
	allPerms := GetAllPermissions()
	actions := UniqueActions(allPerms)

	// Should have at least the core actions
	expectedActions := []string{
		"ssm:GetParameter",
		"sts:AssumeRole",
		"dynamodb:PutItem",
		"dynamodb:GetItem",
		"sns:Publish",
		"cloudtrail:LookupEvents",
		"iam:GetRole",
	}

	actionSet := make(map[string]bool)
	for _, a := range actions {
		actionSet[a] = true
	}

	for _, expected := range expectedActions {
		if !actionSet[expected] {
			t.Errorf("UniqueActions(GetAllPermissions()) missing expected action %s", expected)
		}
	}
}

func TestByService(t *testing.T) {
	tests := []struct {
		name         string
		perms        []FeaturePermissions
		wantServices []string
	}{
		{
			name:         "empty input",
			perms:        []FeaturePermissions{},
			wantServices: nil,
		},
		{
			name: "single service",
			perms: []FeaturePermissions{
				{
					Permissions: []Permission{
						{Service: "ssm", Actions: []string{"ssm:GetParameter"}},
					},
				},
			},
			wantServices: []string{"ssm"},
		},
		{
			name: "multiple services",
			perms: []FeaturePermissions{
				{
					Permissions: []Permission{
						{Service: "ssm", Actions: []string{"ssm:GetParameter"}},
					},
				},
				{
					Permissions: []Permission{
						{Service: "dynamodb", Actions: []string{"dynamodb:PutItem"}},
						{Service: "iam", Actions: []string{"iam:GetRole"}},
					},
				},
			},
			wantServices: []string{"ssm", "dynamodb", "iam"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ByService(tt.perms)

			if len(got) != len(tt.wantServices) {
				t.Errorf("ByService() returned %d services, want %d", len(got), len(tt.wantServices))
			}

			for _, svc := range tt.wantServices {
				if _, ok := got[svc]; !ok {
					t.Errorf("ByService() missing service %s", svc)
				}
			}
		})
	}
}

func TestByService_AllPermissions(t *testing.T) {
	allPerms := GetAllPermissions()
	byService := ByService(allPerms)

	// Expected services
	expectedServices := []string{"ssm", "sts", "dynamodb", "sns", "cloudtrail", "iam"}

	for _, svc := range expectedServices {
		if _, ok := byService[svc]; !ok {
			t.Errorf("ByService(GetAllPermissions()) missing service %s", svc)
		}
	}

	// SSM should have multiple permissions (from policy load, bootstrap plan, bootstrap apply)
	if len(byService["ssm"]) < 2 {
		t.Errorf("ByService() should have multiple SSM permissions, got %d", len(byService["ssm"]))
	}

	// DynamoDB should have permissions from both approvals and breakglass
	if len(byService["dynamodb"]) < 2 {
		t.Errorf("ByService() should have multiple DynamoDB permissions, got %d", len(byService["dynamodb"]))
	}
}

func TestRegistry_NoDuplicateActionsWithinPermission(t *testing.T) {
	// Check for duplicate actions within a single Permission entry (same resource)
	// Note: The same action can appear in different Permission entries if they target
	// different resources (e.g., dynamodb:Query on table and index)
	for _, fp := range GetAllPermissions() {
		t.Run(fp.Feature.String(), func(t *testing.T) {
			for _, p := range fp.Permissions {
				actionSeen := make(map[string]bool)
				for _, action := range p.Actions {
					if actionSeen[action] {
						t.Errorf("Feature %s has duplicate action %s in permission for %s",
							fp.Feature, action, p.Resource)
					}
					actionSeen[action] = true
				}
			}
		})
	}
}

func TestRegistry_AllPermissionsHaveDescription(t *testing.T) {
	for _, fp := range GetAllPermissions() {
		for _, p := range fp.Permissions {
			if p.Description == "" {
				t.Errorf("Feature %s permission for %s has empty description",
					fp.Feature, p.Service)
			}
		}
	}
}

func TestRegistry_AllPermissionsHaveResource(t *testing.T) {
	for _, fp := range GetAllPermissions() {
		for _, p := range fp.Permissions {
			if p.Resource == "" {
				t.Errorf("Feature %s permission for %s has empty resource",
					fp.Feature, p.Service)
			}
		}
	}
}

func TestWebhookHasNoPermissions(t *testing.T) {
	fp, ok := GetFeaturePermissions(FeatureNotifyWebhook)
	if !ok {
		t.Fatal("FeatureNotifyWebhook not found")
	}

	if len(fp.Permissions) != 0 {
		t.Errorf("FeatureNotifyWebhook should have no AWS permissions, got %d", len(fp.Permissions))
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
