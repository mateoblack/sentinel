package permissions

import (
	"testing"
)

func TestSubsystem_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		subsystem Subsystem
		want      bool
	}{
		{"valid core", SubsystemCore, true},
		{"valid credentials", SubsystemCredentials, true},
		{"valid approvals", SubsystemApprovals, true},
		{"valid breakglass", SubsystemBreakGlass, true},
		{"valid notifications", SubsystemNotifications, true},
		{"valid audit", SubsystemAudit, true},
		{"valid enforce", SubsystemEnforce, true},
		{"valid bootstrap", SubsystemBootstrap, true},
		{"invalid empty", Subsystem(""), false},
		{"invalid unknown", Subsystem("unknown"), false},
		{"invalid similar", Subsystem("CORE"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.subsystem.IsValid(); got != tt.want {
				t.Errorf("Subsystem.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubsystem_String(t *testing.T) {
	tests := []struct {
		subsystem Subsystem
		want      string
	}{
		{SubsystemCore, "core"},
		{SubsystemCredentials, "credentials"},
		{SubsystemApprovals, "approvals"},
		{SubsystemBreakGlass, "breakglass"},
		{SubsystemNotifications, "notifications"},
		{SubsystemAudit, "audit"},
		{SubsystemEnforce, "enforce"},
		{SubsystemBootstrap, "bootstrap"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.subsystem.String(); got != tt.want {
				t.Errorf("Subsystem.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllSubsystems(t *testing.T) {
	subsystems := AllSubsystems()

	// Verify count matches expected
	if len(subsystems) != 9 {
		t.Errorf("AllSubsystems() returned %d subsystems, want 9", len(subsystems))
	}

	// Verify all are valid
	for _, s := range subsystems {
		if !s.IsValid() {
			t.Errorf("AllSubsystems() returned invalid subsystem: %s", s)
		}
	}

	// Verify expected subsystems are present
	expected := map[Subsystem]bool{
		SubsystemCore:          false,
		SubsystemCredentials:   false,
		SubsystemApprovals:     false,
		SubsystemBreakGlass:    false,
		SubsystemNotifications: false,
		SubsystemAudit:         false,
		SubsystemEnforce:       false,
		SubsystemBootstrap:     false,
		SubsystemSessions:      false,
	}

	for _, s := range subsystems {
		expected[s] = true
	}

	for s, found := range expected {
		if !found {
			t.Errorf("AllSubsystems() missing expected subsystem: %s", s)
		}
	}
}

func TestFeature_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		feature Feature
		want    bool
	}{
		{"valid policy_load", FeaturePolicyLoad, true},
		{"valid credential_issue", FeatureCredentialIssue, true},
		{"valid approval_workflow", FeatureApprovalWorkflow, true},
		{"valid breakglass", FeatureBreakGlass, true},
		{"valid notify_sns", FeatureNotifySNS, true},
		{"valid notify_webhook", FeatureNotifyWebhook, true},
		{"valid audit_verify", FeatureAuditVerify, true},
		{"valid enforce_analyze", FeatureEnforceAnalyze, true},
		{"valid bootstrap_plan", FeatureBootstrapPlan, true},
		{"valid bootstrap_apply", FeatureBootstrapApply, true},
		{"invalid empty", Feature(""), false},
		{"invalid unknown", Feature("unknown"), false},
		{"invalid similar", Feature("POLICY_LOAD"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.feature.IsValid(); got != tt.want {
				t.Errorf("Feature.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFeature_String(t *testing.T) {
	tests := []struct {
		feature Feature
		want    string
	}{
		{FeaturePolicyLoad, "policy_load"},
		{FeatureCredentialIssue, "credential_issue"},
		{FeatureApprovalWorkflow, "approval_workflow"},
		{FeatureBreakGlass, "breakglass"},
		{FeatureNotifySNS, "notify_sns"},
		{FeatureNotifyWebhook, "notify_webhook"},
		{FeatureAuditVerify, "audit_verify"},
		{FeatureEnforceAnalyze, "enforce_analyze"},
		{FeatureBootstrapPlan, "bootstrap_plan"},
		{FeatureBootstrapApply, "bootstrap_apply"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.feature.String(); got != tt.want {
				t.Errorf("Feature.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllFeatures(t *testing.T) {
	features := AllFeatures()

	// Verify count matches expected
	if len(features) != 11 {
		t.Errorf("AllFeatures() returned %d features, want 11", len(features))
	}

	// Verify all are valid
	for _, f := range features {
		if !f.IsValid() {
			t.Errorf("AllFeatures() returned invalid feature: %s", f)
		}
	}

	// Verify expected features are present
	expected := map[Feature]bool{
		FeaturePolicyLoad:       false,
		FeatureCredentialIssue:  false,
		FeatureApprovalWorkflow: false,
		FeatureBreakGlass:       false,
		FeatureNotifySNS:        false,
		FeatureNotifyWebhook:    false,
		FeatureAuditVerify:      false,
		FeatureEnforceAnalyze:   false,
		FeatureBootstrapPlan:    false,
		FeatureBootstrapApply:   false,
		FeatureSessionTracking:  false,
	}

	for _, f := range features {
		expected[f] = true
	}

	for f, found := range expected {
		if !found {
			t.Errorf("AllFeatures() missing expected feature: %s", f)
		}
	}
}

func TestSubsystem_Features(t *testing.T) {
	tests := []struct {
		name      string
		subsystem Subsystem
		want      []Feature
	}{
		{
			name:      "core has policy_load",
			subsystem: SubsystemCore,
			want:      []Feature{FeaturePolicyLoad},
		},
		{
			name:      "credentials has credential_issue",
			subsystem: SubsystemCredentials,
			want:      []Feature{FeatureCredentialIssue},
		},
		{
			name:      "approvals has approval_workflow",
			subsystem: SubsystemApprovals,
			want:      []Feature{FeatureApprovalWorkflow},
		},
		{
			name:      "breakglass has breakglass",
			subsystem: SubsystemBreakGlass,
			want:      []Feature{FeatureBreakGlass},
		},
		{
			name:      "notifications has sns and webhook",
			subsystem: SubsystemNotifications,
			want:      []Feature{FeatureNotifySNS, FeatureNotifyWebhook},
		},
		{
			name:      "audit has audit_verify",
			subsystem: SubsystemAudit,
			want:      []Feature{FeatureAuditVerify},
		},
		{
			name:      "enforce has enforce_analyze",
			subsystem: SubsystemEnforce,
			want:      []Feature{FeatureEnforceAnalyze},
		},
		{
			name:      "bootstrap has plan and apply",
			subsystem: SubsystemBootstrap,
			want:      []Feature{FeatureBootstrapPlan, FeatureBootstrapApply},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.subsystem.Features()

			if len(got) != len(tt.want) {
				t.Errorf("Subsystem.Features() returned %d features, want %d", len(got), len(tt.want))
				return
			}

			for i, f := range got {
				if f != tt.want[i] {
					t.Errorf("Subsystem.Features()[%d] = %v, want %v", i, f, tt.want[i])
				}
			}
		})
	}
}

func TestSubsystem_Features_Coverage(t *testing.T) {
	// Verify all features are mapped to exactly one subsystem
	allFeatures := AllFeatures()
	featureSeen := make(map[Feature]Subsystem)

	for _, subsystem := range AllSubsystems() {
		for _, feature := range subsystem.Features() {
			if existing, ok := featureSeen[feature]; ok {
				t.Errorf("Feature %s mapped to multiple subsystems: %s and %s", feature, existing, subsystem)
			}
			featureSeen[feature] = subsystem
		}
	}

	// Verify all features have a subsystem
	for _, feature := range allFeatures {
		if _, ok := featureSeen[feature]; !ok {
			t.Errorf("Feature %s is not mapped to any subsystem", feature)
		}
	}
}

func TestPermission_Fields(t *testing.T) {
	// Verify Permission struct can be constructed with expected fields
	p := Permission{
		Service:     "ssm",
		Actions:     []string{"ssm:GetParameter"},
		Resource:    "arn:aws:ssm:*:*:parameter/sentinel/*",
		Description: "Read policy parameters from SSM",
	}

	if p.Service != "ssm" {
		t.Errorf("Permission.Service = %v, want ssm", p.Service)
	}
	if len(p.Actions) != 1 || p.Actions[0] != "ssm:GetParameter" {
		t.Errorf("Permission.Actions = %v, want [ssm:GetParameter]", p.Actions)
	}
	if p.Resource != "arn:aws:ssm:*:*:parameter/sentinel/*" {
		t.Errorf("Permission.Resource = %v, want arn:aws:ssm:*:*:parameter/sentinel/*", p.Resource)
	}
	if p.Description != "Read policy parameters from SSM" {
		t.Errorf("Permission.Description = %v, want Read policy parameters from SSM", p.Description)
	}
}

func TestFeaturePermissions_Fields(t *testing.T) {
	// Verify FeaturePermissions struct can be constructed with expected fields
	fp := FeaturePermissions{
		Feature:   FeaturePolicyLoad,
		Subsystem: SubsystemCore,
		Permissions: []Permission{
			{
				Service:     "ssm",
				Actions:     []string{"ssm:GetParameter"},
				Resource:    "arn:aws:ssm:*:*:parameter/sentinel/*",
				Description: "Read policy parameters",
			},
		},
		Optional: false,
	}

	if fp.Feature != FeaturePolicyLoad {
		t.Errorf("FeaturePermissions.Feature = %v, want %v", fp.Feature, FeaturePolicyLoad)
	}
	if fp.Subsystem != SubsystemCore {
		t.Errorf("FeaturePermissions.Subsystem = %v, want %v", fp.Subsystem, SubsystemCore)
	}
	if len(fp.Permissions) != 1 {
		t.Errorf("FeaturePermissions.Permissions length = %d, want 1", len(fp.Permissions))
	}
	if fp.Optional != false {
		t.Errorf("FeaturePermissions.Optional = %v, want false", fp.Optional)
	}
}
