package config

import (
	"strings"
	"testing"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/policy"
	"gopkg.in/yaml.v3"
)

func TestTemplateID_IsValid(t *testing.T) {
	tests := []struct {
		id    TemplateID
		valid bool
	}{
		{TemplateBasic, true},
		{TemplateApprovals, true},
		{TemplateFull, true},
		{TemplateID("invalid"), false},
		{TemplateID(""), false},
	}

	for _, tc := range tests {
		t.Run(string(tc.id), func(t *testing.T) {
			if got := tc.id.IsValid(); got != tc.valid {
				t.Errorf("IsValid() = %v, want %v", got, tc.valid)
			}
		})
	}
}

func TestTemplateID_String(t *testing.T) {
	tests := []struct {
		id   TemplateID
		want string
	}{
		{TemplateBasic, "basic"},
		{TemplateApprovals, "approvals"},
		{TemplateFull, "full"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.id.String(); got != tc.want {
				t.Errorf("String() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAllTemplateIDs(t *testing.T) {
	ids := AllTemplateIDs()
	if len(ids) != 3 {
		t.Fatalf("AllTemplateIDs() returned %d items, want 3", len(ids))
	}

	expected := map[TemplateID]bool{
		TemplateBasic:     true,
		TemplateApprovals: true,
		TemplateFull:      true,
	}

	for _, id := range ids {
		if !expected[id] {
			t.Errorf("Unexpected template ID: %s", id)
		}
	}
}

func TestGetTemplate(t *testing.T) {
	tests := []struct {
		id       TemplateID
		wantOK   bool
		wantName string
	}{
		{TemplateBasic, true, "Basic Access Policy"},
		{TemplateApprovals, true, "Approval Workflow"},
		{TemplateFull, true, "Full Enterprise"},
		{TemplateID("invalid"), false, ""},
	}

	for _, tc := range tests {
		t.Run(string(tc.id), func(t *testing.T) {
			tmpl, ok := GetTemplate(tc.id)
			if ok != tc.wantOK {
				t.Errorf("GetTemplate() ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && tmpl.Name != tc.wantName {
				t.Errorf("GetTemplate() name = %v, want %v", tmpl.Name, tc.wantName)
			}
		})
	}
}

func TestAllTemplates(t *testing.T) {
	templates := AllTemplates()
	if len(templates) != 3 {
		t.Fatalf("AllTemplates() returned %d items, want 3", len(templates))
	}

	// Verify each template has required fields
	for _, tmpl := range templates {
		if tmpl.ID == "" {
			t.Error("Template has empty ID")
		}
		if tmpl.Name == "" {
			t.Errorf("Template %s has empty Name", tmpl.ID)
		}
		if tmpl.Description == "" {
			t.Errorf("Template %s has empty Description", tmpl.ID)
		}
		if len(tmpl.Features) == 0 {
			t.Errorf("Template %s has no Features", tmpl.ID)
		}
	}
}

func TestGenerateTemplate_Validation(t *testing.T) {
	tests := []struct {
		name     string
		id       TemplateID
		profiles []string
		users    []string
		wantErr  string
	}{
		{
			name:     "invalid template ID",
			id:       TemplateID("invalid"),
			profiles: []string{"dev"},
			wantErr:  "invalid template ID",
		},
		{
			name:    "no profiles",
			id:      TemplateBasic,
			wantErr: "at least one profile",
		},
		{
			name:     "approvals without users",
			id:       TemplateApprovals,
			profiles: []string{"dev"},
			wantErr:  "at least one user",
		},
		{
			name:     "full without users",
			id:       TemplateFull,
			profiles: []string{"dev"},
			wantErr:  "at least one user",
		},
		{
			name:     "basic without users is OK",
			id:       TemplateBasic,
			profiles: []string{"dev"},
			wantErr:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GenerateTemplate(tc.id, tc.profiles, tc.users)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want containing %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGenerateTemplate_Basic(t *testing.T) {
	profiles := []string{"dev", "staging"}

	output, err := GenerateTemplate(TemplateBasic, profiles, nil)
	if err != nil {
		t.Fatalf("GenerateTemplate() error = %v", err)
	}

	// Verify policy is generated
	if output.Policy == "" {
		t.Error("expected Policy to be generated")
	}

	// Verify other configs are empty
	if output.Approval != "" {
		t.Error("expected Approval to be empty for basic template")
	}
	if output.BreakGlass != "" {
		t.Error("expected BreakGlass to be empty for basic template")
	}
	if output.RateLimit != "" {
		t.Error("expected RateLimit to be empty for basic template")
	}

	// Verify header contains expected content
	if !strings.Contains(output.Policy, "# Sentinel Access Policy") {
		t.Error("expected policy to contain header")
	}
	if !strings.Contains(output.Policy, "dev") {
		t.Error("expected policy to contain profile names")
	}

	// Verify YAML is valid and contains expected rules
	var p policy.Policy
	// Strip header comments for YAML parsing
	yamlContent := stripComments(output.Policy)
	if err := yaml.Unmarshal([]byte(yamlContent), &p); err != nil {
		t.Fatalf("failed to parse generated policy YAML: %v", err)
	}

	if p.Version != "1" {
		t.Errorf("policy version = %v, want 1", p.Version)
	}
	// Only one rule - no explicit default-deny needed (policy engine denies by default)
	if len(p.Rules) != 1 {
		t.Errorf("policy rules count = %d, want 1", len(p.Rules))
	}

	// Rule should be allow
	if p.Rules[0].Effect != policy.EffectAllow {
		t.Errorf("rule effect = %v, want allow", p.Rules[0].Effect)
	}
	if len(p.Rules[0].Conditions.Profiles) != 2 {
		t.Errorf("rule profiles = %d, want 2", len(p.Rules[0].Conditions.Profiles))
	}
}

func TestGenerateTemplate_Approvals(t *testing.T) {
	profiles := []string{"prod"}
	users := []string{"alice", "bob"}

	output, err := GenerateTemplate(TemplateApprovals, profiles, users)
	if err != nil {
		t.Fatalf("GenerateTemplate() error = %v", err)
	}

	// Verify policy and approval are generated
	if output.Policy == "" {
		t.Error("expected Policy to be generated")
	}
	if output.Approval == "" {
		t.Error("expected Approval to be generated")
	}

	// Verify break-glass and rate limit are empty
	if output.BreakGlass != "" {
		t.Error("expected BreakGlass to be empty for approvals template")
	}
	if output.RateLimit != "" {
		t.Error("expected RateLimit to be empty for approvals template")
	}

	// Verify access policy has require_approval
	var p policy.Policy
	if err := yaml.Unmarshal([]byte(stripComments(output.Policy)), &p); err != nil {
		t.Fatalf("failed to parse access policy: %v", err)
	}
	if p.Rules[0].Effect != policy.EffectRequireApproval {
		t.Errorf("first rule effect = %v, want require_approval", p.Rules[0].Effect)
	}

	// Verify approval policy has correct structure
	var ap policy.ApprovalPolicy
	if err := yaml.Unmarshal([]byte(stripComments(output.Approval)), &ap); err != nil {
		t.Fatalf("failed to parse approval policy: %v", err)
	}
	if len(ap.Rules) != 1 {
		t.Errorf("approval policy rules = %d, want 1", len(ap.Rules))
	}
	if len(ap.Rules[0].Approvers) != 2 {
		t.Errorf("approvers count = %d, want 2", len(ap.Rules[0].Approvers))
	}
	if ap.Rules[0].AutoApprove == nil {
		t.Error("expected auto_approve to be set")
	}
	if ap.Rules[0].AutoApprove.Time == nil {
		t.Error("expected auto_approve.time to be set")
	}
	if len(ap.Rules[0].AutoApprove.Time.Days) != 5 {
		t.Errorf("auto_approve days = %d, want 5 (business days)", len(ap.Rules[0].AutoApprove.Time.Days))
	}
}

func TestGenerateTemplate_Full(t *testing.T) {
	profiles := []string{"prod", "staging"}
	users := []string{"oncall-team"}

	output, err := GenerateTemplate(TemplateFull, profiles, users)
	if err != nil {
		t.Fatalf("GenerateTemplate() error = %v", err)
	}

	// Verify all configs are generated
	if output.Policy == "" {
		t.Error("expected Policy to be generated")
	}
	if output.Approval == "" {
		t.Error("expected Approval to be generated")
	}
	if output.BreakGlass == "" {
		t.Error("expected BreakGlass to be generated")
	}
	if output.RateLimit == "" {
		t.Error("expected RateLimit to be generated")
	}

	// Verify break-glass policy
	var bgp breakglass.BreakGlassPolicy
	if err := yaml.Unmarshal([]byte(stripComments(output.BreakGlass)), &bgp); err != nil {
		t.Fatalf("failed to parse break-glass policy: %v", err)
	}
	if len(bgp.Rules) != 1 {
		t.Errorf("break-glass rules = %d, want 1", len(bgp.Rules))
	}
	if len(bgp.Rules[0].Users) != 1 {
		t.Errorf("break-glass users = %d, want 1", len(bgp.Rules[0].Users))
	}
	if len(bgp.Rules[0].AllowedReasonCodes) != 4 {
		t.Errorf("break-glass reason codes = %d, want 4", len(bgp.Rules[0].AllowedReasonCodes))
	}

	// Verify rate limit policy
	var rlp breakglass.RateLimitPolicy
	if err := yaml.Unmarshal([]byte(stripComments(output.RateLimit)), &rlp); err != nil {
		t.Fatalf("failed to parse rate limit policy: %v", err)
	}
	if len(rlp.Rules) != 1 {
		t.Errorf("rate limit rules = %d, want 1", len(rlp.Rules))
	}
	if rlp.Rules[0].Cooldown != 30*60*1e9 { // 30 minutes in nanoseconds
		t.Errorf("cooldown = %v, want 30m", rlp.Rules[0].Cooldown)
	}
	if rlp.Rules[0].MaxPerUser != 3 {
		t.Errorf("max_per_user = %d, want 3", rlp.Rules[0].MaxPerUser)
	}
	if rlp.Rules[0].MaxPerProfile != 10 {
		t.Errorf("max_per_profile = %d, want 10", rlp.Rules[0].MaxPerProfile)
	}
}

func TestGenerateTemplate_GeneratedConfigsValidate(t *testing.T) {
	tests := []struct {
		name     string
		id       TemplateID
		profiles []string
		users    []string
	}{
		{
			name:     "basic template",
			id:       TemplateBasic,
			profiles: []string{"dev"},
		},
		{
			name:     "approvals template",
			id:       TemplateApprovals,
			profiles: []string{"prod"},
			users:    []string{"approver"},
		},
		{
			name:     "full template",
			id:       TemplateFull,
			profiles: []string{"prod", "staging"},
			users:    []string{"oncall", "admin"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, err := GenerateTemplate(tc.id, tc.profiles, tc.users)
			if err != nil {
				t.Fatalf("GenerateTemplate() error = %v", err)
			}

			// Validate access policy
			result := Validate(ConfigTypePolicy, []byte(stripComments(output.Policy)), "generated")
			if !result.Valid {
				t.Errorf("generated access policy is invalid: %v", result.Issues)
			}

			// Validate approval policy if present
			if output.Approval != "" {
				result := Validate(ConfigTypeApproval, []byte(stripComments(output.Approval)), "generated")
				if !result.Valid {
					t.Errorf("generated approval policy is invalid: %v", result.Issues)
				}
			}

			// Validate break-glass policy if present
			if output.BreakGlass != "" {
				result := Validate(ConfigTypeBreakGlass, []byte(stripComments(output.BreakGlass)), "generated")
				if !result.Valid {
					t.Errorf("generated break-glass policy is invalid: %v", result.Issues)
				}
			}

			// Validate rate limit policy if present
			if output.RateLimit != "" {
				result := Validate(ConfigTypeRateLimit, []byte(stripComments(output.RateLimit)), "generated")
				if !result.Valid {
					t.Errorf("generated rate limit policy is invalid: %v", result.Issues)
				}
			}
		})
	}
}

// stripComments removes lines starting with # from YAML content.
func stripComments(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}
