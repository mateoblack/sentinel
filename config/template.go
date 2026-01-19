// Package config provides configuration validation and template generation for Sentinel.
package config

import (
	"bytes"
	"fmt"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/policy"
	"gopkg.in/yaml.v3"
)

// TemplateID identifies a pre-built configuration template.
type TemplateID string

const (
	// TemplateBasic is a simple allow policy for configured profiles.
	TemplateBasic TemplateID = "basic"
	// TemplateApprovals is a policy with require_approval and approval workflow.
	TemplateApprovals TemplateID = "approvals"
	// TemplateFull is a complete enterprise setup with all policy types.
	TemplateFull TemplateID = "full"
)

// IsValid returns true if the TemplateID is a known value.
func (t TemplateID) IsValid() bool {
	switch t {
	case TemplateBasic, TemplateApprovals, TemplateFull:
		return true
	}
	return false
}

// String returns the string representation of the TemplateID.
func (t TemplateID) String() string {
	return string(t)
}

// AllTemplateIDs returns all valid template ID values.
func AllTemplateIDs() []TemplateID {
	return []TemplateID{TemplateBasic, TemplateApprovals, TemplateFull}
}

// Template describes a pre-built configuration template.
type Template struct {
	ID          TemplateID
	Name        string
	Description string
	Features    []string // Features this template requires (for permissions)
}

// templateRegistry contains metadata for all templates.
var templateRegistry = map[TemplateID]Template{
	TemplateBasic: {
		ID:          TemplateBasic,
		Name:        "Basic Access Policy",
		Description: "Simple allow policy for configured profiles with default deny",
		Features:    []string{"policy_load"},
	},
	TemplateApprovals: {
		ID:          TemplateApprovals,
		Name:        "Approval Workflow",
		Description: "Policy requiring approvals with business hours auto-approve",
		Features:    []string{"policy_load", "approval_workflow"},
	},
	TemplateFull: {
		ID:          TemplateFull,
		Name:        "Full Enterprise",
		Description: "Complete setup with approvals, break-glass, and rate limiting",
		Features:    []string{"policy_load", "approval_workflow", "breakglass"},
	},
}

// GetTemplate returns the template metadata for the given ID.
// Returns false if the template ID is not found.
func GetTemplate(id TemplateID) (Template, bool) {
	t, ok := templateRegistry[id]
	return t, ok
}

// AllTemplates returns metadata for all available templates.
func AllTemplates() []Template {
	templates := make([]Template, 0, len(templateRegistry))
	for _, id := range AllTemplateIDs() {
		templates = append(templates, templateRegistry[id])
	}
	return templates
}

// TemplateOutput contains the generated configuration YAML strings.
type TemplateOutput struct {
	Policy     string // Access policy YAML
	Approval   string // Approval policy YAML (empty for basic)
	BreakGlass string // Break-glass policy YAML (empty for basic/approvals)
	RateLimit  string // Rate limit policy YAML (empty for basic/approvals)
}

// GenerateTemplate generates configuration files for the specified template.
// profiles must contain at least one profile name.
// users is required for approvals and full templates (for approvers/break-glass authorization).
func GenerateTemplate(id TemplateID, profiles []string, users []string) (*TemplateOutput, error) {
	// Validate inputs
	if !id.IsValid() {
		return nil, fmt.Errorf("invalid template ID: %s", id)
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("at least one profile is required")
	}

	// Users required for approvals and full templates
	if (id == TemplateApprovals || id == TemplateFull) && len(users) == 0 {
		return nil, fmt.Errorf("at least one user is required for %s template", id)
	}

	switch id {
	case TemplateBasic:
		return generateBasicTemplate(profiles)
	case TemplateApprovals:
		return generateApprovalsTemplate(profiles, users)
	case TemplateFull:
		return generateFullTemplate(profiles, users)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", id)
	}
}

// generateBasicTemplate generates a simple allow policy.
// Note: No explicit default-deny rule is needed because the policy engine
// returns deny when no rules match.
func generateBasicTemplate(profiles []string) (*TemplateOutput, error) {
	p := policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "allow-configured-profiles",
				Effect: policy.EffectAllow,
				Conditions: policy.Condition{
					Profiles: profiles,
				},
				Reason: "Access allowed for configured profiles",
			},
		},
	}

	policyYAML, err := marshalWithHeader(p, "Access Policy", profiles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate policy: %w", err)
	}

	return &TemplateOutput{
		Policy: policyYAML,
	}, nil
}

// generateApprovalsTemplate generates policy with require_approval and approval policy.
// Note: No explicit default-deny rule is needed because the policy engine
// returns deny when no rules match.
func generateApprovalsTemplate(profiles []string, users []string) (*TemplateOutput, error) {
	// Access policy with require_approval
	accessPolicy := policy.Policy{
		Version: "1",
		Rules: []policy.Rule{
			{
				Name:   "require-approval-for-profiles",
				Effect: policy.EffectRequireApproval,
				Conditions: policy.Condition{
					Profiles: profiles,
				},
				Reason: "Access requires approval for configured profiles",
			},
		},
	}

	// Approval policy with business hours auto-approve
	approvalPolicy := policy.ApprovalPolicy{
		Version: "1",
		Rules: []policy.ApprovalRule{
			{
				Name:      "approval-rule",
				Profiles:  profiles,
				Approvers: users,
				AutoApprove: &policy.AutoApproveCondition{
					Time: &policy.TimeWindow{
						Days: []policy.Weekday{
							policy.Monday,
							policy.Tuesday,
							policy.Wednesday,
							policy.Thursday,
							policy.Friday,
						},
						Hours: &policy.HourRange{
							Start: "09:00",
							End:   "17:00",
						},
						Timezone: "UTC",
					},
					MaxDuration: time.Hour,
				},
			},
		},
	}

	policyYAML, err := marshalWithHeader(accessPolicy, "Access Policy", profiles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access policy: %w", err)
	}

	approvalYAML, err := marshalWithHeader(approvalPolicy, "Approval Policy", profiles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate approval policy: %w", err)
	}

	return &TemplateOutput{
		Policy:   policyYAML,
		Approval: approvalYAML,
	}, nil
}

// generateFullTemplate generates a complete enterprise configuration.
func generateFullTemplate(profiles []string, users []string) (*TemplateOutput, error) {
	// Start with approvals template
	output, err := generateApprovalsTemplate(profiles, users)
	if err != nil {
		return nil, err
	}

	// Break-glass policy
	breakGlassPolicy := breakglass.BreakGlassPolicy{
		Version: "1",
		Rules: []breakglass.BreakGlassPolicyRule{
			{
				Name:     "break-glass-authorization",
				Profiles: profiles,
				Users:    users,
				AllowedReasonCodes: []breakglass.ReasonCode{
					breakglass.ReasonIncident,
					breakglass.ReasonMaintenance,
					breakglass.ReasonSecurity,
					breakglass.ReasonRecovery,
				},
				MaxDuration: time.Hour,
			},
		},
	}

	// Rate limit policy
	rateLimitPolicy := breakglass.RateLimitPolicy{
		Version: "1",
		Rules: []breakglass.RateLimitRule{
			{
				Name:          "rate-limits",
				Profiles:      profiles,
				Cooldown:      30 * time.Minute,
				MaxPerUser:    3,
				MaxPerProfile: 10,
				QuotaWindow:   24 * time.Hour,
			},
		},
	}

	breakGlassYAML, err := marshalWithHeader(breakGlassPolicy, "Break-Glass Policy", profiles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate break-glass policy: %w", err)
	}

	rateLimitYAML, err := marshalWithHeader(rateLimitPolicy, "Rate Limit Policy", profiles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rate limit policy: %w", err)
	}

	output.BreakGlass = breakGlassYAML
	output.RateLimit = rateLimitYAML

	return output, nil
}

// marshalWithHeader marshals a value to YAML with a header comment.
func marshalWithHeader(v interface{}, title string, profiles []string) (string, error) {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(v); err != nil {
		return "", err
	}
	encoder.Close()

	header := buildTemplateHeader(title, profiles)
	return header + buf.String(), nil
}

// buildTemplateHeader creates a comment header for generated configs.
func buildTemplateHeader(title string, profiles []string) string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("# Sentinel %s\n", title))
	buf.WriteString(fmt.Sprintf("# Profiles: %v\n", profiles))
	buf.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	buf.WriteString("# Customize this configuration to match your requirements.\n\n")

	return buf.String()
}
