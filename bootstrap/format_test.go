package bootstrap

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFormatPlan_MixedStates(t *testing.T) {
	plan := &BootstrapPlan{
		Config: BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Region:     "us-east-1",
		},
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/staging", State: StateExists, CurrentVersion: "3"},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/prod", State: StateCreate},
		},
		Summary: PlanSummary{ToCreate: 2, ToUpdate: 0, ToSkip: 1, Total: 3},
	}

	output := FormatPlan(plan)

	// Check header
	if !strings.Contains(output, "Bootstrap Plan") {
		t.Error("missing header")
	}

	// Check config info
	if !strings.Contains(output, "Policy Root: /sentinel/policies") {
		t.Error("missing policy root")
	}
	if !strings.Contains(output, "Region: us-east-1") {
		t.Error("missing region")
	}

	// Check symbols
	if !strings.Contains(output, "+ /sentinel/policies/dev") {
		t.Error("missing create symbol for dev")
	}
	if !strings.Contains(output, "= /sentinel/policies/staging") {
		t.Error("missing exists symbol for staging")
	}
	if !strings.Contains(output, "v3") {
		t.Error("missing version for staging")
	}
	if !strings.Contains(output, "+ /sentinel/policies/prod") {
		t.Error("missing create symbol for prod")
	}

	// Check summary
	if !strings.Contains(output, "2 to create") {
		t.Error("missing create count in summary")
	}
	if !strings.Contains(output, "1 existing") {
		t.Error("missing existing count in summary")
	}
}

func TestFormatPlan_AllExist(t *testing.T) {
	plan := &BootstrapPlan{
		Config: BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
		},
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateExists, CurrentVersion: "1"},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/prod", State: StateExists, CurrentVersion: "2"},
		},
		Summary: PlanSummary{ToCreate: 0, ToUpdate: 0, ToSkip: 2, Total: 2},
	}

	output := FormatPlan(plan)

	// Should show "default" region when empty
	if !strings.Contains(output, "Region: default") {
		t.Error("missing default region")
	}

	// All should have exists symbol (check for "= /" pattern which indicates exists state)
	if strings.Count(output, "= /") != 2 {
		t.Errorf("expected 2 exists symbols, got %d", strings.Count(output, "= /"))
	}

	// Summary should show 0 to create
	if !strings.Contains(output, "0 to create") {
		t.Error("missing 0 to create in summary")
	}
}

func TestFormatPlan_WithIAMPolicies(t *testing.T) {
	plan := &BootstrapPlan{
		Config: BootstrapConfig{
			PolicyRoot:          "/sentinel/policies",
			GenerateIAMPolicies: true,
		},
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate},
			{Type: ResourceTypeIAMPolicy, Name: "SentinelPolicyReader", State: StateCreate},
			{Type: ResourceTypeIAMPolicy, Name: "SentinelPolicyAdmin", State: StateCreate},
		},
		Summary: PlanSummary{ToCreate: 3, ToUpdate: 0, ToSkip: 0, Total: 3},
	}

	output := FormatPlan(plan)

	// Should have grouped sections
	if !strings.Contains(output, "SSM Parameters:") {
		t.Error("missing SSM Parameters section header")
	}
	if !strings.Contains(output, "IAM Policy Documents:") {
		t.Error("missing IAM Policy Documents section header")
	}

	// Check IAM policies show "generate" action
	if !strings.Contains(output, "SentinelPolicyReader") {
		t.Error("missing SentinelPolicyReader")
	}
	if !strings.Contains(output, "SentinelPolicyAdmin") {
		t.Error("missing SentinelPolicyAdmin")
	}
	if !strings.Contains(output, "(generate)") {
		t.Error("missing generate action for IAM policies")
	}
}

func TestFormatPlan_EmptyResources(t *testing.T) {
	plan := &BootstrapPlan{
		Config: BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
		},
		Resources: []ResourceSpec{},
		Summary:   PlanSummary{Total: 0},
	}

	output := FormatPlan(plan)

	if !strings.Contains(output, "Resources: (none)") {
		t.Error("missing empty resources indicator")
	}
	if !strings.Contains(output, "No resources to manage") {
		t.Error("missing empty summary")
	}
}

func TestFormatPlan_UpdateState(t *testing.T) {
	plan := &BootstrapPlan{
		Config: BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
		},
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateUpdate, CurrentVersion: "5"},
		},
		Summary: PlanSummary{ToCreate: 0, ToUpdate: 1, ToSkip: 0, Total: 1},
	}

	output := FormatPlan(plan)

	// Should show update symbol
	if !strings.Contains(output, "~ /sentinel/policies/dev") {
		t.Error("missing update symbol")
	}
	if !strings.Contains(output, "update") {
		t.Error("missing update label")
	}
	if !strings.Contains(output, "1 to update") {
		t.Error("missing update count in summary")
	}
}

func TestFormatPlan_SkipState(t *testing.T) {
	plan := &BootstrapPlan{
		Config: BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
		},
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/skipped", State: StateSkip},
		},
		Summary: PlanSummary{ToCreate: 0, ToUpdate: 0, ToSkip: 1, Total: 1},
	}

	output := FormatPlan(plan)

	// Should show skip symbol
	if !strings.Contains(output, "- /sentinel/policies/skipped") {
		t.Error("missing skip symbol")
	}
}

func TestFormatPlanJSON_ValidOutput(t *testing.T) {
	plan := &BootstrapPlan{
		Config: BootstrapConfig{
			PolicyRoot: "/sentinel/policies",
			Region:     "us-west-2",
		},
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate},
		},
		Summary:     PlanSummary{ToCreate: 1, ToUpdate: 0, ToSkip: 0, Total: 1},
		GeneratedAt: time.Date(2026, 1, 16, 10, 30, 0, 0, time.UTC),
	}

	jsonBytes, err := FormatPlanJSON(plan)
	if err != nil {
		t.Fatalf("FormatPlanJSON() error = %v", err)
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check expected fields
	if _, ok := parsed["config"]; !ok {
		t.Error("missing config field")
	}
	if _, ok := parsed["resources"]; !ok {
		t.Error("missing resources field")
	}
	if _, ok := parsed["summary"]; !ok {
		t.Error("missing summary field")
	}
	if _, ok := parsed["generated_at"]; !ok {
		t.Error("missing generated_at field")
	}
}

func TestFormatPlanJSON_RoundTrip(t *testing.T) {
	original := &BootstrapPlan{
		Config: BootstrapConfig{
			PolicyRoot:          "/sentinel/policies",
			Region:              "eu-west-1",
			GenerateIAMPolicies: true,
			Profiles: []ProfileConfig{
				{Name: "dev", Description: "Development"},
				{Name: "prod", Description: "Production"},
			},
		},
		Resources: []ResourceSpec{
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/dev", State: StateCreate, Description: "Dev policy"},
			{Type: ResourceTypeSSMParameter, Name: "/sentinel/policies/prod", State: StateExists, CurrentVersion: "7"},
			{Type: ResourceTypeIAMPolicy, Name: "SentinelPolicyReader", State: StateCreate},
		},
		Summary:     PlanSummary{ToCreate: 2, ToUpdate: 0, ToSkip: 1, Total: 3},
		GeneratedAt: time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC),
	}

	// Marshal to JSON
	jsonBytes, err := FormatPlanJSON(original)
	if err != nil {
		t.Fatalf("FormatPlanJSON() error = %v", err)
	}

	// Unmarshal back
	var restored BootstrapPlan
	if err := json.Unmarshal(jsonBytes, &restored); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	// Verify key fields
	if restored.Config.PolicyRoot != original.Config.PolicyRoot {
		t.Errorf("PolicyRoot: got %s, want %s", restored.Config.PolicyRoot, original.Config.PolicyRoot)
	}
	if restored.Config.Region != original.Config.Region {
		t.Errorf("Region: got %s, want %s", restored.Config.Region, original.Config.Region)
	}
	if len(restored.Resources) != len(original.Resources) {
		t.Errorf("Resources count: got %d, want %d", len(restored.Resources), len(original.Resources))
	}
	if restored.Summary.ToCreate != original.Summary.ToCreate {
		t.Errorf("ToCreate: got %d, want %d", restored.Summary.ToCreate, original.Summary.ToCreate)
	}

	// Check specific resource
	if len(restored.Resources) >= 2 {
		if restored.Resources[1].CurrentVersion != "7" {
			t.Errorf("CurrentVersion: got %s, want 7", restored.Resources[1].CurrentVersion)
		}
	}
}

func TestStateSymbol(t *testing.T) {
	tests := []struct {
		state  ResourceState
		symbol string
	}{
		{StateCreate, "+"},
		{StateUpdate, "~"},
		{StateExists, "="},
		{StateSkip, "-"},
		{ResourceState("invalid"), "?"},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := stateSymbol(tt.state); got != tt.symbol {
				t.Errorf("stateSymbol(%s) = %s, want %s", tt.state, got, tt.symbol)
			}
		})
	}
}

func TestStateLabel(t *testing.T) {
	tests := []struct {
		state ResourceState
		label string
	}{
		{StateCreate, "create"},
		{StateUpdate, "update"},
		{StateExists, "exists"},
		{StateSkip, "skip"},
		{ResourceState("invalid"), "unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := stateLabel(tt.state); got != tt.label {
				t.Errorf("stateLabel(%s) = %s, want %s", tt.state, got, tt.label)
			}
		})
	}
}
