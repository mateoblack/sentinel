package bootstrap

import (
	"encoding/json"
	"fmt"
	"strings"
)

// stateSymbol returns the visual indicator for a resource state.
func stateSymbol(state ResourceState) string {
	switch state {
	case StateCreate:
		return "+"
	case StateUpdate:
		return "~"
	case StateExists:
		return "="
	case StateSkip:
		return "-"
	default:
		return "?"
	}
}

// stateLabel returns the human-readable label for a resource state.
func stateLabel(state ResourceState) string {
	switch state {
	case StateCreate:
		return "create"
	case StateUpdate:
		return "update"
	case StateExists:
		return "exists"
	case StateSkip:
		return "skip"
	default:
		return "unknown"
	}
}

// FormatPlan produces human-readable output for a BootstrapPlan.
// The output format is similar to terraform plan output.
func FormatPlan(plan *BootstrapPlan) string {
	var sb strings.Builder

	// Header
	sb.WriteString("Bootstrap Plan\n")
	sb.WriteString("==============\n")

	// Config summary
	sb.WriteString(fmt.Sprintf("Policy Root: %s\n", plan.Config.PolicyRoot))
	region := plan.Config.Region
	if region == "" {
		region = "default"
	}
	sb.WriteString(fmt.Sprintf("Region: %s\n", region))
	sb.WriteString("\n")

	// Empty plan check
	if len(plan.Resources) == 0 {
		sb.WriteString("Resources: (none)\n\n")
		sb.WriteString("Summary: No resources to manage\n")
		return sb.String()
	}

	// Separate resources by type
	var ssmParams, iamPolicies []ResourceSpec
	for _, r := range plan.Resources {
		switch r.Type {
		case ResourceTypeSSMParameter:
			ssmParams = append(ssmParams, r)
		case ResourceTypeIAMPolicy:
			iamPolicies = append(iamPolicies, r)
		}
	}

	// Check if we need to group by type
	hasMultipleTypes := len(ssmParams) > 0 && len(iamPolicies) > 0

	if hasMultipleTypes {
		// Grouped output
		if len(ssmParams) > 0 {
			sb.WriteString("SSM Parameters:\n")
			for _, r := range ssmParams {
				sb.WriteString(formatResource(r))
			}
			sb.WriteString("\n")
		}
		if len(iamPolicies) > 0 {
			sb.WriteString("IAM Policy Documents:\n")
			for _, r := range iamPolicies {
				sb.WriteString(formatIAMResource(r))
			}
			sb.WriteString("\n")
		}
	} else {
		// Simple output
		sb.WriteString("Resources:\n")
		for _, r := range plan.Resources {
			if r.Type == ResourceTypeIAMPolicy {
				sb.WriteString(formatIAMResource(r))
			} else {
				sb.WriteString(formatResource(r))
			}
		}
		sb.WriteString("\n")
	}

	// Summary line
	sb.WriteString(fmt.Sprintf("Summary: %d to create, %d to update, %d existing\n",
		plan.Summary.ToCreate,
		plan.Summary.ToUpdate,
		plan.Summary.ToSkip,
	))

	return sb.String()
}

// formatResource formats a single SSM parameter resource line.
func formatResource(r ResourceSpec) string {
	symbol := stateSymbol(r.State)
	label := stateLabel(r.State)

	// Build version info if available
	versionInfo := ""
	if r.CurrentVersion != "" {
		versionInfo = fmt.Sprintf(", v%s", r.CurrentVersion)
	}

	return fmt.Sprintf("  %s %-35s (SSM Parameter - %s%s)\n",
		symbol, r.Name, label, versionInfo)
}

// formatIAMResource formats a single IAM policy resource line.
func formatIAMResource(r ResourceSpec) string {
	symbol := stateSymbol(r.State)

	// IAM policies are always generated (documents, not actual IAM resources)
	action := "generate"
	if r.State == StateSkip {
		action = "skip"
	}

	return fmt.Sprintf("  %s %-35s (%s)\n", symbol, r.Name, action)
}

// FormatPlanJSON produces JSON output for a BootstrapPlan.
// This is useful for machine-readable output and piping to other tools.
func FormatPlanJSON(plan *BootstrapPlan) ([]byte, error) {
	return json.MarshalIndent(plan, "", "  ")
}
