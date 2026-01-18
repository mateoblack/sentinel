package permissions

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ConsolidatedPermission represents permissions grouped by resource pattern.
type ConsolidatedPermission struct {
	// Service is the AWS service name.
	Service string
	// Actions are all IAM actions for this resource.
	Actions []string
	// Resource is the ARN pattern.
	Resource string
	// Description is a combined description of all features using this resource.
	Description string
}

// IAMPolicyDocument represents an AWS IAM policy document.
type IAMPolicyDocument struct {
	Version   string         `json:"Version"`
	Statement []IAMStatement `json:"Statement"`
}

// IAMStatement represents a single statement in an IAM policy.
type IAMStatement struct {
	Sid      string   `json:"Sid,omitempty"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

// groupByResource consolidates permissions with the same resource pattern,
// merging actions and deduplicating.
func groupByResource(perms []FeaturePermissions) []ConsolidatedPermission {
	// Map: resource -> consolidated permission
	resourceMap := make(map[string]*ConsolidatedPermission)
	// Track order of resources for deterministic output
	resourceOrder := make([]string, 0)

	for _, fp := range perms {
		for _, p := range fp.Permissions {
			key := p.Resource
			if existing, ok := resourceMap[key]; ok {
				// Add new actions (will dedupe later)
				existing.Actions = append(existing.Actions, p.Actions...)
			} else {
				resourceMap[key] = &ConsolidatedPermission{
					Service:     p.Service,
					Actions:     append([]string{}, p.Actions...),
					Resource:    p.Resource,
					Description: p.Description,
				}
				resourceOrder = append(resourceOrder, key)
			}
		}
	}

	// Build result in order, deduplicating and sorting actions
	result := make([]ConsolidatedPermission, 0, len(resourceMap))
	for _, key := range resourceOrder {
		cp := resourceMap[key]
		cp.Actions = dedupeAndSort(cp.Actions)
		result = append(result, *cp)
	}

	return result
}

// dedupeAndSort removes duplicates and sorts strings alphabetically.
func dedupeAndSort(strs []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(strs))
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	sort.Strings(result)
	return result
}

// FormatHuman formats permissions as a human-readable table.
// Groups by subsystem, shows optional/required, lists actions and resources.
func FormatHuman(perms []FeaturePermissions) string {
	if len(perms) == 0 {
		return "No permissions to display.\n"
	}

	// Sort by subsystem then feature for consistent output
	sorted := make([]FeaturePermissions, len(perms))
	copy(sorted, perms)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Subsystem != sorted[j].Subsystem {
			return sorted[i].Subsystem < sorted[j].Subsystem
		}
		return sorted[i].Feature < sorted[j].Feature
	})

	var sb strings.Builder
	sb.WriteString("Sentinel IAM Permissions\n")
	sb.WriteString("========================\n\n")

	currentSubsystem := Subsystem("")
	for _, fp := range sorted {
		// Print subsystem header if changed
		if fp.Subsystem != currentSubsystem {
			if currentSubsystem != "" {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("[%s]\n", fp.Subsystem))
			currentSubsystem = fp.Subsystem
		}

		// Print feature line
		optional := ""
		if fp.Optional {
			optional = " [optional]"
		}
		sb.WriteString(fmt.Sprintf("\n  Feature: %s%s\n", fp.Feature, optional))

		// Print permissions
		if len(fp.Permissions) == 0 {
			sb.WriteString("    (no AWS permissions required)\n")
		} else {
			for _, p := range fp.Permissions {
				sb.WriteString(fmt.Sprintf("    %s\n", strings.Join(p.Actions, ", ")))
				sb.WriteString(fmt.Sprintf("    Resource: %s\n", p.Resource))
			}
		}
	}

	return sb.String()
}

// FormatJSON formats permissions as a JSON IAM policy document.
// Consolidates permissions by resource pattern, deduplicates actions.
func FormatJSON(perms []FeaturePermissions) (string, error) {
	consolidated := groupByResource(perms)

	// Build statements from consolidated permissions
	statements := make([]IAMStatement, 0, len(consolidated))
	for i, cp := range consolidated {
		sid := fmt.Sprintf("Sentinel%d", i+1)
		statements = append(statements, IAMStatement{
			Sid:      sid,
			Effect:   "Allow",
			Action:   cp.Actions,
			Resource: []string{cp.Resource},
		})
	}

	// If no statements, create minimal valid policy
	if len(statements) == 0 {
		statements = []IAMStatement{}
	}

	doc := IAMPolicyDocument{
		Version:   "2012-10-17",
		Statement: statements,
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FormatTerraform formats permissions as Terraform HCL for aws_iam_policy_document.
// Groups statements by service for readability.
func FormatTerraform(perms []FeaturePermissions) string {
	consolidated := groupByResource(perms)

	if len(consolidated) == 0 {
		return `data "aws_iam_policy_document" "sentinel" {
}
`
	}

	var sb strings.Builder
	sb.WriteString(`data "aws_iam_policy_document" "sentinel" {`)
	sb.WriteString("\n")

	for i, cp := range consolidated {
		sid := fmt.Sprintf("Sentinel%s%d", strings.Title(cp.Service), i+1)
		sb.WriteString(fmt.Sprintf("  statement {\n"))
		sb.WriteString(fmt.Sprintf("    sid       = %q\n", sid))
		sb.WriteString(fmt.Sprintf("    effect    = \"Allow\"\n"))
		sb.WriteString(fmt.Sprintf("    actions   = [%s]\n", formatHCLStringList(cp.Actions)))
		sb.WriteString(fmt.Sprintf("    resources = [%q]\n", cp.Resource))
		sb.WriteString(fmt.Sprintf("  }\n"))

		// Add blank line between statements except for last
		if i < len(consolidated)-1 {
			sb.WriteString("\n")
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

// formatHCLStringList formats a string slice as HCL list syntax.
func formatHCLStringList(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	quoted := make([]string, len(strs))
	for i, s := range strs {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}

// FormatCloudFormation formats permissions as CloudFormation YAML.
// Creates an AWS::IAM::ManagedPolicy resource.
func FormatCloudFormation(perms []FeaturePermissions) string {
	consolidated := groupByResource(perms)

	var sb strings.Builder
	sb.WriteString("Type: AWS::IAM::ManagedPolicy\n")
	sb.WriteString("Properties:\n")
	sb.WriteString("  PolicyName: SentinelPermissions\n")
	sb.WriteString("  PolicyDocument:\n")
	sb.WriteString("    Version: \"2012-10-17\"\n")
	sb.WriteString("    Statement:\n")

	if len(consolidated) == 0 {
		sb.WriteString("      []\n")
		return sb.String()
	}

	for i, cp := range consolidated {
		sid := fmt.Sprintf("Sentinel%d", i+1)
		sb.WriteString(fmt.Sprintf("      - Sid: %s\n", sid))
		sb.WriteString("        Effect: Allow\n")
		sb.WriteString("        Action:\n")
		for _, action := range cp.Actions {
			sb.WriteString(fmt.Sprintf("          - %s\n", action))
		}
		sb.WriteString("        Resource:\n")
		sb.WriteString(fmt.Sprintf("          - %s\n", cp.Resource))
	}

	return sb.String()
}
