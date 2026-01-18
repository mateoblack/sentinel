package permissions

import (
	"encoding/json"
	"strings"
	"testing"
)

// testPermissions returns a sample set of permissions for testing.
func testPermissions() []FeaturePermissions {
	return []FeaturePermissions{
		{
			Feature:   FeaturePolicyLoad,
			Subsystem: SubsystemCore,
			Permissions: []Permission{
				{
					Service:     "ssm",
					Actions:     []string{"ssm:GetParameter", "ssm:GetParameters"},
					Resource:    "arn:aws:ssm:*:*:parameter/sentinel/policies/*",
					Description: "Read policy parameters",
				},
			},
			Optional: false,
		},
		{
			Feature:   FeatureNotifySNS,
			Subsystem: SubsystemNotifications,
			Permissions: []Permission{
				{
					Service:     "sns",
					Actions:     []string{"sns:Publish"},
					Resource:    "arn:aws:sns:*:*:sentinel-*",
					Description: "Publish notifications",
				},
			},
			Optional: true,
		},
		{
			Feature:     FeatureNotifyWebhook,
			Subsystem:   SubsystemNotifications,
			Permissions: []Permission{},
			Optional:    true,
		},
	}
}

func TestFormatHuman(t *testing.T) {
	t.Run("includes all features", func(t *testing.T) {
		perms := testPermissions()
		result := FormatHuman(perms)

		// Check header
		if !strings.Contains(result, "Sentinel IAM Permissions") {
			t.Error("expected header in output")
		}

		// Check all features present
		if !strings.Contains(result, "policy_load") {
			t.Error("expected policy_load feature")
		}
		if !strings.Contains(result, "notify_sns") {
			t.Error("expected notify_sns feature")
		}
		if !strings.Contains(result, "notify_webhook") {
			t.Error("expected notify_webhook feature")
		}
	})

	t.Run("shows optional flag", func(t *testing.T) {
		perms := testPermissions()
		result := FormatHuman(perms)

		// notify_sns should show optional
		if !strings.Contains(result, "[optional]") {
			t.Error("expected [optional] flag for optional features")
		}
	})

	t.Run("correct grouping by subsystem", func(t *testing.T) {
		perms := testPermissions()
		result := FormatHuman(perms)

		// Check subsystems appear
		if !strings.Contains(result, "[core]") {
			t.Error("expected [core] subsystem header")
		}
		if !strings.Contains(result, "[notifications]") {
			t.Error("expected [notifications] subsystem header")
		}
	})

	t.Run("shows actions and resources", func(t *testing.T) {
		perms := testPermissions()
		result := FormatHuman(perms)

		if !strings.Contains(result, "ssm:GetParameter") {
			t.Error("expected ssm:GetParameter action")
		}
		if !strings.Contains(result, "Resource: arn:aws:ssm:*:*:parameter/sentinel/policies/*") {
			t.Error("expected SSM resource ARN")
		}
	})

	t.Run("handles feature with no permissions", func(t *testing.T) {
		perms := testPermissions()
		result := FormatHuman(perms)

		// notify_webhook has no AWS permissions
		if !strings.Contains(result, "(no AWS permissions required)") {
			t.Error("expected 'no AWS permissions required' for webhook feature")
		}
	})

	t.Run("empty permissions list", func(t *testing.T) {
		result := FormatHuman([]FeaturePermissions{})
		if !strings.Contains(result, "No permissions to display") {
			t.Error("expected empty message for no permissions")
		}
	})
}

func TestFormatJSON(t *testing.T) {
	t.Run("produces valid JSON", func(t *testing.T) {
		perms := testPermissions()
		result, err := FormatJSON(perms)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify it's valid JSON
		var doc IAMPolicyDocument
		if err := json.Unmarshal([]byte(result), &doc); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
	})

	t.Run("matches IAMPolicyDocument structure", func(t *testing.T) {
		perms := testPermissions()
		result, err := FormatJSON(perms)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var doc IAMPolicyDocument
		if err := json.Unmarshal([]byte(result), &doc); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		if doc.Version != "2012-10-17" {
			t.Errorf("expected Version 2012-10-17, got %s", doc.Version)
		}

		// Should have statements for SSM and SNS (webhook has no permissions)
		if len(doc.Statement) != 2 {
			t.Errorf("expected 2 statements, got %d", len(doc.Statement))
		}

		for _, stmt := range doc.Statement {
			if stmt.Effect != "Allow" {
				t.Errorf("expected Effect Allow, got %s", stmt.Effect)
			}
			if len(stmt.Action) == 0 {
				t.Error("expected actions in statement")
			}
			if len(stmt.Resource) == 0 {
				t.Error("expected resources in statement")
			}
		}
	})

	t.Run("empty permissions produces minimal valid output", func(t *testing.T) {
		result, err := FormatJSON([]FeaturePermissions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var doc IAMPolicyDocument
		if err := json.Unmarshal([]byte(result), &doc); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		if doc.Version != "2012-10-17" {
			t.Errorf("expected Version 2012-10-17, got %s", doc.Version)
		}
		if len(doc.Statement) != 0 {
			t.Errorf("expected 0 statements for empty permissions, got %d", len(doc.Statement))
		}
	})
}

func TestFormatTerraform(t *testing.T) {
	t.Run("produces valid HCL syntax", func(t *testing.T) {
		perms := testPermissions()
		result := FormatTerraform(perms)

		// Check HCL structure
		if !strings.Contains(result, `data "aws_iam_policy_document" "sentinel"`) {
			t.Error("expected terraform data source declaration")
		}
		if !strings.Contains(result, "statement {") {
			t.Error("expected statement block")
		}
		if !strings.Contains(result, "sid       =") {
			t.Error("expected sid attribute")
		}
		if !strings.Contains(result, `effect    = "Allow"`) {
			t.Error("expected effect attribute")
		}
		if !strings.Contains(result, "actions   = [") {
			t.Error("expected actions attribute")
		}
		if !strings.Contains(result, "resources = [") {
			t.Error("expected resources attribute")
		}
	})

	t.Run("actions are quoted correctly", func(t *testing.T) {
		perms := testPermissions()
		result := FormatTerraform(perms)

		if !strings.Contains(result, `"ssm:GetParameter"`) {
			t.Error("expected quoted action")
		}
	})

	t.Run("empty permissions produces minimal valid output", func(t *testing.T) {
		result := FormatTerraform([]FeaturePermissions{})

		expected := `data "aws_iam_policy_document" "sentinel" {
}
`
		if result != expected {
			t.Errorf("expected:\n%s\ngot:\n%s", expected, result)
		}
	})
}

func TestFormatCloudFormation(t *testing.T) {
	t.Run("produces valid YAML structure", func(t *testing.T) {
		perms := testPermissions()
		result := FormatCloudFormation(perms)

		// Check YAML structure
		if !strings.Contains(result, "Type: AWS::IAM::ManagedPolicy") {
			t.Error("expected CloudFormation type")
		}
		if !strings.Contains(result, "Properties:") {
			t.Error("expected Properties block")
		}
		if !strings.Contains(result, "PolicyName: SentinelPermissions") {
			t.Error("expected PolicyName")
		}
		if !strings.Contains(result, "PolicyDocument:") {
			t.Error("expected PolicyDocument")
		}
		if !strings.Contains(result, `Version: "2012-10-17"`) {
			t.Error("expected Version")
		}
		if !strings.Contains(result, "Statement:") {
			t.Error("expected Statement")
		}
	})

	t.Run("correct indentation", func(t *testing.T) {
		perms := testPermissions()
		result := FormatCloudFormation(perms)

		// Check 2-space indentation pattern
		if !strings.Contains(result, "  PolicyName:") {
			t.Error("expected 2-space indent for PolicyName")
		}
		if !strings.Contains(result, "    Version:") {
			t.Error("expected 4-space indent for Version")
		}
		if !strings.Contains(result, "      - Sid:") {
			t.Error("expected 6-space indent for statement items")
		}
	})

	t.Run("actions listed correctly", func(t *testing.T) {
		perms := testPermissions()
		result := FormatCloudFormation(perms)

		if !strings.Contains(result, "        Action:") {
			t.Error("expected Action block")
		}
		if !strings.Contains(result, "          - ssm:GetParameter") {
			t.Error("expected ssm:GetParameter action")
		}
	})

	t.Run("empty permissions produces minimal valid output", func(t *testing.T) {
		result := FormatCloudFormation([]FeaturePermissions{})

		if !strings.Contains(result, "Statement:") {
			t.Error("expected Statement block")
		}
		if !strings.Contains(result, "      []") {
			t.Error("expected empty array for no statements")
		}
	})
}

func TestGroupByResource(t *testing.T) {
	t.Run("deduplicates actions", func(t *testing.T) {
		perms := []FeaturePermissions{
			{
				Feature:   FeatureApprovalWorkflow,
				Subsystem: SubsystemApprovals,
				Permissions: []Permission{
					{
						Service:  "dynamodb",
						Actions:  []string{"dynamodb:Query", "dynamodb:PutItem"},
						Resource: "arn:aws:dynamodb:*:*:table/sentinel-requests",
					},
				},
			},
			{
				Feature:   FeatureBreakGlass,
				Subsystem: SubsystemBreakGlass,
				Permissions: []Permission{
					{
						Service:  "dynamodb",
						Actions:  []string{"dynamodb:Query", "dynamodb:GetItem"}, // Query is duplicate
						Resource: "arn:aws:dynamodb:*:*:table/sentinel-requests",
					},
				},
			},
		}

		result := groupByResource(perms)
		if len(result) != 1 {
			t.Fatalf("expected 1 consolidated permission, got %d", len(result))
		}

		// Should have deduplicated Query
		actionCount := make(map[string]int)
		for _, a := range result[0].Actions {
			actionCount[a]++
		}
		if actionCount["dynamodb:Query"] != 1 {
			t.Error("expected dynamodb:Query to appear once after deduplication")
		}
	})

	t.Run("merges by resource", func(t *testing.T) {
		perms := []FeaturePermissions{
			{
				Feature:   FeaturePolicyLoad,
				Subsystem: SubsystemCore,
				Permissions: []Permission{
					{
						Service:  "ssm",
						Actions:  []string{"ssm:GetParameter"},
						Resource: "arn:aws:ssm:*:*:parameter/sentinel/*",
					},
				},
			},
			{
				Feature:   FeatureBootstrapPlan,
				Subsystem: SubsystemBootstrap,
				Permissions: []Permission{
					{
						Service:  "ssm",
						Actions:  []string{"ssm:GetParametersByPath"},
						Resource: "arn:aws:ssm:*:*:parameter/sentinel/*",
					},
				},
			},
		}

		result := groupByResource(perms)
		if len(result) != 1 {
			t.Fatalf("expected 1 consolidated permission (same resource), got %d", len(result))
		}

		// Should have both actions merged
		if len(result[0].Actions) != 2 {
			t.Errorf("expected 2 actions merged, got %d", len(result[0].Actions))
		}
	})

	t.Run("keeps different resources separate", func(t *testing.T) {
		perms := []FeaturePermissions{
			{
				Feature:   FeaturePolicyLoad,
				Subsystem: SubsystemCore,
				Permissions: []Permission{
					{
						Service:  "ssm",
						Actions:  []string{"ssm:GetParameter"},
						Resource: "arn:aws:ssm:*:*:parameter/sentinel/policies/*",
					},
				},
			},
			{
				Feature:   FeatureNotifySNS,
				Subsystem: SubsystemNotifications,
				Permissions: []Permission{
					{
						Service:  "sns",
						Actions:  []string{"sns:Publish"},
						Resource: "arn:aws:sns:*:*:sentinel-*",
					},
				},
			},
		}

		result := groupByResource(perms)
		if len(result) != 2 {
			t.Fatalf("expected 2 consolidated permissions (different resources), got %d", len(result))
		}
	})

	t.Run("sorts actions alphabetically", func(t *testing.T) {
		perms := []FeaturePermissions{
			{
				Feature:   FeatureApprovalWorkflow,
				Subsystem: SubsystemApprovals,
				Permissions: []Permission{
					{
						Service:  "dynamodb",
						Actions:  []string{"dynamodb:Query", "dynamodb:DeleteItem", "dynamodb:PutItem", "dynamodb:GetItem"},
						Resource: "arn:aws:dynamodb:*:*:table/sentinel-requests",
					},
				},
			},
		}

		result := groupByResource(perms)
		actions := result[0].Actions

		for i := 1; i < len(actions); i++ {
			if actions[i-1] > actions[i] {
				t.Errorf("actions not sorted: %s > %s", actions[i-1], actions[i])
			}
		}
	})
}
