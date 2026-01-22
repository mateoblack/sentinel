package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// Note: Full CLI integration tests require CGO (1password-sdk-go dependency).
// These tests validate logic and formatting without full CLI execution.

func TestGenerateSessionTableIAMPolicy(t *testing.T) {
	tableName := "sentinel-sessions"
	region := "us-east-1"

	policy := generateSessionTableIAMPolicy(tableName, region)

	// Verify it's valid JSON
	var doc IAMPolicyDocument
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		t.Fatalf("generateSessionTableIAMPolicy returned invalid JSON: %v", err)
	}

	// Verify version
	if doc.Version != "2012-10-17" {
		t.Errorf("Expected Version '2012-10-17', got %q", doc.Version)
	}

	// Verify we have 2 statements
	if len(doc.Statement) != 2 {
		t.Fatalf("Expected 2 statements, got %d", len(doc.Statement))
	}

	// Verify provisioning statement
	provStmt := doc.Statement[0]
	if provStmt.Sid != "SentinelSessionTableProvisioning" {
		t.Errorf("Expected provisioning Sid 'SentinelSessionTableProvisioning', got %q", provStmt.Sid)
	}
	if provStmt.Effect != "Allow" {
		t.Errorf("Expected Effect 'Allow', got %q", provStmt.Effect)
	}

	// Check provisioning actions
	expectedProvActions := []string{"dynamodb:CreateTable", "dynamodb:DescribeTable", "dynamodb:UpdateTimeToLive"}
	for _, action := range expectedProvActions {
		found := false
		for _, a := range provStmt.Action {
			if a == action {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing provisioning action: %s", action)
		}
	}

	// Verify table ARN in provisioning resources
	expectedTableARN := "arn:aws:dynamodb:us-east-1:*:table/sentinel-sessions"
	if len(provStmt.Resource) != 1 || provStmt.Resource[0] != expectedTableARN {
		t.Errorf("Expected provisioning resource %q, got %v", expectedTableARN, provStmt.Resource)
	}

	// Verify operations statement
	opsStmt := doc.Statement[1]
	if opsStmt.Sid != "SentinelSessionTableOperations" {
		t.Errorf("Expected operations Sid 'SentinelSessionTableOperations', got %q", opsStmt.Sid)
	}

	// Check operations actions
	expectedOpsActions := []string{"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"}
	for _, action := range expectedOpsActions {
		found := false
		for _, a := range opsStmt.Action {
			if a == action {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Missing operations action: %s", action)
		}
	}

	// Verify both table and index ARN in operations resources
	expectedIndexARN := "arn:aws:dynamodb:us-east-1:*:table/sentinel-sessions/index/*"
	if len(opsStmt.Resource) != 2 {
		t.Errorf("Expected 2 operations resources, got %d", len(opsStmt.Resource))
	}
	hasTableARN := false
	hasIndexARN := false
	for _, r := range opsStmt.Resource {
		if r == expectedTableARN {
			hasTableARN = true
		}
		if r == expectedIndexARN {
			hasIndexARN = true
		}
	}
	if !hasTableARN {
		t.Error("Missing table ARN in operations resources")
	}
	if !hasIndexARN {
		t.Error("Missing index ARN in operations resources")
	}
}

func TestGenerateSessionTableIAMPolicyCustomTable(t *testing.T) {
	tableName := "my-custom-sessions"
	region := "eu-west-1"

	policy := generateSessionTableIAMPolicy(tableName, region)

	// Verify ARNs contain correct table name and region
	if !strings.Contains(policy, "eu-west-1") {
		t.Error("Policy should contain region eu-west-1")
	}
	if !strings.Contains(policy, "my-custom-sessions") {
		t.Error("Policy should contain table name my-custom-sessions")
	}
	if !strings.Contains(policy, "table/my-custom-sessions/index/*") {
		t.Error("Policy should contain index ARN pattern")
	}
}

func TestDefaultSessionTableName(t *testing.T) {
	if DefaultSessionTableName != "sentinel-sessions" {
		t.Errorf("Expected default table name 'sentinel-sessions', got %q", DefaultSessionTableName)
	}
}

func TestInitSessionsCommandInputDefaults(t *testing.T) {
	input := InitSessionsCommandInput{}

	// Verify defaults are zero values
	if input.TableName != "" {
		t.Error("TableName should default to empty string")
	}
	if input.Region != "" {
		t.Error("Region should default to empty string")
	}
	if input.Plan {
		t.Error("Plan should default to false")
	}
	if input.Yes {
		t.Error("Yes should default to false")
	}
	if input.GenerateIAM {
		t.Error("GenerateIAM should default to false")
	}
}
