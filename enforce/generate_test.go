package enforce

import (
	"encoding/json"
	"testing"
)

func TestGenerateTrustPolicy_PatternA(t *testing.T) {
	input := GenerateInput{
		Pattern:      PatternA,
		PrincipalARN: "arn:aws:iam::123456789012:root",
	}

	output, err := GenerateTrustPolicy(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.Pattern != PatternA {
		t.Errorf("expected pattern %s, got %s", PatternA, output.Pattern)
	}

	if output.Policy == nil {
		t.Fatal("expected policy to be non-nil")
	}

	if output.Policy.Version != "2012-10-17" {
		t.Errorf("expected version 2012-10-17, got %s", output.Policy.Version)
	}

	if len(output.Policy.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(output.Policy.Statement))
	}

	stmt := output.Policy.Statement[0]

	if stmt.Sid != "AllowSentinelAccess" {
		t.Errorf("expected Sid 'AllowSentinelAccess', got %s", stmt.Sid)
	}

	if stmt.Effect != "Allow" {
		t.Errorf("expected Effect 'Allow', got %s", stmt.Effect)
	}

	if len(stmt.Principal.AWS) != 1 || stmt.Principal.AWS[0] != "arn:aws:iam::123456789012:root" {
		t.Errorf("expected principal arn:aws:iam::123456789012:root, got %v", stmt.Principal.AWS)
	}

	if len(stmt.Action) != 1 || stmt.Action[0] != "sts:AssumeRole" {
		t.Errorf("expected action sts:AssumeRole, got %v", stmt.Action)
	}

	// Check condition
	stringLike, ok := stmt.Condition["StringLike"]
	if !ok {
		t.Fatal("expected StringLike condition")
	}

	sourceIdentity, ok := stringLike["sts:SourceIdentity"]
	if !ok {
		t.Fatal("expected sts:SourceIdentity in StringLike condition")
	}

	if len(sourceIdentity) != 1 || sourceIdentity[0] != "sentinel:*" {
		t.Errorf("expected sts:SourceIdentity to be sentinel:*, got %v", sourceIdentity)
	}
}

func TestGenerateTrustPolicy_PatternA_JSON(t *testing.T) {
	input := GenerateInput{
		Pattern:      PatternA,
		PrincipalARN: "arn:aws:iam::123456789012:root",
	}

	output, err := GenerateTrustPolicy(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify JSON marshalling works
	jsonBytes, err := json.MarshalIndent(output.Policy, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal policy to JSON: %v", err)
	}

	// Verify JSON contains expected values
	jsonStr := string(jsonBytes)
	expectedStrings := []string{
		`"Version": "2012-10-17"`,
		`"Sid": "AllowSentinelAccess"`,
		`"Effect": "Allow"`,
		`"sts:AssumeRole"`,
		`"StringLike"`,
		`"sts:SourceIdentity"`,
		`"sentinel:*"`,
	}

	for _, expected := range expectedStrings {
		if !contains(jsonStr, expected) {
			t.Errorf("expected JSON to contain %s, got: %s", expected, jsonStr)
		}
	}
}

func TestGenerateTrustPolicy_PatternB(t *testing.T) {
	input := GenerateInput{
		Pattern:      PatternB,
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Users:        []string{"alice", "bob"},
	}

	output, err := GenerateTrustPolicy(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.Pattern != PatternB {
		t.Errorf("expected pattern %s, got %s", PatternB, output.Pattern)
	}

	if len(output.Policy.Statement) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(output.Policy.Statement))
	}

	stmt := output.Policy.Statement[0]

	if stmt.Sid != "AllowSentinelUsers" {
		t.Errorf("expected Sid 'AllowSentinelUsers', got %s", stmt.Sid)
	}

	// Check condition has user-specific patterns
	stringLike, ok := stmt.Condition["StringLike"]
	if !ok {
		t.Fatal("expected StringLike condition")
	}

	sourceIdentity, ok := stringLike["sts:SourceIdentity"]
	if !ok {
		t.Fatal("expected sts:SourceIdentity in StringLike condition")
	}

	if len(sourceIdentity) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(sourceIdentity))
	}

	// Check for user-specific patterns
	expectedPatterns := map[string]bool{
		"sentinel:alice:*": false,
		"sentinel:bob:*":   false,
	}

	for _, pattern := range sourceIdentity {
		if _, ok := expectedPatterns[pattern]; ok {
			expectedPatterns[pattern] = true
		} else {
			t.Errorf("unexpected pattern: %s", pattern)
		}
	}

	for pattern, found := range expectedPatterns {
		if !found {
			t.Errorf("expected pattern not found: %s", pattern)
		}
	}
}

func TestGenerateTrustPolicy_PatternB_MultipleUsers(t *testing.T) {
	input := GenerateInput{
		Pattern:      PatternB,
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Users:        []string{"alice", "bob", "charlie"},
	}

	output, err := GenerateTrustPolicy(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stmt := output.Policy.Statement[0]
	stringLike := stmt.Condition["StringLike"]
	sourceIdentity := stringLike["sts:SourceIdentity"]

	if len(sourceIdentity) != 3 {
		t.Fatalf("expected 3 patterns for 3 users, got %d", len(sourceIdentity))
	}
}

func TestGenerateTrustPolicy_PatternC(t *testing.T) {
	input := GenerateInput{
		Pattern:         PatternC,
		PrincipalARN:    "arn:aws:iam::123456789012:root",
		LegacyPrincipal: "arn:aws:iam::123456789012:role/LegacyServiceRole",
	}

	output, err := GenerateTrustPolicy(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if output.Pattern != PatternC {
		t.Errorf("expected pattern %s, got %s", PatternC, output.Pattern)
	}

	if len(output.Policy.Statement) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(output.Policy.Statement))
	}

	// First statement: Sentinel access
	sentinelStmt := output.Policy.Statement[0]

	if sentinelStmt.Sid != "AllowSentinelAccess" {
		t.Errorf("expected first statement Sid 'AllowSentinelAccess', got %s", sentinelStmt.Sid)
	}

	if len(sentinelStmt.Principal.AWS) != 1 || sentinelStmt.Principal.AWS[0] != "arn:aws:iam::123456789012:root" {
		t.Errorf("expected first statement principal to be root, got %v", sentinelStmt.Principal.AWS)
	}

	stringLike, ok := sentinelStmt.Condition["StringLike"]
	if !ok {
		t.Fatal("expected StringLike condition in first statement")
	}

	sourceIdentity, ok := stringLike["sts:SourceIdentity"]
	if !ok || len(sourceIdentity) != 1 || sourceIdentity[0] != "sentinel:*" {
		t.Errorf("expected sentinel:* pattern in first statement, got %v", sourceIdentity)
	}

	// Second statement: Legacy access
	legacyStmt := output.Policy.Statement[1]

	if legacyStmt.Sid != "AllowLegacyAccess" {
		t.Errorf("expected second statement Sid 'AllowLegacyAccess', got %s", legacyStmt.Sid)
	}

	if len(legacyStmt.Principal.AWS) != 1 || legacyStmt.Principal.AWS[0] != "arn:aws:iam::123456789012:role/LegacyServiceRole" {
		t.Errorf("expected legacy principal, got %v", legacyStmt.Principal.AWS)
	}

	// Legacy statement should have no condition
	if len(legacyStmt.Condition) != 0 {
		t.Errorf("expected no condition in legacy statement, got %v", legacyStmt.Condition)
	}
}

func TestGenerateTrustPolicy_ValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		input       GenerateInput
		expectedErr string
	}{
		{
			name: "missing pattern",
			input: GenerateInput{
				PrincipalARN: "arn:aws:iam::123456789012:root",
			},
			expectedErr: "pattern is required",
		},
		{
			name: "invalid pattern",
			input: GenerateInput{
				Pattern:      TrustPolicyPattern("invalid"),
				PrincipalARN: "arn:aws:iam::123456789012:root",
			},
			expectedErr: "pattern is required",
		},
		{
			name: "missing principal ARN",
			input: GenerateInput{
				Pattern: PatternA,
			},
			expectedErr: "principal ARN is required",
		},
		{
			name: "pattern B without users",
			input: GenerateInput{
				Pattern:      PatternB,
				PrincipalARN: "arn:aws:iam::123456789012:root",
			},
			expectedErr: "users list is required for 'specific-users' pattern",
		},
		{
			name: "pattern B with empty users",
			input: GenerateInput{
				Pattern:      PatternB,
				PrincipalARN: "arn:aws:iam::123456789012:root",
				Users:        []string{},
			},
			expectedErr: "users list is required for 'specific-users' pattern",
		},
		{
			name: "pattern C without legacy principal",
			input: GenerateInput{
				Pattern:      PatternC,
				PrincipalARN: "arn:aws:iam::123456789012:root",
			},
			expectedErr: "legacy principal is required for 'migration' pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateTrustPolicy(tt.input)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectedErr)
			}
			if !contains(err.Error(), tt.expectedErr) {
				t.Errorf("expected error containing %q, got %q", tt.expectedErr, err.Error())
			}
		})
	}
}

func TestGenerateTrustPolicy_PatternA_IgnoresUsers(t *testing.T) {
	// Pattern A should work even if Users is provided (just ignore them)
	input := GenerateInput{
		Pattern:      PatternA,
		PrincipalARN: "arn:aws:iam::123456789012:root",
		Users:        []string{"alice", "bob"}, // These should be ignored
	}

	output, err := GenerateTrustPolicy(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it still generates Pattern A (sentinel:*)
	stmt := output.Policy.Statement[0]
	stringLike := stmt.Condition["StringLike"]
	sourceIdentity := stringLike["sts:SourceIdentity"]

	if len(sourceIdentity) != 1 || sourceIdentity[0] != "sentinel:*" {
		t.Errorf("expected sentinel:* pattern, got %v", sourceIdentity)
	}
}

func TestTrustPolicyPattern_IsValid(t *testing.T) {
	tests := []struct {
		pattern TrustPolicyPattern
		valid   bool
	}{
		{PatternA, true},
		{PatternB, true},
		{PatternC, true},
		{TrustPolicyPattern("any-sentinel"), true},
		{TrustPolicyPattern("specific-users"), true},
		{TrustPolicyPattern("migration"), true},
		{TrustPolicyPattern("invalid"), false},
		{TrustPolicyPattern(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.pattern), func(t *testing.T) {
			if got := tt.pattern.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestTrustPolicyPattern_String(t *testing.T) {
	tests := []struct {
		pattern  TrustPolicyPattern
		expected string
	}{
		{PatternA, "any-sentinel"},
		{PatternB, "specific-users"},
		{PatternC, "migration"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.pattern.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
