package bootstrap

import (
	"os"
	"testing"
)

func TestSuggestionGenerator_GenerateInfrastructureSuggestions_NoMissing(t *testing.T) {
	sg := NewSuggestionGenerator()
	tables := []TableInfo{
		{TableName: "sentinel-requests", Status: "ACTIVE", Region: "us-east-1", Purpose: "approvals"},
		{TableName: "sentinel-breakglass", Status: "ACTIVE", Region: "us-east-1", Purpose: "breakglass"},
		{TableName: "sentinel-sessions", Status: "ACTIVE", Region: "us-east-1", Purpose: "sessions"},
	}

	suggestions := sg.GenerateInfrastructureSuggestions(tables, "us-east-1")

	if len(suggestions) != 0 {
		t.Errorf("expected 0 suggestions, got %d", len(suggestions))
	}
}

func TestSuggestionGenerator_GenerateInfrastructureSuggestions_OneMissing(t *testing.T) {
	sg := NewSuggestionGenerator()
	tables := []TableInfo{
		{TableName: "sentinel-requests", Status: "ACTIVE", Region: "us-east-1", Purpose: "approvals"},
		{TableName: "sentinel-breakglass", Status: "NOT_FOUND", Region: "us-east-1", Purpose: "breakglass"},
		{TableName: "sentinel-sessions", Status: "ACTIVE", Region: "us-east-1", Purpose: "sessions"},
	}

	suggestions := sg.GenerateInfrastructureSuggestions(tables, "us-east-1")

	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}

	s := suggestions[0]
	if s.Type != "command" {
		t.Errorf("expected type 'command', got '%s'", s.Type)
	}
	if s.Command != "sentinel init breakglass --region us-east-1" {
		t.Errorf("unexpected command: %s", s.Command)
	}
	if s.Message != "Create breakglass table (sentinel-breakglass)" {
		t.Errorf("unexpected message: %s", s.Message)
	}
}

func TestSuggestionGenerator_GenerateInfrastructureSuggestions_AllMissing(t *testing.T) {
	sg := NewSuggestionGenerator()
	tables := []TableInfo{
		{TableName: "sentinel-requests", Status: "NOT_FOUND", Region: "us-west-2", Purpose: "approvals"},
		{TableName: "sentinel-breakglass", Status: "NOT_FOUND", Region: "us-west-2", Purpose: "breakglass"},
		{TableName: "sentinel-sessions", Status: "NOT_FOUND", Region: "us-west-2", Purpose: "sessions"},
	}

	suggestions := sg.GenerateInfrastructureSuggestions(tables, "us-west-2")

	if len(suggestions) != 3 {
		t.Fatalf("expected 3 suggestions, got %d", len(suggestions))
	}

	// Verify each suggestion
	expectedCommands := []string{
		"sentinel init approvals --region us-west-2",
		"sentinel init breakglass --region us-west-2",
		"sentinel init sessions --region us-west-2",
	}

	for i, expected := range expectedCommands {
		if suggestions[i].Command != expected {
			t.Errorf("suggestion[%d]: expected command '%s', got '%s'", i, expected, suggestions[i].Command)
		}
		if suggestions[i].Type != "command" {
			t.Errorf("suggestion[%d]: expected type 'command', got '%s'", i, suggestions[i].Type)
		}
	}
}

func TestSuggestionGenerator_GenerateInfrastructureSuggestions_CreatingStatus(t *testing.T) {
	sg := NewSuggestionGenerator()
	tables := []TableInfo{
		{TableName: "sentinel-requests", Status: "CREATING", Region: "us-east-1", Purpose: "approvals"},
		{TableName: "sentinel-breakglass", Status: "NOT_FOUND", Region: "us-east-1", Purpose: "breakglass"},
	}

	suggestions := sg.GenerateInfrastructureSuggestions(tables, "us-east-1")

	// Only NOT_FOUND should generate suggestions, not CREATING
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion (only NOT_FOUND), got %d", len(suggestions))
	}

	if suggestions[0].Command != "sentinel init breakglass --region us-east-1" {
		t.Errorf("unexpected command: %s", suggestions[0].Command)
	}
}

func TestSuggestionGenerator_GenerateShellSuggestion_WithProfile(t *testing.T) {
	sg := NewSuggestionGenerator()

	suggestion := sg.GenerateShellSuggestion("dev")

	if suggestion.Type != "command" {
		t.Errorf("expected type 'command', got '%s'", suggestion.Type)
	}
	if suggestion.Message != "Add shell integration for quick access" {
		t.Errorf("unexpected message: %s", suggestion.Message)
	}
	expectedCmd := `eval "$(sentinel shell init --aws-profile dev)"`
	if suggestion.Command != expectedCmd {
		t.Errorf("expected command '%s', got '%s'", expectedCmd, suggestion.Command)
	}
}

func TestSuggestionGenerator_GenerateShellSuggestion_WithoutProfile(t *testing.T) {
	sg := NewSuggestionGenerator()

	suggestion := sg.GenerateShellSuggestion("")

	if suggestion.Type != "command" {
		t.Errorf("expected type 'command', got '%s'", suggestion.Type)
	}
	expectedCmd := `eval "$(sentinel shell init)"`
	if suggestion.Command != expectedCmd {
		t.Errorf("expected command '%s', got '%s'", expectedCmd, suggestion.Command)
	}
}

func TestGetShellRCFile_Zsh(t *testing.T) {
	// Save and restore SHELL env
	origShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", origShell)

	os.Setenv("SHELL", "/bin/zsh")
	rcFile := GetShellRCFile()

	if rcFile != "~/.zshrc" {
		t.Errorf("expected ~/.zshrc for zsh, got %s", rcFile)
	}
}

func TestGetShellRCFile_Bash(t *testing.T) {
	// Save and restore SHELL env
	origShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", origShell)

	os.Setenv("SHELL", "/bin/bash")
	rcFile := GetShellRCFile()

	if rcFile != "~/.bashrc" {
		t.Errorf("expected ~/.bashrc for bash, got %s", rcFile)
	}
}

func TestGetShellRCFile_Empty(t *testing.T) {
	// Save and restore SHELL env
	origShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", origShell)

	os.Setenv("SHELL", "")
	rcFile := GetShellRCFile()

	// Default to bash when SHELL is empty
	if rcFile != "~/.bashrc" {
		t.Errorf("expected ~/.bashrc for empty SHELL, got %s", rcFile)
	}
}
