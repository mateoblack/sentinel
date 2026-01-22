package bootstrap

import (
	"fmt"
	"os"
	"strings"
)

// Suggestion represents a suggested action for the user.
type Suggestion struct {
	// Type is the suggestion type: "command" for executable commands, "action" for other guidance.
	Type string `json:"type"`
	// Message is the human-readable description of the suggestion.
	Message string `json:"message"`
	// Command is the executable command (only set when Type is "command").
	Command string `json:"command,omitempty"`
}

// SuggestionGenerator creates suggestions based on current status.
type SuggestionGenerator struct{}

// NewSuggestionGenerator creates a new SuggestionGenerator.
func NewSuggestionGenerator() *SuggestionGenerator {
	return &SuggestionGenerator{}
}

// GenerateInfrastructureSuggestions returns suggestions for missing DynamoDB tables.
// For each table with status "NOT_FOUND", it generates a suggestion with the
// appropriate `sentinel init` command.
func (sg *SuggestionGenerator) GenerateInfrastructureSuggestions(tables []TableInfo, region string) []Suggestion {
	var suggestions []Suggestion

	for _, t := range tables {
		if t.Status == "NOT_FOUND" {
			cmd := fmt.Sprintf("sentinel init %s --region %s", t.Purpose, region)
			msg := fmt.Sprintf("Create %s table (%s)", t.Purpose, t.TableName)
			suggestions = append(suggestions, Suggestion{
				Type:    "command",
				Message: msg,
				Command: cmd,
			})
		}
	}

	return suggestions
}

// GenerateShellSuggestion returns a suggestion to add shell integration.
// If awsProfile is provided, it's included in the command.
func (sg *SuggestionGenerator) GenerateShellSuggestion(awsProfile string) Suggestion {
	var cmd string
	if awsProfile != "" {
		cmd = fmt.Sprintf(`eval "$(sentinel shell init --aws-profile %s)"`, awsProfile)
	} else {
		cmd = `eval "$(sentinel shell init)"`
	}

	return Suggestion{
		Type:    "command",
		Message: "Add shell integration for quick access",
		Command: cmd,
	}
}

// GetShellRCFile returns the appropriate shell rc file path based on current shell.
// Returns ~/.zshrc for zsh and ~/.bashrc for bash/other shells.
func GetShellRCFile() string {
	shellEnv := os.Getenv("SHELL")
	if strings.Contains(shellEnv, "zsh") {
		return "~/.zshrc"
	}
	return "~/.bashrc"
}
