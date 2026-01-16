package bootstrap

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// validSSMPathRegex matches valid SSM parameter path characters.
// SSM paths can contain alphanumeric characters, forward slashes, hyphens, and underscores.
var validSSMPathRegex = regexp.MustCompile(`^/[a-zA-Z0-9/_-]+$`)

// validProfileNameRegex matches valid AWS profile names.
// Profile names can contain alphanumeric characters, hyphens, and underscores.
var validProfileNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// isValidSSMPath validates an SSM parameter path format.
func isValidSSMPath(path string) bool {
	if path == "" {
		return false
	}
	if !strings.HasPrefix(path, "/") {
		return false
	}
	if len(path) > MaxPolicyRootLength {
		return false
	}
	return validSSMPathRegex.MatchString(path)
}

// isValidProfileName validates an AWS profile name format.
func isValidProfileName(name string) bool {
	if name == "" {
		return false
	}
	if len(name) > MaxProfileNameLength {
		return false
	}
	return validProfileNameRegex.MatchString(name)
}

// Validate checks if the BootstrapConfig is semantically correct.
// It verifies all required fields are present and valid.
func (c *BootstrapConfig) Validate() error {
	// Validate PolicyRoot
	if c.PolicyRoot == "" {
		return fmt.Errorf("policy_root cannot be empty")
	}
	if !strings.HasPrefix(c.PolicyRoot, "/") {
		return fmt.Errorf("policy_root must start with '/'")
	}
	if len(c.PolicyRoot) > MaxPolicyRootLength {
		return fmt.Errorf("policy_root exceeds maximum length of %d characters", MaxPolicyRootLength)
	}
	if !isValidSSMPath(c.PolicyRoot) {
		return fmt.Errorf("policy_root contains invalid characters: only alphanumeric, '/', '-', '_' allowed")
	}

	// Validate profiles
	if len(c.Profiles) == 0 {
		return fmt.Errorf("at least one profile is required")
	}

	for i, profile := range c.Profiles {
		if err := profile.Validate(); err != nil {
			return fmt.Errorf("profile[%d]: %w", i, err)
		}
	}

	return nil
}

// Validate checks if the ProfileConfig is semantically correct.
// It verifies all required fields are present and valid.
func (p *ProfileConfig) Validate() error {
	// Validate name
	if p.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if len(p.Name) > MaxProfileNameLength {
		return fmt.Errorf("name exceeds maximum length of %d characters", MaxProfileNameLength)
	}
	if !isValidProfileName(p.Name) {
		return fmt.Errorf("name contains invalid characters: only alphanumeric, '-', '_' allowed")
	}

	// Validate InitialPolicy if provided (YAML parse check only)
	if p.InitialPolicy != "" {
		var parsed interface{}
		if err := yaml.Unmarshal([]byte(p.InitialPolicy), &parsed); err != nil {
			return fmt.Errorf("initial_policy is not valid YAML: %w", err)
		}
	}

	return nil
}

// Validate checks if the ResourceSpec is semantically correct.
// It verifies all required fields are present and valid.
func (r *ResourceSpec) Validate() error {
	if !r.Type.IsValid() {
		return fmt.Errorf("invalid resource type: %q", r.Type)
	}
	if r.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if !r.State.IsValid() {
		return fmt.Errorf("invalid resource state: %q", r.State)
	}
	return nil
}

// Validate checks if the BootstrapPlan is semantically correct.
// It verifies the config and all resources are valid.
func (p *BootstrapPlan) Validate() error {
	if err := p.Config.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	for i, resource := range p.Resources {
		if err := resource.Validate(); err != nil {
			return fmt.Errorf("resource[%d]: %w", i, err)
		}
	}

	return nil
}

// HasChanges returns true if any resource requires create or update action.
func (p *BootstrapPlan) HasChanges() bool {
	for _, r := range p.Resources {
		if r.State == StateCreate || r.State == StateUpdate {
			return true
		}
	}
	return false
}

// CountByState returns the number of resources in the given state.
func (p *BootstrapPlan) CountByState(state ResourceState) int {
	count := 0
	for _, r := range p.Resources {
		if r.State == state {
			count++
		}
	}
	return count
}

// Compute populates the summary from a resource list.
func (s *PlanSummary) Compute(resources []ResourceSpec) {
	s.ToCreate = 0
	s.ToUpdate = 0
	s.ToSkip = 0
	s.Total = len(resources)

	for _, r := range resources {
		switch r.State {
		case StateCreate:
			s.ToCreate++
		case StateUpdate:
			s.ToUpdate++
		case StateSkip, StateExists:
			s.ToSkip++
		}
	}
}
