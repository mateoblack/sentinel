// Package bootstrap provides configuration and state management for Sentinel AWS setup automation.
// It defines types for specifying which SSM parameters to create and tracking what resources exist.
package bootstrap

import "time"

const (
	// DefaultPolicyRoot is the default SSM parameter path prefix for policies.
	DefaultPolicyRoot = "/sentinel/policies"

	// PolicyVersion is the current policy schema version.
	PolicyVersion = "1"

	// MaxProfileNameLength is the maximum length for AWS profile names.
	MaxProfileNameLength = 64

	// MaxPolicyRootLength is the maximum length for SSM parameter paths.
	MaxPolicyRootLength = 512
)

// ResourceType identifies the kind of AWS resource being managed.
type ResourceType string

const (
	// ResourceTypeSSMParameter represents a policy parameter in SSM.
	ResourceTypeSSMParameter ResourceType = "ssm_parameter"
	// ResourceTypeIAMPolicy represents a generated IAM policy document.
	ResourceTypeIAMPolicy ResourceType = "iam_policy"
)

// IsValid returns true if the ResourceType is a known value.
func (t ResourceType) IsValid() bool {
	switch t {
	case ResourceTypeSSMParameter, ResourceTypeIAMPolicy:
		return true
	}
	return false
}

// String returns the string representation of the ResourceType.
func (t ResourceType) String() string {
	return string(t)
}

// ResourceState represents the planned action for a resource.
type ResourceState string

const (
	// StateExists indicates the resource already exists in AWS.
	StateExists ResourceState = "exists"
	// StateCreate indicates the resource needs to be created.
	StateCreate ResourceState = "create"
	// StateUpdate indicates the resource exists but needs updating.
	StateUpdate ResourceState = "update"
	// StateSkip indicates no action is needed for this resource.
	StateSkip ResourceState = "skip"
)

// IsValid returns true if the ResourceState is a known value.
func (s ResourceState) IsValid() bool {
	switch s {
	case StateExists, StateCreate, StateUpdate, StateSkip:
		return true
	}
	return false
}

// String returns the string representation of the ResourceState.
func (s ResourceState) String() string {
	return string(s)
}

// BootstrapConfig is the top-level bootstrap specification.
// It defines which profiles to bootstrap and where to store policies.
type BootstrapConfig struct {
	// PolicyRoot is the SSM parameter path prefix (e.g., "/sentinel/policies").
	PolicyRoot string `yaml:"policy_root" json:"policy_root"`

	// Profiles lists the profiles to bootstrap.
	Profiles []ProfileConfig `yaml:"profiles" json:"profiles"`

	// GenerateIAMPolicies controls whether to generate IAM policy documents.
	GenerateIAMPolicies bool `yaml:"generate_iam_policies,omitempty" json:"generate_iam_policies,omitempty"`

	// Region is the AWS region (optional - uses default if empty).
	Region string `yaml:"region,omitempty" json:"region,omitempty"`
}

// ProfileConfig defines per-profile bootstrap configuration.
type ProfileConfig struct {
	// Name is the AWS profile name.
	Name string `yaml:"name" json:"name"`

	// Description is the profile description for policy comments.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// PolicyParameterName is the full SSM parameter name (auto-generated if empty).
	PolicyParameterName string `yaml:"policy_parameter_name,omitempty" json:"policy_parameter_name,omitempty"`

	// InitialPolicy is the initial policy YAML content (optional).
	InitialPolicy string `yaml:"initial_policy,omitempty" json:"initial_policy,omitempty"`
}

// ResourceSpec describes a planned resource operation.
type ResourceSpec struct {
	// Type identifies the kind of resource.
	Type ResourceType `yaml:"type" json:"type"`

	// Name is the resource identifier (SSM param name or IAM policy name).
	Name string `yaml:"name" json:"name"`

	// State is the planned action for this resource.
	State ResourceState `yaml:"state" json:"state"`

	// CurrentVersion is the existing version if any.
	CurrentVersion string `yaml:"current_version,omitempty" json:"current_version,omitempty"`

	// Description is a human-readable description.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// BootstrapPlan represents the full bootstrap plan output.
type BootstrapPlan struct {
	// Config is the input configuration.
	Config BootstrapConfig `yaml:"config" json:"config"`

	// Resources lists the planned operations.
	Resources []ResourceSpec `yaml:"resources" json:"resources"`

	// Summary contains operation counts by state.
	Summary PlanSummary `yaml:"summary" json:"summary"`

	// GeneratedAt is when the plan was generated.
	GeneratedAt time.Time `yaml:"generated_at" json:"generated_at"`
}

// PlanSummary contains operation counts.
type PlanSummary struct {
	// ToCreate is the number of resources to create.
	ToCreate int `yaml:"to_create" json:"to_create"`

	// ToUpdate is the number of resources to update.
	ToUpdate int `yaml:"to_update" json:"to_update"`

	// ToSkip is the number of resources to skip.
	ToSkip int `yaml:"to_skip" json:"to_skip"`

	// Total is the total number of resources in the plan.
	Total int `yaml:"total" json:"total"`
}

// DefaultPolicyParameterName returns the default SSM parameter name for a profile.
// Format: "{policyRoot}/{profile}"
func DefaultPolicyParameterName(policyRoot, profile string) string {
	return policyRoot + "/" + profile
}

// IAMPolicyName returns the IAM policy name in Sentinel format.
// Format: "Sentinel{Prefix}{Suffix}"
func IAMPolicyName(prefix, suffix string) string {
	return "Sentinel" + prefix + suffix
}
