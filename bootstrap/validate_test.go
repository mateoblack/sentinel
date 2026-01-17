package bootstrap

import (
	"strings"
	"testing"
)

func TestBootstrapConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  BootstrapConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: BootstrapConfig{
				PolicyRoot: "/sentinel/policies",
				Profiles: []ProfileConfig{
					{Name: "production"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with multiple profiles",
			config: BootstrapConfig{
				PolicyRoot: "/sentinel/policies",
				Profiles: []ProfileConfig{
					{Name: "production"},
					{Name: "staging"},
					{Name: "dev"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty PolicyRoot fails",
			config: BootstrapConfig{
				PolicyRoot: "",
				Profiles: []ProfileConfig{
					{Name: "production"},
				},
			},
			wantErr: true,
			errMsg:  "policy_root cannot be empty",
		},
		{
			name: "PolicyRoot not starting with / fails",
			config: BootstrapConfig{
				PolicyRoot: "sentinel/policies",
				Profiles: []ProfileConfig{
					{Name: "production"},
				},
			},
			wantErr: true,
			errMsg:  "policy_root must start with '/'",
		},
		{
			name: "PolicyRoot too long fails",
			config: BootstrapConfig{
				PolicyRoot: "/" + strings.Repeat("a", MaxPolicyRootLength),
				Profiles: []ProfileConfig{
					{Name: "production"},
				},
			},
			wantErr: true,
			errMsg:  "policy_root exceeds maximum length",
		},
		{
			name: "PolicyRoot with invalid chars fails",
			config: BootstrapConfig{
				PolicyRoot: "/sentinel/policies@invalid",
				Profiles: []ProfileConfig{
					{Name: "production"},
				},
			},
			wantErr: true,
			errMsg:  "policy_root contains invalid characters",
		},
		{
			name: "PolicyRoot with spaces fails",
			config: BootstrapConfig{
				PolicyRoot: "/sentinel/my policies",
				Profiles: []ProfileConfig{
					{Name: "production"},
				},
			},
			wantErr: true,
			errMsg:  "policy_root contains invalid characters",
		},
		{
			name: "empty profiles fails",
			config: BootstrapConfig{
				PolicyRoot: "/sentinel/policies",
				Profiles:   []ProfileConfig{},
			},
			wantErr: true,
			errMsg:  "at least one profile is required",
		},
		{
			name: "nil profiles fails",
			config: BootstrapConfig{
				PolicyRoot: "/sentinel/policies",
				Profiles:   nil,
			},
			wantErr: true,
			errMsg:  "at least one profile is required",
		},
		{
			name: "invalid profile propagates error",
			config: BootstrapConfig{
				PolicyRoot: "/sentinel/policies",
				Profiles: []ProfileConfig{
					{Name: ""}, // invalid
				},
			},
			wantErr: true,
			errMsg:  "profile[0]:",
		},
		{
			name: "valid path with hyphens and underscores",
			config: BootstrapConfig{
				PolicyRoot: "/my-org/sentinel_policies",
				Profiles: []ProfileConfig{
					{Name: "production"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid deeply nested path",
			config: BootstrapConfig{
				PolicyRoot: "/org/team/app/sentinel/policies",
				Profiles: []ProfileConfig{
					{Name: "production"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestProfileConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		profile ProfileConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid profile",
			profile: ProfileConfig{
				Name: "production",
			},
			wantErr: false,
		},
		{
			name: "valid profile with description",
			profile: ProfileConfig{
				Name:        "production",
				Description: "Production AWS account",
			},
			wantErr: false,
		},
		{
			name: "valid profile with all fields",
			profile: ProfileConfig{
				Name:                "production",
				Description:         "Production AWS account",
				PolicyParameterName: "/sentinel/policies/production",
				InitialPolicy:       "version: \"1\"\nrules: []",
			},
			wantErr: false,
		},
		{
			name: "empty name fails",
			profile: ProfileConfig{
				Name: "",
			},
			wantErr: true,
			errMsg:  "name cannot be empty",
		},
		{
			name: "name too long fails",
			profile: ProfileConfig{
				Name: strings.Repeat("a", MaxProfileNameLength+1),
			},
			wantErr: true,
			errMsg:  "name exceeds maximum length",
		},
		{
			name: "name with invalid chars fails",
			profile: ProfileConfig{
				Name: "production@invalid",
			},
			wantErr: true,
			errMsg:  "name contains invalid characters",
		},
		{
			name: "name with spaces fails",
			profile: ProfileConfig{
				Name: "my profile",
			},
			wantErr: true,
			errMsg:  "name contains invalid characters",
		},
		{
			name: "name with slashes fails",
			profile: ProfileConfig{
				Name: "production/east",
			},
			wantErr: true,
			errMsg:  "name contains invalid characters",
		},
		{
			name: "name exactly at max length passes",
			profile: ProfileConfig{
				Name: strings.Repeat("a", MaxProfileNameLength),
			},
			wantErr: false,
		},
		{
			name: "name with hyphens passes",
			profile: ProfileConfig{
				Name: "prod-east-1",
			},
			wantErr: false,
		},
		{
			name: "name with underscores passes",
			profile: ProfileConfig{
				Name: "prod_east_1",
			},
			wantErr: false,
		},
		{
			name: "invalid YAML in InitialPolicy fails",
			profile: ProfileConfig{
				Name:          "production",
				InitialPolicy: "this: is: invalid: yaml: [",
			},
			wantErr: true,
			errMsg:  "initial_policy is not valid YAML",
		},
		{
			name: "valid YAML in InitialPolicy passes",
			profile: ProfileConfig{
				Name:          "production",
				InitialPolicy: "version: \"1\"\nrules:\n  - name: test\n    effect: allow",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestResourceSpec_Validate(t *testing.T) {
	tests := []struct {
		name    string
		spec    ResourceSpec
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid spec",
			spec: ResourceSpec{
				Type:  ResourceTypeSSMParameter,
				Name:  "/sentinel/policies/production",
				State: StateCreate,
			},
			wantErr: false,
		},
		{
			name: "valid spec with all fields",
			spec: ResourceSpec{
				Type:           ResourceTypeIAMPolicy,
				Name:           "SentinelProductionReadOnly",
				State:          StateUpdate,
				CurrentVersion: "v1",
				Description:    "IAM policy for production read-only access",
			},
			wantErr: false,
		},
		{
			name: "invalid type fails",
			spec: ResourceSpec{
				Type:  ResourceType("invalid"),
				Name:  "/sentinel/policies/production",
				State: StateCreate,
			},
			wantErr: true,
			errMsg:  "invalid resource type",
		},
		{
			name: "empty type fails",
			spec: ResourceSpec{
				Type:  "",
				Name:  "/sentinel/policies/production",
				State: StateCreate,
			},
			wantErr: true,
			errMsg:  "invalid resource type",
		},
		{
			name: "empty name fails",
			spec: ResourceSpec{
				Type:  ResourceTypeSSMParameter,
				Name:  "",
				State: StateCreate,
			},
			wantErr: true,
			errMsg:  "name cannot be empty",
		},
		{
			name: "invalid state fails",
			spec: ResourceSpec{
				Type:  ResourceTypeSSMParameter,
				Name:  "/sentinel/policies/production",
				State: ResourceState("invalid"),
			},
			wantErr: true,
			errMsg:  "invalid resource state",
		},
		{
			name: "empty state fails",
			spec: ResourceSpec{
				Type:  ResourceTypeSSMParameter,
				Name:  "/sentinel/policies/production",
				State: "",
			},
			wantErr: true,
			errMsg:  "invalid resource state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestBootstrapPlan_HasChanges(t *testing.T) {
	tests := []struct {
		name      string
		resources []ResourceSpec
		expected  bool
	}{
		{
			name:      "empty resources returns false",
			resources: []ResourceSpec{},
			expected:  false,
		},
		{
			name: "all skip returns false",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateSkip},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateSkip},
			},
			expected: false,
		},
		{
			name: "all exists returns false",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateExists},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateExists},
			},
			expected: false,
		},
		{
			name: "has create returns true",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateSkip},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateCreate},
			},
			expected: true,
		},
		{
			name: "has update returns true",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateSkip},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateUpdate},
			},
			expected: true,
		},
		{
			name: "mixed states with create returns true",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateExists},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateCreate},
				{Type: ResourceTypeSSMParameter, Name: "c", State: StateSkip},
			},
			expected: true,
		},
		{
			name: "only create returns true",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateCreate},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := &BootstrapPlan{Resources: tt.resources}
			got := plan.HasChanges()
			if got != tt.expected {
				t.Errorf("HasChanges() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBootstrapPlan_CountByState(t *testing.T) {
	tests := []struct {
		name      string
		resources []ResourceSpec
		state     ResourceState
		expected  int
	}{
		{
			name:      "empty resources",
			resources: []ResourceSpec{},
			state:     StateCreate,
			expected:  0,
		},
		{
			name: "count creates",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateCreate},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateCreate},
				{Type: ResourceTypeSSMParameter, Name: "c", State: StateSkip},
			},
			state:    StateCreate,
			expected: 2,
		},
		{
			name: "count skips",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateCreate},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateSkip},
				{Type: ResourceTypeSSMParameter, Name: "c", State: StateSkip},
				{Type: ResourceTypeSSMParameter, Name: "d", State: StateSkip},
			},
			state:    StateSkip,
			expected: 3,
		},
		{
			name: "count updates",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateUpdate},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateCreate},
			},
			state:    StateUpdate,
			expected: 1,
		},
		{
			name: "count exists",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateExists},
			},
			state:    StateExists,
			expected: 1,
		},
		{
			name: "no matches",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateCreate},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateCreate},
			},
			state:    StateUpdate,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := &BootstrapPlan{Resources: tt.resources}
			got := plan.CountByState(tt.state)
			if got != tt.expected {
				t.Errorf("CountByState(%q) = %d, want %d", tt.state, got, tt.expected)
			}
		})
	}
}

func TestPlanSummary_Compute(t *testing.T) {
	tests := []struct {
		name        string
		resources   []ResourceSpec
		wantCreate  int
		wantUpdate  int
		wantSkip    int
		wantTotal   int
	}{
		{
			name:        "empty resources",
			resources:   []ResourceSpec{},
			wantCreate:  0,
			wantUpdate:  0,
			wantSkip:    0,
			wantTotal:   0,
		},
		{
			name: "all creates",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateCreate},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateCreate},
			},
			wantCreate: 2,
			wantUpdate: 0,
			wantSkip:   0,
			wantTotal:  2,
		},
		{
			name: "mixed states",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateCreate},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateUpdate},
				{Type: ResourceTypeSSMParameter, Name: "c", State: StateSkip},
				{Type: ResourceTypeSSMParameter, Name: "d", State: StateExists},
			},
			wantCreate: 1,
			wantUpdate: 1,
			wantSkip:   2, // skip + exists both count as skip
			wantTotal:  4,
		},
		{
			name: "all skips",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateSkip},
				{Type: ResourceTypeSSMParameter, Name: "b", State: StateSkip},
			},
			wantCreate: 0,
			wantUpdate: 0,
			wantSkip:   2,
			wantTotal:  2,
		},
		{
			name: "exists counts as skip",
			resources: []ResourceSpec{
				{Type: ResourceTypeSSMParameter, Name: "a", State: StateExists},
			},
			wantCreate: 0,
			wantUpdate: 0,
			wantSkip:   1,
			wantTotal:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := &PlanSummary{}
			summary.Compute(tt.resources)

			if summary.ToCreate != tt.wantCreate {
				t.Errorf("ToCreate = %d, want %d", summary.ToCreate, tt.wantCreate)
			}
			if summary.ToUpdate != tt.wantUpdate {
				t.Errorf("ToUpdate = %d, want %d", summary.ToUpdate, tt.wantUpdate)
			}
			if summary.ToSkip != tt.wantSkip {
				t.Errorf("ToSkip = %d, want %d", summary.ToSkip, tt.wantSkip)
			}
			if summary.Total != tt.wantTotal {
				t.Errorf("Total = %d, want %d", summary.Total, tt.wantTotal)
			}
		})
	}
}

func TestBootstrapPlan_Validate(t *testing.T) {
	validConfig := BootstrapConfig{
		PolicyRoot: "/sentinel/policies",
		Profiles: []ProfileConfig{
			{Name: "production"},
		},
	}

	validResource := ResourceSpec{
		Type:  ResourceTypeSSMParameter,
		Name:  "/sentinel/policies/production",
		State: StateCreate,
	}

	tests := []struct {
		name    string
		plan    BootstrapPlan
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid plan",
			plan: BootstrapPlan{
				Config:    validConfig,
				Resources: []ResourceSpec{validResource},
			},
			wantErr: false,
		},
		{
			name: "valid plan with no resources",
			plan: BootstrapPlan{
				Config:    validConfig,
				Resources: []ResourceSpec{},
			},
			wantErr: false,
		},
		{
			name: "invalid config fails",
			plan: BootstrapPlan{
				Config: BootstrapConfig{
					PolicyRoot: "", // invalid
					Profiles:   []ProfileConfig{{Name: "production"}},
				},
				Resources: []ResourceSpec{validResource},
			},
			wantErr: true,
			errMsg:  "config:",
		},
		{
			name: "invalid resource fails",
			plan: BootstrapPlan{
				Config: validConfig,
				Resources: []ResourceSpec{
					{Type: "", Name: "test", State: StateCreate}, // invalid type
				},
			},
			wantErr: true,
			errMsg:  "resource[0]:",
		},
		{
			name: "second invalid resource reports correct index",
			plan: BootstrapPlan{
				Config: validConfig,
				Resources: []ResourceSpec{
					validResource,
					{Type: ResourceTypeSSMParameter, Name: "", State: StateCreate}, // invalid name
				},
			},
			wantErr: true,
			errMsg:  "resource[1]:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.plan.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Test internal validation helpers
func TestIsValidSSMPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{name: "valid simple path", path: "/sentinel/policies", expected: true},
		{name: "valid with hyphens", path: "/my-org/sentinel", expected: true},
		{name: "valid with underscores", path: "/my_org/sentinel", expected: true},
		{name: "valid deep path", path: "/a/b/c/d/e", expected: true},
		{name: "empty is invalid", path: "", expected: false},
		{name: "no leading slash", path: "sentinel/policies", expected: false},
		{name: "with spaces", path: "/sentinel/my policies", expected: false},
		{name: "with special chars", path: "/sentinel@policies", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidSSMPath(tt.path)
			if got != tt.expected {
				t.Errorf("isValidSSMPath(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestIsValidProfileName(t *testing.T) {
	tests := []struct {
		name     string
		profile  string
		expected bool
	}{
		{name: "valid simple", profile: "production", expected: true},
		{name: "valid with hyphens", profile: "prod-east-1", expected: true},
		{name: "valid with underscores", profile: "prod_east_1", expected: true},
		{name: "valid alphanumeric", profile: "prod123", expected: true},
		{name: "empty is invalid", profile: "", expected: false},
		{name: "with spaces", profile: "my profile", expected: false},
		{name: "with slashes", profile: "prod/east", expected: false},
		{name: "with special chars", profile: "prod@east", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidProfileName(tt.profile)
			if got != tt.expected {
				t.Errorf("isValidProfileName(%q) = %v, want %v", tt.profile, got, tt.expected)
			}
		})
	}
}

// TestIsValidSSMPath_EdgeCases tests security-relevant edge cases for SSM path validation.
func TestIsValidSSMPath_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Unicode and special character attacks
		{name: "unicode chars rejected", path: "/sentinel/polic\u00edes", expected: false},
		{name: "zero-width char rejected (U+200B)", path: "/sentinel/\u200Bpolicies", expected: false},
		{name: "zero-width joiner rejected (U+200D)", path: "/sentinel/pol\u200Dicies", expected: false},
		{name: "zero-width non-joiner rejected (U+200C)", path: "/sentinel/\u200Cpolicies", expected: false},
		{name: "left-to-right override rejected (U+202D)", path: "/sentinel/\u202Dpolicies", expected: false},
		{name: "homoglyph latin small a with ring rejected", path: "/sentinel/p\u00e5licies", expected: false},
		{name: "cyrillic a rejected (looks like latin a)", path: "/sentinel/p\u0430licies", expected: false},
		{name: "full-width solidus rejected (U+FF0F)", path: "/sentinel\uFF0Fpolicies", expected: false},

		// Path traversal attempts
		{name: "path traversal ../ rejected", path: "/sentinel/../policies", expected: false},
		{name: "double dots rejected", path: "/sentinel/..policies", expected: false},
		{name: "encoded path traversal", path: "/sentinel/%2e%2e/policies", expected: false},

		// Maximum length boundary
		{name: "path at max length passes", path: "/" + strings.Repeat("a", MaxPolicyRootLength-1), expected: true},
		{name: "path exceeds max length fails", path: "/" + strings.Repeat("a", MaxPolicyRootLength), expected: false},

		// Empty path components (// in path) - regex allows consecutive slashes
		// This is valid per AWS SSM, though unusual
		{name: "double slash in path allowed", path: "/sentinel//policies", expected: true},
		{name: "triple slash allowed", path: "/sentinel///policies", expected: true},
		{name: "trailing double slash allowed", path: "/sentinel/policies//", expected: true},

		// Path start edge cases
		{name: "path not starting with / fails", path: "sentinel/policies", expected: false},
		{name: "empty path fails", path: "", expected: false},
		{name: "only slash is valid", path: "/a", expected: true},

		// Whitespace variations
		{name: "tab character rejected", path: "/sentinel/\tpolicies", expected: false},
		{name: "newline rejected", path: "/sentinel/\npolicies", expected: false},
		{name: "carriage return rejected", path: "/sentinel/\rpolicies", expected: false},
		{name: "leading space rejected", path: " /sentinel/policies", expected: false},
		{name: "trailing space rejected", path: "/sentinel/policies ", expected: false},

		// Null byte injection
		{name: "null byte rejected", path: "/sentinel/\x00policies", expected: false},

		// Valid edge cases that should pass
		{name: "numeric path component", path: "/sentinel/123", expected: true},
		{name: "mixed case path", path: "/Sentinel/Policies", expected: true},
		{name: "path with hyphens and underscores", path: "/my-org_prod/policies-v1", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidSSMPath(tt.path)
			if got != tt.expected {
				t.Errorf("isValidSSMPath(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

// TestIsValidProfileName_EdgeCases tests security-relevant edge cases for profile name validation.
func TestIsValidProfileName_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		profile  string
		expected bool
	}{
		// Unicode and special character attacks
		{name: "unicode char rejected", profile: "produc\u00e7ion", expected: false},
		{name: "zero-width char rejected (U+200B)", profile: "prod\u200Buction", expected: false},
		{name: "zero-width joiner rejected (U+200D)", profile: "prod\u200Duction", expected: false},
		{name: "cyrillic a rejected (looks like latin a)", profile: "production", expected: true},
		{name: "cyrillic o rejected", profile: "pr\u043educti\u043en", expected: false},
		{name: "full-width letters rejected (A)", profile: "pro\uFF21uction", expected: false},
		{name: "full-width hyphen rejected (U+FF0D)", profile: "prod\uFF0Deast", expected: false},

		// Maximum length boundary
		{name: "profile at max length passes", profile: strings.Repeat("a", MaxProfileNameLength), expected: true},
		{name: "profile exceeds max length fails", profile: strings.Repeat("a", MaxProfileNameLength+1), expected: false},

		// Whitespace variations
		{name: "tab rejected", profile: "prod\tuction", expected: false},
		{name: "newline rejected", profile: "prod\nuction", expected: false},
		{name: "carriage return rejected", profile: "prod\ruction", expected: false},
		{name: "leading space rejected", profile: " production", expected: false},
		{name: "trailing space rejected", profile: "production ", expected: false},

		// Special characters that should fail
		{name: "dot rejected", profile: "prod.east", expected: false},
		{name: "colon rejected", profile: "prod:east", expected: false},
		{name: "semicolon rejected", profile: "prod;east", expected: false},
		{name: "equals rejected", profile: "prod=east", expected: false},
		{name: "plus rejected", profile: "prod+east", expected: false},
		{name: "ampersand rejected", profile: "prod&east", expected: false},
		{name: "hash rejected", profile: "prod#east", expected: false},
		{name: "dollar rejected", profile: "prod$east", expected: false},
		{name: "percent rejected", profile: "prod%east", expected: false},
		{name: "caret rejected", profile: "prod^east", expected: false},
		{name: "asterisk rejected", profile: "prod*east", expected: false},
		{name: "parentheses rejected", profile: "prod(east)", expected: false},
		{name: "brackets rejected", profile: "prod[east]", expected: false},
		{name: "braces rejected", profile: "prod{east}", expected: false},
		{name: "pipe rejected", profile: "prod|east", expected: false},
		{name: "backslash rejected", profile: "prod\\east", expected: false},
		{name: "quote rejected", profile: "prod\"east", expected: false},
		{name: "single quote rejected", profile: "prod'east", expected: false},
		{name: "backtick rejected", profile: "prod`east", expected: false},
		{name: "tilde rejected", profile: "prod~east", expected: false},
		{name: "question mark rejected", profile: "prod?east", expected: false},
		{name: "exclamation rejected", profile: "prod!east", expected: false},
		{name: "comma rejected", profile: "prod,east", expected: false},
		{name: "less than rejected", profile: "prod<east", expected: false},
		{name: "greater than rejected", profile: "prod>east", expected: false},

		// Null byte injection
		{name: "null byte rejected", profile: "prod\x00east", expected: false},

		// Valid edge cases that should pass
		{name: "numeric only", profile: "12345", expected: true},
		{name: "single char", profile: "a", expected: true},
		{name: "starts with number", profile: "1production", expected: true},
		{name: "all hyphens and underscores mixed", profile: "a-b_c-d_e", expected: true},
		{name: "upper case", profile: "PRODUCTION", expected: true},
		{name: "mixed case", profile: "ProdEast1", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidProfileName(tt.profile)
			if got != tt.expected {
				t.Errorf("isValidProfileName(%q) = %v, want %v", tt.profile, got, tt.expected)
			}
		})
	}
}
