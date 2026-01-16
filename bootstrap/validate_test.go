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
