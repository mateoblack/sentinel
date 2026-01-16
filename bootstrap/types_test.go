package bootstrap

import "testing"

func TestResourceType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		rt       ResourceType
		expected bool
	}{
		{
			name:     "ssm_parameter is valid",
			rt:       ResourceTypeSSMParameter,
			expected: true,
		},
		{
			name:     "iam_policy is valid",
			rt:       ResourceTypeIAMPolicy,
			expected: true,
		},
		{
			name:     "empty string is invalid",
			rt:       "",
			expected: false,
		},
		{
			name:     "unknown type is invalid",
			rt:       ResourceType("unknown"),
			expected: false,
		},
		{
			name:     "similar but wrong type is invalid",
			rt:       ResourceType("ssm-parameter"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rt.IsValid()
			if got != tt.expected {
				t.Errorf("ResourceType(%q).IsValid() = %v, want %v", tt.rt, got, tt.expected)
			}
		})
	}
}

func TestResourceType_String(t *testing.T) {
	tests := []struct {
		name     string
		rt       ResourceType
		expected string
	}{
		{
			name:     "ssm_parameter",
			rt:       ResourceTypeSSMParameter,
			expected: "ssm_parameter",
		},
		{
			name:     "iam_policy",
			rt:       ResourceTypeIAMPolicy,
			expected: "iam_policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rt.String()
			if got != tt.expected {
				t.Errorf("ResourceType(%q).String() = %q, want %q", tt.rt, got, tt.expected)
			}
		})
	}
}

func TestResourceState_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		state    ResourceState
		expected bool
	}{
		{
			name:     "exists is valid",
			state:    StateExists,
			expected: true,
		},
		{
			name:     "create is valid",
			state:    StateCreate,
			expected: true,
		},
		{
			name:     "update is valid",
			state:    StateUpdate,
			expected: true,
		},
		{
			name:     "skip is valid",
			state:    StateSkip,
			expected: true,
		},
		{
			name:     "empty string is invalid",
			state:    "",
			expected: false,
		},
		{
			name:     "unknown state is invalid",
			state:    ResourceState("unknown"),
			expected: false,
		},
		{
			name:     "delete is invalid (not a valid state)",
			state:    ResourceState("delete"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.state.IsValid()
			if got != tt.expected {
				t.Errorf("ResourceState(%q).IsValid() = %v, want %v", tt.state, got, tt.expected)
			}
		})
	}
}

func TestResourceState_String(t *testing.T) {
	tests := []struct {
		name     string
		state    ResourceState
		expected string
	}{
		{
			name:     "exists",
			state:    StateExists,
			expected: "exists",
		},
		{
			name:     "create",
			state:    StateCreate,
			expected: "create",
		},
		{
			name:     "update",
			state:    StateUpdate,
			expected: "update",
		},
		{
			name:     "skip",
			state:    StateSkip,
			expected: "skip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.state.String()
			if got != tt.expected {
				t.Errorf("ResourceState(%q).String() = %q, want %q", tt.state, got, tt.expected)
			}
		})
	}
}

func TestDefaultPolicyParameterName(t *testing.T) {
	tests := []struct {
		name       string
		policyRoot string
		profile    string
		expected   string
	}{
		{
			name:       "standard path",
			policyRoot: "/sentinel/policies",
			profile:    "production",
			expected:   "/sentinel/policies/production",
		},
		{
			name:       "custom root",
			policyRoot: "/myorg/sentinel",
			profile:    "dev",
			expected:   "/myorg/sentinel/dev",
		},
		{
			name:       "profile with hyphens",
			policyRoot: "/sentinel/policies",
			profile:    "prod-east-1",
			expected:   "/sentinel/policies/prod-east-1",
		},
		{
			name:       "profile with underscores",
			policyRoot: "/sentinel/policies",
			profile:    "prod_east_1",
			expected:   "/sentinel/policies/prod_east_1",
		},
		{
			name:       "deep nested root",
			policyRoot: "/org/team/sentinel/policies",
			profile:    "staging",
			expected:   "/org/team/sentinel/policies/staging",
		},
		{
			name:       "empty profile",
			policyRoot: "/sentinel/policies",
			profile:    "",
			expected:   "/sentinel/policies/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DefaultPolicyParameterName(tt.policyRoot, tt.profile)
			if got != tt.expected {
				t.Errorf("DefaultPolicyParameterName(%q, %q) = %q, want %q",
					tt.policyRoot, tt.profile, got, tt.expected)
			}
		})
	}
}

func TestIAMPolicyName(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		suffix   string
		expected string
	}{
		{
			name:     "standard naming",
			prefix:   "Production",
			suffix:   "ReadOnly",
			expected: "SentinelProductionReadOnly",
		},
		{
			name:     "empty prefix",
			prefix:   "",
			suffix:   "Admin",
			expected: "SentinelAdmin",
		},
		{
			name:     "empty suffix",
			prefix:   "Staging",
			suffix:   "",
			expected: "SentinelStaging",
		},
		{
			name:     "both empty",
			prefix:   "",
			suffix:   "",
			expected: "Sentinel",
		},
		{
			name:     "long names",
			prefix:   "MyOrganization",
			suffix:   "PowerUserAccess",
			expected: "SentinelMyOrganizationPowerUserAccess",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IAMPolicyName(tt.prefix, tt.suffix)
			if got != tt.expected {
				t.Errorf("IAMPolicyName(%q, %q) = %q, want %q",
					tt.prefix, tt.suffix, got, tt.expected)
			}
		})
	}
}
