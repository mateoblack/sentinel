package bootstrap

import (
	"bytes"
	"fmt"
	"time"

	"github.com/byteness/aws-vault/v7/policy"
	"gopkg.in/yaml.v3"
)

// GenerateSamplePolicy creates a valid starter policy YAML for a profile.
// The generated policy contains a default deny rule that users can customize.
// It returns an error if the profile name is empty.
func GenerateSamplePolicy(profile, description string) (string, error) {
	if profile == "" {
		return "", fmt.Errorf("profile name cannot be empty")
	}

	// Build policy struct
	p := policy.Policy{
		Version: PolicyVersion,
		Rules: []policy.Rule{
			{
				Name:   "default-deny",
				Effect: policy.EffectDeny,
				Conditions: policy.Condition{
					Profiles: []string{profile},
				},
				Reason: "Default deny - customize this policy",
			},
		},
	}

	// Validate before marshaling
	if err := p.Validate(); err != nil {
		return "", fmt.Errorf("generated policy is invalid: %w", err)
	}

	// Marshal to YAML with 2-space indent
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&p); err != nil {
		return "", fmt.Errorf("failed to marshal policy: %w", err)
	}
	encoder.Close()

	// Build header comment
	header := buildPolicyHeader(profile, description)

	return header + buf.String(), nil
}

// buildPolicyHeader creates the comment header for a generated policy.
func buildPolicyHeader(profile, description string) string {
	var header bytes.Buffer

	header.WriteString(fmt.Sprintf("# Sentinel policy for profile: %s\n", profile))
	if description != "" {
		header.WriteString(fmt.Sprintf("# %s\n", description))
	}
	header.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	header.WriteString("# Customize this policy to match your access requirements.\n\n")

	return header.String()
}
