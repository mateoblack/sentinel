package policy

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// ParsePolicy parses a YAML byte slice into a Policy struct.
// It returns an error if the input is empty, contains invalid YAML syntax,
// or is missing required fields like version.
func ParsePolicy(data []byte) (*Policy, error) {
	// Check for empty input
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("empty policy")
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}

	// Check for required version field
	if policy.Version == "" {
		return nil, fmt.Errorf("missing version field")
	}

	return &policy, nil
}

// ParsePolicyFromReader parses a Policy from an io.Reader.
// It reads the entire contents and delegates to ParsePolicy.
func ParsePolicyFromReader(r io.Reader) (*Policy, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy: %w", err)
	}
	return ParsePolicy(data)
}
