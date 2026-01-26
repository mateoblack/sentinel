package policy

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// MarshalPolicy serializes a Policy to YAML bytes.
// Returns the YAML representation suitable for storage or display.
func MarshalPolicy(p *Policy) ([]byte, error) {
	return yaml.Marshal(p)
}

// MarshalPolicyToWriter serializes a Policy to YAML and writes to w.
func MarshalPolicyToWriter(p *Policy, w io.Writer) error {
	data, err := MarshalPolicy(p)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}
	_, err = w.Write(data)
	return err
}
