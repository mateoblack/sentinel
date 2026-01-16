package enforce

import (
	"encoding/json"
	"fmt"
)

// ParseTrustPolicy parses a JSON byte slice into a TrustPolicyDocument.
// It handles the flexible AWS JSON format where Principal and Action
// can be strings, arrays, or objects.
func ParseTrustPolicy(data []byte) (*TrustPolicyDocument, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty trust policy")
	}

	var doc TrustPolicyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if err := doc.Validate(); err != nil {
		return nil, err
	}

	return &doc, nil
}

// Validate checks that the TrustPolicyDocument has required fields
// and valid values.
func (d *TrustPolicyDocument) Validate() error {
	if d.Version == "" {
		return fmt.Errorf("missing Version field")
	}
	if len(d.Statement) == 0 {
		return fmt.Errorf("missing Statement field")
	}
	for i, stmt := range d.Statement {
		if stmt.Effect != "Allow" && stmt.Effect != "Deny" {
			return fmt.Errorf("statement %d: Effect must be Allow or Deny, got %q", i, stmt.Effect)
		}
		if len(stmt.Action) == 0 {
			return fmt.Errorf("statement %d: missing Action field", i)
		}
	}
	return nil
}

// UnmarshalJSON implements custom JSON unmarshaling for StringOrSlice.
// It handles both single string values and arrays of strings.
func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	// First try as string
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = StringOrSlice{str}
		return nil
	}

	// Then try as array
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return fmt.Errorf("expected string or []string: %w", err)
	}
	*s = StringOrSlice(arr)
	return nil
}

// MarshalJSON implements JSON marshaling for StringOrSlice.
// If there's a single value, it marshals as a string; otherwise as an array.
func (s StringOrSlice) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}

// UnmarshalJSON implements custom JSON unmarshaling for Principal.
// AWS trust policies allow Principal to be:
//   - "*" (any principal)
//   - {"AWS": "arn:..."} or {"AWS": ["arn1", "arn2"]}
//   - {"Service": "ec2.amazonaws.com"}
//   - {"Federated": "arn:..."}
func (p *Principal) UnmarshalJSON(data []byte) error {
	// First try as wildcard string "*"
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		if str == "*" {
			p.Wildcard = true
			return nil
		}
		return fmt.Errorf("Principal string must be \"*\", got %q", str)
	}

	// Then try as object with AWS/Service/Federated keys
	type principalAlias struct {
		AWS       StringOrSlice `json:"AWS,omitempty"`
		Service   StringOrSlice `json:"Service,omitempty"`
		Federated StringOrSlice `json:"Federated,omitempty"`
	}
	var obj principalAlias
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("expected Principal as \"*\" or object: %w", err)
	}

	p.AWS = obj.AWS
	p.Service = obj.Service
	p.Federated = obj.Federated
	p.Wildcard = false
	return nil
}

// MarshalJSON implements JSON marshaling for Principal.
func (p Principal) MarshalJSON() ([]byte, error) {
	if p.Wildcard {
		return json.Marshal("*")
	}
	type principalAlias struct {
		AWS       StringOrSlice `json:"AWS,omitempty"`
		Service   StringOrSlice `json:"Service,omitempty"`
		Federated StringOrSlice `json:"Federated,omitempty"`
	}
	return json.Marshal(principalAlias{
		AWS:       p.AWS,
		Service:   p.Service,
		Federated: p.Federated,
	})
}

// Contains checks if the StringOrSlice contains the given value.
func (s StringOrSlice) Contains(value string) bool {
	for _, v := range s {
		if v == value {
			return true
		}
	}
	return false
}
