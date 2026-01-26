package policy

import (
	"bytes"
	"strings"
	"testing"
)

func TestMarshalPolicy_RoundTrip(t *testing.T) {
	// Create a policy with various fields
	original := &Policy{
		Version: Version("1"),
		Rules: []Rule{
			{
				Name:   "allow-prod-access",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"prod", "staging"},
					Users:    []string{"alice", "bob"},
				},
				Reason: "Allow team access to production",
			},
			{
				Name:   "deny-weekends",
				Effect: EffectDeny,
				Conditions: Condition{
					Time: &TimeWindow{
						Days: []Weekday{Saturday, Sunday},
					},
				},
			},
		},
	}

	// Marshal to YAML
	data, err := MarshalPolicy(original)
	if err != nil {
		t.Fatalf("MarshalPolicy failed: %v", err)
	}

	// Parse back
	parsed, err := ParsePolicy(data)
	if err != nil {
		t.Fatalf("ParsePolicy failed: %v", err)
	}

	// Verify equivalence
	if string(parsed.Version) != string(original.Version) {
		t.Errorf("Version mismatch: got %q, want %q", parsed.Version, original.Version)
	}

	if len(parsed.Rules) != len(original.Rules) {
		t.Fatalf("Rules count mismatch: got %d, want %d", len(parsed.Rules), len(original.Rules))
	}

	// Check first rule
	if parsed.Rules[0].Name != original.Rules[0].Name {
		t.Errorf("Rule[0].Name mismatch: got %q, want %q", parsed.Rules[0].Name, original.Rules[0].Name)
	}
	if parsed.Rules[0].Effect != original.Rules[0].Effect {
		t.Errorf("Rule[0].Effect mismatch: got %q, want %q", parsed.Rules[0].Effect, original.Rules[0].Effect)
	}
	if len(parsed.Rules[0].Conditions.Profiles) != len(original.Rules[0].Conditions.Profiles) {
		t.Errorf("Rule[0].Conditions.Profiles count mismatch: got %d, want %d",
			len(parsed.Rules[0].Conditions.Profiles), len(original.Rules[0].Conditions.Profiles))
	}

	// Check second rule
	if parsed.Rules[1].Name != original.Rules[1].Name {
		t.Errorf("Rule[1].Name mismatch: got %q, want %q", parsed.Rules[1].Name, original.Rules[1].Name)
	}
	if parsed.Rules[1].Conditions.Time == nil {
		t.Error("Rule[1].Conditions.Time is nil, expected TimeWindow")
	} else if len(parsed.Rules[1].Conditions.Time.Days) != 2 {
		t.Errorf("Rule[1].Conditions.Time.Days count mismatch: got %d, want 2",
			len(parsed.Rules[1].Conditions.Time.Days))
	}
}

func TestMarshalPolicy_Format(t *testing.T) {
	policy := &Policy{
		Version: Version("1"),
		Rules: []Rule{
			{
				Name:   "test-rule",
				Effect: EffectAllow,
				Conditions: Condition{
					Profiles: []string{"test"},
				},
			},
		},
	}

	data, err := MarshalPolicy(policy)
	if err != nil {
		t.Fatalf("MarshalPolicy failed: %v", err)
	}

	yaml := string(data)

	// Check for expected YAML structure
	if !strings.Contains(yaml, "version:") {
		t.Error("YAML output missing 'version:' field")
	}
	if !strings.Contains(yaml, "rules:") {
		t.Error("YAML output missing 'rules:' field")
	}
	if !strings.Contains(yaml, "name: test-rule") {
		t.Error("YAML output missing rule name")
	}
	if !strings.Contains(yaml, "effect: allow") {
		t.Error("YAML output missing rule effect")
	}
}

func TestMarshalPolicyToWriter(t *testing.T) {
	policy := &Policy{
		Version: Version("1"),
		Rules: []Rule{
			{
				Name:   "writer-test",
				Effect: EffectDeny,
				Conditions: Condition{
					Users: []string{"test-user"},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := MarshalPolicyToWriter(policy, &buf)
	if err != nil {
		t.Fatalf("MarshalPolicyToWriter failed: %v", err)
	}

	// Verify written content
	written := buf.String()
	if !strings.Contains(written, "version:") {
		t.Error("Written output missing 'version:' field")
	}
	if !strings.Contains(written, "name: writer-test") {
		t.Error("Written output missing rule name")
	}

	// Verify it can be parsed back
	parsed, err := ParsePolicy(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePolicy failed on written output: %v", err)
	}
	if parsed.Rules[0].Name != "writer-test" {
		t.Errorf("Parsed rule name mismatch: got %q, want %q", parsed.Rules[0].Name, "writer-test")
	}
}

func TestMarshalPolicy_EmptyPolicy(t *testing.T) {
	policy := &Policy{
		Version: Version("1"),
		Rules:   []Rule{},
	}

	data, err := MarshalPolicy(policy)
	if err != nil {
		t.Fatalf("MarshalPolicy failed: %v", err)
	}

	yaml := string(data)
	if !strings.Contains(yaml, "version:") {
		t.Error("YAML output missing 'version:' field for empty policy")
	}
}
