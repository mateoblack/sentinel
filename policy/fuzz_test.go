// Package policy provides fuzz tests for policy parsing and validation.
// Fuzz tests help discover parsing bugs, memory issues from YAML bombs,
// and edge cases that could cause panics or crashes.
//
// Run fuzz tests:
//
//	go test -fuzz=FuzzParsePolicy -fuzztime=60s ./policy/...
//	go test -fuzz=FuzzValidatePolicy -fuzztime=60s ./policy/...
package policy

import (
	"strings"
	"testing"
)

// FuzzParsePolicy tests policy YAML parsing with random inputs
// to catch parsing bugs and edge cases that could cause panics or crashes.
//
// Run: go test -fuzz=FuzzParsePolicy -fuzztime=60s ./policy/...
func FuzzParsePolicy(f *testing.F) {
	// Seed corpus with valid and malformed policies
	seeds := []string{
		// Valid minimal policy
		`version: "1"
rules:
  - name: test-rule
    effect: allow
    conditions:
      profiles: ["test"]`,

		// Empty
		"",

		// Whitespace only
		"   \n\t\n   ",

		// Invalid YAML syntax
		"{{{{",
		"[[[",
		"}}}",
		"version: [",
		`version: "1"
rules: [{"broken`,

		// Missing version
		`rules:
  - name: test
    effect: allow
    conditions:
      profiles: ["test"]`,

		// Invalid version
		`version: "999"
rules:
  - name: test
    effect: allow
    conditions:
      profiles: ["test"]`,

		// Deeply nested structure
		`version: "1"
rules:
  - name: deep
    effect: allow
    conditions:
      profiles:
        - a:
            b:
              c:
                d: deep`,

		// Very long profile name
		`version: "1"
rules:
  - name: long-profile
    effect: allow
    conditions:
      profiles: ["` + strings.Repeat("a", 10000) + `"]`,

		// Many profiles
		`version: "1"
rules:
  - name: many-profiles
    effect: allow
    conditions:
      profiles: ["` + strings.Join(makeStrings(1000, "profile"), `","`) + `"]`,

		// Unicode in values
		`version: "1"
rules:
  - name: unicode-rule
    effect: allow
    conditions:
      users: ["用户名", "пользователь", "Benutzer"]`,

		// Null bytes in YAML
		"version: \"1\"\x00rules: []",

		// YAML aliases (potential for billion laughs attack)
		`a: &a ["lol","lol","lol"]
b: &b [*a,*a,*a]
c: &c [*b,*b,*b]`,

		// Larger YAML alias expansion
		`x: &x ["lol","lol","lol","lol","lol","lol","lol","lol","lol","lol"]
y: &y [*x,*x,*x,*x,*x,*x,*x,*x,*x,*x]
z: [*y,*y,*y,*y,*y,*y,*y,*y,*y,*y]`,

		// Type coercion attempts
		`version: 1
rules:
  - name: type-coerce
    effect: yes
    conditions:
      profiles: true`,

		// Effect as non-string
		`version: "1"
rules:
  - name: bad-effect
    effect: 123
    conditions:
      profiles: ["test"]`,

		// Special YAML values
		`version: "1"
rules:
  - name: special-values
    effect: allow
    conditions:
      profiles: [null, ~, true, false, .inf, -.inf, .nan]`,

		// Tab indentation (YAML typically uses spaces)
		"version: \"1\"\nrules:\n\t- name: tabs\n\t  effect: allow\n\t  conditions:\n\t    profiles: [\"test\"]",

		// Mixed indentation
		`version: "1"
rules:
  - name: mixed
    effect: allow
    conditions:
     profiles: ["test"]`,

		// Trailing garbage
		`version: "1"
rules:
  - name: test
    effect: allow
    conditions:
      profiles: ["test"]
garbage after policy`,

		// Multiple documents
		`---
version: "1"
rules:
  - name: doc1
    effect: allow
    conditions:
      profiles: ["test"]
---
version: "1"
rules:
  - name: doc2
    effect: deny
    conditions:
      profiles: ["test2"]`,

		// Empty rules array
		`version: "1"
rules: []`,

		// Rule with no conditions
		`version: "1"
rules:
  - name: no-conditions
    effect: allow
    conditions: {}`,

		// Rule with empty arrays
		`version: "1"
rules:
  - name: empty-arrays
    effect: allow
    conditions:
      profiles: []
      users: []`,

		// Very long rule name
		`version: "1"
rules:
  - name: "` + strings.Repeat("x", 10000) + `"
    effect: allow
    conditions:
      profiles: ["test"]`,

		// Injection in string values
		`version: "1"
rules:
  - name: "injection; rm -rf /"
    effect: allow
    conditions:
      profiles: ["test$(whoami)"]`,

		// Newlines in strings
		`version: "1"
rules:
  - name: |
      multi
      line
      name
    effect: allow
    conditions:
      profiles: ["test"]`,

		// Binary-like content
		"\x00\x01\x02\x03\x04\x05",

		// Large number
		`version: "1"
rules:
  - name: big-number
    effect: allow
    conditions:
      profiles: ["test"]
    max_server_duration: 99999999999999999999999999999999`,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Parse should never panic regardless of input
		policy, err := ParsePolicy([]byte(input))

		if err == nil && policy != nil {
			// If parsing succeeds, validate the result
			// Validation may fail (invalid policy data) but should not panic
			_ = policy.Validate()

			// Check for excessive data sizes that could indicate resource exhaustion
			for _, rule := range policy.Rules {
				// Reject rules with excessive number of conditions
				if len(rule.Conditions.Users) > 100000 {
					t.Errorf("ParsePolicy accepted rule with >100000 users: %d", len(rule.Conditions.Users))
				}
				if len(rule.Conditions.Profiles) > 100000 {
					t.Errorf("ParsePolicy accepted rule with >100000 profiles: %d", len(rule.Conditions.Profiles))
				}
			}

			// Check for excessive number of rules
			if len(policy.Rules) > 100000 {
				t.Errorf("ParsePolicy accepted policy with >100000 rules: %d", len(policy.Rules))
			}
		}
	})
}

// FuzzValidatePolicy focuses on validation logic after successful parse.
// This tests semantic validation rather than parsing.
//
// Run: go test -fuzz=FuzzValidatePolicy -fuzztime=30s ./policy/...
func FuzzValidatePolicy(f *testing.F) {
	// Seed with structurally valid but semantically questionable policies
	seeds := []string{
		// Empty conditions
		`version: "1"
rules:
  - name: empty-conditions
    effect: allow
    conditions:
      users: []
      profiles: []`,

		// Invalid effect value
		`version: "1"
rules:
  - name: bad-effect
    effect: invalid_effect
    conditions:
      profiles: ["test"]`,

		// Missing rule name
		`version: "1"
rules:
  - effect: allow
    conditions:
      profiles: ["test"]`,

		// Invalid weekday
		`version: "1"
rules:
  - name: bad-day
    effect: allow
    conditions:
      profiles: ["test"]
      time:
        days: ["notaday"]`,

		// Invalid timezone
		`version: "1"
rules:
  - name: bad-tz
    effect: allow
    conditions:
      profiles: ["test"]
      time:
        timezone: "Invalid/Timezone"`,

		// Invalid hour format
		`version: "1"
rules:
  - name: bad-hours
    effect: allow
    conditions:
      profiles: ["test"]
      time:
        hours:
          start: "25:00"
          end: "99:99"`,

		// Unknown version
		`version: "999"
rules: []`,

		// Valid complete policy
		`version: "1"
rules:
  - name: complete-rule
    effect: allow
    reason: "Test rule"
    conditions:
      profiles: ["prod"]
      users: ["alice", "bob"]
      time:
        days: ["monday", "tuesday"]
        hours:
          start: "09:00"
          end: "17:00"
        timezone: "America/New_York"`,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		policy, parseErr := ParsePolicy([]byte(input))
		if parseErr != nil {
			return // Can't validate unparseable input
		}

		// Validate should never panic, even on malformed policies
		_ = policy.Validate()
	})
}

// FuzzParsePolicyFromReader tests the reader-based parsing function.
//
// Run: go test -fuzz=FuzzParsePolicyFromReader -fuzztime=30s ./policy/...
func FuzzParsePolicyFromReader(f *testing.F) {
	// Basic seeds
	f.Add(`version: "1"
rules:
  - name: test
    effect: allow
    conditions:
      profiles: ["test"]`)
	f.Add("")
	f.Add("{{invalid yaml")

	f.Fuzz(func(t *testing.T, input string) {
		reader := strings.NewReader(input)
		// Should never panic
		_, _ = ParsePolicyFromReader(reader)
	})
}

// makeStrings creates n strings with the given prefix.
// Helper for generating large seed inputs.
func makeStrings(n int, prefix string) []string {
	result := make([]string, n)
	for i := 0; i < n; i++ {
		result[i] = prefix + string(rune('0'+i%10))
	}
	return result
}
