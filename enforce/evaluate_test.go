package enforce

import (
	"testing"
)

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		// Literal matching
		{
			name:    "exact match",
			pattern: "hello",
			value:   "hello",
			want:    true,
		},
		{
			name:    "case sensitive mismatch",
			pattern: "Hello",
			value:   "hello",
			want:    false,
		},
		{
			name:    "no match different strings",
			pattern: "hello",
			value:   "world",
			want:    false,
		},
		{
			name:    "empty pattern empty value",
			pattern: "",
			value:   "",
			want:    true,
		},
		{
			name:    "empty pattern non-empty value",
			pattern: "",
			value:   "hello",
			want:    false,
		},

		// Star wildcard (*)
		{
			name:    "star matches everything",
			pattern: "*",
			value:   "anything",
			want:    true,
		},
		{
			name:    "star matches empty",
			pattern: "*",
			value:   "",
			want:    true,
		},
		{
			name:    "prefix star",
			pattern: "*world",
			value:   "helloworld",
			want:    true,
		},
		{
			name:    "suffix star",
			pattern: "hello*",
			value:   "helloworld",
			want:    true,
		},
		{
			name:    "middle star",
			pattern: "hello*world",
			value:   "hello beautiful world",
			want:    true,
		},
		{
			name:    "multiple stars",
			pattern: "*hello*world*",
			value:   "say hello to the world today",
			want:    true,
		},
		{
			name:    "consecutive stars",
			pattern: "hello**world",
			value:   "helloworld",
			want:    true,
		},
		{
			name:    "star no match",
			pattern: "hello*world",
			value:   "helloplanet",
			want:    false,
		},

		// Question mark wildcard (?)
		{
			name:    "single question mark",
			pattern: "h?llo",
			value:   "hello",
			want:    true,
		},
		{
			name:    "multiple question marks",
			pattern: "h???o",
			value:   "hello",
			want:    true,
		},
		{
			name:    "question mark at start",
			pattern: "?ello",
			value:   "hello",
			want:    true,
		},
		{
			name:    "question mark at end",
			pattern: "hell?",
			value:   "hello",
			want:    true,
		},
		{
			name:    "question mark no match short value",
			pattern: "h?llo",
			value:   "hllo",
			want:    false,
		},
		{
			name:    "question mark no match empty",
			pattern: "?",
			value:   "",
			want:    false,
		},

		// Combined wildcards
		{
			name:    "star and question mark",
			pattern: "h?llo*",
			value:   "hello world",
			want:    true,
		},
		{
			name:    "question then star",
			pattern: "?*",
			value:   "x",
			want:    true,
		},
		{
			name:    "star then question",
			pattern: "*?",
			value:   "anything",
			want:    true,
		},

		// Sentinel-specific patterns
		{
			name:    "sentinel wildcard",
			pattern: "sentinel:*",
			value:   "sentinel:alice:a1b2c3d4",
			want:    true,
		},
		{
			name:    "sentinel user wildcard",
			pattern: "sentinel:alice:*",
			value:   "sentinel:alice:a1b2c3d4",
			want:    true,
		},
		{
			name:    "sentinel user mismatch",
			pattern: "sentinel:bob:*",
			value:   "sentinel:alice:a1b2c3d4",
			want:    false,
		},
		{
			name:    "sentinel exact match",
			pattern: "sentinel:alice:a1b2c3d4",
			value:   "sentinel:alice:a1b2c3d4",
			want:    true,
		},
		{
			name:    "sentinel prefix only",
			pattern: "sentinel:*",
			value:   "notsentinel:alice:xyz",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchPattern(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("MatchPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestHasSourceIdentityCondition(t *testing.T) {
	tests := []struct {
		name string
		stmt *Statement
		want bool
	}{
		{
			name: "nil statement",
			stmt: nil,
			want: false,
		},
		{
			name: "no condition",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
			},
			want: false,
		},
		{
			name: "StringLike with sentinel:*",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
			want: true,
		},
		{
			name: "StringLike with user-specific pattern",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:alice:*"},
					},
				},
			},
			want: true,
		},
		{
			name: "StringEquals with sentinel pattern",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringEquals": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:alice:abc123"},
					},
				},
			},
			want: true,
		},
		{
			name: "multiple patterns including sentinel",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:alice:*", "sentinel:bob:*"},
					},
				},
			},
			want: true,
		},
		{
			name: "wrong condition key",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"aws:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
			want: false,
		},
		{
			name: "non-sentinel pattern",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"other:*"},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasSourceIdentityCondition(tt.stmt)
			if got != tt.want {
				t.Errorf("HasSourceIdentityCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetSourceIdentityPatterns(t *testing.T) {
	tests := []struct {
		name string
		stmt *Statement
		want []string
	}{
		{
			name: "nil statement",
			stmt: nil,
			want: nil,
		},
		{
			name: "no condition",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
			},
			want: nil,
		},
		{
			name: "StringLike patterns",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
			want: []string{"sentinel:*"},
		},
		{
			name: "multiple patterns",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:alice:*", "sentinel:bob:*"},
					},
				},
			},
			want: []string{"sentinel:alice:*", "sentinel:bob:*"},
		},
		{
			name: "StringNotLike patterns",
			stmt: &Statement{
				Effect: "Deny",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringNotLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
				},
			},
			want: []string{"sentinel:*"},
		},
		{
			name: "multiple operators",
			stmt: &Statement{
				Effect: "Allow",
				Action: StringOrSlice{"sts:AssumeRole"},
				Condition: ConditionBlock{
					"StringLike": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:*"},
					},
					"StringEquals": ConditionOperator{
						"sts:SourceIdentity": StringOrSlice{"sentinel:specific:value"},
					},
				},
			},
			want: []string{"sentinel:*", "sentinel:specific:value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetSourceIdentityPatterns(tt.stmt)
			if len(got) != len(tt.want) {
				t.Errorf("GetSourceIdentityPatterns() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("GetSourceIdentityPatterns()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestEvaluateCondition(t *testing.T) {
	tests := []struct {
		name     string
		operator string
		pattern  string
		value    string
		want     bool
	}{
		// StringLike
		{
			name:     "StringLike match",
			operator: "StringLike",
			pattern:  "sentinel:*",
			value:    "sentinel:alice:abc",
			want:     true,
		},
		{
			name:     "StringLike no match",
			operator: "StringLike",
			pattern:  "sentinel:*",
			value:    "other:alice:abc",
			want:     false,
		},

		// StringNotLike
		{
			name:     "StringNotLike match",
			operator: "StringNotLike",
			pattern:  "sentinel:*",
			value:    "other:alice:abc",
			want:     true,
		},
		{
			name:     "StringNotLike no match",
			operator: "StringNotLike",
			pattern:  "sentinel:*",
			value:    "sentinel:alice:abc",
			want:     false,
		},

		// StringEquals
		{
			name:     "StringEquals match",
			operator: "StringEquals",
			pattern:  "sentinel:alice:abc",
			value:    "sentinel:alice:abc",
			want:     true,
		},
		{
			name:     "StringEquals no match",
			operator: "StringEquals",
			pattern:  "sentinel:alice:abc",
			value:    "sentinel:alice:xyz",
			want:     false,
		},

		// StringNotEquals
		{
			name:     "StringNotEquals match",
			operator: "StringNotEquals",
			pattern:  "sentinel:alice:abc",
			value:    "sentinel:alice:xyz",
			want:     true,
		},
		{
			name:     "StringNotEquals no match",
			operator: "StringNotEquals",
			pattern:  "sentinel:alice:abc",
			value:    "sentinel:alice:abc",
			want:     false,
		},

		// Unknown operator
		{
			name:     "unknown operator",
			operator: "Unknown",
			pattern:  "sentinel:*",
			value:    "sentinel:alice:abc",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateCondition(tt.operator, tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("EvaluateCondition(%q, %q, %q) = %v, want %v", tt.operator, tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestHasSentinelWildcardPattern(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		want     bool
	}{
		{
			name:     "empty patterns",
			patterns: nil,
			want:     false,
		},
		{
			name:     "has sentinel:*",
			patterns: []string{"sentinel:*"},
			want:     true,
		},
		{
			name:     "has sentinel:* among others",
			patterns: []string{"sentinel:alice:*", "sentinel:*", "other:*"},
			want:     true,
		},
		{
			name:     "user-specific only",
			patterns: []string{"sentinel:alice:*", "sentinel:bob:*"},
			want:     false,
		},
		{
			name:     "no sentinel patterns",
			patterns: []string{"other:*"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasSentinelWildcardPattern(tt.patterns)
			if got != tt.want {
				t.Errorf("HasSentinelWildcardPattern(%v) = %v, want %v", tt.patterns, got, tt.want)
			}
		})
	}
}

func TestIsSentinelPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{
			name:    "sentinel:*",
			pattern: "sentinel:*",
			want:    true,
		},
		{
			name:    "sentinel:alice:*",
			pattern: "sentinel:alice:*",
			want:    true,
		},
		{
			name:    "sentinel:alice:abc123",
			pattern: "sentinel:alice:abc123",
			want:    true,
		},
		{
			name:    "other:*",
			pattern: "other:*",
			want:    false,
		},
		{
			name:    "empty",
			pattern: "",
			want:    false,
		},
		{
			name:    "just sentinel",
			pattern: "sentinel",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSentinelPattern(tt.pattern)
			if got != tt.want {
				t.Errorf("IsSentinelPattern(%q) = %v, want %v", tt.pattern, got, tt.want)
			}
		})
	}
}
