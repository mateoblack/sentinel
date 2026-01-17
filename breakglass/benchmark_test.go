package breakglass

import (
	"testing"
	"time"
)

// Rate limit policy fixtures for benchmarks

// singleRulePolicy: 1 rule for all profiles
func singleRulePolicy() *RateLimitPolicy {
	return &RateLimitPolicy{
		Version: "1",
		Rules: []RateLimitRule{
			{
				Name:       "default-limits",
				Profiles:   []string{}, // Empty = wildcard (all profiles)
				Cooldown:   5 * time.Minute,
				MaxPerUser: 10,
				QuotaWindow: 24 * time.Hour,
			},
		},
	}
}

// multiRulePolicy: 10 rules with different profiles
func multiRulePolicy() *RateLimitPolicy {
	profiles := []string{"dev", "staging", "qa", "uat", "prod-ro", "prod-rw", "admin", "backup", "monitoring", "production"}
	rules := make([]RateLimitRule, 10)
	for i := 0; i < 10; i++ {
		rules[i] = RateLimitRule{
			Name:        "rule-" + profiles[i],
			Profiles:    []string{profiles[i]},
			Cooldown:    time.Duration(i+1) * time.Minute,
			MaxPerUser:  10 - i,
			QuotaWindow: 24 * time.Hour,
		}
	}
	return &RateLimitPolicy{Version: "1", Rules: rules}
}

// BenchmarkFindRateLimitRule_FirstMatch benchmarks immediate match (first rule matches)
func BenchmarkFindRateLimitRule_FirstMatch(b *testing.B) {
	policy := multiRulePolicy()
	profile := "dev" // First profile in list

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		FindRateLimitRule(policy, profile)
	}
}

// BenchmarkFindRateLimitRule_LastMatch benchmarks worst case (10 rules, match on last)
func BenchmarkFindRateLimitRule_LastMatch(b *testing.B) {
	policy := multiRulePolicy()
	profile := "production" // Last profile in list

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		FindRateLimitRule(policy, profile)
	}
}

// BenchmarkFindRateLimitRule_NoMatch benchmarks no matching rule
func BenchmarkFindRateLimitRule_NoMatch(b *testing.B) {
	policy := multiRulePolicy()
	profile := "nonexistent" // No matching rule

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		FindRateLimitRule(policy, profile)
	}
}

// BenchmarkFindRateLimitRule_Wildcard benchmarks wildcard rule (empty Profiles)
func BenchmarkFindRateLimitRule_Wildcard(b *testing.B) {
	policy := singleRulePolicy() // Uses wildcard rule
	profile := "any-profile"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		FindRateLimitRule(policy, profile)
	}
}

// BenchmarkContainsOrEmpty_Empty benchmarks empty slice (wildcard)
// Expected: immediate return true (len check)
func BenchmarkContainsOrEmpty_Empty(b *testing.B) {
	slice := []string{} // Empty = wildcard
	value := "anything"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		containsOrEmpty(slice, value)
	}
}

// BenchmarkContainsOrEmpty_Found benchmarks value found in slice (first position)
func BenchmarkContainsOrEmpty_Found(b *testing.B) {
	slice := []string{"production", "staging", "development"}
	value := "production" // First position

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		containsOrEmpty(slice, value)
	}
}

// BenchmarkContainsOrEmpty_FoundLast benchmarks value found at last position
func BenchmarkContainsOrEmpty_FoundLast(b *testing.B) {
	slice := []string{"production", "staging", "development"}
	value := "development" // Last position

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		containsOrEmpty(slice, value)
	}
}

// BenchmarkContainsOrEmpty_NotFound benchmarks value not in slice
func BenchmarkContainsOrEmpty_NotFound(b *testing.B) {
	slice := []string{"production", "staging", "development"}
	value := "nonexistent"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		containsOrEmpty(slice, value)
	}
}

// Sub-benchmarks using b.Run for table-driven approach
func BenchmarkFindRateLimitRule(b *testing.B) {
	multiPolicy := multiRulePolicy()
	singlePolicy := singleRulePolicy()

	b.Run("FirstMatch", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			FindRateLimitRule(multiPolicy, "dev")
		}
	})

	b.Run("MiddleMatch", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			FindRateLimitRule(multiPolicy, "prod-ro")
		}
	})

	b.Run("LastMatch", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			FindRateLimitRule(multiPolicy, "production")
		}
	})

	b.Run("NoMatch", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			FindRateLimitRule(multiPolicy, "nonexistent")
		}
	})

	b.Run("Wildcard", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			FindRateLimitRule(singlePolicy, "any-profile")
		}
	})

	b.Run("NilPolicy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			FindRateLimitRule(nil, "production")
		}
	})
}

func BenchmarkContainsOrEmpty(b *testing.B) {
	emptySlice := []string{}
	shortSlice := []string{"production", "staging", "development"}
	longSlice := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}

	b.Run("Empty", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			containsOrEmpty(emptySlice, "anything")
		}
	})

	b.Run("Found/First", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			containsOrEmpty(shortSlice, "production")
		}
	})

	b.Run("Found/Last", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			containsOrEmpty(shortSlice, "development")
		}
	})

	b.Run("NotFound/Short", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			containsOrEmpty(shortSlice, "nonexistent")
		}
	})

	b.Run("NotFound/Long", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			containsOrEmpty(longSlice, "nonexistent")
		}
	})
}

// BenchmarkRateLimitPolicy_Validate benchmarks policy validation
func BenchmarkRateLimitPolicy_Validate(b *testing.B) {
	policy := multiRulePolicy()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = policy.Validate()
	}
}

// BenchmarkRateLimitRule benchmarks table-driven rule operations
func BenchmarkRateLimitRule(b *testing.B) {
	multiPolicy := multiRulePolicy()

	b.Run("Validate/Single", func(b *testing.B) {
		rule := &multiPolicy.Rules[0]
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = rule.validate(0)
		}
	})

	b.Run("Validate/Policy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = multiPolicy.Validate()
		}
	})
}
