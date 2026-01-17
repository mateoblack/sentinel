package policy

import (
	"context"
	"testing"
	"time"
)

// Policy fixtures for benchmarks

// smallPolicy: 1 rule with user/profile match
func smallPolicy() *Policy {
	return &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "allow-production",
				Effect: EffectAllow,
				Conditions: Condition{
					Users:    []string{"alice"},
					Profiles: []string{"production"},
				},
				Reason: "production access for alice",
			},
		},
	}
}

// mediumPolicy: 10 rules with conditions
func mediumPolicy() *Policy {
	rules := make([]Rule, 10)
	profiles := []string{"dev", "staging", "qa", "uat", "prod-ro", "prod-rw", "admin", "backup", "monitoring", "production"}
	users := []string{"user0", "user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8", "alice"}
	for i := 0; i < 10; i++ {
		rules[i] = Rule{
			Name:   "rule-" + profiles[i],
			Effect: EffectAllow,
			Conditions: Condition{
				Users:    []string{users[i]},
				Profiles: []string{profiles[i]},
			},
			Reason: "access for " + users[i],
		}
	}
	return &Policy{Version: "1", Rules: rules}
}

// largePolicy: 50 rules (stress test)
func largePolicy() *Policy {
	rules := make([]Rule, 50)
	for i := 0; i < 50; i++ {
		rules[i] = Rule{
			Name:   "rule-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Effect: EffectAllow,
			Conditions: Condition{
				Users:    []string{"user" + string(rune('0'+i%10))},
				Profiles: []string{"profile" + string(rune('0'+i%10))},
			},
			Reason: "access rule " + string(rune('0'+i)),
		}
	}
	return &Policy{Version: "1", Rules: rules}
}

// timeWindowPolicy: policy with time window constraints
func timeWindowPolicy() *Policy {
	return &Policy{
		Version: "1",
		Rules: []Rule{
			{
				Name:   "business-hours-only",
				Effect: EffectAllow,
				Conditions: Condition{
					Users:    []string{"alice"},
					Profiles: []string{"production"},
					Time: &TimeWindow{
						Days: []Weekday{Monday, Tuesday, Wednesday, Thursday, Friday},
						Hours: &HourRange{
							Start: "09:00",
							End:   "17:00",
						},
						Timezone: "America/New_York",
					},
				},
				Reason: "business hours access",
			},
		},
	}
}

// BenchmarkEvaluate_SimpleRule benchmarks single rule, direct match
func BenchmarkEvaluate_SimpleRule(b *testing.B) {
	policy := smallPolicy()
	// Use deterministic time: Tuesday, Jan 14, 2025 at 10:30 UTC
	fixedTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)
	req := &Request{
		User:    "alice",
		Profile: "production",
		Time:    fixedTime,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Evaluate(policy, req)
	}
}

// BenchmarkEvaluate_MultipleRules benchmarks 10 rules, match on last rule (worst case)
func BenchmarkEvaluate_MultipleRules(b *testing.B) {
	policy := mediumPolicy()
	// Use deterministic time
	fixedTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)
	// Request that matches last rule
	req := &Request{
		User:    "alice",
		Profile: "production",
		Time:    fixedTime,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Evaluate(policy, req)
	}
}

// BenchmarkEvaluate_TimeWindow benchmarks rule with time window constraint
func BenchmarkEvaluate_TimeWindow(b *testing.B) {
	policy := timeWindowPolicy()
	// Use deterministic time: Tuesday (weekday) at 10:30 EST (15:30 UTC)
	// This is within business hours in America/New_York
	fixedTime := time.Date(2025, time.January, 14, 15, 30, 0, 0, time.UTC)
	req := &Request{
		User:    "alice",
		Profile: "production",
		Time:    fixedTime,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Evaluate(policy, req)
	}
}

// BenchmarkEvaluate_NoMatch benchmarks default deny path (no matching rule)
func BenchmarkEvaluate_NoMatch(b *testing.B) {
	policy := mediumPolicy()
	// Use deterministic time
	fixedTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)
	// Request that matches no rules
	req := &Request{
		User:    "nonexistent",
		Profile: "nonexistent",
		Time:    fixedTime,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Evaluate(policy, req)
	}
}

// BenchmarkEvaluate_LargePolicy benchmarks 50 rules (stress test)
func BenchmarkEvaluate_LargePolicy(b *testing.B) {
	policy := largePolicy()
	// Use deterministic time
	fixedTime := time.Date(2025, time.January, 14, 10, 30, 0, 0, time.UTC)
	// Request that matches no rules (worst case traversal)
	req := &Request{
		User:    "nomatch",
		Profile: "nomatch",
		Time:    fixedTime,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Evaluate(policy, req)
	}
}

// mockLoader implements PolicyLoader for benchmark testing
type mockLoader struct {
	policy *Policy
}

func (m *mockLoader) Load(ctx context.Context, parameterName string) (*Policy, error) {
	return m.policy, nil
}

// BenchmarkCachedLoader_Hit benchmarks cache hit path (no underlying load)
func BenchmarkCachedLoader_Hit(b *testing.B) {
	underlying := &mockLoader{policy: smallPolicy()}
	cached := NewCachedLoader(underlying, 5*time.Minute)

	ctx := context.Background()
	// Prime the cache
	_, _ = cached.Load(ctx, "/sentinel/policy")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = cached.Load(ctx, "/sentinel/policy")
	}
}

// BenchmarkCachedLoader_Miss benchmarks cache miss path (fresh load)
// Note: This benchmarks the miss path by using unique keys each iteration
func BenchmarkCachedLoader_Miss(b *testing.B) {
	underlying := &mockLoader{policy: smallPolicy()}
	cached := NewCachedLoader(underlying, 5*time.Minute)

	ctx := context.Background()
	keys := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		// Generate unique keys to force cache misses
		keys[i] = "/sentinel/policy/" + string(rune('a'+i%26)) + string(rune('0'+i/100))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = cached.Load(ctx, keys[i])
	}
}

// Sub-benchmarks using b.Run for table-driven approach
func BenchmarkEvaluate(b *testing.B) {
	fixedTime := time.Date(2025, time.January, 14, 15, 30, 0, 0, time.UTC) // Tuesday 10:30 EST

	benchmarks := []struct {
		name    string
		policy  *Policy
		request *Request
	}{
		{
			name:   "SimpleRule",
			policy: smallPolicy(),
			request: &Request{
				User:    "alice",
				Profile: "production",
				Time:    fixedTime,
			},
		},
		{
			name:   "MultipleRules/FirstMatch",
			policy: mediumPolicy(),
			request: &Request{
				User:    "user0",
				Profile: "dev",
				Time:    fixedTime,
			},
		},
		{
			name:   "MultipleRules/LastMatch",
			policy: mediumPolicy(),
			request: &Request{
				User:    "alice",
				Profile: "production",
				Time:    fixedTime,
			},
		},
		{
			name:   "MultipleRules/NoMatch",
			policy: mediumPolicy(),
			request: &Request{
				User:    "nobody",
				Profile: "unknown",
				Time:    fixedTime,
			},
		},
		{
			name:   "TimeWindow/Match",
			policy: timeWindowPolicy(),
			request: &Request{
				User:    "alice",
				Profile: "production",
				Time:    fixedTime,
			},
		},
		{
			name:   "LargePolicy/NoMatch",
			policy: largePolicy(),
			request: &Request{
				User:    "nobody",
				Profile: "unknown",
				Time:    fixedTime,
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				Evaluate(bm.policy, bm.request)
			}
		})
	}
}

func BenchmarkCachedLoader(b *testing.B) {
	underlying := &mockLoader{policy: smallPolicy()}

	b.Run("Hit", func(b *testing.B) {
		cached := NewCachedLoader(underlying, 5*time.Minute)
		ctx := context.Background()
		// Prime the cache
		_, _ = cached.Load(ctx, "/sentinel/policy")

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = cached.Load(ctx, "/sentinel/policy")
		}
	})

	b.Run("Miss", func(b *testing.B) {
		// Create fresh cached loader for each benchmark run
		cached := NewCachedLoader(underlying, 5*time.Minute)
		ctx := context.Background()

		// Pre-generate unique keys to avoid allocation in hot path
		keys := make([]string, b.N)
		for i := 0; i < b.N; i++ {
			keys[i] = "/sentinel/policy/" + string(rune('a'+i%26)) + string(rune('0'+(i/26)%10))
		}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = cached.Load(ctx, keys[i])
		}
	})
}
