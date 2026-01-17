package identity

import (
	"testing"
)

// BenchmarkNewRequestID benchmarks request ID generation (crypto/rand)
// Note: crypto/rand performance varies by OS due to underlying entropy sources.
// Expected allocations: 1 alloc for the byte slice (4 bytes)
func BenchmarkNewRequestID(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewRequestID()
	}
}

// BenchmarkValidateRequestID benchmarks regex validation of request IDs
// Expected allocations: 0 (regex is pre-compiled)
func BenchmarkValidateRequestID(b *testing.B) {
	// Valid request ID
	validID := "a1b2c3d4"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ValidateRequestID(validID)
	}
}

// BenchmarkValidateRequestID_Invalid benchmarks validation of invalid IDs
func BenchmarkValidateRequestID_Invalid(b *testing.B) {
	invalidID := "INVALID!"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ValidateRequestID(invalidID)
	}
}

// BenchmarkBuildSourceIdentity benchmarks SourceIdentity string building (Format method)
// Expected allocations: 1 (string concatenation result)
func BenchmarkBuildSourceIdentity(b *testing.B) {
	si := &SourceIdentity{
		User:      "alice",
		RequestID: "a1b2c3d4",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = si.Format()
	}
}

// BenchmarkParseSourceIdentity benchmarks SourceIdentity parsing
// Expected allocations: 2+ (split result, SourceIdentity struct)
func BenchmarkParseSourceIdentity(b *testing.B) {
	sourceIdentity := "sentinel:alice:a1b2c3d4"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(sourceIdentity)
	}
}

// BenchmarkParseSourceIdentity_Invalid benchmarks parsing of invalid strings
func BenchmarkParseSourceIdentity_Invalid(b *testing.B) {
	invalidSourceIdentity := "invalid:format"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(invalidSourceIdentity)
	}
}

// BenchmarkSanitizeUser benchmarks user string sanitization
// Expected allocations: 1 (strings.Builder result)
func BenchmarkSanitizeUser(b *testing.B) {
	// User with mixed alphanumeric and special characters
	user := "alice.smith@example.com"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = SanitizeUser(user)
	}
}

// BenchmarkSanitizeUser_Clean benchmarks sanitization of already clean usernames
func BenchmarkSanitizeUser_Clean(b *testing.B) {
	// Already clean alphanumeric username
	user := "alicesmith"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = SanitizeUser(user)
	}
}

// BenchmarkSanitizeUser_Long benchmarks sanitization with truncation
func BenchmarkSanitizeUser_Long(b *testing.B) {
	// Username that will be truncated to MaxUserLength (20)
	user := "verylongusernamethatwillbetruncated"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = SanitizeUser(user)
	}
}

// BenchmarkSourceIdentity_Validate benchmarks validation of SourceIdentity struct
func BenchmarkSourceIdentity_Validate(b *testing.B) {
	si := &SourceIdentity{
		User:      "alice",
		RequestID: "a1b2c3d4",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = si.Validate()
	}
}

// BenchmarkNew benchmarks creating a new SourceIdentity with validation
// Expected allocations: 1 (SourceIdentity struct)
func BenchmarkNew(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = New("alice", "a1b2c3d4")
	}
}

// Sub-benchmarks using b.Run for table-driven approach
func BenchmarkIdentity(b *testing.B) {
	b.Run("NewRequestID", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = NewRequestID()
		}
	})

	b.Run("ValidateRequestID/Valid", func(b *testing.B) {
		validID := "a1b2c3d4"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ValidateRequestID(validID)
		}
	})

	b.Run("ValidateRequestID/Invalid", func(b *testing.B) {
		invalidID := "INVALID!"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ValidateRequestID(invalidID)
		}
	})

	b.Run("Format", func(b *testing.B) {
		si := &SourceIdentity{User: "alice", RequestID: "a1b2c3d4"}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = si.Format()
		}
	})

	b.Run("Parse/Valid", func(b *testing.B) {
		source := "sentinel:alice:a1b2c3d4"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = Parse(source)
		}
	})

	b.Run("Parse/Invalid", func(b *testing.B) {
		source := "invalid:format"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = Parse(source)
		}
	})

	b.Run("SanitizeUser/Dirty", func(b *testing.B) {
		user := "alice.smith@example.com"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = SanitizeUser(user)
		}
	})

	b.Run("SanitizeUser/Clean", func(b *testing.B) {
		user := "alicesmith"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = SanitizeUser(user)
		}
	})

	b.Run("SanitizeUser/Long", func(b *testing.B) {
		user := "verylongusernamethatwillbetruncated"
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = SanitizeUser(user)
		}
	})

	b.Run("Validate", func(b *testing.B) {
		si := &SourceIdentity{User: "alice", RequestID: "a1b2c3d4"}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = si.Validate()
		}
	})

	b.Run("New", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = New("alice", "a1b2c3d4")
		}
	})
}
