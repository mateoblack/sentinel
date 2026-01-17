package identity

import (
	"sync"
	"testing"
)

func TestNewRequestID_Format(t *testing.T) {
	id := NewRequestID()

	// Must be exactly 8 characters
	if len(id) != RequestIDLength {
		t.Errorf("NewRequestID() length = %d, want %d", len(id), RequestIDLength)
	}

	// Must be valid according to ValidateRequestID
	if !ValidateRequestID(id) {
		t.Errorf("NewRequestID() = %q is not valid", id)
	}

	// Must be lowercase hex
	for i, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("NewRequestID() char %d = %q is not lowercase hex", i, string(c))
		}
	}
}

func TestNewRequestID_Uniqueness(t *testing.T) {
	// Generate 1000 IDs and verify no collisions
	const count = 1000
	seen := make(map[string]bool, count)

	for i := 0; i < count; i++ {
		id := NewRequestID()
		if seen[id] {
			t.Errorf("collision detected: %q generated more than once in %d iterations", id, i+1)
			return
		}
		seen[id] = true
	}
}

func TestValidateRequestID(t *testing.T) {
	var testCases = []struct {
		name  string
		id    string
		valid bool
	}{
		{
			name:  "valid - all digits",
			id:    "12345678",
			valid: true,
		},
		{
			name:  "valid - all lowercase hex letters",
			id:    "abcdef12",
			valid: true,
		},
		{
			name:  "valid - mixed",
			id:    "a1b2c3d4",
			valid: true,
		},
		{
			name:  "valid - all zeros",
			id:    "00000000",
			valid: true,
		},
		{
			name:  "valid - deadbeef",
			id:    "deadbeef",
			valid: true,
		},
		{
			name:  "invalid - too short",
			id:    "1234567",
			valid: false,
		},
		{
			name:  "invalid - too long",
			id:    "123456789",
			valid: false,
		},
		{
			name:  "invalid - empty",
			id:    "",
			valid: false,
		},
		{
			name:  "invalid - uppercase",
			id:    "ABCDEF12",
			valid: false,
		},
		{
			name:  "invalid - mixed case",
			id:    "AbCdEf12",
			valid: false,
		},
		{
			name:  "invalid - non-hex letters",
			id:    "ghijklmn",
			valid: false,
		},
		{
			name:  "invalid - special characters",
			id:    "1234-567",
			valid: false,
		},
		{
			name:  "invalid - spaces",
			id:    "1234 567",
			valid: false,
		},
		{
			name:  "invalid - unicode",
			id:    "12345678\u00e9",
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateRequestID(tc.id)
			if got != tc.valid {
				t.Errorf("ValidateRequestID(%q) = %v, want %v", tc.id, got, tc.valid)
			}
		})
	}
}

func TestNewRequestID_MultipleCalls(t *testing.T) {
	// Verify multiple calls produce different results
	ids := make([]string, 10)
	for i := range ids {
		ids[i] = NewRequestID()
	}

	// Check all are unique
	seen := make(map[string]bool)
	for _, id := range ids {
		if seen[id] {
			t.Error("duplicate ID generated")
		}
		seen[id] = true
	}

	// Check all are valid
	for i, id := range ids {
		if !ValidateRequestID(id) {
			t.Errorf("id[%d] = %q is invalid", i, id)
		}
	}
}

// =============================================================================
// Entropy and Security Tests
// =============================================================================

// TestNewRequestID_EntropyDistribution tests character distribution across many IDs.
// This is an informal chi-squared style check to ensure no obvious bias.
func TestNewRequestID_EntropyDistribution(t *testing.T) {
	const sampleSize = 10000
	hexChars := "0123456789abcdef"

	// Count occurrences of each hex char at each position (8 positions)
	positionCounts := make([]map[rune]int, RequestIDLength)
	for i := range positionCounts {
		positionCounts[i] = make(map[rune]int)
	}

	// Generate samples
	for i := 0; i < sampleSize; i++ {
		id := NewRequestID()
		for pos, char := range id {
			positionCounts[pos][char]++
		}
	}

	// Expected count per character per position (uniform distribution)
	// 16 hex chars, sampleSize IDs, so expected ~sampleSize/16 per char
	expectedCount := float64(sampleSize) / 16.0
	// Allow 30% deviation (reasonable for statistical test)
	minAllowed := expectedCount * 0.7
	maxAllowed := expectedCount * 1.3

	t.Run("character distribution per position", func(t *testing.T) {
		for pos := 0; pos < RequestIDLength; pos++ {
			for _, char := range hexChars {
				count := positionCounts[pos][char]
				if float64(count) < minAllowed || float64(count) > maxAllowed {
					t.Errorf("Position %d, char %q: count %d outside expected range [%.0f, %.0f]",
						pos, string(char), count, minAllowed, maxAllowed)
				}
			}
		}
	})

	t.Run("all hex characters represented at each position", func(t *testing.T) {
		for pos := 0; pos < RequestIDLength; pos++ {
			for _, char := range hexChars {
				if positionCounts[pos][char] == 0 {
					t.Errorf("Position %d: hex char %q never appeared in %d samples", pos, string(char), sampleSize)
				}
			}
		}
	})
}

// TestNewRequestID_FallbackBehavior documents the fallback to "00000000" if crypto/rand fails.
// NOTE: This behavior is acceptable because crypto/rand failure indicates a catastrophic
// system failure (entropy exhaustion, broken random device, etc.). In such cases,
// returning a predictable value is better than panicking, and the calling code
// can check for "00000000" if needed. In practice, crypto/rand.Read never fails
// on properly configured systems.
func TestNewRequestID_FallbackBehavior(t *testing.T) {
	t.Run("document fallback behavior", func(t *testing.T) {
		// We cannot easily test the fallback path without mocking crypto/rand,
		// which would require restructuring the code. Instead, we document
		// the expected fallback value here.
		const expectedFallback = "00000000"

		// Verify the fallback value is itself valid
		if !ValidateRequestID(expectedFallback) {
			t.Errorf("fallback value %q is not valid", expectedFallback)
		}

		// The fallback "00000000" is:
		// - Valid per format rules (8 lowercase hex chars)
		// - Clearly identifiable as a fallback (all zeros)
		// - Won't cause parsing failures downstream
		t.Log("Fallback to '00000000' on crypto/rand failure is acceptable because:")
		t.Log("  - crypto/rand failure indicates catastrophic system failure")
		t.Log("  - Better to return valid format than panic")
		t.Log("  - Zeros are clearly identifiable if manual inspection needed")
	})
}

// TestNewRequestID_ConcurrencySafety tests that NewRequestID is safe for concurrent use.
func TestNewRequestID_ConcurrencySafety(t *testing.T) {
	const goroutines = 100
	const idsPerGoroutine = 10

	var wg sync.WaitGroup
	seen := sync.Map{}
	duplicateFound := false
	var duplicateMu sync.Mutex

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < idsPerGoroutine; i++ {
				id := NewRequestID()

				// Check for duplicate
				if _, loaded := seen.LoadOrStore(id, true); loaded {
					duplicateMu.Lock()
					duplicateFound = true
					duplicateMu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	if duplicateFound {
		t.Error("duplicate ID found during concurrent generation")
	}

	// Verify total count
	count := 0
	seen.Range(func(_, _ interface{}) bool {
		count++
		return true
	})

	expectedTotal := goroutines * idsPerGoroutine
	if count != expectedTotal {
		t.Errorf("generated %d unique IDs, expected %d", count, expectedTotal)
	}
}

// TestValidateRequestID_BoundaryTests tests edge cases for ValidateRequestID.
func TestValidateRequestID_BoundaryTests(t *testing.T) {
	t.Run("exactly 8 chars with non-hex at each position", func(t *testing.T) {
		// Valid base
		base := []byte("12345678")

		// Test non-hex at each position (0-7)
		for pos := 0; pos < RequestIDLength; pos++ {
			testID := make([]byte, RequestIDLength)
			copy(testID, base)
			testID[pos] = 'g' // non-hex letter

			if ValidateRequestID(string(testID)) {
				t.Errorf("Position %d: ID %q with non-hex char should be invalid", pos, string(testID))
			}
		}
	})

	t.Run("empty string explicitly rejected", func(t *testing.T) {
		if ValidateRequestID("") {
			t.Error("empty string should be invalid")
		}
	})

	t.Run("single character rejected", func(t *testing.T) {
		if ValidateRequestID("a") {
			t.Error("single character should be invalid")
		}
	})

	t.Run("7 character string rejected", func(t *testing.T) {
		if ValidateRequestID("1234567") {
			t.Error("7 chars should be invalid (need exactly 8)")
		}
	})

	t.Run("9 character string rejected", func(t *testing.T) {
		if ValidateRequestID("123456789") {
			t.Error("9 chars should be invalid (need exactly 8)")
		}
	})

	t.Run("uppercase hex rejected", func(t *testing.T) {
		// Test uppercase at each position
		for pos := 0; pos < RequestIDLength; pos++ {
			testID := []byte("abcdef12")
			testID[pos] = 'A' + byte(pos%6) // A-F

			if ValidateRequestID(string(testID)) {
				t.Errorf("ID %q with uppercase should be invalid", string(testID))
			}
		}
	})

	t.Run("all hex boundaries valid", func(t *testing.T) {
		// Test edge hex values
		validCases := []string{
			"00000000", // all zeros
			"ffffffff", // all f's
			"01234567", // sequential digits
			"abcdef01", // sequential letters + digits
		}

		for _, id := range validCases {
			if !ValidateRequestID(id) {
				t.Errorf("ID %q should be valid", id)
			}
		}
	})

	t.Run("invalid chars at boundaries", func(t *testing.T) {
		// Characters just outside valid range
		invalidCases := []struct {
			name string
			id   string
		}{
			{"char before 0", string([]byte{'/', '1', '2', '3', '4', '5', '6', '7'})}, // '/' is before '0'
			{"char after 9 before a", string([]byte{'1', '2', '3', '4', '5', '6', '7', ':'})}, // ':' is after '9'
			{"char after f", string([]byte{'1', '2', '3', '4', '5', '6', '7', 'g'})},  // 'g' is after 'f'
		}

		for _, tc := range invalidCases {
			t.Run(tc.name, func(t *testing.T) {
				if ValidateRequestID(tc.id) {
					t.Errorf("ID %q should be invalid", tc.id)
				}
			})
		}
	})
}
