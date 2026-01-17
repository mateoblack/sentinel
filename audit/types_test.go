package audit

import (
	"testing"
	"time"
)

func TestParseSourceIdentity(t *testing.T) {
	tests := []struct {
		name           string
		sourceIdentity string
		wantUser       string
		wantRequestID  string
		wantIsSentinel bool
	}{
		{
			name:           "valid sentinel format",
			sourceIdentity: "sentinel:alice:a1b2c3d4",
			wantUser:       "alice",
			wantRequestID:  "a1b2c3d4",
			wantIsSentinel: true,
		},
		{
			name:           "valid sentinel with longer request-id",
			sourceIdentity: "sentinel:bob:deadbeef12345678",
			wantUser:       "bob",
			wantRequestID:  "deadbeef12345678",
			wantIsSentinel: true,
		},
		{
			name:           "valid sentinel with sanitized username",
			sourceIdentity: "sentinel:johndoeexample:abc123",
			wantUser:       "johndoeexample",
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		{
			name:           "empty string",
			sourceIdentity: "",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "non-sentinel format",
			sourceIdentity: "other:format:here",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel prefix only",
			sourceIdentity: "sentinel:",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel with user only",
			sourceIdentity: "sentinel:alice",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel with empty user",
			sourceIdentity: "sentinel::a1b2c3d4",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel with empty request-id",
			sourceIdentity: "sentinel:alice:",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "random string",
			sourceIdentity: "randomstring",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "similar prefix but not sentinel",
			sourceIdentity: "sentinelx:alice:abc",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel with multiple colons in request-id",
			sourceIdentity: "sentinel:alice:abc:def:ghi",
			wantUser:       "alice",
			wantRequestID:  "abc:def:ghi",
			wantIsSentinel: true,
		},
		// Security edge cases: prefix case sensitivity
		{
			name:           "wrong case - uppercase SENTINEL",
			sourceIdentity: "SENTINEL:alice:abc123",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "wrong case - mixed case Sentinel",
			sourceIdentity: "Sentinel:alice:abc123",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "wrong case - alternating sEnTiNeL",
			sourceIdentity: "sEnTiNeL:alice:abc123",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		// Security edge cases: prefix with whitespace
		{
			name:           "prefix with leading whitespace",
			sourceIdentity: " sentinel:alice:abc123",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "prefix with trailing whitespace after colon",
			sourceIdentity: "sentinel: alice:abc123",
			wantUser:       " alice",
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		// Security edge cases: similar-looking prefix attacks
		{
			name:           "similar prefix with zero-width space",
			sourceIdentity: "sentinel\u200B:alice:abc123",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "similar prefix with zero-width joiner",
			sourceIdentity: "sentinel\u200D:alice:abc123",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "similar prefix with soft hyphen",
			sourceIdentity: "sentinel\u00AD:alice:abc123",
			wantUser:       "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		// Request-ID extraction edge cases
		{
			name:           "very long request-id (100+ chars)",
			sourceIdentity: "sentinel:alice:abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567890123456789",
			wantUser:       "alice",
			wantRequestID:  "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567890123456789",
			wantIsSentinel: true,
		},
		{
			name:           "request-id with special characters",
			sourceIdentity: "sentinel:alice:abc!@#$%^&*()_+-={}[]|\\;'\"<>,.?/",
			wantUser:       "alice",
			wantRequestID:  "abc!@#$%^&*()_+-={}[]|\\;'\"<>,.?/",
			wantIsSentinel: true,
		},
		{
			name:           "request-id with only colons",
			sourceIdentity: "sentinel:alice::::",
			wantUser:       "alice",
			wantRequestID:  ":::",
			wantIsSentinel: true,
		},
		// User field security edge cases
		{
			name:           "user with only whitespace",
			sourceIdentity: "sentinel:   :abc123",
			wantUser:       "   ",
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		{
			name:           "user with null byte",
			sourceIdentity: "sentinel:alice\x00bob:abc123",
			wantUser:       "alice\x00bob",
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		{
			name:           "user with newline",
			sourceIdentity: "sentinel:alice\nbob:abc123",
			wantUser:       "alice\nbob",
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		// Format boundary tests
		{
			name:           "exactly 64 char SourceIdentity (AWS limit)",
			sourceIdentity: "sentinel:user123:abcdefghijklmnopqrstuvwxyz0123456789abcdef",
			wantUser:       "user123",
			wantRequestID:  "abcdefghijklmnopqrstuvwxyz0123456789abcdef",
			wantIsSentinel: true,
		},
		{
			name:           "beyond 64 char AWS limit (should still parse)",
			sourceIdentity: "sentinel:verylongusername:abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
			wantUser:       "verylongusername",
			wantRequestID:  "abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
			wantIsSentinel: true,
		},
		{
			name:           "minimal valid format",
			sourceIdentity: "sentinel:a:b",
			wantUser:       "a",
			wantRequestID:  "b",
			wantIsSentinel: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, gotRequestID, gotIsSentinel := ParseSourceIdentity(tt.sourceIdentity)

			if gotUser != tt.wantUser {
				t.Errorf("ParseSourceIdentity(%q) user = %q, want %q", tt.sourceIdentity, gotUser, tt.wantUser)
			}
			if gotRequestID != tt.wantRequestID {
				t.Errorf("ParseSourceIdentity(%q) requestID = %q, want %q", tt.sourceIdentity, gotRequestID, tt.wantRequestID)
			}
			if gotIsSentinel != tt.wantIsSentinel {
				t.Errorf("ParseSourceIdentity(%q) isSentinel = %v, want %v", tt.sourceIdentity, gotIsSentinel, tt.wantIsSentinel)
			}
		})
	}
}

func TestVerificationResult_HasIssues(t *testing.T) {
	tests := []struct {
		name   string
		result VerificationResult
		want   bool
	}{
		{
			name:   "no issues",
			result: VerificationResult{Issues: nil},
			want:   false,
		},
		{
			name:   "empty issues slice",
			result: VerificationResult{Issues: []SessionIssue{}},
			want:   false,
		},
		{
			name: "has issues",
			result: VerificationResult{
				Issues: []SessionIssue{
					{Severity: SeverityWarning, Type: IssueTypeMissingSourceIdentity, Message: "test"},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasIssues(); got != tt.want {
				t.Errorf("VerificationResult.HasIssues() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerificationResult_PassRate(t *testing.T) {
	tests := []struct {
		name   string
		result VerificationResult
		want   float64
	}{
		{
			name:   "no sessions - returns 100%",
			result: VerificationResult{TotalSessions: 0, SentinelSessions: 0},
			want:   100.0,
		},
		{
			name:   "all sentinel sessions",
			result: VerificationResult{TotalSessions: 10, SentinelSessions: 10},
			want:   100.0,
		},
		{
			name:   "no sentinel sessions",
			result: VerificationResult{TotalSessions: 10, SentinelSessions: 0},
			want:   0.0,
		},
		{
			name:   "half sentinel sessions",
			result: VerificationResult{TotalSessions: 10, SentinelSessions: 5},
			want:   50.0,
		},
		{
			name:   "75% sentinel sessions",
			result: VerificationResult{TotalSessions: 100, SentinelSessions: 75},
			want:   75.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.result.PassRate()
			// Use tolerance for floating point comparison
			if got < tt.want-0.01 || got > tt.want+0.01 {
				t.Errorf("VerificationResult.PassRate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIssueSeverity_IsValid(t *testing.T) {
	tests := []struct {
		severity IssueSeverity
		want     bool
	}{
		{SeverityWarning, true},
		{SeverityError, true},
		{IssueSeverity("unknown"), false},
		{IssueSeverity(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if got := tt.severity.IsValid(); got != tt.want {
				t.Errorf("IssueSeverity(%q).IsValid() = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

func TestIssueSeverity_String(t *testing.T) {
	if got := SeverityWarning.String(); got != "warning" {
		t.Errorf("SeverityWarning.String() = %q, want %q", got, "warning")
	}
	if got := SeverityError.String(); got != "error" {
		t.Errorf("SeverityError.String() = %q, want %q", got, "error")
	}
}

func TestIssueType_IsValid(t *testing.T) {
	tests := []struct {
		issueType IssueType
		want      bool
	}{
		{IssueTypeMissingSourceIdentity, true},
		{IssueTypeBypassDetected, true},
		{IssueTypeUnexpectedSourceIdentity, true},
		{IssueType("unknown"), false},
		{IssueType(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.issueType), func(t *testing.T) {
			if got := tt.issueType.IsValid(); got != tt.want {
				t.Errorf("IssueType(%q).IsValid() = %v, want %v", tt.issueType, got, tt.want)
			}
		})
	}
}

func TestIssueType_String(t *testing.T) {
	if got := IssueTypeMissingSourceIdentity.String(); got != "missing_source_identity" {
		t.Errorf("IssueTypeMissingSourceIdentity.String() = %q, want %q", got, "missing_source_identity")
	}
	if got := IssueTypeBypassDetected.String(); got != "bypass_detected" {
		t.Errorf("IssueTypeBypassDetected.String() = %q, want %q", got, "bypass_detected")
	}
	if got := IssueTypeUnexpectedSourceIdentity.String(); got != "unexpected_source_identity" {
		t.Errorf("IssueTypeUnexpectedSourceIdentity.String() = %q, want %q", got, "unexpected_source_identity")
	}
}

func TestSessionInfo_Fields(t *testing.T) {
	// Test that SessionInfo can be constructed and fields accessed
	now := time.Now()
	info := SessionInfo{
		SourceIdentity: "sentinel:alice:abc123",
		EventTime:      now,
		EventID:        "event-123",
		EventName:      "AssumeRole",
		EventSource:    "sts.amazonaws.com",
		RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
		Username:       "alice",
		IsSentinel:     true,
		User:           "alice",
		RequestID:      "abc123",
	}

	if info.SourceIdentity != "sentinel:alice:abc123" {
		t.Errorf("SessionInfo.SourceIdentity = %q, want %q", info.SourceIdentity, "sentinel:alice:abc123")
	}
	if info.EventName != "AssumeRole" {
		t.Errorf("SessionInfo.EventName = %q, want %q", info.EventName, "AssumeRole")
	}
	if !info.IsSentinel {
		t.Error("SessionInfo.IsSentinel = false, want true")
	}
}

func TestVerifyInput_Fields(t *testing.T) {
	// Test that VerifyInput can be constructed and fields accessed
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now()
	input := VerifyInput{
		StartTime: start,
		EndTime:   end,
		RoleARN:   "arn:aws:iam::123456789012:role/TestRole",
		Username:  "alice",
	}

	if !input.StartTime.Equal(start) {
		t.Errorf("VerifyInput.StartTime = %v, want %v", input.StartTime, start)
	}
	if input.RoleARN != "arn:aws:iam::123456789012:role/TestRole" {
		t.Errorf("VerifyInput.RoleARN = %q, want %q", input.RoleARN, "arn:aws:iam::123456789012:role/TestRole")
	}
}
