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
		wantApprovalID string
		wantRequestID  string
		wantIsSentinel bool
	}{
		// New 4-part format tests
		{
			name:           "valid new format - direct access",
			sourceIdentity: "sentinel:alice:direct:a1b2c3d4",
			wantUser:       "alice",
			wantApprovalID: "",
			wantRequestID:  "a1b2c3d4",
			wantIsSentinel: true,
		},
		{
			name:           "valid new format - with approval ID",
			sourceIdentity: "sentinel:alice:abcd1234:a1b2c3d4",
			wantUser:       "alice",
			wantApprovalID: "abcd1234",
			wantRequestID:  "a1b2c3d4",
			wantIsSentinel: true,
		},
		{
			name:           "valid new format - sanitized username with approval",
			sourceIdentity: "sentinel:johndoeexample:deadbeef:abc12345",
			wantUser:       "johndoeexample",
			wantApprovalID: "deadbeef",
			wantRequestID:  "abc12345",
			wantIsSentinel: true,
		},
		// Legacy 3-part format tests (backward compatibility)
		{
			name:           "valid legacy format",
			sourceIdentity: "sentinel:alice:a1b2c3d4",
			wantUser:       "alice",
			wantApprovalID: "",
			wantRequestID:  "a1b2c3d4",
			wantIsSentinel: true,
		},
		{
			name:           "valid legacy format with longer request-id",
			sourceIdentity: "sentinel:bob:deadbeef12345678",
			wantUser:       "bob",
			wantApprovalID: "",
			wantRequestID:  "deadbeef12345678",
			wantIsSentinel: true,
		},
		{
			name:           "valid legacy format with sanitized username",
			sourceIdentity: "sentinel:johndoeexample:abc123",
			wantUser:       "johndoeexample",
			wantApprovalID: "",
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		// Invalid format tests
		{
			name:           "empty string",
			sourceIdentity: "",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "non-sentinel format",
			sourceIdentity: "other:format:here",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel prefix only",
			sourceIdentity: "sentinel:",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel with user only",
			sourceIdentity: "sentinel:alice",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel with empty user in legacy format",
			sourceIdentity: "sentinel::a1b2c3d4",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel with empty user in new format",
			sourceIdentity: "sentinel::direct:a1b2c3d4",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel with empty request-id in legacy format",
			sourceIdentity: "sentinel:alice:",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "sentinel with empty request-id in new format",
			sourceIdentity: "sentinel:alice:direct:",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "random string",
			sourceIdentity: "randomstring",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "similar prefix but not sentinel",
			sourceIdentity: "sentinelx:alice:abc",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "too many parts (5 parts)",
			sourceIdentity: "sentinel:alice:direct:a1b2c3d4:extra",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		// Security edge cases: prefix case sensitivity
		{
			name:           "wrong case - uppercase SENTINEL",
			sourceIdentity: "SENTINEL:alice:direct:abc123",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "wrong case - mixed case Sentinel",
			sourceIdentity: "Sentinel:alice:direct:abc123",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "wrong case - alternating sEnTiNeL",
			sourceIdentity: "sEnTiNeL:alice:direct:abc123",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		// Security edge cases: prefix with whitespace
		{
			name:           "prefix with leading whitespace",
			sourceIdentity: " sentinel:alice:direct:abc123",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "prefix with trailing whitespace after colon",
			sourceIdentity: "sentinel: alice:direct:abc123",
			wantUser:       " alice",
			wantApprovalID: "", // "direct" marker is converted to empty string
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		// Security edge cases: similar-looking prefix attacks
		{
			name:           "similar prefix with zero-width space",
			sourceIdentity: "sentinel\u200B:alice:direct:abc123",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "similar prefix with zero-width joiner",
			sourceIdentity: "sentinel\u200D:alice:direct:abc123",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		{
			name:           "similar prefix with soft hyphen",
			sourceIdentity: "sentinel\u00AD:alice:direct:abc123",
			wantUser:       "",
			wantApprovalID: "",
			wantRequestID:  "",
			wantIsSentinel: false,
		},
		// User field security edge cases - new format
		{
			name:           "user with only whitespace - new format",
			sourceIdentity: "sentinel:   :direct:abc123",
			wantUser:       "   ",
			wantApprovalID: "",
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		{
			name:           "user with null byte - new format",
			sourceIdentity: "sentinel:alice\x00bob:direct:abc123",
			wantUser:       "alice\x00bob",
			wantApprovalID: "",
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		{
			name:           "user with newline - new format",
			sourceIdentity: "sentinel:alice\nbob:direct:abc123",
			wantUser:       "alice\nbob",
			wantApprovalID: "",
			wantRequestID:  "abc123",
			wantIsSentinel: true,
		},
		// Approval ID extraction tests
		{
			name:           "approval ID with non-direct marker",
			sourceIdentity: "sentinel:alice:12345678:a1b2c3d4",
			wantUser:       "alice",
			wantApprovalID: "12345678",
			wantRequestID:  "a1b2c3d4",
			wantIsSentinel: true,
		},
		{
			name:           "approval ID case sensitivity - direct must be lowercase",
			sourceIdentity: "sentinel:alice:DIRECT:a1b2c3d4",
			wantUser:       "alice",
			wantApprovalID: "DIRECT",
			wantRequestID:  "a1b2c3d4",
			wantIsSentinel: true,
		},
		// Format boundary tests - new format
		{
			name:           "max length new format (47 chars with approval)",
			sourceIdentity: "sentinel:abcdefghij0123456789:deadbeef:12345678",
			wantUser:       "abcdefghij0123456789",
			wantApprovalID: "deadbeef",
			wantRequestID:  "12345678",
			wantIsSentinel: true,
		},
		{
			name:           "minimal valid new format",
			sourceIdentity: "sentinel:a:direct:b",
			wantUser:       "a",
			wantApprovalID: "",
			wantRequestID:  "b",
			wantIsSentinel: true,
		},
		{
			name:           "minimal valid legacy format",
			sourceIdentity: "sentinel:a:b",
			wantUser:       "a",
			wantApprovalID: "",
			wantRequestID:  "b",
			wantIsSentinel: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUser, gotApprovalID, gotRequestID, gotIsSentinel := ParseSourceIdentity(tt.sourceIdentity)

			if gotUser != tt.wantUser {
				t.Errorf("ParseSourceIdentity(%q) user = %q, want %q", tt.sourceIdentity, gotUser, tt.wantUser)
			}
			if gotApprovalID != tt.wantApprovalID {
				t.Errorf("ParseSourceIdentity(%q) approvalID = %q, want %q", tt.sourceIdentity, gotApprovalID, tt.wantApprovalID)
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
	// Test that SessionInfo can be constructed and fields accessed - new format
	now := time.Now()
	info := SessionInfo{
		SourceIdentity: "sentinel:alice:abcd1234:abc12345",
		EventTime:      now,
		EventID:        "event-123",
		EventName:      "AssumeRole",
		EventSource:    "sts.amazonaws.com",
		RoleARN:        "arn:aws:iam::123456789012:role/TestRole",
		Username:       "alice",
		IsSentinel:     true,
		User:           "alice",
		ApprovalID:     "abcd1234",
		RequestID:      "abc12345",
	}

	if info.SourceIdentity != "sentinel:alice:abcd1234:abc12345" {
		t.Errorf("SessionInfo.SourceIdentity = %q, want %q", info.SourceIdentity, "sentinel:alice:abcd1234:abc12345")
	}
	if info.EventName != "AssumeRole" {
		t.Errorf("SessionInfo.EventName = %q, want %q", info.EventName, "AssumeRole")
	}
	if !info.IsSentinel {
		t.Error("SessionInfo.IsSentinel = false, want true")
	}
	if info.ApprovalID != "abcd1234" {
		t.Errorf("SessionInfo.ApprovalID = %q, want %q", info.ApprovalID, "abcd1234")
	}

	// Test with direct access (no approval)
	infoNoApproval := SessionInfo{
		SourceIdentity: "sentinel:alice:direct:abc12345",
		IsSentinel:     true,
		User:           "alice",
		ApprovalID:     "",
		RequestID:      "abc12345",
	}

	if infoNoApproval.ApprovalID != "" {
		t.Errorf("SessionInfo.ApprovalID for direct access = %q, want empty", infoNoApproval.ApprovalID)
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

// PassRate edge cases

func TestVerificationResult_PassRate_EdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result VerificationResult
		want   float64
		delta  float64 // tolerance for floating point comparison
	}{
		{
			name:   "1 total, 0 sentinel = 0%",
			result: VerificationResult{TotalSessions: 1, SentinelSessions: 0},
			want:   0.0,
			delta:  0.001,
		},
		{
			name:   "1 total, 1 sentinel = 100%",
			result: VerificationResult{TotalSessions: 1, SentinelSessions: 1},
			want:   100.0,
			delta:  0.001,
		},
		{
			name:   "large numbers - 1,000,000 sessions",
			result: VerificationResult{TotalSessions: 1000000, SentinelSessions: 750000},
			want:   75.0,
			delta:  0.001,
		},
		{
			name:   "floating point precision - 1/3 sessions",
			result: VerificationResult{TotalSessions: 3, SentinelSessions: 1},
			want:   33.333333,
			delta:  0.001,
		},
		{
			name:   "floating point precision - 2/3 sessions",
			result: VerificationResult{TotalSessions: 3, SentinelSessions: 2},
			want:   66.666666,
			delta:  0.001,
		},
		{
			name:   "very small percentage - 1/1000000",
			result: VerificationResult{TotalSessions: 1000000, SentinelSessions: 1},
			want:   0.0001,
			delta:  0.00001,
		},
		{
			name:   "almost 100% - 999999/1000000",
			result: VerificationResult{TotalSessions: 1000000, SentinelSessions: 999999},
			want:   99.9999,
			delta:  0.0001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.result.PassRate()
			if got < tt.want-tt.delta || got > tt.want+tt.delta {
				t.Errorf("PassRate() = %v, want %v (delta %v)", got, tt.want, tt.delta)
			}
		})
	}
}

// HasIssues consistency tests

func TestVerificationResult_HasIssues_Consistency(t *testing.T) {
	t.Parallel()
	t.Run("adding issue changes HasIssues from false to true", func(t *testing.T) {
		t.Parallel()
		result := VerificationResult{}
		if result.HasIssues() {
			t.Error("HasIssues() = true before adding issues, want false")
		}

		result.Issues = append(result.Issues, SessionIssue{
			Severity: SeverityWarning,
			Type:     IssueTypeMissingSourceIdentity,
			Message:  "test issue",
		})

		if !result.HasIssues() {
			t.Error("HasIssues() = false after adding issue, want true")
		}
	})

	t.Run("multiple issues still returns true", func(t *testing.T) {
		t.Parallel()
		result := VerificationResult{
			Issues: []SessionIssue{
				{Severity: SeverityWarning, Type: IssueTypeMissingSourceIdentity, Message: "issue 1"},
				{Severity: SeverityWarning, Type: IssueTypeMissingSourceIdentity, Message: "issue 2"},
				{Severity: SeverityError, Type: IssueTypeBypassDetected, Message: "issue 3"},
			},
		}

		if !result.HasIssues() {
			t.Error("HasIssues() = false with multiple issues, want true")
		}
	})
}

// Type validation tests

func TestIssueSeverity_IsValid_EdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		severity IssueSeverity
		want     bool
	}{
		{
			name:     "empty string is invalid",
			severity: IssueSeverity(""),
			want:     false,
		},
		{
			name:     "whitespace is invalid",
			severity: IssueSeverity(" "),
			want:     false,
		},
		{
			name:     "uppercase WARNING is invalid",
			severity: IssueSeverity("WARNING"),
			want:     false,
		},
		{
			name:     "uppercase ERROR is invalid",
			severity: IssueSeverity("ERROR"),
			want:     false,
		},
		{
			name:     "mixed case is invalid",
			severity: IssueSeverity("Warning"),
			want:     false,
		},
		{
			name:     "unknown type is invalid",
			severity: IssueSeverity("critical"),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.severity.IsValid(); got != tt.want {
				t.Errorf("IssueSeverity(%q).IsValid() = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

func TestIssueType_IsValid_EdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		issueType IssueType
		want      bool
	}{
		{
			name:      "empty string is invalid",
			issueType: IssueType(""),
			want:      false,
		},
		{
			name:      "whitespace is invalid",
			issueType: IssueType(" "),
			want:      false,
		},
		{
			name:      "partial match is invalid",
			issueType: IssueType("missing"),
			want:      false,
		},
		{
			name:      "uppercase is invalid",
			issueType: IssueType("MISSING_SOURCE_IDENTITY"),
			want:      false,
		},
		{
			name:      "unknown type is invalid",
			issueType: IssueType("unknown_issue_type"),
			want:      false,
		},
		{
			name:      "similar but wrong is invalid",
			issueType: IssueType("missing_sourceIdentity"),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.issueType.IsValid(); got != tt.want {
				t.Errorf("IssueType(%q).IsValid() = %v, want %v", tt.issueType, got, tt.want)
			}
		})
	}
}

// SessionIssue with nil SessionInfo test

func TestSessionIssue_NilSessionInfo(t *testing.T) {
	t.Parallel()
	// SessionIssue with nil SessionInfo should be valid
	issue := SessionIssue{
		Severity:    SeverityWarning,
		Type:        IssueTypeMissingSourceIdentity,
		SessionInfo: nil, // explicitly nil
		Message:     "test issue without session info",
	}

	// Should not panic when accessing fields
	if issue.SessionInfo != nil {
		t.Error("SessionInfo should be nil")
	}
	if !issue.Severity.IsValid() {
		t.Error("Severity should be valid")
	}
	if !issue.Type.IsValid() {
		t.Error("Type should be valid")
	}
}
