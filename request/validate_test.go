package request

import (
	"strings"
	"testing"
	"time"
)

// validRequest returns a fully valid Request for testing.
// Tests can modify specific fields to test validation failures.
func validRequest() *Request {
	now := time.Now()
	return &Request{
		ID:            "abcdef1234567890",
		Requester:     "alice",
		Profile:       "production",
		Justification: "Need access for deployment review",
		Duration:      time.Hour,
		Status:        StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultRequestTTL),
	}
}

func TestRequestValidate_Valid(t *testing.T) {
	r := validRequest()
	if err := r.Validate(); err != nil {
		t.Errorf("Validate() returned error for valid request: %v", err)
	}
}

func TestRequestValidate_EmptyID(t *testing.T) {
	r := validRequest()
	r.ID = ""
	err := r.Validate()
	if err == nil {
		t.Error("Validate() should fail for empty ID")
	}
	if !strings.Contains(err.Error(), "invalid request ID") {
		t.Errorf("Validate() error = %q, should mention invalid request ID", err)
	}
}

func TestRequestValidate_InvalidID(t *testing.T) {
	testCases := []struct {
		name string
		id   string
	}{
		{"too short", "abcdef12345678"},
		{"too long", "abcdef123456789012"},
		{"uppercase", "ABCDEF1234567890"},
		{"non-hex", "ghijkl1234567890"},
		{"wrong length (8 chars)", "abcdef12"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := validRequest()
			r.ID = tc.id
			err := r.Validate()
			if err == nil {
				t.Errorf("Validate() should fail for ID %q", tc.id)
			}
		})
	}
}

func TestRequestValidate_EmptyRequester(t *testing.T) {
	r := validRequest()
	r.Requester = ""
	err := r.Validate()
	if err == nil {
		t.Error("Validate() should fail for empty requester")
	}
	if !strings.Contains(err.Error(), "requester") {
		t.Errorf("Validate() error = %q, should mention requester", err)
	}
}

func TestRequestValidate_EmptyProfile(t *testing.T) {
	r := validRequest()
	r.Profile = ""
	err := r.Validate()
	if err == nil {
		t.Error("Validate() should fail for empty profile")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("Validate() error = %q, should mention profile", err)
	}
}

func TestRequestValidate_JustificationTooShort(t *testing.T) {
	r := validRequest()
	r.Justification = "short"
	err := r.Validate()
	if err == nil {
		t.Error("Validate() should fail for justification too short")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("Validate() error = %q, should mention too short", err)
	}
}

func TestRequestValidate_JustificationTooLong(t *testing.T) {
	r := validRequest()
	r.Justification = strings.Repeat("x", MaxJustificationLength+1)
	err := r.Validate()
	if err == nil {
		t.Error("Validate() should fail for justification too long")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("Validate() error = %q, should mention too long", err)
	}
}

func TestRequestValidate_JustificationBoundary(t *testing.T) {
	// Exactly at minimum should pass
	t.Run("exactly minimum", func(t *testing.T) {
		r := validRequest()
		r.Justification = strings.Repeat("x", MinJustificationLength)
		if err := r.Validate(); err != nil {
			t.Errorf("Validate() should pass for justification at minimum: %v", err)
		}
	})

	// Exactly at maximum should pass
	t.Run("exactly maximum", func(t *testing.T) {
		r := validRequest()
		r.Justification = strings.Repeat("x", MaxJustificationLength)
		if err := r.Validate(); err != nil {
			t.Errorf("Validate() should pass for justification at maximum: %v", err)
		}
	})

	// One below minimum should fail
	t.Run("one below minimum", func(t *testing.T) {
		r := validRequest()
		r.Justification = strings.Repeat("x", MinJustificationLength-1)
		if err := r.Validate(); err == nil {
			t.Error("Validate() should fail for justification below minimum")
		}
	})

	// One above maximum should fail
	t.Run("one above maximum", func(t *testing.T) {
		r := validRequest()
		r.Justification = strings.Repeat("x", MaxJustificationLength+1)
		if err := r.Validate(); err == nil {
			t.Error("Validate() should fail for justification above maximum")
		}
	})
}

func TestRequestValidate_InvalidStatus(t *testing.T) {
	r := validRequest()
	r.Status = "invalid"
	err := r.Validate()
	if err == nil {
		t.Error("Validate() should fail for invalid status")
	}
	if !strings.Contains(err.Error(), "invalid status") {
		t.Errorf("Validate() error = %q, should mention invalid status", err)
	}
}

func TestRequestValidate_ZeroDuration(t *testing.T) {
	r := validRequest()
	r.Duration = 0
	err := r.Validate()
	if err == nil {
		t.Error("Validate() should fail for zero duration")
	}
	if !strings.Contains(err.Error(), "duration") && !strings.Contains(err.Error(), "positive") {
		t.Errorf("Validate() error = %q, should mention duration must be positive", err)
	}
}

func TestRequestValidate_NegativeDuration(t *testing.T) {
	r := validRequest()
	r.Duration = -time.Hour
	err := r.Validate()
	if err == nil {
		t.Error("Validate() should fail for negative duration")
	}
	if !strings.Contains(err.Error(), "duration") && !strings.Contains(err.Error(), "positive") {
		t.Errorf("Validate() error = %q, should mention duration must be positive", err)
	}
}

func TestRequestValidate_ExcessiveDuration(t *testing.T) {
	r := validRequest()
	r.Duration = MaxDuration + time.Minute
	err := r.Validate()
	if err == nil {
		t.Error("Validate() should fail for excessive duration")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("Validate() error = %q, should mention exceeds maximum", err)
	}
}

func TestRequestValidate_DurationBoundary(t *testing.T) {
	// Exactly at maximum should pass
	t.Run("exactly maximum", func(t *testing.T) {
		r := validRequest()
		r.Duration = MaxDuration
		if err := r.Validate(); err != nil {
			t.Errorf("Validate() should pass for duration at maximum: %v", err)
		}
	})

	// One nanosecond above maximum should fail
	t.Run("one above maximum", func(t *testing.T) {
		r := validRequest()
		r.Duration = MaxDuration + time.Nanosecond
		if err := r.Validate(); err == nil {
			t.Error("Validate() should fail for duration above maximum")
		}
	})

	// Minimum positive should pass
	t.Run("minimum positive", func(t *testing.T) {
		r := validRequest()
		r.Duration = time.Nanosecond
		if err := r.Validate(); err != nil {
			t.Errorf("Validate() should pass for minimum positive duration: %v", err)
		}
	})
}

func TestRequestValidate_ZeroTimestamps(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(*Request)
		field string
	}{
		{
			name:  "zero created_at",
			setup: func(r *Request) { r.CreatedAt = time.Time{} },
			field: "created_at",
		},
		{
			name:  "zero updated_at",
			setup: func(r *Request) { r.UpdatedAt = time.Time{} },
			field: "updated_at",
		},
		{
			name:  "zero expires_at",
			setup: func(r *Request) { r.ExpiresAt = time.Time{} },
			field: "expires_at",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := validRequest()
			tc.setup(r)
			err := r.Validate()
			if err == nil {
				t.Errorf("Validate() should fail for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("Validate() error = %q, should mention %s", err, tc.field)
			}
		})
	}
}

func TestCanTransitionTo_FromPending(t *testing.T) {
	testCases := []struct {
		name      string
		newStatus RequestStatus
		allowed   bool
	}{
		{
			name:      "pending to approved",
			newStatus: StatusApproved,
			allowed:   true,
		},
		{
			name:      "pending to denied",
			newStatus: StatusDenied,
			allowed:   true,
		},
		{
			name:      "pending to expired",
			newStatus: StatusExpired,
			allowed:   true,
		},
		{
			name:      "pending to cancelled",
			newStatus: StatusCancelled,
			allowed:   true,
		},
		{
			name:      "pending to pending (no-op)",
			newStatus: StatusPending,
			allowed:   false,
		},
		{
			name:      "pending to invalid status",
			newStatus: "invalid",
			allowed:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Request{Status: StatusPending}
			got := r.CanTransitionTo(tc.newStatus)
			if got != tc.allowed {
				t.Errorf("CanTransitionTo(%q) = %v, want %v", tc.newStatus, got, tc.allowed)
			}
		})
	}
}

func TestCanTransitionTo_FromTerminal(t *testing.T) {
	terminalStatuses := []RequestStatus{
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	targetStatuses := []RequestStatus{
		StatusPending,
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	for _, currentStatus := range terminalStatuses {
		for _, targetStatus := range targetStatuses {
			t.Run(string(currentStatus)+"_to_"+string(targetStatus), func(t *testing.T) {
				r := &Request{Status: currentStatus}
				if r.CanTransitionTo(targetStatus) {
					t.Errorf("CanTransitionTo(%q) from terminal status %q should return false",
						targetStatus, currentStatus)
				}
			})
		}
	}
}

func TestCanTransitionTo_AllValidTransitions(t *testing.T) {
	// Exhaustive test of all valid state transitions
	// pending is the only non-terminal state, so all valid transitions start from pending
	r := &Request{Status: StatusPending}

	// These transitions should all be allowed
	validTransitions := []RequestStatus{
		StatusApproved,
		StatusDenied,
		StatusExpired,
		StatusCancelled,
	}

	for _, target := range validTransitions {
		if !r.CanTransitionTo(target) {
			t.Errorf("pending should be able to transition to %q", target)
		}
	}
}
