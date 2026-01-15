package breakglass

import (
	"strings"
	"testing"
	"time"
)

// validBreakGlassEvent returns a fully valid BreakGlassEvent for testing.
// Tests can modify specific fields to test validation failures.
func validBreakGlassEvent() *BreakGlassEvent {
	now := time.Now()
	return &BreakGlassEvent{
		ID:            "abcdef1234567890",
		Invoker:       "alice",
		Profile:       "production",
		ReasonCode:    ReasonIncident,
		Justification: "Production incident requiring immediate database access to investigate data corruption",
		Duration:      time.Hour,
		Status:        StatusActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		ExpiresAt:     now.Add(DefaultBreakGlassTTL),
	}
}

func TestBreakGlassEventValidate_Valid(t *testing.T) {
	e := validBreakGlassEvent()
	if err := e.Validate(); err != nil {
		t.Errorf("Validate() returned error for valid event: %v", err)
	}
}

func TestBreakGlassEventValidate_EmptyID(t *testing.T) {
	e := validBreakGlassEvent()
	e.ID = ""
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for empty ID")
	}
	if !strings.Contains(err.Error(), "invalid break-glass ID") {
		t.Errorf("Validate() error = %q, should mention invalid break-glass ID", err)
	}
}

func TestBreakGlassEventValidate_InvalidID(t *testing.T) {
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
			e := validBreakGlassEvent()
			e.ID = tc.id
			err := e.Validate()
			if err == nil {
				t.Errorf("Validate() should fail for ID %q", tc.id)
			}
		})
	}
}

func TestBreakGlassEventValidate_EmptyInvoker(t *testing.T) {
	e := validBreakGlassEvent()
	e.Invoker = ""
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for empty invoker")
	}
	if !strings.Contains(err.Error(), "invoker") {
		t.Errorf("Validate() error = %q, should mention invoker", err)
	}
}

func TestBreakGlassEventValidate_EmptyProfile(t *testing.T) {
	e := validBreakGlassEvent()
	e.Profile = ""
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for empty profile")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("Validate() error = %q, should mention profile", err)
	}
}

func TestBreakGlassEventValidate_InvalidReasonCode(t *testing.T) {
	e := validBreakGlassEvent()
	e.ReasonCode = "invalid"
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for invalid reason code")
	}
	if !strings.Contains(err.Error(), "invalid reason code") {
		t.Errorf("Validate() error = %q, should mention invalid reason code", err)
	}
}

func TestBreakGlassEventValidate_JustificationTooShort(t *testing.T) {
	e := validBreakGlassEvent()
	e.Justification = "short"
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for justification too short")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("Validate() error = %q, should mention too short", err)
	}
}

func TestBreakGlassEventValidate_JustificationTooLong(t *testing.T) {
	e := validBreakGlassEvent()
	e.Justification = strings.Repeat("x", MaxJustificationLength+1)
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for justification too long")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("Validate() error = %q, should mention too long", err)
	}
}

func TestBreakGlassEventValidate_JustificationBoundary(t *testing.T) {
	// Exactly at minimum should pass
	t.Run("exactly minimum", func(t *testing.T) {
		e := validBreakGlassEvent()
		e.Justification = strings.Repeat("x", MinJustificationLength)
		if err := e.Validate(); err != nil {
			t.Errorf("Validate() should pass for justification at minimum: %v", err)
		}
	})

	// Exactly at maximum should pass
	t.Run("exactly maximum", func(t *testing.T) {
		e := validBreakGlassEvent()
		e.Justification = strings.Repeat("x", MaxJustificationLength)
		if err := e.Validate(); err != nil {
			t.Errorf("Validate() should pass for justification at maximum: %v", err)
		}
	})

	// One below minimum should fail
	t.Run("one below minimum", func(t *testing.T) {
		e := validBreakGlassEvent()
		e.Justification = strings.Repeat("x", MinJustificationLength-1)
		if err := e.Validate(); err == nil {
			t.Error("Validate() should fail for justification below minimum")
		}
	})

	// One above maximum should fail
	t.Run("one above maximum", func(t *testing.T) {
		e := validBreakGlassEvent()
		e.Justification = strings.Repeat("x", MaxJustificationLength+1)
		if err := e.Validate(); err == nil {
			t.Error("Validate() should fail for justification above maximum")
		}
	})
}

func TestBreakGlassEventValidate_InvalidStatus(t *testing.T) {
	e := validBreakGlassEvent()
	e.Status = "invalid"
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for invalid status")
	}
	if !strings.Contains(err.Error(), "invalid status") {
		t.Errorf("Validate() error = %q, should mention invalid status", err)
	}
}

func TestBreakGlassEventValidate_ZeroDuration(t *testing.T) {
	e := validBreakGlassEvent()
	e.Duration = 0
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for zero duration")
	}
	if !strings.Contains(err.Error(), "duration") && !strings.Contains(err.Error(), "positive") {
		t.Errorf("Validate() error = %q, should mention duration must be positive", err)
	}
}

func TestBreakGlassEventValidate_NegativeDuration(t *testing.T) {
	e := validBreakGlassEvent()
	e.Duration = -time.Hour
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for negative duration")
	}
	if !strings.Contains(err.Error(), "duration") && !strings.Contains(err.Error(), "positive") {
		t.Errorf("Validate() error = %q, should mention duration must be positive", err)
	}
}

func TestBreakGlassEventValidate_ExcessiveDuration(t *testing.T) {
	e := validBreakGlassEvent()
	e.Duration = MaxDuration + time.Minute
	err := e.Validate()
	if err == nil {
		t.Error("Validate() should fail for excessive duration")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("Validate() error = %q, should mention exceeds maximum", err)
	}
}

func TestBreakGlassEventValidate_DurationBoundary(t *testing.T) {
	// Exactly at maximum should pass
	t.Run("exactly maximum", func(t *testing.T) {
		e := validBreakGlassEvent()
		e.Duration = MaxDuration
		if err := e.Validate(); err != nil {
			t.Errorf("Validate() should pass for duration at maximum: %v", err)
		}
	})

	// One nanosecond above maximum should fail
	t.Run("one above maximum", func(t *testing.T) {
		e := validBreakGlassEvent()
		e.Duration = MaxDuration + time.Nanosecond
		if err := e.Validate(); err == nil {
			t.Error("Validate() should fail for duration above maximum")
		}
	})

	// Minimum positive should pass
	t.Run("minimum positive", func(t *testing.T) {
		e := validBreakGlassEvent()
		e.Duration = time.Nanosecond
		if err := e.Validate(); err != nil {
			t.Errorf("Validate() should pass for minimum positive duration: %v", err)
		}
	})
}

func TestBreakGlassEventValidate_ZeroTimestamps(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(*BreakGlassEvent)
		field string
	}{
		{
			name:  "zero created_at",
			setup: func(e *BreakGlassEvent) { e.CreatedAt = time.Time{} },
			field: "created_at",
		},
		{
			name:  "zero updated_at",
			setup: func(e *BreakGlassEvent) { e.UpdatedAt = time.Time{} },
			field: "updated_at",
		},
		{
			name:  "zero expires_at",
			setup: func(e *BreakGlassEvent) { e.ExpiresAt = time.Time{} },
			field: "expires_at",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := validBreakGlassEvent()
			tc.setup(e)
			err := e.Validate()
			if err == nil {
				t.Errorf("Validate() should fail for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("Validate() error = %q, should mention %s", err, tc.field)
			}
		})
	}
}

func TestCanTransitionTo_FromActive(t *testing.T) {
	testCases := []struct {
		name      string
		newStatus BreakGlassStatus
		allowed   bool
	}{
		{
			name:      "active to closed",
			newStatus: StatusClosed,
			allowed:   true,
		},
		{
			name:      "active to expired",
			newStatus: StatusExpired,
			allowed:   true,
		},
		{
			name:      "active to active (no-op)",
			newStatus: StatusActive,
			allowed:   false,
		},
		{
			name:      "active to invalid status",
			newStatus: "invalid",
			allowed:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := &BreakGlassEvent{Status: StatusActive}
			got := e.CanTransitionTo(tc.newStatus)
			if got != tc.allowed {
				t.Errorf("CanTransitionTo(%q) = %v, want %v", tc.newStatus, got, tc.allowed)
			}
		})
	}
}

func TestCanTransitionTo_FromTerminal(t *testing.T) {
	terminalStatuses := []BreakGlassStatus{
		StatusClosed,
		StatusExpired,
	}

	targetStatuses := []BreakGlassStatus{
		StatusActive,
		StatusClosed,
		StatusExpired,
	}

	for _, currentStatus := range terminalStatuses {
		for _, targetStatus := range targetStatuses {
			t.Run(string(currentStatus)+"_to_"+string(targetStatus), func(t *testing.T) {
				e := &BreakGlassEvent{Status: currentStatus}
				if e.CanTransitionTo(targetStatus) {
					t.Errorf("CanTransitionTo(%q) from terminal status %q should return false",
						targetStatus, currentStatus)
				}
			})
		}
	}
}

func TestCanTransitionTo_AllValidTransitions(t *testing.T) {
	// Exhaustive test of all valid state transitions
	// active is the only non-terminal state, so all valid transitions start from active
	e := &BreakGlassEvent{Status: StatusActive}

	// These transitions should all be allowed
	validTransitions := []BreakGlassStatus{
		StatusClosed,
		StatusExpired,
	}

	for _, target := range validTransitions {
		if !e.CanTransitionTo(target) {
			t.Errorf("active should be able to transition to %q", target)
		}
	}
}

func TestBreakGlassEventValidate_AllReasonCodes(t *testing.T) {
	validCodes := []ReasonCode{
		ReasonIncident,
		ReasonMaintenance,
		ReasonSecurity,
		ReasonRecovery,
		ReasonOther,
	}

	for _, code := range validCodes {
		t.Run(string(code), func(t *testing.T) {
			e := validBreakGlassEvent()
			e.ReasonCode = code
			if err := e.Validate(); err != nil {
				t.Errorf("Validate() should pass for reason code %q: %v", code, err)
			}
		})
	}
}

func TestBreakGlassEventValidate_AllStatuses(t *testing.T) {
	validStatuses := []BreakGlassStatus{
		StatusActive,
		StatusClosed,
		StatusExpired,
	}

	for _, status := range validStatuses {
		t.Run(string(status), func(t *testing.T) {
			e := validBreakGlassEvent()
			e.Status = status
			if err := e.Validate(); err != nil {
				t.Errorf("Validate() should pass for status %q: %v", status, err)
			}
		})
	}
}
