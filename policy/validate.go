package policy

import (
	"fmt"
	"io"
	"regexp"
	"time"
)

// hourFormatRegex matches HH:MM format (24-hour, two digits each)
var hourFormatRegex = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

// Validate checks if the Policy is semantically correct.
// It verifies version is present and valid, at least one rule exists,
// and all rules are valid.
func (p *Policy) Validate() error {
	// Validate version is supported
	if !p.Version.IsValid() {
		return fmt.Errorf("unsupported policy version '%s', supported versions: %v", p.Version, SupportedVersions)
	}

	if len(p.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}

	for i, rule := range p.Rules {
		if err := rule.validate(i); err != nil {
			return err
		}
	}

	return nil
}

// validate checks if a Rule is semantically correct.
// It verifies name is present, effect is valid, and conditions exist.
func (r *Rule) validate(index int) error {
	if r.Name == "" {
		return fmt.Errorf("rule at index %d missing name", index)
	}

	if !r.Effect.IsValid() {
		return fmt.Errorf("invalid effect '%s' in rule '%s'", r.Effect, r.Name)
	}

	if err := r.Conditions.validate(r.Name); err != nil {
		return err
	}

	return nil
}

// validate checks if a Condition has at least one matcher and validates nested structs.
func (c *Condition) validate(ruleName string) error {
	hasCondition := len(c.Profiles) > 0 || len(c.Users) > 0 || c.Time != nil

	if !hasCondition {
		return fmt.Errorf("rule '%s' has no conditions", ruleName)
	}

	if c.Time != nil {
		if err := c.Time.validate(ruleName); err != nil {
			return err
		}
	}

	return nil
}

// validate checks if a TimeWindow is semantically correct.
// It validates weekdays, timezone, and hour ranges.
func (t *TimeWindow) validate(ruleName string) error {
	for _, day := range t.Days {
		if !day.IsValid() {
			return fmt.Errorf("invalid weekday '%s' in rule '%s'", day, ruleName)
		}
	}

	if t.Timezone != "" {
		if _, err := time.LoadLocation(t.Timezone); err != nil {
			return fmt.Errorf("invalid timezone '%s'", t.Timezone)
		}
	}

	if t.Hours != nil {
		if err := t.Hours.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate checks if an HourRange has valid HH:MM format times.
// Both start and end must be in 24-hour format with two digits each.
func (h *HourRange) Validate() error {
	if err := validateHourFormat(h.Start); err != nil {
		return err
	}
	if err := validateHourFormat(h.End); err != nil {
		return err
	}
	return nil
}

// validateHourFormat checks if a time string is in valid HH:MM 24-hour format.
// The regex already validates hour (00-23) and minute (00-59) ranges.
func validateHourFormat(timeStr string) error {
	if !hourFormatRegex.MatchString(timeStr) {
		return fmt.Errorf("invalid hour format '%s'", timeStr)
	}
	return nil
}

// ValidatePolicy validates a policy from raw YAML bytes.
// Returns a detailed error if validation fails, nil if valid.
// This is the entry point for CLI validation commands.
func ValidatePolicy(data []byte) error {
	p, err := ParsePolicy(data)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}
	return nil
}

// ValidatePolicyFromReader validates a policy from an io.Reader.
// Convenient for validating files.
func ValidatePolicyFromReader(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read policy: %w", err)
	}
	return ValidatePolicy(data)
}
