package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// hourFormatRegex matches HH:MM format (24-hour, two digits each)
var hourFormatRegex = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

// Validate checks if the Policy is semantically correct.
// It verifies version is present, at least one rule exists,
// and all rules are valid.
func (p *Policy) Validate() error {
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
func validateHourFormat(timeStr string) error {
	if !hourFormatRegex.MatchString(timeStr) {
		return fmt.Errorf("invalid hour format '%s'", timeStr)
	}

	// Parse and validate ranges
	matches := hourFormatRegex.FindStringSubmatch(timeStr)
	if matches == nil {
		return fmt.Errorf("invalid hour format '%s'", timeStr)
	}

	hour, _ := strconv.Atoi(matches[1])
	minute, _ := strconv.Atoi(matches[2])

	if hour < 0 || hour > 23 {
		return fmt.Errorf("invalid hour format '%s'", timeStr)
	}
	if minute < 0 || minute > 59 {
		return fmt.Errorf("invalid hour format '%s'", timeStr)
	}

	return nil
}
