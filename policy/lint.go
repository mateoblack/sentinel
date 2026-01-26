// Package policy defines Sentinel's access control policy schema.
package policy

// LintIssueType categorizes the type of lint issue detected.
type LintIssueType string

const (
	// LintAllowBeforeDeny indicates an allow rule precedes a deny rule for the same profiles.
	LintAllowBeforeDeny LintIssueType = "allow-before-deny"
	// LintUnreachableRule indicates a rule that will never match due to a prior broader rule.
	LintUnreachableRule LintIssueType = "unreachable-rule"
	// LintOverlappingTimeWindows indicates rules with overlapping time windows and different effects.
	LintOverlappingTimeWindows LintIssueType = "overlapping-time-windows"
)

// LintIssue represents a potential problem detected in a policy.
type LintIssue struct {
	Type      LintIssueType // Type of issue detected
	RuleIndex int           // 0-indexed position of the problematic rule
	RuleName  string        // Name of the problematic rule
	Message   string        // Compiler-style terse description
}

// LintPolicy analyzes a policy for common mistakes and returns any issues found.
// It checks for:
// - Allow rules that precede deny rules for the same profiles
// - Unreachable rules shadowed by broader rules with the same effect
// - Overlapping time windows between rules with different effects
func LintPolicy(p *Policy) []LintIssue {
	var issues []LintIssue

	issues = append(issues, checkAllowBeforeDeny(p)...)
	issues = append(issues, checkUnreachableRules(p)...)
	issues = append(issues, checkOverlappingTimeWindows(p)...)

	return issues
}

// checkAllowBeforeDeny detects allow rules that precede deny rules for the same profiles.
// This is a common policy mistake because deny rules should typically come first.
func checkAllowBeforeDeny(p *Policy) []LintIssue {
	var issues []LintIssue

	for i, rule := range p.Rules {
		if rule.Effect != EffectAllow {
			continue
		}

		// Check subsequent rules for deny with overlapping profiles
		for j := i + 1; j < len(p.Rules); j++ {
			laterRule := p.Rules[j]
			if laterRule.Effect != EffectDeny {
				continue
			}

			// Check if profiles overlap
			if profilesOverlap(rule.Conditions.Profiles, laterRule.Conditions.Profiles) {
				issues = append(issues, LintIssue{
					Type:      LintAllowBeforeDeny,
					RuleIndex: i,
					RuleName:  rule.Name,
					Message:   "allow rule '" + rule.Name + "' at index " + itoa(i) + " precedes deny rule '" + laterRule.Name + "' for same profiles",
				})
				break // Only report once per allow rule
			}
		}
	}

	return issues
}

// checkUnreachableRules detects rules that will never match because a prior rule
// has less restrictive or equal conditions with the same effect.
func checkUnreachableRules(p *Policy) []LintIssue {
	var issues []LintIssue

	for i, rule := range p.Rules {
		// Check if any earlier rule shadows this one
		for j := 0; j < i; j++ {
			earlierRule := p.Rules[j]

			// Rules with different effects don't shadow each other
			if earlierRule.Effect != rule.Effect {
				continue
			}

			// Check if earlier rule is less restrictive (shadows this rule)
			if ruleShadows(earlierRule, rule) {
				issues = append(issues, LintIssue{
					Type:      LintUnreachableRule,
					RuleIndex: i,
					RuleName:  rule.Name,
					Message:   "rule '" + rule.Name + "' at index " + itoa(i) + " is unreachable (shadowed by rule '" + earlierRule.Name + "' at index " + itoa(j) + ")",
				})
				break // Only report once per unreachable rule
			}
		}
	}

	return issues
}

// checkOverlappingTimeWindows detects rules with overlapping time windows and different effects.
// This creates ambiguous behavior as to which rule should apply.
func checkOverlappingTimeWindows(p *Policy) []LintIssue {
	var issues []LintIssue

	for i, rule := range p.Rules {
		if rule.Conditions.Time == nil {
			continue
		}

		for j := i + 1; j < len(p.Rules); j++ {
			laterRule := p.Rules[j]
			if laterRule.Conditions.Time == nil {
				continue
			}

			// Only flag when effects differ (creates ambiguous behavior)
			if rule.Effect == laterRule.Effect {
				continue
			}

			// Check if profiles overlap (rules must apply to same profiles)
			if !profilesOverlap(rule.Conditions.Profiles, laterRule.Conditions.Profiles) {
				continue
			}

			// Check if time windows overlap
			if timeWindowsOverlap(rule.Conditions.Time, laterRule.Conditions.Time) {
				issues = append(issues, LintIssue{
					Type:      LintOverlappingTimeWindows,
					RuleIndex: i,
					RuleName:  rule.Name,
					Message:   "rules '" + rule.Name + "' and '" + laterRule.Name + "' have overlapping time windows with different effects",
				})
			}
		}
	}

	return issues
}

// profilesOverlap returns true if two profile lists have any overlap.
// An empty list is treated as a wildcard that matches anything.
func profilesOverlap(a, b []string) bool {
	// Empty list = wildcard, matches everything
	if len(a) == 0 || len(b) == 0 {
		return true
	}

	// Check for any common element
	for _, pa := range a {
		for _, pb := range b {
			if pa == pb {
				return true
			}
		}
	}

	return false
}

// ruleShadows returns true if earlierRule shadows laterRule.
// A rule shadows another if it has less restrictive or equal conditions.
// Less restrictive = empty list (wildcard) beats specific list.
func ruleShadows(earlierRule, laterRule Rule) bool {
	// Check users: empty users in earlier rule shadows any users in later rule
	if len(earlierRule.Conditions.Users) == 0 && len(laterRule.Conditions.Users) > 0 {
		// Earlier has wildcard users, later has specific users
		// Check if profiles also allow shadowing
		if profilesShadow(earlierRule.Conditions.Profiles, laterRule.Conditions.Profiles) {
			// Check time doesn't restrict the earlier rule
			if !timeRestrictsMore(earlierRule.Conditions.Time, laterRule.Conditions.Time) {
				return true
			}
		}
	}

	// Check profiles: empty profiles in earlier rule shadows any profiles in later rule
	if len(earlierRule.Conditions.Profiles) == 0 && len(laterRule.Conditions.Profiles) > 0 {
		// Earlier has wildcard profiles, later has specific profiles
		if usersShadow(earlierRule.Conditions.Users, laterRule.Conditions.Users) {
			if !timeRestrictsMore(earlierRule.Conditions.Time, laterRule.Conditions.Time) {
				return true
			}
		}
	}

	// Check if both users and profiles are wildcards in earlier rule
	if len(earlierRule.Conditions.Users) == 0 && len(earlierRule.Conditions.Profiles) == 0 {
		// Check if time condition in earlier rule doesn't restrict more
		if !timeRestrictsMore(earlierRule.Conditions.Time, laterRule.Conditions.Time) {
			return true
		}
	}

	return false
}

// profilesShadow returns true if earlier profiles would shadow later profiles.
// Empty (wildcard) shadows anything.
func profilesShadow(earlier, later []string) bool {
	if len(earlier) == 0 {
		return true // Wildcard shadows anything
	}
	// If earlier has specific profiles, it only shadows if later has same or subset
	return profilesOverlap(earlier, later)
}

// usersShadow returns true if earlier users would shadow later users.
// Empty (wildcard) shadows anything.
func usersShadow(earlier, later []string) bool {
	if len(earlier) == 0 {
		return true // Wildcard shadows anything
	}
	return usersOverlap(earlier, later)
}

// usersOverlap returns true if two user lists have any overlap.
// An empty list is treated as a wildcard that matches anything.
func usersOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, ua := range a {
		for _, ub := range b {
			if ua == ub {
				return true
			}
		}
	}
	return false
}

// timeRestrictsMore returns true if earlier time window is more restrictive than later.
// If earlier has a time restriction but later doesn't, earlier is more restrictive.
func timeRestrictsMore(earlier, later *TimeWindow) bool {
	if earlier == nil {
		return false // No time restriction in earlier
	}
	if later == nil {
		return true // Earlier has restriction, later doesn't
	}
	// Both have time restrictions - would need detailed analysis
	// For now, if both have restrictions, don't assume shadowing
	return false
}

// timeWindowsOverlap returns true if two time windows overlap.
// Overlap requires both overlapping days AND overlapping hours.
func timeWindowsOverlap(a, b *TimeWindow) bool {
	if a == nil || b == nil {
		return false
	}

	// Check if days overlap
	if !daysOverlap(a.Days, b.Days) {
		return false
	}

	// Check if hours overlap
	if a.Hours != nil && b.Hours != nil {
		return hoursOverlap(a.Hours, b.Hours)
	}

	// If either has no hour restriction, consider it all-day
	return true
}

// daysOverlap returns true if two weekday lists have any overlap.
// An empty list is treated as all days (wildcard).
func daysOverlap(a, b []Weekday) bool {
	if len(a) == 0 || len(b) == 0 {
		return true // Empty = all days
	}

	for _, da := range a {
		for _, db := range b {
			if da == db {
				return true
			}
		}
	}

	return false
}

// hoursOverlap returns true if two hour ranges overlap.
// Hour range overlap: max(start1, start2) < min(end1, end2)
func hoursOverlap(a, b *HourRange) bool {
	if a == nil || b == nil {
		return true // No restriction = all hours
	}

	// Parse start and end times as minutes since midnight
	aStart := parseTimeToMinutes(a.Start)
	aEnd := parseTimeToMinutes(a.End)
	bStart := parseTimeToMinutes(b.Start)
	bEnd := parseTimeToMinutes(b.End)

	// Calculate overlap
	maxStart := aStart
	if bStart > maxStart {
		maxStart = bStart
	}

	minEnd := aEnd
	if bEnd < minEnd {
		minEnd = bEnd
	}

	return maxStart < minEnd
}

// parseTimeToMinutes converts an HH:MM string to minutes since midnight.
// Assumes valid format (already validated by schema validation).
func parseTimeToMinutes(timeStr string) int {
	if len(timeStr) != 5 {
		return 0
	}
	hours := (int(timeStr[0]-'0') * 10) + int(timeStr[1]-'0')
	minutes := (int(timeStr[3]-'0') * 10) + int(timeStr[4]-'0')
	return hours*60 + minutes
}

// itoa converts an int to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
