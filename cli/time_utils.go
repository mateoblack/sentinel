package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDuration parses a duration string with support for days (d).
// Standard time.ParseDuration supports hours (h), minutes (m), seconds (s),
// milliseconds (ms), microseconds (us), and nanoseconds (ns), but not days.
// This function extends parsing to support days as well.
//
// Examples: "7d", "24h", "30m", "1d12h", "2d6h30m"
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// Handle days specially since time.ParseDuration doesn't support 'd'
	if strings.Contains(s, "d") {
		// Split on 'd' and convert days to hours
		parts := strings.SplitN(s, "d", 2)
		days, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		daysDuration := time.Duration(days) * 24 * time.Hour

		// If there's a remainder after 'd', parse it
		if len(parts) > 1 && parts[1] != "" {
			remainder, err := time.ParseDuration(parts[1])
			if err != nil {
				return 0, fmt.Errorf("invalid duration: %s", s)
			}
			return daysDuration + remainder, nil
		}
		return daysDuration, nil
	}

	// Standard duration parsing
	return time.ParseDuration(s)
}
