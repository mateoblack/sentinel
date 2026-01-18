package cli

import (
	"fmt"
	"io"
	"os"

	sentinelerrors "github.com/byteness/aws-vault/v7/errors"
)

// FormatErrorWithSuggestion writes error to stderr with suggestion if available.
// Returns the original error for chaining.
func FormatErrorWithSuggestion(err error) error {
	return FormatErrorWithSuggestionTo(os.Stderr, err)
}

// FormatErrorWithSuggestionTo writes to a specific writer (for testing).
// Returns the original error for chaining.
func FormatErrorWithSuggestionTo(w io.Writer, err error) error {
	if err == nil {
		return nil
	}

	sentErr, ok := sentinelerrors.IsSentinelError(err)
	if ok {
		fmt.Fprintf(w, "Error: %s\n", sentErr.Error())
		if suggestion := sentErr.Suggestion(); suggestion != "" {
			fmt.Fprintf(w, "\nSuggestion: %s\n", suggestion)
		}
		if ctx := sentErr.Context(); len(ctx) > 0 {
			fmt.Fprintf(w, "\nDetails:\n")
			for k, v := range ctx {
				fmt.Fprintf(w, "  %s: %s\n", k, v)
			}
		}
	} else {
		fmt.Fprintf(w, "Error: %v\n", err)
	}
	return err
}
