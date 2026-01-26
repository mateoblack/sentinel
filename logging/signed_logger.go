package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// SignedLogger wraps a Logger to automatically sign all log entries.
// It writes JSON Lines output where each line is a SignedEntry containing
// the original log entry with its cryptographic signature.
type SignedLogger struct {
	writer io.Writer
	config *SignatureConfig
}

// NewSignedLogger creates a SignedLogger with the given writer and config.
// The config must have a valid secret key (at least 32 bytes).
func NewSignedLogger(w io.Writer, config *SignatureConfig) *SignedLogger {
	return &SignedLogger{
		writer: w,
		config: config,
	}
}

// LogDecision signs and writes a decision log entry.
func (l *SignedLogger) LogDecision(entry DecisionLogEntry) {
	l.writeSignedEntry(entry)
}

// LogApproval signs and writes an approval log entry.
func (l *SignedLogger) LogApproval(entry ApprovalLogEntry) {
	l.writeSignedEntry(entry)
}

// LogBreakGlass signs and writes a break-glass log entry.
func (l *SignedLogger) LogBreakGlass(entry BreakGlassLogEntry) {
	l.writeSignedEntry(entry)
}

// writeSignedEntry creates a signed entry and writes it as JSON.
// On signing errors, it logs to stderr but doesn't fail (fail-open for availability).
func (l *SignedLogger) writeSignedEntry(entry any) {
	signed, err := NewSignedEntry(entry, l.config)
	if err != nil {
		// Fail-open: log error to stderr but continue
		// This matches the rate limiter pattern from Phase 116
		fmt.Fprintf(os.Stderr, "signing error: %v\n", err)
		// Still write the unsigned entry as fallback
		l.writeFallback(entry)
		return
	}

	data, err := json.Marshal(signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		return
	}

	l.writer.Write(data)
	l.writer.Write([]byte("\n"))
}

// writeFallback writes an unsigned entry when signing fails.
// This ensures audit logs are still captured even if signing is misconfigured.
func (l *SignedLogger) writeFallback(entry any) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.writer.Write(data)
	l.writer.Write([]byte("\n"))
}
