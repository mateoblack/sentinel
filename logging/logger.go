// Package logging provides structured logging for access decisions.
// It defines a Logger interface and implementations for JSON output
// and no-op logging.
package logging

import (
	"encoding/json"
	"io"
)

// Logger defines the interface for logging access decisions and approval events.
type Logger interface {
	// LogDecision logs a decision entry.
	LogDecision(entry DecisionLogEntry)

	// LogApproval logs an approval workflow event.
	LogApproval(entry ApprovalLogEntry)
}

// JSONLogger implements Logger with JSON Lines output.
// Each entry is written as a single line of JSON suitable for log aggregation.
type JSONLogger struct {
	writer io.Writer
}

// NewJSONLogger creates a new JSONLogger that writes to the given writer.
func NewJSONLogger(w io.Writer) *JSONLogger {
	return &JSONLogger{writer: w}
}

// LogDecision writes the entry as a single line of JSON.
func (l *JSONLogger) LogDecision(entry DecisionLogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.writer.Write(data)
	l.writer.Write([]byte("\n"))
}

// LogApproval writes the approval entry as a single line of JSON.
func (l *JSONLogger) LogApproval(entry ApprovalLogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.writer.Write(data)
	l.writer.Write([]byte("\n"))
}

// NopLogger implements Logger but discards all entries.
// Useful for testing or when logging is disabled.
type NopLogger struct{}

// NewNopLogger creates a new NopLogger that discards all entries.
func NewNopLogger() *NopLogger {
	return &NopLogger{}
}

// LogDecision discards the entry.
func (l *NopLogger) LogDecision(entry DecisionLogEntry) {
	// Intentionally empty - discards all entries
}

// LogApproval discards the approval entry.
func (l *NopLogger) LogApproval(entry ApprovalLogEntry) {
	// Intentionally empty - discards all entries
}
