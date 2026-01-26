package cli

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/logging"
)

// ConfigureAuditVerifyLogsCommand sets up the audit verify-logs command.
func ConfigureAuditVerifyLogsCommand(app *kingpin.Application, s *Sentinel) {
	// Get or create the audit command (might already exist from other audit commands)
	auditCmd := app.GetCommand("audit")
	if auditCmd == nil {
		auditCmd = app.Command("audit", "Audit and verification commands")
	}

	var file, keyHex, keyFile string

	cmd := auditCmd.Command("verify-logs", "Verify HMAC signatures in audit log files")

	cmd.Arg("file", "Path to log file (use - for stdin)").
		Required().
		StringVar(&file)

	cmd.Flag("key", "Hex-encoded HMAC key (64 chars for 32 bytes)").
		StringVar(&keyHex)

	cmd.Flag("key-file", "Path to file containing hex-encoded key").
		StringVar(&keyFile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := AuditVerifyLogsCommand(file, keyHex, keyFile)
		if err != nil {
			if strings.Contains(err.Error(), "verification failed") {
				os.Exit(1)
			}
			app.FatalIfError(err, "audit verify-logs")
		}
		return nil
	})
}

// AuditVerifyLogsInput contains the input for the audit verify-logs command.
type AuditVerifyLogsInput struct {
	// File is the path to the log file to verify (use "-" for stdin)
	File string
	// Key is the hex-encoded HMAC key (64 chars for 32 bytes)
	Key string
	// KeyFile is the path to a file containing the hex-encoded key
	KeyFile string
}

// VerifyLogsResult contains the results of log verification.
type VerifyLogsResult struct {
	FilePath    string             `json:"file_path"`
	TotalLines  int                `json:"total_lines"`
	VerifiedOK  int                `json:"verified_ok"`
	InvalidSig  int                `json:"invalid_sig"`
	ParseErrors int                `json:"parse_errors"`
	Failures    []VerifyLogFailure `json:"failures,omitempty"`
}

// VerifyLogFailure represents a single verification failure.
type VerifyLogFailure struct {
	Line    int    `json:"line"`
	Type    string `json:"type"` // "invalid_signature" or "parse_error"
	Message string `json:"message"`
}

// maxDetailedFailures is the maximum number of failures to include with details.
const maxDetailedFailures = 10

// AuditVerifyLogsCommand verifies HMAC signatures in a log file.
func AuditVerifyLogsCommand(file, keyHex, keyFile string) error {
	// Load the key
	key, err := loadVerifyKey(keyHex, keyFile)
	if err != nil {
		return err
	}

	// Validate key length
	if len(key) < logging.MinKeyLength {
		return fmt.Errorf("key must be at least %d bytes (%d hex chars), got %d bytes",
			logging.MinKeyLength, logging.MinKeyLength*2, len(key))
	}

	// Open the input file (or stdin)
	var reader io.Reader
	var filePath string
	if file == "-" {
		reader = os.Stdin
		filePath = "<stdin>"
	} else {
		f, err := os.Open(file)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		defer f.Close()
		reader = f
		filePath = file
	}

	// Verify the log file
	result, err := verifyLogFile(reader, key, filePath)
	if err != nil {
		return err
	}

	// Output results
	outputVerifyResults(result)

	// Return error if any failures (for scripting exit code)
	if result.InvalidSig > 0 || result.ParseErrors > 0 {
		return fmt.Errorf("verification failed: %d invalid signatures, %d parse errors",
			result.InvalidSig, result.ParseErrors)
	}

	return nil
}

// loadVerifyKey loads the HMAC key from flag or file.
func loadVerifyKey(keyHex, keyFile string) ([]byte, error) {
	// Check that at least one key source is provided
	if keyHex == "" && keyFile == "" {
		return nil, fmt.Errorf("either --key or --key-file is required")
	}

	// Prefer --key if both provided
	var hexKey string
	if keyHex != "" {
		hexKey = keyHex
	} else {
		// Read from file
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		// Trim whitespace (common when reading from file)
		hexKey = string(data)
		// Remove newlines and spaces
		hexKey = trimKeyWhitespace(hexKey)
	}

	// Decode hex key
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}

	return key, nil
}

// trimKeyWhitespace removes whitespace from a hex key string.
func trimKeyWhitespace(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			result = append(result, c)
		}
	}
	return string(result)
}

// verifyLogFile reads and verifies all entries in a log file.
func verifyLogFile(reader io.Reader, key []byte, filePath string) (*VerifyLogsResult, error) {
	result := &VerifyLogsResult{
		FilePath: filePath,
		Failures: make([]VerifyLogFailure, 0),
	}

	scanner := bufio.NewScanner(reader)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines
		if line == "" {
			continue
		}

		result.TotalLines++

		// Parse as SignedEntry
		var entry logging.SignedEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			result.ParseErrors++
			if len(result.Failures) < maxDetailedFailures {
				result.Failures = append(result.Failures, VerifyLogFailure{
					Line:    lineNum,
					Type:    "parse_error",
					Message: fmt.Sprintf("invalid JSON: %v", err),
				})
			}
			continue
		}

		// Check for missing signature
		if entry.Signature == "" {
			result.ParseErrors++
			if len(result.Failures) < maxDetailedFailures {
				result.Failures = append(result.Failures, VerifyLogFailure{
					Line:    lineNum,
					Type:    "parse_error",
					Message: "missing signature field",
				})
			}
			continue
		}

		// Verify signature
		valid, err := entry.Verify(key)
		if err != nil {
			result.ParseErrors++
			if len(result.Failures) < maxDetailedFailures {
				result.Failures = append(result.Failures, VerifyLogFailure{
					Line:    lineNum,
					Type:    "parse_error",
					Message: fmt.Sprintf("verification error: %v", err),
				})
			}
			continue
		}

		if !valid {
			result.InvalidSig++
			if len(result.Failures) < maxDetailedFailures {
				result.Failures = append(result.Failures, VerifyLogFailure{
					Line:    lineNum,
					Type:    "invalid_signature",
					Message: "invalid signature (possible tampering)",
				})
			}
			continue
		}

		result.VerifiedOK++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return result, nil
}

// outputVerifyResults prints verification results to stdout.
func outputVerifyResults(result *VerifyLogsResult) {
	fmt.Printf("Verifying: %s\n", result.FilePath)
	fmt.Printf("  Lines scanned: %d\n", result.TotalLines)
	fmt.Printf("  Verified OK:   %d\n", result.VerifiedOK)
	fmt.Printf("  Invalid sig:   %d\n", result.InvalidSig)
	fmt.Printf("  Parse errors:  %d\n", result.ParseErrors)
	fmt.Println()

	totalFailures := result.InvalidSig + result.ParseErrors
	if totalFailures > 0 {
		fmt.Printf("VERIFICATION FAILED: %d entries have integrity issues\n", totalFailures)
		for _, f := range result.Failures {
			fmt.Printf("  Line %d: %s\n", f.Line, f.Message)
		}
		if totalFailures > maxDetailedFailures {
			fmt.Printf("  ... and %d more failures\n", totalFailures-maxDetailedFailures)
		}
		fmt.Println()
		fmt.Println("Exit code: 1")
	} else {
		fmt.Printf("VERIFICATION PASSED: All %d entries have valid signatures\n", result.TotalLines)
		fmt.Println("Exit code: 0")
	}
}
