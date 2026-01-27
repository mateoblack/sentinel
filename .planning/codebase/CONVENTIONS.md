# Coding Conventions

**Analysis Date:** 2026-01-13

## Naming Patterns

**Files:**
- `lowercase.go` - All Go source files
- `*_test.go` - Test files co-located with source
- `*_unix.go`, `*_windows.go` - Platform-specific with build tags
- `*provider.go` - Credential provider implementations
- `*keyring.go` - Keyring wrapper types

**Functions:**
- `PascalCase` - Exported functions (`NewMasterCredentialsProvider`, `LoadConfig`)
- `camelCase` - Unexported functions (`roleSessionName`, `isMasterCredentialsProvider`)
- `ConfigureXCommand` - CLI command registration pattern
- `handleX` - Not used; commands use direct function calls

**Variables:**
- `camelCase` - Local variables and parameters
- `PascalCase` - Exported struct fields (required for JSON marshaling)
- `UPPER_SNAKE_CASE` - Not used; Go prefers `camelCase` constants
- No underscore prefix for private (Go visibility via case)

**Types:**
- `PascalCase` - All types (`AssumeRoleProvider`, `ConfigFile`)
- No `I` prefix for interfaces
- `*Provider` suffix - Credential provider types
- `*Input` suffix - Command input structs (`AddCommandInput`)

## Code Style

**Formatting:**
- Tool: `gofmt` (via `make fmt`)
- Tabs for indentation (Go standard)
- No explicit line length limit (gofmt handles)

**Linting:**
- Tool: golangci-lint (`.golangci.yaml`)
- 20+ linters enabled including:
  - `bodyclose`, `contextcheck`, `depguard`
  - `errchkjson`, `errname`, `exhaustive`
  - `govet`, `misspell`, `revive`
- Run: `make vet` for go vet, `make lint` for golint

## Import Organization

**Order:**
1. Standard library (`context`, `fmt`, `os`)
2. Blank line
3. External packages (`github.com/aws/...`, `github.com/byteness/...`)
4. Blank line
5. Internal packages (same module)

**Example from `cli/add.go`:**
```go
import (
    "fmt"
    "log"
    "os"

    "github.com/alecthomas/kingpin/v2"
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/byteness/aws-vault/v7/prompt"
    "github.com/byteness/aws-vault/v7/vault"
    "github.com/byteness/keyring"
)
```

**Path Aliases:**
- `osexec "os/exec"` - Renamed import to avoid conflict with vault exec

## Error Handling

**Patterns:**
- Return `error` as last return value
- Check errors immediately: `if err != nil { return err }`
- Wrap errors with context: `fmt.Errorf("failed to X: %w", err)`
- Fatal errors at CLI level: `app.FatalIfError(err, "command")`

**Error Types:**
- Standard `error` interface throughout
- No custom error types defined
- String errors via `fmt.Errorf()`

**Known Issues:**
- Some paths use `panic()` inappropriately (see CONCERNS.md)
- Some use `log.Fatalf()` without proper cleanup

## Logging

**Framework:**
- Standard Go `log` package
- No structured logging

**Patterns:**
- `log.Println()` - Informational messages
- `log.Fatalf()` - Fatal errors (exits program)
- Debug flag controls verbosity

## Comments

**When to Comment:**
- Package-level doc comments required
- Exported function doc comments (GoDoc format)
- Complex logic explanation

**GoDoc Format:**
```go
// Format outputs an ISO-8601 datetime string from the given time,
// in a format compatible with all of the AWS SDKs
func Format(t time.Time) string
```

**TODO Comments:**
- Format: `// TODO: description`
- Example: `// TODO: needs more testing`

## Function Design

**Size:**
- No strict limit, but some files large (config.go: 694 lines)
- Helper functions extracted for reuse

**Parameters:**
- Input structs for commands (`AddCommandInput`, `ExecCommandInput`)
- Context as first parameter for async operations
- Options passed directly, not as config objects

**Return Values:**
- Single value + error pattern
- Named returns rarely used
- Early returns for error cases

## Module Design

**Exports:**
- Named exports only (Go standard)
- Public API via capitalized names
- No index files (Go doesn't use them)

**Package Organization:**
- One package per directory
- Internal packages not used (flat structure)
- Clear domain boundaries: cli, vault, server, prompt

---

*Convention analysis: 2026-01-13*
*Update when patterns change*
