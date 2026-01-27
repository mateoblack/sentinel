# Testing Patterns

**Analysis Date:** 2026-01-13

## Test Framework

**Runner:**
- Go standard `testing` package
- No external test framework

**Assertion Library:**
- Go standard library (manual if/t.Errorf patterns)
- `github.com/google/go-cmp v0.7.0` - Comprehensive comparison

**Run Commands:**
```bash
make test                    # Run all tests (go test -v ./...)
go test ./...                # Run all tests
go test ./vault/...          # Run vault package tests
go test -v ./cli/add_test.go # Single file
```

## Test File Organization

**Location:**
- Co-located with source: `*.go` alongside `*_test.go`
- No separate tests/ directory

**Naming:**
- `{source}_test.go` - Test file for {source}.go
- All test files in same package as source

**Structure:**
```
cli/
  add.go
  add_test.go
  exec.go
  exec_test.go
vault/
  config.go
  config_test.go
  vault.go
  vault_test.go
```

## Test Structure

**Suite Organization:**
```go
func TestFunctionName(t *testing.T) {
    // Table-driven test pattern
    var testCases = []struct {
        Input    string
        Expected bool
    }{
        {"case1", true},
        {"case2", false},
    }

    for _, tc := range testCases {
        result := FunctionName(tc.Input)
        if result != tc.Expected {
            t.Errorf("got %v, want %v", result, tc.Expected)
        }
    }
}
```

**Example Tests:**
```go
func ExampleAddCommand() {
    // Setup
    f, err := os.CreateTemp("", "aws-config")
    if err != nil {
        log.Fatal(err)
    }
    defer os.Remove(f.Name())

    // Execute
    // ... test code ...

    // Output:
    // Added credentials to profile "foo" in vault
}
```

**Patterns:**
- Table-driven tests for multiple scenarios
- Example functions for documentation and basic coverage
- `t.Helper()` for helper functions

## Mocking

**Framework:**
- No formal mocking framework
- Function parameters for dependency injection
- Interface-based mocking

**Patterns:**
```go
// Dependency injection via function parameter
func (p *CredentialProcessProvider) retrieveWith(
    ctx context.Context,
    fn func(string) (string, error),
) (aws.Credentials, error) {
    // fn can be mocked in tests
}
```

**What to Mock:**
- External process execution
- AWS API calls (where needed)
- File system operations

**What NOT to Mock:**
- Config parsing (use temp files)
- Internal pure functions

## Fixtures and Factories

**Test Data:**
```go
// Inline in tests
func TestConfigParsing(t *testing.T) {
    configContent := []byte(`
[profile test]
region = us-east-1
`)
    // Use configContent in test
}

// Helper function pattern
func newConfigFile(t *testing.T, b []byte) string {
    t.Helper()
    f, err := os.CreateTemp("", "aws-config")
    if err != nil {
        t.Fatal(err)
    }
    // ... write and return path
}
```

**Location:**
- Inline in test files for simple data
- Helper functions in same test file
- No shared fixtures directory

## Coverage

**Requirements:**
- No enforced coverage target
- Focus on critical paths

**Configuration:**
- Go built-in coverage

**View Coverage:**
```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Test Types

**Unit Tests:**
- Majority of tests
- Test single functions in isolation
- Fast execution

**Example Tests:**
- Documentation-driven
- Verify basic functionality
- Show usage patterns

**Integration Tests:**
- Config file parsing tests
- Process execution tests (with temp files)

**E2E Tests:**
- Not present
- Manual testing via CLI

## Common Patterns

**Temp File Pattern:**
```go
func TestWithTempFile(t *testing.T) {
    f, err := os.CreateTemp("", "prefix")
    if err != nil {
        t.Fatal(err)
    }
    defer os.Remove(f.Name())

    // Use f.Name() in test
}
```

**Error Testing:**
```go
func TestErrorCase(t *testing.T) {
    _, err := FunctionThatFails()
    if err == nil {
        t.Error("expected error, got nil")
    }
}
```

**Table-Driven with Names:**
```go
var testCases = []struct {
    name     string
    input    string
    expected bool
}{
    {"valid input", "good", true},
    {"empty input", "", false},
}

for _, tc := range testCases {
    t.Run(tc.name, func(t *testing.T) {
        // test logic
    })
}
```

## Test Files Summary

| File | Lines | Coverage Area |
|------|-------|---------------|
| `vault/config_test.go` | 625 | Config parsing |
| `vault/vault_test.go` | 125 | Provider logic |
| `vault/credentialprocessprovider_test.go` | 109 | External process |
| `cli/add_test.go` | 34 | Add command |
| `vault/sessionkeyring_test.go` | 28 | Session storage |
| `cli/export_test.go` | 25 | Export command |
| `iso8601/iso8601_test.go` | 24 | Timestamp format |
| `cli/exec_test.go` | 22 | Exec command |
| `cli/list_test.go` | 22 | List command |
| **Total** | **1,014** | |

---

*Testing analysis: 2026-01-13*
*Update when test patterns change*
