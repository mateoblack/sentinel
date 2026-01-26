# Security Testing Guide

This document describes Sentinel's security regression testing framework, which validates all security-critical code paths and prevents security regressions across releases.

## Overview

Security regression tests serve as guards against code changes that might inadvertently weaken security. They verify that:

1. **Default deny** - No credentials are issued without explicit policy allow
2. **Input validation** - All untrusted input is sanitized before use
3. **Timing-safe operations** - Constant-time comparison prevents timing attacks
4. **State integrity** - Optimistic locking prevents concurrent write corruption
5. **Credential isolation** - Keyring stores prevent credential leakage

### When to Add Security Tests

Add security regression tests when:

- Implementing a new security feature (authentication, authorization, encryption)
- Fixing a security vulnerability (add test to prevent regression)
- Handling untrusted input (user data, network data, file paths)
- Working with secrets (credentials, tokens, keys)
- Implementing access control logic

## Test Naming Convention

All security regression tests use the `TestSecurityRegression_` prefix:

```go
func TestSecurityRegression_CategoryName_SpecificTest(t *testing.T) {
    // Test implementation
}
```

**Categories include:**
- `DefaultDeny` - Tests that default deny is enforced
- `RuleBypass` - Tests that rules cannot be bypassed
- `TimeWindow` - Tests time-based access control
- `EffectIsolation` - Tests that effects work correctly
- `PathTraversal` - Tests path traversal prevention
- `CommandInjection` - Tests command injection prevention
- `TimingAttack` - Tests timing-safe operations
- `StateTransition` - Tests valid state transitions only

**Benefits of prefix convention:**
- CI can filter tests: `go test -run TestSecurityRegression ./...`
- Easy to count security tests across codebase
- Clear separation from functional tests

## Test Organization

Security tests are organized per-package in dedicated files:

```
package/
  foo.go                    # Implementation
  foo_test.go              # Unit tests
  security_test.go         # Security regression tests
  foo_security_test.go     # Alternative: feature-specific security tests
```

Each security test file follows a standard structure:

```go
package mypackage

import (
    "testing"
)

// ============================================================================
// Security Regression Tests for Feature X (Phase NNN)
// ============================================================================
//
// These tests verify:
// 1. Security property A
// 2. Security property B
// 3. Security property C
//
// Tests use TestSecurityRegression_ prefix for CI/CD filtering.
// ============================================================================

func TestSecurityRegression_Category_SpecificTest(t *testing.T) {
    // ...
}
```

## Test Patterns

### THREAT Comments

Document the attack scenario being tested:

```go
// THREAT: Attacker crafts profile name with shell metacharacters
// to execute arbitrary commands when the name is used in shell context.
func TestSecurityRegression_ShellInjection_ProfileName(t *testing.T) {
    // ...
}
```

### SECURITY VIOLATION Markers

Mark test failures with clear violation markers for CI detection:

```go
if decision.Effect == EffectAllow {
    t.Errorf("SECURITY VIOLATION: Empty policy allowed credential issuance")
}
```

The security test runner scans for `SECURITY VIOLATION` markers in output.

### Table-Driven Attack Vector Tests

Use table-driven tests to cover multiple attack vectors:

```go
func TestSecurityRegression_CommandInjectionPrevention(t *testing.T) {
    injectionAttempts := []struct {
        name        string
        input       string
        description string
    }{
        {
            name:        "semicolon_rm",
            input:       "profile;rm -rf /",
            description: "semicolon command separator",
        },
        {
            name:        "backtick_whoami",
            input:       "profile`whoami`",
            description: "backtick command substitution",
        },
        // ... more attack vectors
    }

    for _, tc := range injectionAttempts {
        t.Run(tc.name, func(t *testing.T) {
            err := ValidateProfileName(tc.input)
            if err == nil {
                t.Errorf("SECURITY VIOLATION: Command injection not blocked: %q (%s)",
                    tc.input, tc.description)
            }
        })
    }
}
```

### AST Verification for Code Patterns

Use AST analysis to verify security-critical code patterns:

```go
// Verify constant-time comparison is used (not bytes.Equal or ==)
func TestSecurityRegression_TimingSafeComparison(t *testing.T) {
    // Parse the source file
    fset := token.NewFileSet()
    node, err := parser.ParseFile(fset, "auth.go", nil, 0)
    if err != nil {
        t.Fatalf("Failed to parse: %v", err)
    }

    // Walk AST looking for timing-unsafe comparison
    ast.Inspect(node, func(n ast.Node) bool {
        if call, ok := n.(*ast.CallExpr); ok {
            if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
                if sel.Sel.Name == "Equal" {
                    // Found bytes.Equal or similar - potential timing attack
                    t.Errorf("SECURITY VIOLATION: Found timing-unsafe comparison")
                }
            }
        }
        return true
    })
}
```

## v1.18 Security Coverage

The v1.18 security hardening milestone includes comprehensive security tests for each phase:

### Phase 126: Policy Signing and Verification

**File:** `policy/security_regression_test.go`

Tests:
- Default deny enforcement (empty policy, nil policy, no matching rules)
- Rule bypass prevention (case sensitivity, partial string rejection)
- Time window boundary conditions (nanosecond precision, timezone handling)
- Effect isolation (first match wins, invalid effects cannot produce allow)

### Phase 127: Break-Glass MFA

**File:** `mfa/security_test.go`

Tests:
- TOTP timing attack prevention (constant-time validation)
- MFA bypass prevention (cannot skip MFA step)
- Code replay prevention (codes cannot be reused)

### Phase 128: Audit Log Integrity

**File:** `logging/security_test.go`

Tests:
- HMAC signature verification for log entries
- Tamper detection (modified entries fail verification)
- Timing-safe signature comparison

### Phase 129: Local Server Security

**Files:** `sentinel/server_security_test.go`, `sentinel/server_unix_test.go`

Tests:
- Unix socket peer credential verification
- Process authentication (UID/PID binding)
- Token timing-safe comparison
- Token binding security (PID=0 tokens bound on first use)

### Phase 130: Identity Hardening

**File:** `identity/security_test.go`

Tests:
- Partition validation (all AWS partitions: aws, aws-cn, aws-us-gov, aws-iso, aws-iso-b)
- ARN injection prevention (path traversal, null bytes, control characters)
- Identity extraction consistency (CLI and Lambda produce identical results)
- Username sanitization (alphanumeric only output)

### Phase 131: DynamoDB Security

**Files:** `session/dynamodb_security_test.go`, `request/dynamodb_security_test.go`, `breakglass/dynamodb_security_test.go`

Tests:
- Optimistic locking prevents concurrent write corruption
- Conditional writes enforce version consistency
- State transition validation (only valid transitions allowed)
- Double-spend prevention for approvals

### Phase 132: Keyring Protection

**File:** `vault/keyring_security_test.go`

Tests:
- macOS Keychain: not accessible when device locked
- macOS Keychain: iCloud sync disabled
- macOS Keychain: other applications cannot access
- Linux keyctl: possessor-only permissions

### Phase 133: Rate Limit Hardening

**File:** `ratelimit/security_test.go`

Tests:
- Atomic increment prevents race conditions
- Window reset is atomic with increment
- Per-user rate limiting by IAM ARN
- Fail-open behavior on DynamoDB errors

### Phase 134: Input Sanitization

**Files:** `validate/security_test.go`, `shell/security_test.go`

Tests:
- Path traversal prevention (../, //, ./, etc.)
- Command injection prevention (;, |, &, $(), backticks)
- Null byte injection prevention
- Unicode homoglyph prevention
- Log injection sanitization (control characters escaped)
- Shell escaping for function generation
- Function name sanitization (sentinel- prefix, alphanumeric only)

### Phase 135: Security Validation

**File:** `security/v118_integration_test.go`

Integration tests validating cross-phase security:
- Identity + Validation: sanitized usernames are safe for all contexts
- State transitions: all DynamoDB stores validate transitions consistently
- End-to-end policy evaluation with hardened identity extraction

## Running Security Tests

### Run All Security Tests

```bash
# Via Makefile (recommended)
make test-security

# Direct go test
go test -race -count=1 -run TestSecurityRegression ./...

# Verbose output
make test-security-verbose

# Or with script
./scripts/security-test.sh -v
```

### List Security Test Files

```bash
./scripts/security-test.sh -l
```

### Run Security Tests for Specific Package

```bash
go test -race -count=1 -run TestSecurityRegression ./validate/...
go test -race -count=1 -run TestSecurityRegression ./identity/...
```

### Run All Tests (Including Security)

```bash
make test-all
```

## Adding New Security Tests

### Step 1: Create or Update Security Test File

```bash
# Create new security test file for package
touch mypackage/security_test.go

# Or add to existing file
vim mypackage/security_test.go
```

### Step 2: Add Test File Header

```go
package mypackage

import (
    "testing"
)

// ============================================================================
// Security Regression Tests for Feature Name (Phase NNN)
// ============================================================================
//
// THREAT MODEL:
// [Describe what attacks these tests protect against]
//
// SECURITY PROPERTIES:
// 1. [Property this test verifies]
// 2. [Another property]
//
// Tests use TestSecurityRegression_ prefix for CI/CD filtering.
// ============================================================================
```

### Step 3: Write Tests

```go
// TestSecurityRegression_Category_SpecificBehavior documents the threat
// and verifies the security property holds.
//
// THREAT: [Describe the attack scenario]
func TestSecurityRegression_Category_SpecificBehavior(t *testing.T) {
    attackVectors := []struct {
        name        string
        input       string
        description string
    }{
        // Add all known attack vectors
    }

    for _, tc := range attackVectors {
        t.Run(tc.name, func(t *testing.T) {
            // Test the security property
            if securityPropertyViolated {
                t.Errorf("SECURITY VIOLATION: %s (%s)", tc.input, tc.description)
            }
        })
    }
}
```

### Step 4: Verify Discovery

```bash
# Verify test is discovered
./scripts/security-test.sh -l | grep mypackage

# Run just the new tests
go test -v -run TestSecurityRegression ./mypackage/...
```

### Template for New Security Test File

```go
package mypackage

import (
    "testing"
)

// ============================================================================
// Security Regression Tests for [Feature] (Phase [N])
// ============================================================================
//
// THREAT MODEL:
// [Describe what attacks this feature is vulnerable to]
//
// SECURITY PROPERTIES:
// 1. [First security property to verify]
// 2. [Second security property to verify]
//
// Tests use TestSecurityRegression_ prefix for CI/CD filtering.
// ============================================================================

// TestSecurityRegression_[Category]_[Specific] verifies [security property].
//
// THREAT: [Specific attack this test prevents]
func TestSecurityRegression_[Category]_[Specific](t *testing.T) {
    tests := []struct {
        name        string
        input       interface{}
        wantSecure  bool
        description string
    }{
        // Positive test: valid input accepted
        {
            name:        "valid_input",
            input:       "safe-value",
            wantSecure:  true,
            description: "legitimate input should be accepted",
        },
        // Negative tests: attack vectors rejected
        {
            name:        "attack_vector_1",
            input:       "malicious-value",
            wantSecure:  false,
            description: "attack description",
        },
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            result := FunctionUnderTest(tc.input)

            if tc.wantSecure && !result.IsSecure() {
                t.Errorf("Expected secure result for %v (%s)", tc.input, tc.description)
            }
            if !tc.wantSecure && result.IsSecure() {
                t.Errorf("SECURITY VIOLATION: Attack not blocked: %v (%s)",
                    tc.input, tc.description)
            }
        })
    }
}
```

## CI Integration

### How Security Tests Run in CI

Security tests are run automatically on:
- Every pull request
- Every push to main branch

The CI workflow:
1. Runs `make test-security` to execute all security regression tests
2. Counts total security tests and fails if count drops below threshold
3. Scans output for `SECURITY VIOLATION` markers
4. Fails the build if any security tests fail

### Blocking vs Advisory

Security tests are **blocking** - the build fails if any security test fails.

This prevents:
- Accidental removal of security tests
- Merging code that breaks security properties
- Gradual erosion of security test coverage

### Security Test Count Threshold

The CI workflow enforces a minimum security test count:

```yaml
# Fail if security test count drops below threshold
if [ "$SECURITY_TESTS" -lt 250 ]; then
    echo "ERROR: Security test count dropped below threshold"
    exit 1
fi
```

Current threshold: **250 tests** (actual count: ~297)

If the count drops, it indicates security tests were removed (intentionally or accidentally).

## Best Practices

### DO:
- Use `TestSecurityRegression_` prefix for all security tests
- Document the threat being tested in comments
- Use `SECURITY VIOLATION` marker in failure messages
- Test both positive (valid input accepted) and negative (attacks blocked) cases
- Use table-driven tests to cover multiple attack vectors
- Include edge cases (empty input, max length, boundary values)

### DON'T:
- Mix security tests with functional tests in the same test function
- Skip security tests in CI (they should always run)
- Remove security tests without understanding why they exist
- Assume input is safe because it comes from "trusted" sources

## Security Test Inventory

Current security test files and packages:

| Package | File | Phase | Tests |
|---------|------|-------|-------|
| breakglass | dynamodb_security_test.go | 131 | DynamoDB security |
| breakglass | ratelimit_security_test.go | 133 | Rate limiting |
| breakglass | state_security_test.go | 131 | State transitions |
| breakglass | security_regression_test.go | 131 | Regression tests |
| cli | identity_security_test.go | 130 | CLI identity |
| identity | security_test.go | 130 | Identity hardening |
| lambda | handler_security_test.go | 130 | Lambda handler |
| lambda | security_test.go | 130 | Lambda security |
| policy | security_regression_test.go | 126 | Policy evaluation |
| ratelimit | security_test.go | 133 | Rate limiting |
| request | dynamodb_security_test.go | 131 | DynamoDB security |
| request | state_security_test.go | 131 | State transitions |
| request | security_regression_test.go | 131 | Regression tests |
| security | v118_integration_test.go | 135 | Integration tests |
| sentinel | server_security_test.go | 129 | Server security |
| sentinel | server_unix_test.go | 129 | Unix socket auth |
| session | dynamodb_security_test.go | 131 | DynamoDB security |
| shell | security_test.go | 134 | Shell escaping |
| validate | security_test.go | 134 | Input validation |
| vault | keyring_security_test.go | 132 | Keyring protection |

Total: **~24 security test files** across **~16 packages** with **~297 individual tests**

---

*Last updated: v1.18 Security Hardening Milestone*
