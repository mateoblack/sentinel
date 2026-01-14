# Codebase Concerns

**Analysis Date:** 2026-01-13

## Tech Debt

**Panic usage in production code:**
- Issue: `panic()` called in critical paths instead of returning errors
- Files:
  - `vault/config.go:213` - panic in `ProfileSection()` struct mapping
  - `vault/config.go:233` - panic in `SSOSessionSection()` struct mapping
  - `server/ecsserver.go:55` - panic in `generateRandomString()` if crypto/rand fails
  - `prompt/prompt.go:24` - panic in prompt method selection
- Why: Quick implementation without proper error propagation
- Impact: Application crashes instead of graceful error handling
- Fix approach: Replace panics with error returns, propagate to CLI layer

**Unsafe fatal exits without cleanup:**
- Issue: `log.Fatalf()` / `log.Fatalln()` called without graceful shutdown
- Files:
  - `server/ec2server.go:56` - Fatal on server listen failure
  - `server/ec2proxy.go:56` - Fatal on proxy error
  - `cli/export.go:168` - Fatal in `mustNewKey()`
  - `cli/global.go:99` - Fatal in `MustGetProfileNames()`
  - `cli/exec.go:289` - Fatal after background server started
  - `vault/config.go:497` - Fatal when parsing AWS_SESSION_TAGS
- Why: Error handling shortcuts
- Impact: No cleanup, potential resource leaks
- Fix approach: Return errors, let CLI layer handle exit

**Archived library still in use:**
- Issue: Using archived `github.com/AlecAivazis/survey/v2` alongside replacement
- Files: `cli/global.go:240-269` - Both `pickAwsProfile()` and `pickAwsProfile2()` exist
- Why: Migration in progress, not complete
- Impact: Technical debt, two implementations for same feature
- Fix approach: Complete migration to `github.com/charmbracelet/huh`, remove survey

## Known Bugs

**No known bugs documented**
- Codebase appears stable
- TODO comments indicate planned improvements, not bugs

## Security Considerations

**Environment variable exposure:**
- Risk: `AWS_VAULT_FILE_PASSPHRASE` readable in process list
- File: `cli/global.go:223`
- Current mitigation: None
- Recommendations: Document security implications, suggest alternative input methods

**Credential masking may be insufficient:**
- Risk: `FormatKeyForDisplay()` shows last 4 characters of access key
- File: `vault/vault.go:40-41`
- Current mitigation: Only used for display
- Recommendations: Review if 4 characters provides sufficient obfuscation

**Missing input validation:**
- Risk: Role ARN passed without validation before AssumeRole
- File: `server/ecsserver.go:129-133`
- Current mitigation: AWS SDK validates on call
- Recommendations: Add local validation for faster failure

## Performance Bottlenecks

**Sequential keyring operations:**
- Problem: Loop operations on keyring without batching
- Files: `cli/rotate.go:136-141`, `vault/sessionkeyring.go:120-145`
- Measurement: Not measured, likely minor for typical use
- Cause: Keyring API doesn't support batch operations
- Improvement path: Cache reads, batch where possible

**Base64 encoding overhead:**
- Problem: Profile name and MFA serial encoded/decoded for every session key
- File: `vault/sessionkeyring.go:55-67`
- Measurement: Negligible for typical use
- Cause: Key format requirements for storage
- Improvement path: Cache decoded values if needed

## Fragile Areas

**Config file parsing (vault/config.go):**
- File: `vault/config.go` (694 lines)
- Why fragile: Complex recursive profile resolution, many edge cases
- Common failures: Circular references, missing profiles
- Safe modification: Add comprehensive tests before changes
- Test coverage: Good (625 lines in config_test.go)

**Session key encoding (vault/sessionkeyring.go):**
- File: `vault/sessionkeyring.go:17-23`
- Why fragile: Complex regex patterns for session key parsing
- Common failures: Format changes break compatibility
- Safe modification: Add more test cases for edge patterns
- Test coverage: Partial (28 lines in test file)

## Scaling Limits

**Not applicable:**
- Local CLI tool with no server-side scaling concerns
- Keyring operations limited by OS credential storage

## Dependencies at Risk

**Archived library:**
- Package: `github.com/AlecAivazis/survey/v2 v2.3.7`
- Risk: Archived, no longer maintained
- Impact: No security updates, no new features
- Migration plan: Replace with `github.com/charmbracelet/huh` (in progress)

**Beta dependency:**
- Package: `github.com/1password/onepassword-sdk-go v0.4.0-beta.2`
- Risk: API may change before stable release
- Impact: Breaking changes on upgrade
- Migration plan: Pin version, update when stable

## Missing Critical Features

**No known missing critical features:**
- Core functionality (credential management) complete
- Platform support comprehensive

## Test Coverage Gaps

**Untested packages:**
- `cli/proxy.go` - Proxy functionality
- `cli/rotate.go` - Credential rotation
- `server/ec2proxy.go` - Network proxy
- `server/ec2server.go` - Metadata server
- `prompt/` - All prompt drivers
- Risk: Regressions could go unnoticed
- Priority: Medium (core paths tested)
- Difficulty: Requires mocking OS-specific features

**Panic paths untested:**
- `vault/config.go:213, 233` - Panic on struct mapping errors
- Risk: Unknown failure modes
- Priority: High (should not panic in production)
- Difficulty: Need to trigger error conditions in ini mapping

**Low overall test coverage:**
- Only 1,014 lines of test code for codebase
- Most tests are Example-based, not comprehensive unit tests
- Risk: Subtle bugs may not be caught
- Priority: Medium
- Difficulty: Time investment to add comprehensive tests

## Context Usage Issues

**context.TODO() abuse:**
- Issue: `context.TODO()` used instead of proper context propagation
- Files:
  - `cli/export.go:138, 174, 202`
  - `cli/exec.go:212, 282, 301`
  - `cli/rotate.go:85, 109, 116, 146`
- Impact: Operations cannot be cancelled, may hang indefinitely
- Fix approach: Accept context from CLI layer, propagate through calls

---

*Concerns audit: 2026-01-13*
*Update as issues are fixed or new ones discovered*
