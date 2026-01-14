# Technology Stack

**Analysis Date:** 2026-01-13

## Languages

**Primary:**
- Go 1.25 - All application code (`go.mod`)

**Secondary:**
- None (pure Go codebase)

## Runtime

**Environment:**
- Go 1.25 (from `go.mod`)
- Cross-platform: macOS (Intel/Apple Silicon), Linux (amd64/arm64/arm7/ppc64le), Windows (386/amd64/arm64), FreeBSD

**Package Manager:**
- Go Modules
- Lockfile: `go.sum` (present)

## Frameworks

**Core:**
- None (vanilla Go CLI)

**CLI:**
- kingpin/v2 v2.4.0 - CLI framework with argument parsing (`main.go`, `cli/global.go`)

**Testing:**
- Go standard `testing` package - Unit tests
- No external test framework

**Build/Dev:**
- Make - Build automation (`Makefile`)
- GoReleaser - Multi-platform binary releases (`.goreleaser.yaml`)
- golangci-lint - Code linting (`.golangci.yaml`)

## Key Dependencies

**Critical:**
- `github.com/aws/aws-sdk-go-v2 v1.41.0` - AWS SDK v2 core (`vault/vault.go`)
- `github.com/aws/aws-sdk-go-v2/service/sts v1.41.5` - AWS STS for credential operations
- `github.com/aws/aws-sdk-go-v2/service/sso v1.30.8` - AWS SSO integration
- `github.com/byteness/keyring v1.6.1` - Cross-platform credential storage (`cli/global.go`)
- `gopkg.in/ini.v1 v1.67.0` - AWS config file parsing (`vault/config.go`)

**UI/Terminal:**
- `github.com/charmbracelet/huh v0.8.0` - Interactive form library (`cli/global.go`)
- `github.com/charmbracelet/lipgloss v1.1.0` - Terminal styling
- `github.com/AlecAivazis/survey/v2 v2.3.7` - Interactive prompts (archived, being replaced)
- `github.com/mattn/go-tty v0.0.7` - TTY interaction (`prompt/terminal.go`)

**Infrastructure:**
- `golang.org/x/term v0.38.0` - Terminal utilities
- `github.com/skratchdot/open-golang` - Cross-platform URL/file opening

## Configuration

**Environment:**
- AWS config file: `~/.aws/config` (INI format)
- Environment variables:
  - `AWS_CONFIG_FILE` - Custom config file location
  - `AWS_VAULT_BACKEND` - Credential storage backend
  - `AWS_VAULT_PROMPT` - MFA prompt driver
  - `AWS_VAULT_KEYCHAIN_NAME` - macOS keychain name
  - `AWS_VAULT_FILE_PASSPHRASE` - File storage passphrase
  - `AWS_VAULT_BIOMETRICS` - Enable Touch ID

**Build:**
- `Makefile` - Build targets and version injection
- `.goreleaser.yaml` - Release configuration

## Platform Requirements

**Development:**
- Any platform with Go 1.25+
- macOS: CGO required for Keychain integration

**Production:**
- Distributed as standalone binary
- macOS binaries code-signed with Developer ID
- DMG packages for macOS distribution

---

*Stack analysis: 2026-01-13*
*Update after major dependency changes*
