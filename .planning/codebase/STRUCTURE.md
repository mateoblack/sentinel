# Codebase Structure

**Analysis Date:** 2026-01-13

## Directory Layout

```
overseer/
├── main.go                 # CLI entry point (kingpin app setup)
├── go.mod / go.sum         # Go module dependencies
├── Makefile                # Build automation
├── README.md / USAGE.md    # Documentation
├── SECURITY.md             # Security policy
├── .golangci.yaml          # Linter configuration
├── .goreleaser.yaml        # Release configuration
│
├── cli/                    # User command implementations
├── vault/                  # Credential management engine
├── server/                 # Local credential servers
├── prompt/                 # MFA prompt drivers
├── iso8601/                # Timestamp utilities
├── contrib/                # Community contributions
├── bin/                    # Build scripts
└── .github/                # CI/CD workflows
```

## Directory Purposes

**cli/**
- Purpose: CLI command handlers
- Contains: One file per command + global configuration
- Key files:
  - `global.go` - AwsVault struct, keyring setup, global flags
  - `add.go` - Add credentials to keyring
  - `exec.go` - Execute commands with AWS credentials
  - `list.go` - List profiles and sessions
  - `export.go` - Export credentials in various formats
  - `clear.go`, `remove.go`, `rotate.go` - Credential management
  - `login.go`, `proxy.go` - AWS Console and proxy features
- Subdirectories: None

**vault/**
- Purpose: Core credential logic
- Contains: Providers, keyring wrappers, config parsing
- Key files:
  - `vault.go` - TempCredentialsCreator, provider factory
  - `config.go` - AWS config file parsing (694 lines)
  - `*provider.go` - Credential provider implementations
  - `*keyring.go` - Keyring wrapper types
  - `mfa.go`, `mfa_unix.go`, `mfa_windows.go` - MFA handling
- Subdirectories: None

**server/**
- Purpose: Local HTTP servers for credential injection
- Contains: EC2/ECS metadata endpoints
- Key files:
  - `ec2server.go` - EC2 metadata emulator (127.0.0.1:9099)
  - `ecsserver.go` - ECS container credentials
  - `ec2proxy.go` - Proxy routing
  - `ec2alias_*.go` - Platform-specific alias setup
  - `httplog.go` - HTTP logging middleware
- Subdirectories: None

**prompt/**
- Purpose: MFA input handling
- Contains: Platform-specific prompt drivers
- Key files:
  - `prompt.go` - Driver registry
  - `terminal.go` - Terminal input
  - `osascript.go` - macOS AppleScript dialogs
  - `zenity.go` - Linux GTK dialogs
  - `kdialog.go` - KDE dialogs
  - `ykman.go` - YubiKey manager
  - `wincredui_windows.go` - Windows credential UI
- Subdirectories: None

**iso8601/**
- Purpose: AWS-compatible timestamp formatting
- Contains: `iso8601.go`, `iso8601_test.go`
- Subdirectories: None

**contrib/**
- Purpose: Community contributions and tooling
- Subdirectories:
  - `_aws-vault-proxy/` - External proxy tool
  - `completions/` - Shell completions
  - `docker/` - Docker configurations
  - `scripts/` - Utility scripts

## Key File Locations

**Entry Points:**
- `main.go` - CLI entry point

**Configuration:**
- `go.mod` - Go module definition
- `Makefile` - Build targets
- `.golangci.yaml` - Linter rules
- `.goreleaser.yaml` - Release configuration

**Core Logic:**
- `vault/vault.go` - Provider factory and composition
- `vault/config.go` - AWS config parsing
- `cli/global.go` - Keyring initialization

**Testing:**
- `cli/*_test.go` - CLI command tests
- `vault/*_test.go` - Vault logic tests
- `iso8601/iso8601_test.go` - Timestamp tests

**Documentation:**
- `README.md` - Project overview
- `USAGE.md` - Usage guide
- `SECURITY.md` - Security policy

## Naming Conventions

**Files:**
- `lowercase.go` - Standard Go files
- `*_test.go` - Test files (co-located with source)
- `*_unix.go`, `*_windows.go` - Platform-specific (build tags)

**Directories:**
- Lowercase, single-word names
- Organized by function, not layer

**Special Patterns:**
- `*provider.go` - AWS credential provider implementations
- `*keyring.go` - Keyring wrapper types
- `ec2*`, `ecs*` - AWS service emulation

## Where to Add New Code

**New CLI Command:**
- Implementation: `cli/{command}.go`
- Tests: `cli/{command}_test.go`
- Registration: Add to `main.go`

**New Credential Provider:**
- Implementation: `vault/{name}provider.go`
- Tests: `vault/{name}provider_test.go`
- Integration: Add to `vault/vault.go` GetProviderForProfile()

**New Prompt Driver:**
- Implementation: `prompt/{driver}.go`
- Registration: Add to `prompt/prompt.go` Methods map

**New Server Endpoint:**
- Implementation: `server/{name}server.go`
- Platform-specific: `server/{name}_{platform}.go`

**Utilities:**
- Shared helpers: Create new package or add to relevant domain package

## Special Directories

**bin/**
- Purpose: Build scripts (create-dmg)
- Source: Manually maintained
- Committed: Yes

**.github/**
- Purpose: CI/CD configuration
- Contains: workflows/, labeler.yaml, dependabot.yml
- Committed: Yes

**contrib/**
- Purpose: Community-maintained tooling
- Source: Community contributions
- Committed: Yes

---

*Structure analysis: 2026-01-13*
*Update when directory structure changes*
