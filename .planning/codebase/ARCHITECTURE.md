# Architecture

**Analysis Date:** 2026-01-13

## Pattern Overview

**Overall:** CLI-Driven Credential Management Tool

**Key Characteristics:**
- Command-based CLI using kingpin framework
- Provider chain pattern for credential resolution
- Multi-backend secure credential storage
- Local metadata server emulation for SDK compatibility

## Layers

**Presentation Layer (CLI):**
- Purpose: User command handling and output formatting
- Contains: Command handlers, input parsing, output formatting
- Location: `cli/*.go`
- Depends on: vault (credential logic), prompt (MFA input), server (metadata servers)
- Used by: `main.go` entry point

**Credential Provider Layer:**
- Purpose: AWS credential resolution and caching
- Contains: Multiple `aws.CredentialsProvider` implementations
- Location: `vault/*provider.go`
- Depends on: keyring (storage), AWS SDK (STS calls)
- Used by: CLI commands, server layer

**Storage Layer:**
- Purpose: Secure credential and session persistence
- Contains: Keyring wrappers, session caching
- Location: `vault/*keyring.go`
- Depends on: byteness/keyring (OS integration)
- Used by: Provider layer

**Server Layer:**
- Purpose: Local credential endpoints for AWS SDK consumption
- Contains: EC2 metadata emulator, ECS container endpoint
- Location: `server/*.go`
- Depends on: Credential providers
- Used by: exec command (subprocess credential injection)

**Prompt Layer:**
- Purpose: MFA token input handling
- Contains: Platform-specific prompt drivers
- Location: `prompt/*.go`
- Depends on: OS-specific UI (osascript, zenity, kdialog, terminal)
- Used by: Credential providers needing MFA

## Data Flow

**Credential Resolution Flow:**

1. CLI parses profile name from user input
2. `TempCredentialsCreator.GetProviderForProfile()` called (`vault/vault.go`)
3. Provider chain constructed based on profile config:
   - Check for stored credentials → `KeyringProvider`
   - Check for SSO → `SSORoleCredentialsProvider`
   - Check for source profile → Recursive resolution
   - Check for credential process → `CredentialProcessProvider`
4. Wrap with `CachedSessionProvider` if caching enabled
5. Apply `AssumeRoleProvider` if role ARN present
6. Return composed provider

**Exec Command Flow:**

1. User: `aws-vault exec profile -- command`
2. Load profile config from `~/.aws/config` (`vault/config.go`)
3. Get credentials provider (above flow)
4. Option A: Set credentials as environment variables
5. Option B: Start EC2 metadata server (`server/ec2server.go` on 127.0.0.1:9099)
6. Option C: Start ECS container server (`server/ecsserver.go`)
7. Execute subprocess with credentials available

**State Management:**
- File-based: All state in system keyring or `~/.aws/config`
- Session caching in keyring with expiration metadata
- No persistent in-memory state between commands

## Key Abstractions

**CredentialsProvider:**
- Purpose: AWS SDK interface for credential retrieval
- Examples: `KeyringProvider`, `AssumeRoleProvider`, `SSORoleCredentialsProvider`
- Location: `vault/*provider.go`
- Pattern: Interface implementation with composition

**StsSessionProvider:**
- Purpose: Internal interface for cacheable STS operations
- Examples: `SessionTokenProvider`, `AssumeRoleProvider`
- Location: `vault/cachedsessionprovider.go`
- Pattern: Wrapped by `CachedSessionProvider`

**Keyring Wrappers:**
- Purpose: Typed access to system credential storage
- Examples: `CredentialKeyring`, `SessionKeyring`, `OIDCTokenKeyring`
- Location: `vault/*keyring.go`
- Pattern: Composition over byteness/keyring interface

**ConfigFile:**
- Purpose: AWS config file parsing and profile resolution
- Location: `vault/config.go`
- Pattern: Facade over gopkg.in/ini.v1

## Entry Points

**CLI Entry:**
- Location: `main.go`
- Triggers: User runs `aws-vault <command>`
- Responsibilities: Register commands, parse args, dispatch to handlers

**Commands:**
- Location: `cli/*.go` (one file per command)
- Triggers: Matched command from CLI
- Responsibilities: Validate input, call vault functions, format output

**EC2 Metadata Server:**
- Location: `server/ec2server.go`
- Triggers: `--ec2-server` flag on exec
- Responsibilities: Emulate EC2 metadata endpoint at 127.0.0.1:9099

**ECS Container Server:**
- Location: `server/ecsserver.go`
- Triggers: `--ecs-server` flag on exec
- Responsibilities: Provide container credentials via HTTP

## Error Handling

**Strategy:** Throw errors up to CLI level, exit with appropriate code

**Patterns:**
- Providers return `(aws.Credentials, error)`
- CLI handlers call `app.FatalIfError()` for terminal errors
- Some critical paths use `panic()` (identified as concern)

## Cross-Cutting Concerns

**Logging:**
- Standard Go `log` package
- Debug mode via `--debug` flag
- No structured logging

**MFA:**
- Prompt driver registry in `prompt/prompt.go`
- OS-specific implementations (terminal, osascript, zenity, kdialog, ykman, wincredui)
- Configured via `--prompt` flag or `AWS_VAULT_PROMPT` env var

**Session Caching:**
- Implemented in `CachedSessionProvider`
- Sessions stored in system keyring with encoded metadata
- Expiration tracking via `SessionMetadata`

---

*Architecture analysis: 2026-01-13*
*Update when major patterns change*
