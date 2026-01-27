# External Integrations

**Analysis Date:** 2026-01-13

## APIs & External Services

**AWS Security Token Service (STS):**
- Purpose: Temporary credential generation
- SDK: `github.com/aws/aws-sdk-go-v2/service/sts v1.41.5`
- Operations: GetSessionToken, AssumeRole, AssumeRoleWithWebIdentity, GetFederationToken
- Files: `vault/vault.go`, `vault/sessiontokenprovider.go`, `vault/assumeroleprovider.go`

**AWS Single Sign-On (SSO):**
- Purpose: SSO-based credential retrieval
- SDK: `github.com/aws/aws-sdk-go-v2/service/sso v1.30.8`
- SDK: `github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.12`
- Files: `vault/ssorolecredentialsprovider.go`, `vault/oidctokenkeyring.go`

**AWS Identity and Access Management (IAM):**
- Purpose: User information retrieval
- SDK: `github.com/aws/aws-sdk-go-v2/service/iam v1.53.1`
- Files: `vault/getuser.go`

## Data Storage

**Databases:**
- Not applicable - CLI tool with no database

**Credential Storage:**
- Provider: `github.com/byteness/keyring v1.6.1`
- Backends supported:
  - macOS Keychain (`keychain`)
  - Windows Credential Manager (`wincred`)
  - Linux Secret Service/GNOME Keyring (`secret-service`)
  - KWallet (`kwallet`)
  - Pass password manager (`pass`)
  - Encrypted file (`file`)
  - 1Password Connect (`op-connect`)
  - 1Password Service Accounts (`op-service-account`)
- Configuration: `AWS_VAULT_BACKEND` env var or `--backend` flag
- Files: `cli/global.go`, `vault/credentialkeyring.go`, `vault/sessionkeyring.go`

**File Storage:**
- AWS config: `~/.aws/config` (read-only, except for add command)
- Files: `vault/config.go`

**Caching:**
- Session tokens cached in system keyring
- OIDC tokens cached in keyring
- Files: `vault/sessionkeyring.go`, `vault/oidctokenkeyring.go`

## Authentication & Identity

**Auth Provider:**
- AWS IAM credentials (stored in keyring)
- AWS SSO (browser-based OAuth flow)
- Token storage: System keyring (platform-specific secure storage)
- Session management: Cached sessions with expiration tracking

**MFA Integrations:**
- Terminal input
- macOS osascript dialogs
- Linux zenity (GTK)
- Linux kdialog (KDE)
- YubiKey Manager (`ykman`)
- Windows credential UI
- Files: `prompt/*.go`

**1Password Integration:**
- 1Password Connect: `github.com/1Password/connect-sdk-go v1.5.4`
- 1Password Service Accounts: `github.com/1password/onepassword-sdk-go v0.4.0-beta.2`
- Configuration: `AWS_VAULT_OP_CONNECT_TOKEN`, `AWS_VAULT_OP_SERVICE_ACCOUNT_TOKEN`

## Monitoring & Observability

**Error Tracking:**
- Not configured - local CLI tool

**Analytics:**
- Not applicable

**Logs:**
- Standard Go `log` package to stderr
- Debug mode via `--debug` flag

## CI/CD & Deployment

**Hosting:**
- GitHub Releases - Binary distribution
- Homebrew Cask - macOS package manager

**CI Pipeline:**
- GitHub Actions
- Workflows:
  - `.github/workflows/go.yml` - Test and lint
  - `.github/workflows/release.yaml` - Build releases
  - `.github/workflows/pr.yaml` - PR checks
  - `.github/workflows/stale.yml` - Stale issue management
- Secrets: Code signing credentials for macOS

**Release Process:**
- GoReleaser for multi-platform builds
- DMG creation for macOS
- SHA256 checksums for verification

## Environment Configuration

**Development:**
- Required: Go 1.25+
- macOS: Xcode command line tools (for CGO/Keychain)
- No .env files used

**Production:**
- Standalone binary
- Configuration via `~/.aws/config` and environment variables
- Credentials in system keyring

## Local Servers

**EC2 Metadata Emulator:**
- Endpoint: `http://127.0.0.1:9099/latest/meta-data/`
- Purpose: Provide credentials to AWS SDKs expecting EC2 metadata
- Files: `server/ec2server.go`
- Security: Loopback-only, host header validation

**ECS Container Credentials:**
- Endpoint: `http://127.0.0.1:{port}/`
- Purpose: ECS-compatible credential endpoint
- Files: `server/ecsserver.go`
- Auth: Token-based authorization

## Webhooks & Callbacks

**Incoming:**
- Not applicable

**Outgoing:**
- Browser opening for SSO login flow
- File: `vault/ssorolecredentialsprovider.go`
- Library: `github.com/skratchdot/open-golang`

---

*Integration audit: 2026-01-13*
*Update when adding/removing external services*
