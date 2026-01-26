# Changelog

All notable changes to Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.14.0] - 2026-01-25

### Added

#### Phase 97: Foundation (2026-01-24)
- Lambda TVM binary build pipeline (`make lambda-tvm`)
- API Gateway v2 HTTP request parsing
- Caller identity extraction from IAM authorizer context

#### Phase 98: Credential Vending (2026-01-25)
- STS AssumeRole with SourceIdentity stamping
- AWS container credentials format response
- IAM role templates for Lambda execution role and protected roles

#### Phase 99: Policy & Session Integration (2026-01-25)
- Policy evaluation before credential issuance
- Session tracking with DynamoDB integration
- Approval and break-glass override support
- Decision logging in JSON Lines format

#### Phase 100: API Gateway (2026-01-25)
- Multi-path routing (/ for credentials, /profiles for discovery)
- Profile discovery endpoint via SSM GetParametersByPath
- Lambda authorizer for instant session revocation
- LAMBDA_TVM_DEPLOYMENT.md with comprehensive setup guide
- Resource policy examples for VPC/IP restriction

#### Phase 101: Client Integration (2026-01-25)
- **Remote TVM flag**: `sentinel exec --remote-server <url>` connects to Lambda TVM
- **Container credentials**: Sets `AWS_CONTAINER_CREDENTIALS_FULL_URI` for SDK integration
- **SCP patterns**: Documentation for enforcing TVM-only access via AWS SCPs
- **Client examples**: Direct SDK integration without Sentinel CLI changes

#### Phase 102: Infrastructure as Code (2026-01-25)
- Added Terraform module for Lambda TVM deployment (`terraform/sentinel-tvm/`)
- Added Terraform module for protected roles (`terraform/sentinel-protected-role/`)
- Added CDK TypeScript example for Lambda TVM (`cdk/sentinel-tvm/`)
- Added cost optimization guide (`docs/LAMBDA_TVM_COSTS.md`)

#### Phase 103: Testing & Documentation (2026-01-25)
- Security regression tests for TVM bypass prevention
- End-to-end testing documentation (`docs/LAMBDA_TVM_TESTING.md`)
- Migration guide comparing CLI server vs Lambda TVM (`docs/LAMBDA_TVM_MIGRATION.md`)
- Complete v1.14 milestone documentation

**v1.14 Milestone Complete:** Lambda TVM provides server-side credential vending with enforced policy evaluation. Protected roles trust only the Lambda execution role, preventing client-side bypass.

## [1.16.0] - 2026-01-26

### Added

- Timing-safe bearer token comparison via `crypto/subtle.ConstantTimeCompare`
- AWS Secrets Manager integration for MDM API tokens with 1-hour client-side caching
- CI/CD security scanning with govulncheck, gosec, and Trivy in GitHub Actions
- DynamoDB KMS encryption by default for all Sentinel tables
- API rate limiting (100 req/min sliding window) for Lambda TVM and credential servers
- Error sanitization across all credential endpoints (log details, return generic messages)
- Security integration tests validating hardening patterns

## [1.15.0] - 2026-01-25

### Added

- Device posture schema with DeviceID (64-char hex) and PostureStatus types
- MDM Provider interface with Jamf Pro implementation for server-side device verification
- Lambda TVM queries MDM APIs on credential requests (fail-open default, fail-closed option)
- Policy device conditions: `require_mdm`, `require_encryption`, `require_mdm_compliant`
- Session device binding with DeviceID field for forensic correlation
- `sentinel device-sessions` command to list sessions by device
- `sentinel devices` command with anomaly detection (multi-user, high-profile-count)
- Device-based session revocation via `--device-id` flag

## [1.13.0] - 2026-01-24

### Added

- New `require_server_session` policy effect enforcing server mode with session tracking
- `session_table` field in policy rules for specifying session tracking table
- Actionable error messages guiding users from credential_process to exec --server --session-table
- `SENTINEL_SESSION_TABLE` environment variable for default session table in server mode
- Policy `session_table` field override for per-profile table configuration
- `sentinel audit untracked-sessions` command to detect credential usage bypassing session tracking via CloudTrail
- `sentinel audit session-compliance` command for per-profile compliance reporting against `require_server_session` policies
- `--since` flag for `server-sessions` command to filter by time range (e.g., 7d, 30d, 24h)
- CSV output format for `server-sessions` command (`--output csv`) for audit exports
- `source_identity` field in `server-sessions` JSON and CSV output for CloudTrail correlation

### Fixed

- Server mode now correctly uses SSO credential profile (`--aws-profile`) instead of policy target profile
  - Previously caused "InvalidClientTokenId" errors when using SSO credentials with `--server`
- Server mode subprocess now correctly uses container credentials
  - Prevents AWS SDK from reading `~/.aws/config` which could override container credentials
  - Fixes "InvalidClientTokenId" errors when using `--server` with existing AWS config files

### Changed

- Policy evaluation now checks session table presence for require_server_session effect
- `sentinel init sessions` output now prioritizes env var suggestion over CLI flag

## [1.12.3] - 2026-01-24

### Security

- **CRITICAL**: SourceIdentity now encodes approval status for AWS-side enforcement
  - New 4-part format: `sentinel:<user>:<approval-marker>:<request-id>`
  - Approval marker is either `direct` (no approval) or 8-char hex approval ID
  - Enables AWS SCPs to block direct access and require approved requests
  - Prevents bypassing `require_approval` policies via aws-vault or aws sso
  - Legacy 3-part format still supported for parsing (backward compatible)

### Changed

- SourceIdentity format updated from 3-part to 4-part
- All documentation updated to reflect new format

### Fixed

- `permissions check` now works with AWS SSO and assumed-role credentials
  - Automatically converts STS assumed-role ARNs to IAM role ARNs for SimulatePrincipalPolicy
  - Previously failed with "Invalid ARN" error for SSO users
- Fixed `--feature` flag on `permissions check` (was incorrectly named `--features`)

## [1.12.2] - 2026-01-23

### Security

- **CRITICAL**: Fixed `require_approval` policy effect not being enforced
  - Prior to this fix, policies with `effect: require_approval` would issue credentials without checking for an approved request
  - The approval check was only triggered for `effect: deny`, allowing `require_approval` to fall through to credential issuance
  - Affects: `sentinel credentials`, `sentinel exec`

### Added

- `--aws-profile` flag for SSO credential separation on credential issuance commands:
  - `sentinel request`
  - `sentinel credentials`
  - `sentinel exec`
  - `sentinel breakglass`

### Fixed

- DynamoDB reserved keyword error when querying by `status` in request list operations
- Bootstrap command now provisions DynamoDB tables even when SSM parameters have no changes

## [1.12.1] - 2026-01-23

### Fixed

- Optimistic locking bug in DynamoDB store Update methods
  - The `UpdatedAt` field was being modified before the condition check, causing all updates to fail with "concurrent modification detected"
  - Affects: `breakglass-close`, `approve`, `deny` commands

## [1.10.0] - 2026-01-20

### Added

- **Server Mode**: SentinelServer HTTP server with per-request policy evaluation
- `--server` flag for `sentinel exec` enabling AWS_CONTAINER_CREDENTIALS_FULL_URI integration
- CredentialMode-aware policies with `mode` condition (server, cli, credential_process)
- 15-minute default server sessions with MaxServerDuration policy caps
- Session tracking via DynamoDB with `--session-table` flag
- `require_server` policy effect for mandatory server mode enforcement
- `sentinel server-sessions` command to list tracked sessions
- `sentinel server-session` command to view session details
- `sentinel server-revoke` command to revoke active sessions
- `--server-duration` flag for configurable session duration

### Changed

- Policy evaluation now considers credential mode for mode-conditional rules
- Server mode credentials use short-lived sessions (15 min default) for rapid revocation

## [1.10.1] - 2026-01-19

### Added

- Test coverage for bootstrap command SSO credential loading via `--aws-profile`
- Test coverage for whoami command SSO credential loading via `--profile`
- SSO profile test patterns for future credential testing

## [1.9.0] - 2026-01-19

### Added

- `--aws-profile` flag for SSO credential loading on all infrastructure commands:
  - `sentinel list`, `sentinel check`, `sentinel approve`, `sentinel deny`
  - `sentinel breakglass-list`, `sentinel breakglass-check`, `sentinel breakglass-close`
  - `sentinel init bootstrap`, `sentinel init status`
  - `sentinel enforce plan`, `sentinel audit verify`
  - `sentinel permissions list`, `sentinel permissions check`
  - `sentinel config validate`

### Changed

- All commands now support SSO profile credential loading via AWS SDK shared config

## [1.8.0] - 2026-01-19

### Added

- `--auto-login` flag for automatic SSO re-authentication on expired tokens
- `--stdout` flag for credentials command to print credentials to stdout
- OIDCClient interface for testable OIDC token refresh operations
- WithAutoLogin generic retry wrapper for transparent SSO credential refresh
- GetSSOConfigForProfile helper for SSO configuration lookup

### Changed

- Improved SSO credential flow with automatic token refresh capability
- Better error messages for expired SSO sessions

## [1.7.1] - 2026-01-19

### Security

- **CRITICAL**: Fixed policy evaluation using OS username instead of AWS identity
  - Prior to this fix, policy rules matching on `users` would evaluate against the local OS username, not the AWS-authenticated identity
  - An attacker could bypass user-based policy restrictions by running Sentinel as a different local user
  - All commands now extract username from AWS STS GetCallerIdentity ARN
  - Affects: credential issuance, break-glass authorization, approval workflows, request submission

### Added

- `sentinel whoami` command to display AWS identity and policy username
- `GetAWSUsername()` and `GetAWSIdentity()` helpers in identity package
- `STSAPI` interface for testability of AWS identity operations

### Changed

- All CLI commands now use AWS identity instead of OS username
- Policy evaluation uses sanitized username from AWS ARN
- Break-glass and approval authorization use AWS identity

### Fixed

- Policy bypass via OS user impersonation (security-critical)

## [1.7.0] - 2026-01-18

### Added

- Permission schema mapping 10 features to required IAM actions
- `sentinel permissions` CLI with Terraform/CloudFormation/JSON output formats
- Feature auto-detection probing SSM and DynamoDB for minimal permissions
- `sentinel permissions check` for validating credentials via IAM SimulatePrincipalPolicy
- `sentinel init wizard` for interactive first-time setup
- Structured error types with 17 error codes and actionable suggestions
- `sentinel config validate` for pre-runtime configuration validation
- Quick start templates (basic, approvals, full) via `sentinel config generate`
- Streamlined onboarding documentation (QUICKSTART.md, PERMISSIONS.md)

## [1.6.0] - 2026-01-17

### Added

- Comprehensive test infrastructure with mock framework
- >80% test coverage on all Sentinel packages (94.1% average)
- Security regression test suite for denial path validation
- Performance benchmarks for policy evaluation and identity generation
- Pre-release validation with GO recommendation

## [1.5.0] - 2026-01-16

### Added

- IAM trust policy analysis and enforcement status reporting
- Trust policy template generation (Pattern A/B/C)
- CloudTrail session verification for SourceIdentity compliance
- `sentinel audit verify` command for unmanaged session detection
- Drift detection with `--require-sentinel` flag
- Enforcement documentation (ENFORCEMENT.md, ASSURANCE.md)

## [1.4.0] - 2026-01-16

### Added

- Bootstrap planner to analyze existing SSM parameters
- Automated SSM parameter creation for policy storage
- Sample policy generation based on profile configuration
- IAM policy document generation for least-privilege access
- `sentinel bootstrap` command for deployment automation
- `sentinel status` command for deployment health monitoring

## [1.3.0] - 2026-01-16

### Added

- Break-glass emergency access with mandatory justification
- Time-bounded break-glass sessions with automatic duration capping
- Break-glass rate limiting with cooldowns and quotas
- Break-glass notifications for immediate security awareness
- Break-glass policies for authorization control
- Post-incident review commands: `breakglass-list`, `breakglass-check`, `breakglass-close`

## [1.2.0] - 2026-01-15

### Added

- Request/approve workflow with DynamoDB state machine
- SNS and Webhook notification hooks for request lifecycle events
- Approval policies with auto-approve conditions and approver routing
- Approval audit trail logging for compliance
- CLI commands: `request`, `list`, `check`, `approve`, `deny`

## [1.1.0] - 2026-01-15

### Added

- SourceIdentity stamping on all role assumptions
- CloudTrail correlation via request-id in decision logs
- IAM trust policy enforcement patterns documented
- SCP enforcement patterns for organization-wide control

## [1.0.0] - 2026-01-14

### Added

- Policy evaluation before credential issuance
- AWS-native policy store (SSM Parameter Store)
- `credential_process` integration (`sentinel credentials --profile X`)
- Decision logging (user, profile, allow/deny, rule matched)
- `sentinel exec` command for direct invocation
- Compatibility with existing aws-vault profiles
