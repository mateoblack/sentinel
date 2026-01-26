# Security

## Reporting Security Issues

If you discover a security vulnerability in Sentinel, please report it by:

1. **GitHub Security Advisory**: Open a private security advisory on [GitHub](https://github.com/byteness/aws-vault/security/advisories/new)
2. **Email**: Contact the maintainers directly at security@byteness.io

Please do not disclose security vulnerabilities publicly until they have been addressed.

## Security Advisories

### SENTINEL-2026-001: Policy Bypass via OS Username (Fixed in v1.7.1)

**Severity**: Critical
**Affected Versions**: v1.0.0 - v1.7.0
**Fixed Version**: v1.7.1

#### Summary

Sentinel versions prior to v1.7.1 used the local OS username (`os/user.Current()`) for policy evaluation instead of the AWS-authenticated identity. This allowed policy bypass through local user impersonation.

#### Impact

An attacker with local access could:
- Bypass user-based policy restrictions by running Sentinel as a different local user
- Invoke break-glass emergency access as unauthorized users
- Approve requests as unauthorized approvers
- Submit requests with spoofed requester identity

#### Root Cause

The credential issuance flow called `user.Current()` to get the username for policy evaluation. This returned the local OS username (e.g., from `/etc/passwd` on Linux) rather than the AWS-authenticated identity from STS GetCallerIdentity.

#### Fix

v1.7.1 replaces all `user.Current()` calls with `identity.GetAWSUsername()`, which:
1. Calls STS GetCallerIdentity to get the authenticated ARN
2. Parses the ARN to extract the username (IAM user name, assumed-role session name, etc.)
3. Sanitizes the username for policy matching

#### Affected Commands

- `sentinel credentials` - Policy evaluation for credential issuance
- `sentinel exec` - Policy evaluation for command execution
- `sentinel breakglass` - Authorization check for emergency access
- `sentinel breakglass-close` - Closer identity verification
- `sentinel breakglass-list` - User filtering
- `sentinel approve` - Approver identity verification
- `sentinel deny` - Denier identity verification
- `sentinel request` - Requester identity
- `sentinel list` - User filtering

#### Remediation

Upgrade to Sentinel v1.7.1 or later:

```bash
go install github.com/byteness/aws-vault/v7/cmd/sentinel@v1.7.1
```

#### Verification

After upgrading, verify the fix with:

```bash
# Should display your AWS identity, not OS username
sentinel whoami
```

The output should show your AWS ARN and the extracted policy username based on your AWS credentials.

#### Timeline

- 2026-01-18: Vulnerability identified during security review
- 2026-01-19: Fix developed and tested
- 2026-01-19: v1.7.1 released with fix

## v1.16 Security Hardening

Version 1.16 addresses findings from a comprehensive security audit with the following improvements:

### Timing Attack Mitigation (Phase 113)

Bearer token comparisons in credential servers now use `crypto/subtle.ConstantTimeCompare()` instead of direct string comparison, preventing timing-based oracle attacks.

**Affected Components:**
- Sentinel credential server (`sentinel/server.go`)
- ECS credential server (`server/ecsserver.go`)

### Secrets Management (Phase 114)

MDM API tokens migrated from environment variables to AWS Secrets Manager with client-side caching:

- **Cache TTL**: 1 hour (optimized for Lambda cold start patterns)
- **Backward Compatible**: Environment variable fallback with deprecation warning
- **Interface-based**: `SecretsLoader` interface enables testing and future extension

### CI/CD Security Scanning (Phase 115)

Automated security scanning integrated into CI/CD pipeline:

| Tool | Coverage | Schedule |
|------|----------|----------|
| govulncheck | Go vulnerability database | PR, Push, Weekly |
| gosec | Static application security testing | PR, Push, Weekly |
| Trivy | Container/filesystem scanning | PR, Push, Weekly |

### DynamoDB Encryption (Phase 116)

All DynamoDB tables use AWS-managed KMS encryption:

- Approval requests table
- Break-glass events table
- Server sessions table

### API Rate Limiting (Phase 117)

Rate limiting protects credential endpoints from abuse:

| Endpoint | Default Limit | Key |
|----------|---------------|-----|
| Lambda TVM | 100 req/min | IAM User ARN |
| Credential Server | 100 req/min | Remote Address |

Rate limit responses include RFC 7231 compliant `Retry-After` header.

### Error Sanitization (Phase 119)

All credential endpoints sanitize error responses to prevent information leakage:

- **Pattern**: Log detailed errors internally, return generic messages to clients
- **Preserved**: Rate limit retry-after and policy deny reasons (intentional user-facing)
- **Protected**: SSM paths, ARN parsing errors, MDM provider failures, credential retrieval errors

### Security Regression Tests

Comprehensive security regression tests validate:

- Timing-safe token comparison (AST verification)
- Rate limiter bypass resistance (concurrent access tests)
- Error message sanitization (no internal details leaked)
- Memory bounds on rate limiters

Run security tests locally:

```bash
go test ./... -run Security
```

## Security Best Practices

### Policy Configuration

1. **Principle of Least Privilege**: Configure policies to grant minimum necessary access
2. **Time-bounded Access**: Use time windows to restrict access to business hours
3. **Approval Requirements**: Require approval for sensitive profiles
4. **Break-glass Controls**: Configure rate limits and notifications for emergency access

### IAM Trust Policies

Enforce SourceIdentity requirements on IAM roles to ensure all sessions are created through Sentinel:

```json
{
  "Condition": {
    "StringLike": {
      "sts:SourceIdentity": "sentinel:*"
    }
  }
}
```

See [ENFORCEMENT.md](ENFORCEMENT.md) for trust policy patterns.

### Audit and Monitoring

1. **Enable Decision Logging**: Configure `--log-file` for all Sentinel commands
2. **CloudTrail Integration**: Correlate Sentinel logs with CloudTrail events
3. **Session Verification**: Use `sentinel audit verify` to detect unmanaged sessions
4. **Drift Detection**: Enable `--require-sentinel` flag for compliance checks

### Deployment Security

1. **SSM Parameter Store**: Store policies in SSM with appropriate IAM permissions
2. **DynamoDB Encryption**: Enable encryption at rest for approval/break-glass tables
3. **SNS Notifications**: Configure immediate alerts for break-glass events
4. **IAM Boundaries**: Use permission boundaries to limit Sentinel's AWS access

### Security Scanning

Sentinel integrates with multiple security scanning tools for comprehensive coverage:

1. **CI/CD Integration**: All PRs are automatically scanned for vulnerabilities before merge
2. **Weekly Scheduled Scans**: Automated weekly scans catch newly disclosed vulnerabilities
3. **GitHub Security Tab**: View all security alerts at the [GitHub Security tab](https://github.com/byteness/aws-vault/security)
4. **Local Scanning**: Run `govulncheck ./...` to scan locally before committing

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.16.x  | :white_check_mark: |
| 1.15.x  | :x:                |
| 1.14.x  | :x:                |
| < 1.14  | :x:                |

Security updates are provided for the latest minor version only. Users are encouraged to upgrade to the latest version.

## Dependency Security

### Automated Scanning

Sentinel uses automated security scanning in CI/CD to continuously monitor for vulnerabilities:

| Tool | Trigger | Purpose |
|------|---------|---------|
| [govulncheck](.github/workflows/govulncheck.yml) | PR, Push, Weekly | Go vulnerability database scanning |
| [gosec](.github/workflows/goseccheck.yml) | PR, Push, Weekly | Static application security testing (SAST) |
| [Trivy](.github/workflows/trivy-scan.yml) | PR, Push, Weekly | Container and filesystem vulnerability scanning |

All security scan results are uploaded to GitHub Security tab for centralized vulnerability tracking.

### Last Audit

**Date**: 2026-01-26
**Result**: Clean - no vulnerabilities found
**govulncheck**: All dependencies at patched versions

### Dependency Sources

All direct dependencies in `go.mod` are:

- **Trusted Sources**: Official AWS SDK, established Go standard library extensions, and vetted community libraries
- **Actively Maintained**: All dependencies have commits within the last 12 months
- **Security Patched**: Free of known vulnerabilities as of the last audit date

Key security-relevant dependencies:

| Package | Current Version | Notes |
|---------|-----------------|-------|
| golang.org/x/crypto | v0.47.0 | Patched against SSH vulnerabilities (>= v0.45.0 required) |
| github.com/aws/aws-sdk-go-v2 | v1.41.x | Official AWS SDK, regularly updated |
| github.com/aws/aws-lambda-go | v1.47.0 | Official AWS Lambda runtime |

### Local Vulnerability Scanning

Developers can run local vulnerability scans:

```bash
# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Scan the codebase
govulncheck ./...
```

### Reporting Dependency Vulnerabilities

If you discover a vulnerability in a Sentinel dependency, please:

1. Check if the dependency has a newer patched version available
2. Report via [GitHub Security Advisory](https://github.com/byteness/aws-vault/security/advisories/new) if it affects Sentinel
3. For upstream vulnerabilities, also report to the dependency maintainer
