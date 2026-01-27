# Security Policy

This security policy applies to public projects under the [ByteNess organization][gh-organization] on GitHub.

## Comprehensive Threat Model

For detailed security analysis of Sentinel, see the [STRIDE Threat Model](docs/STRIDE_THREAT_MODEL.md), which provides:

- 30+ analyzed threats across all STRIDE categories
- Risk scoring with impact/likelihood assessment
- Verification of existing security controls
- Priority recommendations for hardening

For security advisory history and detailed documentation, see [docs/SECURITY.md](docs/SECURITY.md).

## v2.0 Security Hardening Features

Version 2.0 incorporates comprehensive security hardening from v1.15-v1.18:

### Policy Integrity (v1.18)
- **KMS Policy Signing**: RSASSA_PSS_SHA_256 signatures prevent cache poisoning
- **Fail-Closed Enforcement**: Invalid or unsigned policies are rejected by VerifyingLoader
- **Signing Key Separation**: `kms:Sign` permission separate from SSM write access

### Authentication Hardening
- **Break-Glass MFA Enforcement**: TOTP/SMS verification required for emergency access
- **Unix Socket Process Authentication**: SO_PEERCRED binding prevents token interception
- **Timing-Safe Token Comparison**: `crypto/subtle.ConstantTimeCompare` for bearer tokens

### Audit and Integrity
- **HMAC-Signed Audit Logs**: SHA256-HMAC signatures enable tamper detection
- **CloudWatch Forwarding**: Centralized, tamper-evident log storage
- **DynamoDB State Validation**: Optimistic locking prevents concurrent modification

### Input Validation and Sanitization
- **Profile Name Validation**: ASCII-only, path traversal rejection, length limits
- **Command Injection Prevention**: All user inputs sanitized before use
- **Error Sanitization**: Internal details hidden, generic messages returned to clients

## Known Risks

The following risks are documented and require appropriate mitigation:

### 1. Optional Enforcement (Medium Risk)
- **Issue**: SCPs and IAM trust policies that enforce Sentinel-only access are optional
- **Impact**: Users with direct IAM credentials can bypass Sentinel policy evaluation
- **Mitigation**: Deploy SCPs requiring `sts:SourceIdentity` like `sentinel:*` (see [docs/SCP_REFERENCE.md](docs/SCP_REFERENCE.md))

### 2. Supply Chain Dependencies (Medium Risk)
- **Issue**: Third-party Go dependencies could be compromised
- **Impact**: Malicious code could exfiltrate credentials
- **Mitigation**: CI/CD security scanning (govulncheck, gosec, Trivy), dependency pinning, SBOM generation

### 3. Keychain Security Model (Low Risk)
- **Issue**: Keychain access equals full credential compromise
- **Impact**: Root/admin access to workstation can extract cached credentials
- **Mitigation**: Short credential lifetimes (1 hour recommended), `require_server` policy effect for production profiles

### 4. Environment Variable Exposure (Mitigable)
- **Issue**: Standard `exec` mode exports credentials to environment variables
- **Impact**: Credentials visible via `/proc/$PID/environ` on Linux
- **Mitigation**: Use `--server` mode for long-running processes, enforce `require_server` for sensitive profiles

## Security/Bugfix Versions

Security and bug fixes are generally provided only for the last minor version.
Fixes are released either as part of the next minor version or as an on-demand patch version.

Security fixes are given priority and might be enough to cause a new version to be released.

## Reporting a Vulnerability

We encourage responsible disclosure of security vulnerabilities.
If you find something suspicious, we encourage and appreciate your report!

### Ways to report

In order for the vulnerability reports to reach maintainers as soon as possible, the preferred way is to use the "Report a vulnerability" button under the "Security" tab of the associated GitHub project.
This creates a private communication channel between the reporter and the maintainers.

[gh-organization]: https://github.com/ByteNess
