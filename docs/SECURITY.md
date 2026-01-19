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

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.7.x   | :white_check_mark: |
| 1.6.x   | :x:                |
| < 1.6   | :x:                |

Security updates are provided for the latest minor version only. Users are encouraged to upgrade to the latest version.
