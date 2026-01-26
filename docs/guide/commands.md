# CLI Reference

Complete reference for all Sentinel commands.

## Global Flags

These flags apply to all commands:

| Flag | Description | Default |
|------|-------------|---------|
| `--debug` | Show debugging output | false |
| `--backend` | Secret backend to use | System default |
| `--keychain` | Name of macOS keychain | `aws-vault` |
| `--secret-service-collection` | Name of secret-service collection | `awsvault` |

## Credential Operations

### credentials

Retrieve AWS credentials after policy evaluation. Outputs JSON for use with `credential_process`.

**Usage:**
```bash
sentinel credentials --profile PROFILE --policy-parameter PATH [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--profile` | Name of the AWS profile | Yes |
| `--policy-parameter` | SSM parameter path (e.g., `/sentinel/policies/default`) | Yes |
| `--region` | AWS region for SSM | No |
| `--duration` / `-d` | Session duration | No (default: 1h) |
| `--no-session` / `-n` | Skip GetSessionToken | No |
| `--log-file` | Path to write decision logs | No |
| `--log-stderr` | Write decision logs to stderr | No |
| `--require-sentinel` | Warn if role lacks trust policy enforcement | No |
| `--auto-login` | Automatically trigger SSO login when credentials are expired or missing | No |
| `--stdout` | Print SSO URL instead of opening browser (used with --auto-login) | No |
| `--aws-profile` | AWS profile for SSO credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# Basic usage
sentinel credentials --profile dev --policy-parameter /sentinel/policies/dev

# With logging
sentinel credentials --profile prod --policy-parameter /sentinel/policies/prod --log-file /var/log/sentinel/decisions.log

# With drift detection
sentinel credentials --profile prod --policy-parameter /sentinel/policies/prod --require-sentinel
```

**Output (JSON):**

```json
{
  "Version": 1,
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "SessionToken": "...",
  "Expiration": "2026-01-17T11:30:00Z"
}
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Credentials issued successfully |
| 1 | Access denied or error |

---

### exec

Execute a command with policy-gated AWS credentials.

> **Security Note:** Users can run ANY command with vended credentials. Sentinel controls which credentials users can obtain (via policy evaluation), not which commands they execute. Grant Sentinel access only to users you trust with the full scope of the profile's IAM permissions. See [Trust Model](../SECURITY.md#trust-model) for details.

**Usage:**
```bash
sentinel exec --profile PROFILE --policy-parameter PATH [flags] [-- command args...]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--profile` | Name of the AWS profile | Yes |
| `--policy-parameter` | SSM parameter path | Yes |
| `--region` | AWS region for SSM | No |
| `--duration` / `-d` | Session duration | No (default: 1h) |
| `--no-session` / `-n` | Skip GetSessionToken | No |
| `--log-file` | Path to write decision logs | No |
| `--log-stderr` | Write decision logs to stderr | No |
| `--aws-profile` | AWS profile for SSO credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# Start a shell
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev

# Run a specific command
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev -- aws s3 ls

# With custom duration
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev -d 2h -- terraform plan
```

**Environment Variables Set:**

| Variable | Value |
|----------|-------|
| `AWS_ACCESS_KEY_ID` | Access key ID |
| `AWS_SECRET_ACCESS_KEY` | Secret access key |
| `AWS_SESSION_TOKEN` | Session token |
| `AWS_CREDENTIAL_EXPIRATION` | ISO8601 expiration time |
| `AWS_SENTINEL` | Profile name (prevents nesting) |

#### Environment Variables

| Variable | Description |
|----------|-------------|
| `SENTINEL_SESSION_TABLE` | Default DynamoDB table for session tracking in server mode. Overridden by `--session-table` flag. |

**Example:**
```bash
export SENTINEL_SESSION_TABLE=sentinel-sessions
sentinel exec --server --profile prod -- aws s3 ls
# Session tracking enabled automatically
```

#### Server Mode

Server mode starts a local credential server that evaluates policy on every credential request. This enables real-time revocation - changing policy immediately affects subsequent credential requests.

**Flags:**
- `--server, -s` - Enable server mode (starts credential server instead of env vars)
- `--server-port PORT` - Port for credential server (default: auto-assigned)
- `--server-duration` - Session duration in server mode (default: 15m for rapid revocation)
- `--session-table TABLE` - DynamoDB table for session tracking (optional, enables revocation). Falls back to `SENTINEL_SESSION_TABLE` env var.
- `--lazy` - Skip credential prefetch on server startup
- `--auto-login` - Automatically trigger SSO login when credentials are expired or missing
- `--stdout` - Print SSO URL instead of opening browser (used with --auto-login)

**How it works:**

1. Server listens on localhost with a random auth token
2. Sets `AWS_CONTAINER_CREDENTIALS_FULL_URI` for the subprocess
3. Each credential request from the subprocess triggers policy evaluation
4. Credentials are served or denied based on current policy

**Example:**

```bash
# Start terraform with server mode credentials
sentinel exec --server --profile production -- terraform plan

# Server mode with explicit port
sentinel exec --server --server-port 9999 --profile staging -- aws s3 ls
```

**Server mode vs standard exec:**

| Aspect | Standard exec | Server mode |
|--------|--------------|-------------|
| Policy evaluation | Once at startup | Every credential request |
| Revocation timing | Next exec invocation | Immediate (next request) |
| Credential delivery | Environment variables | HTTP credential server |
| Credential lifetime | Full session duration | Can be shorter TTL |
| Use case | Short-lived commands | Long-running processes |

**When to use server mode:**

- Long-running processes that need revocation capability
- Profiles requiring real-time access control
- Compliance scenarios requiring per-request audit
- Terraform/CDK operations on sensitive infrastructure

**Incompatible flags:**
- `--server` cannot be combined with `--no-session` (server requires session credentials)

---

## Access Request Commands

### request

Submit an access request for approval.

**Usage:**
```bash
sentinel request --profile PROFILE --justification TEXT --request-table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--profile` | AWS profile to request access to | Yes |
| `--justification` | Reason for access (10-500 chars) | Yes |
| `--request-table` | DynamoDB table name | Yes |
| `--duration` | How long access is needed (max 8h) | No (default: 1h) |
| `--region` | AWS region for DynamoDB | No |
| `--aws-profile` | AWS profile for SSO credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# Submit a request
sentinel request \
  --profile prod \
  --justification "Deploy hotfix for incident INC-123" \
  --request-table sentinel-requests

# With custom duration
sentinel request \
  --profile prod \
  --justification "Investigate production issue" \
  --duration 4h \
  --request-table sentinel-requests
```

**Output (JSON):**

```json
{
  "request_id": "a1b2c3d4e5f67890",
  "profile": "prod",
  "status": "pending",
  "expires_at": "2026-01-17T18:30:00Z",
  "auto_approved": false
}
```

---

### list

List access requests.

**Usage:**
```bash
sentinel list --request-table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--request-table` | DynamoDB table name | Yes |
| `--requester` | Filter by requester (default: current user) | No |
| `--status` | Filter by status (pending, approved, denied, expired, cancelled) | No |
| `--profile` | Filter by AWS profile | No |
| `--limit` | Maximum results | No (default: 100) |
| `--region` | AWS region for DynamoDB | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# List your requests
sentinel list --request-table sentinel-requests

# List pending requests (all users)
sentinel list --request-table sentinel-requests --status pending

# List requests for specific profile
sentinel list --request-table sentinel-requests --profile prod
```

**Output (JSON):**

```json
{
  "requests": [
    {
      "id": "a1b2c3d4e5f67890",
      "profile": "prod",
      "status": "pending",
      "requester": "alice",
      "created_at": "2026-01-17T10:30:00Z",
      "expires_at": "2026-01-17T18:30:00Z"
    }
  ]
}
```

---

### check

Check status of a specific access request.

**Usage:**
```bash
sentinel check REQUEST_ID --request-table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--request-table` | DynamoDB table name | Yes |
| `--region` | AWS region for DynamoDB | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
sentinel check a1b2c3d4e5f67890 --request-table sentinel-requests
```

**Output (JSON):**

```json
{
  "id": "a1b2c3d4e5f67890",
  "requester": "alice",
  "profile": "prod",
  "justification": "Deploy hotfix for INC-123",
  "duration": "1h",
  "status": "pending",
  "created_at": "2026-01-17T10:30:00Z",
  "updated_at": "2026-01-17T10:30:00Z",
  "expires_at": "2026-01-17T18:30:00Z"
}
```

---

### approve

Approve a pending access request.

**Usage:**
```bash
sentinel approve REQUEST_ID --request-table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--request-table` | DynamoDB table name | Yes |
| `--comment` | Optional approval comment | No |
| `--region` | AWS region for DynamoDB | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# Approve a request
sentinel approve a1b2c3d4e5f67890 --request-table sentinel-requests

# With comment
sentinel approve a1b2c3d4e5f67890 --request-table sentinel-requests --comment "Verified incident ticket"
```

**Output (JSON):**

```json
{
  "id": "a1b2c3d4e5f67890",
  "profile": "prod",
  "status": "approved",
  "approver": "bob",
  "approver_comment": "Verified incident ticket",
  "updated_at": "2026-01-17T10:35:00Z"
}
```

---

### deny

Deny a pending access request.

**Usage:**
```bash
sentinel deny REQUEST_ID --request-table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--request-table` | DynamoDB table name | Yes |
| `--comment` | Optional denial comment | No |
| `--region` | AWS region for DynamoDB | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
sentinel deny a1b2c3d4e5f67890 --request-table sentinel-requests --comment "Use staging instead"
```

**Output (JSON):**

```json
{
  "id": "a1b2c3d4e5f67890",
  "profile": "prod",
  "status": "denied",
  "approver": "bob",
  "approver_comment": "Use staging instead",
  "updated_at": "2026-01-17T10:35:00Z"
}
```

---

## Break-Glass Commands

### breakglass

Invoke emergency break-glass access.

**Usage:**
```bash
sentinel breakglass --profile PROFILE --reason-code CODE --justification TEXT --breakglass-table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--profile` | AWS profile for break-glass | Yes |
| `--reason-code` | Reason category: incident, maintenance, security, recovery, other | Yes |
| `--justification` | Detailed explanation (20-1000 chars) | Yes |
| `--breakglass-table` | DynamoDB table name | Yes |
| `--duration` | Emergency access duration (max 4h) | No (default: 1h) |
| `--region` | AWS region for DynamoDB | No |
| `--aws-profile` | AWS profile for SSO credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# Invoke break-glass for incident
sentinel breakglass \
  --profile prod \
  --reason-code incident \
  --justification "Production database outage, need immediate access to investigate" \
  --breakglass-table sentinel-breakglass

# With custom duration
sentinel breakglass \
  --profile prod \
  --reason-code maintenance \
  --justification "Emergency maintenance window for critical patch" \
  --duration 2h \
  --breakglass-table sentinel-breakglass
```

**Output (JSON):**

```json
{
  "event_id": "a1b2c3d4e5f67890",
  "profile": "prod",
  "reason_code": "incident",
  "status": "active",
  "expires_at": "2026-01-17T11:30:00Z",
  "request_id": "b2c3d4e5f6789012"
}
```

---

### breakglass-list

List break-glass events.

**Usage:**
```bash
sentinel breakglass-list --breakglass-table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--breakglass-table` | DynamoDB table name | Yes |
| `--invoker` | Filter by invoker (default: current user) | No |
| `--status` | Filter by status (active, closed, expired) | No |
| `--profile` | Filter by AWS profile | No |
| `--limit` | Maximum results | No (default: 100) |
| `--region` | AWS region for DynamoDB | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# List your break-glass events
sentinel breakglass-list --breakglass-table sentinel-breakglass

# List active events
sentinel breakglass-list --breakglass-table sentinel-breakglass --status active

# List events for specific profile
sentinel breakglass-list --breakglass-table sentinel-breakglass --profile prod
```

**Output (JSON):**

```json
{
  "events": [
    {
      "id": "a1b2c3d4e5f67890",
      "profile": "prod",
      "status": "active",
      "invoker": "alice",
      "reason_code": "incident",
      "created_at": "2026-01-17T10:30:00Z",
      "expires_at": "2026-01-17T11:30:00Z"
    }
  ]
}
```

---

### breakglass-check

Check details of a break-glass event.

**Usage:**
```bash
sentinel breakglass-check EVENT_ID --breakglass-table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--breakglass-table` | DynamoDB table name | Yes |
| `--region` | AWS region for DynamoDB | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
sentinel breakglass-check a1b2c3d4e5f67890 --breakglass-table sentinel-breakglass
```

**Output (JSON):**

```json
{
  "id": "a1b2c3d4e5f67890",
  "invoker": "alice",
  "profile": "prod",
  "reason_code": "incident",
  "justification": "Production database outage, need immediate access",
  "duration": "1h",
  "status": "active",
  "created_at": "2026-01-17T10:30:00Z",
  "updated_at": "2026-01-17T10:30:00Z",
  "expires_at": "2026-01-17T11:30:00Z",
  "request_id": "b2c3d4e5f6789012"
}
```

---

### breakglass-close

Close an active break-glass event.

**Usage:**
```bash
sentinel breakglass-close EVENT_ID --reason TEXT --breakglass-table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--reason` | Reason for closing early | Yes |
| `--breakglass-table` | DynamoDB table name | Yes |
| `--region` | AWS region for DynamoDB | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
sentinel breakglass-close a1b2c3d4e5f67890 \
  --reason "Incident resolved, no longer need access" \
  --breakglass-table sentinel-breakglass
```

**Output (JSON):**

```json
{
  "id": "a1b2c3d4e5f67890",
  "profile": "prod",
  "status": "closed",
  "closed_by": "alice",
  "closed_reason": "Incident resolved, no longer need access",
  "updated_at": "2026-01-17T10:45:00Z"
}
```

---

## Infrastructure Commands

### init bootstrap

Bootstrap SSM policy parameters and optionally provision DynamoDB tables.

**Usage:**
```bash
sentinel init bootstrap --profile PROFILE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--profile` | AWS profile to bootstrap (repeatable) | Yes |
| `--plan` | Show plan without applying | No |
| `--yes` / `-y` | Auto-approve, skip confirmation | No |
| `--policy-root` | SSM parameter path prefix | No (default: `/sentinel/policies`) |
| `--region` | AWS region for SSM and DynamoDB | No |
| `--generate-iam-policies` | Output IAM policy documents | No |
| `--json` | Machine-readable JSON output | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |
| `--with-approvals` | Also create approval requests table | No |
| `--with-breakglass` | Also create break-glass events table | No |
| `--with-sessions` | Also create server sessions table | No |
| `--all` | Enable all optional infrastructure | No |

**Examples:**

```bash
# Preview changes
sentinel init bootstrap --profile dev --plan

# Bootstrap single profile
sentinel init bootstrap --profile dev

# Bootstrap multiple profiles
sentinel init bootstrap --profile dev --profile staging --profile prod

# Auto-approve with IAM policies
sentinel init bootstrap --profile dev --yes --generate-iam-policies

# Bootstrap with approval workflow table
sentinel init bootstrap --profile dev --with-approvals --region us-east-1

# Bootstrap with all optional infrastructure
sentinel init bootstrap --profile dev --all --region us-east-1
```

---

### init status

Show current Sentinel policy status and optionally DynamoDB table status.

**Usage:**
```bash
sentinel init status [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--policy-root` | SSM parameter path prefix | No (default: `/sentinel/policies`) |
| `--region` | AWS region for SSM and DynamoDB | No |
| `--json` | Machine-readable JSON output | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |
| `--check-tables` | Check DynamoDB table status (requires --region) | No |

**Examples:**

```bash
sentinel init status
sentinel init status --json
sentinel init status --check-tables --region us-east-1
```

**Output:**

```
Sentinel Status
===============

Policy Parameters (/sentinel/policies):
  dev        v3  (2026-01-15 14:30:22)
  staging    v1  (2026-01-15 14:30:25)
  prod       v5  (2026-01-16 09:15:00)

Total: 3 policy parameters
```

---

### init approvals

Provision the DynamoDB table for approval workflow requests.

**Usage:**
```bash
sentinel init approvals --region REGION [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--table` | DynamoDB table name | `sentinel-requests` |
| `--region` | AWS region for DynamoDB (required) | - |
| `--aws-profile` | AWS profile for credentials | Default chain |
| `--plan` | Preview without creating | false |
| `--yes` / `-y` | Skip confirmation | false |
| `--generate-iam` | Output IAM policy document | false |

**Examples:**

```bash
# Preview table creation
sentinel init approvals --plan --region us-east-1

# Create with confirmation prompt
sentinel init approvals --region us-east-1

# Auto-approve for scripting
sentinel init approvals --region us-east-1 --yes

# Generate IAM policy
sentinel init approvals --generate-iam --region us-east-1
```

---

### init breakglass

Provision the DynamoDB table for break-glass emergency access events.

**Usage:**
```bash
sentinel init breakglass --region REGION [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--table` | DynamoDB table name | `sentinel-breakglass` |
| `--region` | AWS region for DynamoDB (required) | - |
| `--aws-profile` | AWS profile for credentials | Default chain |
| `--plan` | Preview without creating | false |
| `--yes` / `-y` | Skip confirmation | false |
| `--generate-iam` | Output IAM policy document | false |

**Examples:**

```bash
sentinel init breakglass --region us-east-1 --yes
```

---

### init sessions

Provision the DynamoDB table for server mode session tracking.

**Usage:**
```bash
sentinel init sessions --region REGION [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--table` | DynamoDB table name | `sentinel-sessions` |
| `--region` | AWS region for DynamoDB (required) | - |
| `--aws-profile` | AWS profile for credentials | Default chain |
| `--plan` | Preview without creating | false |
| `--yes` / `-y` | Skip confirmation | false |
| `--generate-iam` | Output IAM policy document | false |

**Examples:**

```bash
sentinel init sessions --region us-east-1 --yes
```

---

## Enforcement Commands

### enforce plan

Analyze role trust policies for Sentinel enforcement.

**Usage:**
```bash
sentinel enforce plan --role ROLE_ARN [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--role` | Role ARN to analyze (repeatable) | Yes |
| `--region` | AWS region for IAM | No |
| `--json` | Machine-readable JSON output | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# Analyze single role
sentinel enforce plan --role=arn:aws:iam::123456789012:role/ProductionAdmin

# Analyze multiple roles
sentinel enforce plan \
  --role=arn:aws:iam::123456789012:role/ProductionAdmin \
  --role=arn:aws:iam::123456789012:role/ProductionReadOnly
```

**Output:**

```
Sentinel Enforcement Analysis
=============================

Role: arn:aws:iam::123456789012:role/ProductionAdmin
Status: FULL ✓
Level: trust-policy

Summary
-------
Full enforcement:    1 role(s)
Partial enforcement: 0 role(s)
No enforcement:      0 role(s)
```

**Status Values:**

| Status | Symbol | Meaning |
|--------|--------|---------|
| FULL | ✓ | All statements require Sentinel SourceIdentity |
| PARTIAL | ⚠ | Some statements require Sentinel, others don't |
| NONE | ✗ | No Sentinel enforcement |
| ERROR | - | Failed to analyze |

---

### enforce generate trust-policy

Generate IAM trust policy JSON with Sentinel conditions.

**Usage:**
```bash
sentinel enforce generate trust-policy --pattern PATTERN --principal ARN [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--pattern` | Pattern: `any-sentinel`, `specific-users`, or `migration` | Yes |
| `--principal` | AWS principal ARN | Yes |
| `--users` | Username for `specific-users` pattern (repeatable) | For `specific-users` |
| `--legacy-principal` | Legacy principal ARN for `migration` pattern | For `migration` |

**Examples:**

```bash
# Any Sentinel credentials
sentinel enforce generate trust-policy \
  --pattern=any-sentinel \
  --principal=arn:aws:iam::123456789012:root

# Specific users
sentinel enforce generate trust-policy \
  --pattern=specific-users \
  --principal=arn:aws:iam::123456789012:root \
  --users=alice --users=bob

# Migration (Sentinel OR legacy)
sentinel enforce generate trust-policy \
  --pattern=migration \
  --principal=arn:aws:iam::123456789012:root \
  --legacy-principal=arn:aws:iam::123456789012:role/LegacyRole
```

---

## Audit Commands

### audit verify

Verify CloudTrail sessions for Sentinel enforcement.

**Usage:**
```bash
sentinel audit verify --start TIME --end TIME [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--start` | Start of time window (RFC3339) | Yes |
| `--end` | End of time window (RFC3339) | Yes |
| `--role` | Filter by role ARN | No |
| `--user` | Filter by username | No |
| `--region` | AWS region for CloudTrail | No |
| `--json` | Machine-readable JSON output | No |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# Last hour
sentinel audit verify \
  --start=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ) \
  --end=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Specific time window
sentinel audit verify \
  --start=2026-01-15T00:00:00Z \
  --end=2026-01-16T00:00:00Z

# Filter by role
sentinel audit verify \
  --start=2026-01-15T00:00:00Z \
  --end=2026-01-16T00:00:00Z \
  --role=arn:aws:iam::123456789012:role/ProductionAdmin
```

**Output:**

```
CloudTrail Session Verification
================================

Time Window: 2026-01-15T00:00:00Z to 2026-01-16T00:00:00Z

Summary
-------
Total sessions:       42
Sentinel sessions:    38 (90.5%)
Non-Sentinel:         4

Issues (4)
----------
[WARNING] Session assumed role without Sentinel SourceIdentity
  Event ID: abc123...
  Time: 2026-01-15T14:32:00Z

Result: 4 issue(s) found
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All sessions verified |
| 1 | Issues found |

### audit untracked-sessions

Detect credential usage that bypassed session tracking by cross-referencing CloudTrail AssumeRole events with DynamoDB session records.

**Usage:**
```bash
sentinel audit untracked-sessions --since DURATION --region REGION --table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--since` | How far back to search (e.g., 7d, 24h, 30m) | Yes |
| `--until` | End of search window (default: now) | No |
| `--region` | AWS region for CloudTrail and DynamoDB | Yes |
| `--table` | DynamoDB table name for sessions | Yes |
| `--role` | Filter by role ARN | No |
| `--profile` | Filter by AWS profile | No |
| `--json` | Output in JSON format | No |
| `--aws-profile` | AWS profile for credentials | No |

**Examples:**

```bash
# Check last 7 days
sentinel audit untracked-sessions \
  --since 7d \
  --region us-east-1 \
  --table sentinel-sessions

# Check specific time window (last 24h excluding last hour)
sentinel audit untracked-sessions \
  --since 24h \
  --until 1h \
  --region us-east-1 \
  --table sentinel-sessions

# Filter by role
sentinel audit untracked-sessions \
  --since 7d \
  --region us-east-1 \
  --table sentinel-sessions \
  --role arn:aws:iam::123456789012:role/ProductionAdmin
```

**Output:**

```
Untracked Session Detection
===========================

Time Window: 2026-01-17T00:00:00Z to 2026-01-24T00:00:00Z

Summary
-------
Total events:     42
Tracked:          38 (90.5%)
Untracked:        4
Orphaned:         0

Untracked Sessions (4)
----------------------
[no_source_identity] 2026-01-20T14:32:00Z
  Event ID: abc123...
  Role: arn:aws:iam::123456789012:role/ProductionAdmin
  Source IP: 10.0.1.50
  Reason: No SourceIdentity set on AssumeRole

Result: 4 untracked session(s) detected - compliance gap
```

**Categories:**

| Category | Description |
|----------|-------------|
| `no_source_identity` | AssumeRole without any SourceIdentity |
| `non_sentinel_format` | SourceIdentity doesn't match `sentinel:*:*:*` format |
| `orphaned` | Sentinel SourceIdentity but no matching DynamoDB session |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All sessions tracked |
| 1 | Untracked sessions found |

### audit session-compliance

Report session tracking compliance by profile, comparing actual tracking against `require_server_session` policy requirements.

**Usage:**
```bash
sentinel audit session-compliance --since DURATION --region REGION --table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--since` | How far back to search (e.g., 7d, 24h, 30m) | Yes |
| `--until` | End of search window (default: now) | No |
| `--region` | AWS region for CloudTrail and DynamoDB | Yes |
| `--table` | DynamoDB table name for sessions | Yes |
| `--profile` | Check specific profile only | No |
| `--policy` | Policy file for requirement checking | No |
| `--json` | Output in JSON format | No |
| `--aws-profile` | AWS profile for credentials | No |

**Examples:**

```bash
# Check all profiles for last 7 days
sentinel audit session-compliance \
  --since 7d \
  --region us-east-1 \
  --table sentinel-sessions

# Check specific profile with policy file
sentinel audit session-compliance \
  --since 7d \
  --region us-east-1 \
  --table sentinel-sessions \
  --profile prod-admin \
  --policy /path/to/policy.yaml
```

**Output:**

```
Session Compliance Report
=========================

Time Window: 2026-01-17T00:00:00Z to 2026-01-24T00:00:00Z

Profile Compliance
------------------
Profile               Policy Required  Tracked     Untracked   Compliance
dev                   No               15          3           83.3%
staging               No               22          0           100.0%
prod-admin            Yes              18          2           90.0% !
prod-readonly         Yes              45          0           100.0%

Summary
-------
Profiles with require_server_session: 2
Fully compliant profiles: 3
Profiles with gaps: 1

Result: 1 profile(s) with compliance gaps
```

The `!` marker indicates profiles with compliance gaps (untracked sessions where policy requires tracking).

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All required profiles compliant |
| 1 | Compliance gaps found |

---

## Permissions Commands

### permissions / permissions list

Show IAM permissions required by Sentinel features. Running `sentinel permissions` without a subcommand defaults to `permissions list`.

**Usage:**
```bash
sentinel permissions [flags]
sentinel permissions list [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--format` | Output format: human, json, terraform, cloudformation (or cf) | human |
| `--subsystem` | Filter by subsystem (core, credentials, approvals, breakglass, notifications, audit, enforce, bootstrap) | - |
| `--feature` | Filter by specific feature | - |
| `--required-only` | Exclude optional features (notify_sns, notify_webhook) | false |
| `--detect` | Auto-detect configured features and show only required permissions | false |
| `--region` | AWS region for detection (only with --detect) | - |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | - |

**Examples:**

```bash
# Show all permissions (human readable)
sentinel permissions

# Output as JSON IAM policy
sentinel permissions --format json

# Output as Terraform data source
sentinel permissions --format terraform

# Output as CloudFormation
sentinel permissions --format cloudformation

# Filter by subsystem
sentinel permissions --subsystem approvals

# Filter by feature
sentinel permissions --feature policy_load

# Auto-detect configured features
sentinel permissions --detect

# Exclude optional features
sentinel permissions --required-only
```

**Output (human format):**

```
Sentinel IAM Permissions
========================

Feature: policy_load (core)
  Service: ssm
  Actions:
    - ssm:GetParameter
    - ssm:GetParameters
    - ssm:GetParametersByPath
  Resource: arn:aws:ssm:*:*:parameter/sentinel/policies/*

Feature: credential_issue (credentials)
  Service: sts
  Actions:
    - sts:AssumeRole
  Resource: arn:aws:iam::*:role/*
...
```

---

### permissions check

Validate AWS credentials have required permissions.

**Usage:**
```bash
sentinel permissions check [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--auto-detect` | Auto-detect configured features and check only those | false |
| `--feature` | Check specific feature(s), comma-separated | - |
| `--output` | Output format: human, json | human |
| `--aws-region` | AWS region for API calls | - |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | - |

**Examples:**

```bash
# Check all features
sentinel permissions check

# Auto-detect and check
sentinel permissions check --auto-detect

# Check specific features
sentinel permissions check --feature policy_load,credential_issue

# JSON output
sentinel permissions check --output json
```

**Output (human format):**

```
Checking permissions for 3 features...

# policy_load
  # ssm:GetParameter on arn:aws:ssm:*:*:parameter/sentinel/policies/*
  # ssm:GetParameters on arn:aws:ssm:*:*:parameter/sentinel/policies/*

# credential_issue
  # sts:AssumeRole on arn:aws:iam::*:role/*

X approval_workflow
  X dynamodb:PutItem on arn:aws:dynamodb:*:*:table/sentinel-requests - Access Denied

Summary: 2 passed, 1 failed, 0 error
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All permission checks passed |
| 1 | One or more checks failed or errored |

---

## Config Commands

### config validate

Validate Sentinel configuration files.

**Usage:**
```bash
sentinel config validate [paths...] [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--path` / `-p` | Local file to validate (repeatable) | - |
| `--ssm` | SSM parameter to load and validate (repeatable) | - |
| `--type` | Config type: policy, approval, breakglass, ratelimit, bootstrap (auto-detect if not specified) | - |
| `--output` | Output format: human, json | human |
| `--region` | AWS region for SSM operations | - |
| `--aws-profile` | AWS profile for SSM credentials (optional, uses default chain if not specified) | - |

**Examples:**

```bash
# Validate local file
sentinel config validate policy.yaml

# Validate multiple files
sentinel config validate policy.yaml approval.yaml breakglass.yaml

# Validate with explicit type
sentinel config validate --path policy.yaml --type policy

# Validate SSM parameter
sentinel config validate --ssm /sentinel/policies/dev

# Validate both local and SSM
sentinel config validate policy.yaml --ssm /sentinel/policies/prod

# JSON output
sentinel config validate policy.yaml --output json
```

**Output (human format):**

```
Validating 2 configurations...

# policy.yaml (policy)
  Valid

X approval.yaml (approval)
  Errors:
    - rules[0].conditions: missing required field 'profiles'
  Suggestions:
    - add profiles field to specify which AWS profiles this rule applies to

Summary: 1 valid, 1 invalid (1 errors, 0 warnings)
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | All configurations valid (warnings don't affect exit code) |
| 1 | One or more configurations have errors |

---

### config generate

Generate Sentinel configuration templates.

**Usage:**
```bash
sentinel config generate --template TEMPLATE --profile PROFILE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--template` / `-t` | Template type: basic, approvals, full | Yes |
| `--profile` / `-p` | AWS profile to include (repeatable) | Yes |
| `--user` / `-u` | User for approvers/break-glass (repeatable) | For approvals/full |
| `--output-dir` / `-o` | Directory to write config files (omit for stdout) | No |
| `--json` | Output as JSON instead of YAML | No |

**Templates:**

| Template | Includes |
|----------|----------|
| `basic` | Access policy only |
| `approvals` | Access policy + approval policy |
| `full` | Access policy + approval + break-glass + rate limit |

**Examples:**

```bash
# Generate basic config for dev profile
sentinel config generate --template basic --profile dev

# Generate full config with users
sentinel config generate --template full --profile dev --profile prod --user alice --user bob

# Write to directory
sentinel config generate --template full --profile dev --user alice --output-dir ./sentinel-config

# JSON output
sentinel config generate --template basic --profile dev --json
```

**Output (stdout):**

```yaml
# Access Policy (policy.yaml)
# ===========================
version: "1"
rules:
  - name: allow-dev-access
    effect: allow
    conditions:
      profiles:
        - dev
    reason: Allowed by Sentinel policy

  - name: default-deny
    effect: deny
    conditions: {}
    reason: No matching allow rule
```

**Output (--output-dir):**

```
Generated 4 config files in ./sentinel-config:
  + policy.yaml
  + approval.yaml
  + breakglass.yaml
  + ratelimit.yaml
```

---

## Init Wizard

### init wizard

Interactive setup wizard for Sentinel configuration.

**Usage:**
```bash
sentinel init wizard [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--profile` | Pre-select profiles (repeatable) | - |
| `--feature` | Pre-select features (repeatable) | - |
| `--region` | AWS region | - |
| `--skip-detection` | Skip auto-detection step | false |
| `--format` | Output format: human, json | human |

**Interactive Mode:**

When run without `--profile` and `--feature` flags, the wizard runs interactively:

```bash
sentinel init wizard
```

**Output:**

```
Step 1/6: Welcome
======================================================
Welcome to Sentinel!

This wizard will help you configure Sentinel for your AWS environment.

Step 2/6: Profile Selection
======================================================
Found 3 AWS profiles in ~/.aws/config:

  [1] dev
  [2] staging
  [3] prod

Which profiles should Sentinel manage? (comma-separated, e.g., 1,2,3 or 'all'): 1,3

Selected: dev, prod

Step 3/6: Feature Selection
======================================================
Which features do you need?

  [1] policy_load        - Load policies from SSM (required)
  [2] credential_issue   - Issue credentials with SourceIdentity (required)
  [3] approval_workflow  - Request/approve access flow
  [4] breakglass         - Emergency access bypass
  [5] audit_verify       - CloudTrail session verification
  [6] enforce_analyze    - IAM trust policy analysis
  [7] bootstrap_plan     - Bootstrap planning
  [8] bootstrap_apply    - Bootstrap SSM parameter creation
  [9] notify_sns         - SNS notifications (optional)

Select features (comma-separated, e.g., 1,2,3 or 'all'): 1,2,3,4
...
```

**Non-Interactive Mode:**

For scripting, provide both `--profile` and `--feature`:

```bash
sentinel init wizard \
  --profile dev \
  --profile prod \
  --feature policy_load \
  --feature credential_issue \
  --feature approval_workflow \
  --region us-west-2
```

**JSON Output:**

```bash
sentinel init wizard \
  --profile dev \
  --feature policy_load \
  --feature credential_issue \
  --format json
```

```json
{
  "profiles": ["dev"],
  "features": ["policy_load", "credential_issue"],
  "region": "us-west-2",
  "iam_policy": {
    "Version": "2012-10-17",
    "Statement": [...]
  },
  "sample_policies": {
    "dev": "version: \"1\"\nrules:\n  ..."
  },
  "next_steps": [
    "1. Create the IAM policy and attach to your Sentinel user/role",
    "2. Save the sample policies to SSM:\n   sentinel init bootstrap --profile dev --region us-west-2",
    "3. Verify permissions:\n   sentinel permissions check --auto-detect",
    "4. Configure credential_process in ~/.aws/config:..."
  ]
}
```

---

## Identity Commands

### whoami

Show current AWS identity and the policy username used for Sentinel policy evaluation.

**Usage:**
```bash
sentinel whoami [flags]
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--region` | AWS region for STS operations | - |
| `--profile` | AWS profile for credentials (uses SSO credential provider if profile is SSO-configured) | - |
| `--json` | Output in JSON format | false |

**Examples:**

```bash
# Show current identity
sentinel whoami

# With specific profile
sentinel whoami --profile dev

# JSON output
sentinel whoami --json
```

**Output (human format):**

```
AWS Identity
============

ARN:             arn:aws:iam::123456789012:user/alice
Account:         123456789012
Identity Type:   iam-user
Raw Username:    alice
Policy Username: alice

The policy username is used for matching against Sentinel policy rules.
```

**Output (JSON):**

```json
{
  "arn": "arn:aws:iam::123456789012:user/alice",
  "account_id": "123456789012",
  "identity_type": "iam-user",
  "raw_username": "alice",
  "policy_username": "alice"
}
```

---

## Server Session Commands

These commands manage server sessions when using `sentinel exec --server` with session tracking enabled via `--session-table`.

### server-sessions

List server sessions.

**Usage:**
```bash
sentinel server-sessions --region REGION --table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--region` | AWS region for DynamoDB | Yes |
| `--table` | DynamoDB table name for sessions | Yes |
| `--status` | Filter by status (active, revoked, expired) | No |
| `--user` | Filter by user | No |
| `--profile` | Filter by AWS profile served | No |
| `--since` | Only show sessions started within this duration (e.g., 7d, 30d, 24h) | No |
| `--limit` | Maximum number of results | No (default: 100) |
| `--output` | Output format (human, json, csv) | No (default: human) |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
# List your sessions
sentinel server-sessions --region us-east-1 --table sentinel-sessions

# List active sessions
sentinel server-sessions --region us-east-1 --table sentinel-sessions --status active

# List sessions for specific profile
sentinel server-sessions --region us-east-1 --table sentinel-sessions --profile prod

# List sessions from the last 7 days
sentinel server-sessions --region us-east-1 --table sentinel-sessions --since 7d

# List active sessions from the last 24 hours
sentinel server-sessions --region us-east-1 --table sentinel-sessions --since 24h --status active

# JSON output
sentinel server-sessions --region us-east-1 --table sentinel-sessions --output json

# CSV export for audit reporting
sentinel server-sessions --region us-east-1 --table sentinel-sessions --since 30d --output csv > sessions.csv
```

**Output (JSON):**

```json
{
  "sessions": [
    {
      "id": "a1b2c3d4e5f67890",
      "user": "alice",
      "profile": "prod",
      "status": "active",
      "started_at": "2026-01-20T10:30:00Z",
      "last_access_at": "2026-01-20T10:45:00Z",
      "expires_at": "2026-01-20T10:45:00Z",
      "request_count": 15,
      "server_instance_id": "b2c3d4e5f6789012",
      "source_identity": "sentinel:alice:a1b2c3d4"
    }
  ]
}
```

**Output (CSV):**

```csv
id,user,profile,status,started_at,last_access_at,expires_at,request_count,server_instance_id,source_identity
a1b2c3d4e5f67890,alice,prod,active,2026-01-20T10:30:00Z,2026-01-20T10:45:00Z,2026-01-20T11:30:00Z,15,b2c3d4e5f6789012,sentinel:alice:a1b2c3d4
```

---

### server-session

Show details of a specific server session.

**Usage:**
```bash
sentinel server-session SESSION_ID --region REGION --table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--region` | AWS region for DynamoDB | Yes |
| `--table` | DynamoDB table name for sessions | Yes |
| `--output` | Output format (human, json) | No (default: human) |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
sentinel server-session a1b2c3d4e5f67890 --region us-east-1 --table sentinel-sessions

# JSON output
sentinel server-session a1b2c3d4e5f67890 --region us-east-1 --table sentinel-sessions --output json
```

**Output (JSON):**

```json
{
  "id": "a1b2c3d4e5f67890",
  "user": "alice",
  "profile": "prod",
  "status": "active",
  "started_at": "2026-01-20T10:30:00Z",
  "last_access_at": "2026-01-20T10:45:00Z",
  "expires_at": "2026-01-20T10:45:00Z",
  "request_count": 15,
  "server_instance_id": "b2c3d4e5f6789012"
}
```

---

### server-revoke

Revoke an active server session. Revoked sessions will be denied credentials on their next request.

**Usage:**
```bash
sentinel server-revoke SESSION_ID --reason TEXT --region REGION --table TABLE [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--reason` | Reason for revocation | Yes |
| `--region` | AWS region for DynamoDB | Yes |
| `--table` | DynamoDB table name for sessions | Yes |
| `--aws-profile` | AWS profile for credentials (optional, uses default chain if not specified) | No |

**Examples:**

```bash
sentinel server-revoke a1b2c3d4e5f67890 \
  --reason "Suspicious activity detected" \
  --region us-east-1 \
  --table sentinel-sessions
```

**Output (JSON):**

```json
{
  "id": "a1b2c3d4e5f67890",
  "profile": "prod",
  "status": "revoked",
  "revoked_by": "bob",
  "revoked_reason": "Suspicious activity detected",
  "revoked_at": "2026-01-20T10:50:00Z"
}
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Session revoked successfully |
| 1 | Error (session not found, already revoked, or API error) |

---

## Shell Commands

### shell init

Generate shell wrapper functions for all Sentinel profiles discovered from SSM Parameter Store. This command simplifies daily usage by creating shell functions that wrap `sentinel exec` with the appropriate profile and policy-parameter flags.

**Usage:**
```bash
sentinel shell init [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--policy-root` | SSM parameter path prefix for policies | No (default: `/sentinel/policies`) |
| `--region` | AWS region for SSM operations | No |
| `--aws-profile` | AWS profile for credentials | No |
| `--format` | Output format: bash, zsh | No (default: auto-detect from `$SHELL`) |
| `--include-server` | Also generate `-server` variants for real-time revocation mode | No (default: false) |

**Examples:**

```bash
# Basic usage - evaluate output directly
eval "$(sentinel shell init)"

# Add to shell profile for permanent setup
echo 'eval "$(sentinel shell init)"' >> ~/.bashrc   # bash
echo 'eval "$(sentinel shell init)"' >> ~/.zshrc   # zsh

# Generate with server mode variants for real-time revocation
eval "$(sentinel shell init --include-server)"

# Specify output format explicitly
sentinel shell init --format zsh

# Use custom policy root
sentinel shell init --policy-root /custom/policies

# Combine flags
eval "$(sentinel shell init --include-server --policy-root /mycompany/sentinel/policies)"
```

**Output:**

The command generates shell functions and completion registrations. Example output for a profile named "production":

```bash
# Sentinel shell functions - generated by sentinel shell init
# Add to your .bashrc/.zshrc: eval "$(sentinel shell init)"

sentinel-production() {
    sentinel exec --profile production --policy-parameter /sentinel/policies/production -- "$@"
}

# With --include-server flag, also generates:
sentinel-production-server() {
    sentinel exec --server --profile production --policy-parameter /sentinel/policies/production -- "$@"
}

# Completion registrations (bash)
if [[ -n "${BASH_VERSION:-}" ]]; then
    complete -o default -o bashdefault sentinel-production
fi

# Completion registrations (zsh)
if [[ -n "${ZSH_VERSION:-}" ]]; then
    compdef _command_names sentinel-production
fi
```

**Generated Functions:**

| Function Pattern | Description |
|------------------|-------------|
| `sentinel-{profile}` | Standard exec wrapper with env var credentials |
| `sentinel-{profile}-server` | Server mode wrapper (only with `--include-server`) |

The function names are sanitized: non-alphanumeric characters in profile names are replaced with hyphens.

**Usage After Setup:**

```bash
# Instead of:
sentinel exec --profile production --policy-parameter /sentinel/policies/production -- aws s3 ls

# Just use:
sentinel-production aws s3 ls

# With server mode (if --include-server was used):
sentinel-production-server terraform plan
```

---

## Policy Commands

Commands for managing Sentinel policies stored in AWS SSM Parameter Store. These commands enable a GitOps-style workflow for policy management with validation, diff previews, and cryptographic signing.

### Policy Workflow

The recommended workflow for policy changes:

```bash
# 1. Pull current policy from SSM
sentinel policy pull myprofile -o policy.yaml

# 2. Edit the policy locally
$EDITOR policy.yaml

# 3. Validate syntax locally (no AWS credentials needed)
sentinel policy validate policy.yaml

# 4. Preview changes before pushing
sentinel policy diff myprofile policy.yaml

# 5. Push the updated policy
sentinel policy push myprofile policy.yaml

# 6. Optional: Sign policy for integrity verification
sentinel policy sign policy.yaml --key-id alias/sentinel-signing -o policy.sig
sentinel policy push myprofile policy.yaml --sign --key-id alias/sentinel-signing
```

---

### policy pull

Fetch policy YAML from SSM Parameter Store.

**Usage:**
```bash
sentinel policy pull PROFILE [flags]
```

**Arguments:**

| Argument | Description | Required |
|----------|-------------|----------|
| `PROFILE` | AWS profile name to pull policy for | Yes |

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--policy-root` | SSM parameter path prefix for policies | No (default: `/sentinel/policies`) |
| `--policy-parameter` | Explicit SSM parameter path (overrides profile-based path) | No |
| `--output` / `-o` | Output file path (omit for stdout) | No |
| `--region` | AWS region for SSM operations | No |
| `--aws-profile` | AWS profile for SSM credentials | No |

**Examples:**

```bash
# Pull policy to stdout
sentinel policy pull myprofile

# Save to file
sentinel policy pull myprofile -o policy.yaml

# Use specific region
sentinel policy pull myprofile --region us-west-2 -o policy.yaml

# Use explicit SSM path
sentinel policy pull myprofile --policy-parameter /custom/path/policy

# Pipeline usage: pull, transform with yq, inspect
sentinel policy pull myprofile | yq '.rules[] | select(.effect == "allow")'
```

**Output:**

When using `-o`, the policy YAML is written to the specified file and a confirmation is printed to stderr:
```
Policy written to policy.yaml
```

When outputting to stdout, only the raw YAML is printed (suitable for piping).

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Policy retrieved successfully |
| 1 | Error (policy not found, AWS credentials issue, etc.) |

---

### policy push

Validate and upload policy to SSM Parameter Store.

**Usage:**
```bash
sentinel policy push PROFILE INPUT_FILE [flags]
```

**Arguments:**

| Argument | Description | Required |
|----------|-------------|----------|
| `PROFILE` | Target profile name for the policy | Yes |
| `INPUT_FILE` | Path to policy YAML file | Yes |

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--policy-root` | SSM parameter path prefix for policies | No (default: `/sentinel/policies`) |
| `--policy-parameter` | Explicit SSM parameter path (overrides profile-based path) | No |
| `--region` | AWS region for SSM operations | No |
| `--aws-profile` | AWS profile for SSM credentials | No |
| `--no-backup` | Skip fetching existing policy as backup | No |
| `--force` / `-f` | Skip confirmation prompt | No |
| `--sign` | Sign policy with KMS before pushing | No |
| `--key-id` | KMS key ARN or alias for signing (required with `--sign`) | With `--sign` |

**Examples:**

```bash
# Push with confirmation prompt
sentinel policy push myprofile policy.yaml

# Push without confirmation (CI/CD)
sentinel policy push myprofile policy.yaml --force

# Push with signing
sentinel policy push myprofile policy.yaml --sign --key-id alias/sentinel-signing

# Push to specific region
sentinel policy push myprofile policy.yaml --region us-west-2

# Push without fetching backup
sentinel policy push myprofile policy.yaml --no-backup
```

**Interactive Confirmation:**

Without `--force`, the command shows a confirmation prompt:
```
Existing policy found (version 3)

Parameter path: /sentinel/policies/myprofile
Status: updating existing policy

Proceed? [y/N]: y
Policy successfully pushed to /sentinel/policies/myprofile
```

**With Signing:**

When `--sign` is specified, the policy is signed and the signature is stored in a separate SSM parameter:
```
Policy successfully pushed to /sentinel/policies/myprofile
Signature pushed to /sentinel/policies/myprofile/signature
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Policy pushed successfully (or cancelled by user) |
| 1 | Error (validation failed, AWS credentials issue, etc.) |

---

### policy diff

Show unified diff between local file and SSM policy.

**Usage:**
```bash
sentinel policy diff PROFILE INPUT_FILE [flags]
```

**Arguments:**

| Argument | Description | Required |
|----------|-------------|----------|
| `PROFILE` | Target profile name for the policy | Yes |
| `INPUT_FILE` | Path to local policy YAML file | Yes |

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--policy-root` | SSM parameter path prefix for policies | No (default: `/sentinel/policies`) |
| `--policy-parameter` | Explicit SSM parameter path (overrides profile-based path) | No |
| `--region` | AWS region for SSM operations | No |
| `--aws-profile` | AWS profile for SSM credentials | No |
| `--no-color` | Disable colorized output | No |

**Examples:**

```bash
# Show diff with colors
sentinel policy diff myprofile policy.yaml

# Show diff without colors (for piping/logging)
sentinel policy diff myprofile policy.yaml --no-color

# CI/CD: Check if changes exist
if sentinel policy diff myprofile policy.yaml --no-color > /dev/null 2>&1; then
  echo "No changes"
else
  echo "Changes detected"
fi
```

**Output:**

Unified diff format with optional ANSI colors:
```diff
--- a//sentinel/policies/myprofile
+++ b/policy.yaml
@@ -1,5 +1,6 @@
 version: "1"
 rules:
   - name: allow-dev-access
     effect: allow
+    conditions:
+      time_window: business_hours
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | No changes (local matches remote) |
| 1 | Changes exist (scripting-friendly for CI/CD change detection) |

**Note:** Exit code 1 for "changes exist" is intentional for CI/CD scripting. This allows using the exit code to detect whether a policy needs to be pushed.

---

### policy validate

Validate local policy YAML without AWS credentials.

**Usage:**
```bash
sentinel policy validate INPUT_FILE [flags]
```

**Arguments:**

| Argument | Description | Required |
|----------|-------------|----------|
| `INPUT_FILE` | Path to policy YAML file | Yes |

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--quiet` / `-q` | Only show errors, no success message | No |

**Examples:**

```bash
# Validate with success message
sentinel policy validate policy.yaml
# Output: Policy is valid

# Quiet mode (for scripts)
sentinel policy validate policy.yaml -q
# No output on success

# Validate in CI/CD pipeline
if sentinel policy validate policy.yaml -q; then
  echo "Validation passed"
else
  echo "Validation failed"
  exit 1
fi

# Validate multiple files
for f in policies/*.yaml; do
  if ! sentinel policy validate "$f" -q; then
    echo "Invalid: $f"
    exit 1
  fi
done
```

**Output:**

On success (without `--quiet`):
```
Policy is valid
```

On failure:
```
Error: invalid policy: rules[0].conditions: missing required field 'profiles'

Suggestion: fix the policy YAML and try again
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Policy is valid |
| 1 | Policy is invalid or file not found |

---

### policy sign

Sign a policy file with KMS using RSASSA_PSS_SHA_256.

**Usage:**
```bash
sentinel policy sign POLICY_FILE --key-id KEY [flags]
```

**Arguments:**

| Argument | Description | Required |
|----------|-------------|----------|
| `POLICY_FILE` | Path to policy YAML file to sign | Yes |

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--key-id` | KMS key ARN or alias for signing | Yes |
| `--output` / `-o` | Output file for signature (omit for stdout) | No |
| `--region` | AWS region for KMS operations | No |
| `--aws-profile` | AWS profile for KMS credentials | No |

**Examples:**

```bash
# Sign and output to stdout
sentinel policy sign policy.yaml --key-id alias/sentinel-signing

# Sign and save to file
sentinel policy sign policy.yaml --key-id alias/sentinel-signing -o policy.sig

# Sign with specific region
sentinel policy sign policy.yaml --key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 --region us-east-1
```

**Output (JSON):**

```json
{
  "signature": "base64-encoded-signature...",
  "metadata": {
    "key_id": "alias/sentinel-signing",
    "algorithm": "RSASSA_PSS_SHA_256",
    "signed_at": "2026-01-20T10:30:00Z",
    "policy_hash": "sha256:abcd1234..."
  }
}
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Policy signed successfully |
| 1 | Error (invalid policy, KMS key issue, permissions, etc.) |

---

### policy verify

Verify a detached KMS signature against a policy file.

**Usage:**
```bash
sentinel policy verify POLICY_FILE --key-id KEY --signature FILE [flags]
```

**Arguments:**

| Argument | Description | Required |
|----------|-------------|----------|
| `POLICY_FILE` | Path to policy YAML file to verify | Yes |

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--key-id` | KMS key ARN or alias for verification | Yes |
| `--signature` / `-s` | Signature file (JSON format from sign command) | Yes |
| `--region` | AWS region for KMS operations | No |
| `--aws-profile` | AWS profile for KMS credentials | No |

**Examples:**

```bash
# Verify signature
sentinel policy verify policy.yaml --key-id alias/sentinel-signing -s policy.sig

# Verify with explicit key ARN
sentinel policy verify policy.yaml \
  --key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
  -s policy.sig

# CI/CD: Verify before deploying
if sentinel policy verify policy.yaml --key-id alias/sentinel-signing -s policy.sig; then
  sentinel policy push myprofile policy.yaml --force
else
  echo "Signature verification failed!"
  exit 1
fi
```

**Output:**

On success:
```
Signature valid
```

On failure:
```
Signature invalid: policy content does not match signature
  Expected hash: sha256:abcd1234...
  Computed hash: sha256:efgh5678...
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Signature is valid |
| 1 | Signature is invalid or verification error |

---

### CI/CD Integration Examples

**GitHub Actions - Policy Validation:**

```yaml
- name: Validate policies
  run: |
    for policy in policies/*.yaml; do
      sentinel policy validate "$policy" -q
    done
```

**GitHub Actions - Change Detection:**

```yaml
- name: Check for policy changes
  id: diff
  run: |
    if sentinel policy diff production policies/prod.yaml --no-color; then
      echo "changed=false" >> $GITHUB_OUTPUT
    else
      echo "changed=true" >> $GITHUB_OUTPUT
    fi

- name: Push if changed
  if: steps.diff.outputs.changed == 'true'
  run: sentinel policy push production policies/prod.yaml --force
```

**Signed Policy Workflow:**

```bash
# Developer signs policy
sentinel policy sign policy.yaml --key-id alias/sentinel-signing -o policy.sig
git add policy.yaml policy.sig
git commit -m "Update production policy"
git push

# CI/CD verifies signature before deploying
sentinel policy verify policy.yaml --key-id alias/sentinel-signing -s policy.sig
sentinel policy push production policy.yaml --force
```
