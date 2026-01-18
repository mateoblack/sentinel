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

Bootstrap SSM policy parameters.

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
| `--region` | AWS region for SSM | No |
| `--generate-iam-policies` | Output IAM policy documents | No |
| `--json` | Machine-readable JSON output | No |
| `--description` | Description for generated policies | No |

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
```

---

### init status

Show current Sentinel policy status.

**Usage:**
```bash
sentinel init status [flags]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--policy-root` | SSM parameter path prefix | No (default: `/sentinel/policies`) |
| `--region` | AWS region for SSM | No |
| `--json` | Machine-readable JSON output | No |

**Examples:**

```bash
sentinel init status
sentinel init status --json
```

**Output:**

```
Sentinel Policy Status
======================

Policy Root: /sentinel/policies

Profiles:
  dev        v3  (last modified: 2026-01-15 14:30:22)
  staging    v1  (last modified: 2026-01-15 14:30:25)
  prod       v5  (last modified: 2026-01-16 09:15:00)

Total: 3 policy parameters
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
