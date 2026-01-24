# Policy Reference

Complete YAML schema documentation for all Sentinel policy types.

## Policy Types Overview

| Policy Type | Purpose | Location |
|-------------|---------|----------|
| Access Policy | Controls who can access which profiles | SSM Parameter Store |
| Approval Policy | Defines approvers and auto-approve rules | Application config |
| Break-Glass Policy | Controls who can invoke break-glass | Application config |
| Rate Limit Policy | Prevents break-glass abuse | Application config |

## Access Policy

Access policies define rules for credential issuance. Each rule specifies conditions and an effect (allow, deny, or require_approval).

### Schema

```yaml
version: "1"
rules:
  - name: string              # Rule identifier
    effect: string            # allow | deny | require_approval | require_server | require_server_session
    session_table: string     # DynamoDB table for session tracking (optional, used with require_server_session)
    conditions:               # All conditions must match
      profiles: [string]      # AWS profile names (empty = any)
      users: [string]         # Usernames (empty = any)
      mode: [string]          # Credential modes: server, cli, credential_process (empty = any)
      time:                   # Time constraints (optional)
        days: [string]        # Weekdays (empty = any)
        hours:                # Hour range (optional)
          start: "HH:MM"      # 24-hour format
          end: "HH:MM"        # 24-hour format
        timezone: string      # IANA timezone (optional)
    reason: string            # Explanation for logging
```

### Effects

| Effect | Description |
|--------|-------------|
| `allow` | Grant access - issue credentials |
| `deny` | Reject access - no credentials issued |
| `require_approval` | Request must be approved before access |
| `require_server` | Grant access only via server mode (`sentinel exec --server`) |
| `require_server_session` | Grant access only via server mode with session tracking (`sentinel exec --server --session-table`) |

### require_server Effect

The `require_server` effect enforces server mode for credential delivery. This is the recommended pattern for sensitive profiles requiring:

- **Instant revocation**: Server mode evaluates policy per-request, so policy changes take effect immediately
- **Per-request audit**: Every credential fetch is logged with policy decision
- **Short-lived credentials**: Server mode enforces shorter credential TTLs (default 15 minutes)

**Example:**

```yaml
version: "1"
rules:
  # Production requires server mode for instant revocation capability
  - name: prod-requires-server
    effect: require_server
    conditions:
      profiles: [production]
    reason: Production requires server mode for instant revocation

  # Development allows any mode
  - name: dev-allow
    effect: allow
    conditions:
      profiles: [development]
```

**Behavior:**

| Request Mode | Effect |
|--------------|--------|
| `sentinel exec --server prod -- aws s3 ls` | Allow |
| `sentinel exec prod -- aws s3 ls` | Deny with message: "policy requires server mode" |
| `sentinel credentials --profile prod` | Deny with message: "policy requires server mode" |

**Note:** `require_server` denials cannot be bypassed by approval workflows or break-glass. If you need emergency access that bypasses server mode, use a separate rule with `allow` effect that checks for break-glass context.

### require_server_session

The `require_server_session` effect allows access only when credentials are issued via server mode with session tracking enabled. This is the strictest enforcement mode, ensuring all credentials are both policy-evaluated per-request AND tracked for revocation.

```yaml
policies:
  - name: prod-requires-tracked-sessions
    match:
      profile: prod-*
    effect: require_server_session
    session_table: sentinel-sessions  # Optional: specify table (otherwise uses --session-table flag)
```

**Behavior:**
- If `--server` flag AND `--session-table` flag are provided: access allowed (credentials issued)
- If `--server` flag without `--session-table`: denied with "Policy requires session tracking"
- If neither `--server` nor `--session-table`: denied with "Policy requires server mode with session tracking"
- `credential_process` mode always denied (doesn't support sessions)

#### Session Table Configuration

The `session_table` field specifies which DynamoDB table to use for session tracking:

```yaml
policies:
  - match:
      profile: prod
    effect: require_server_session
    session_table: prod-sentinel-sessions
```

**Precedence order (highest to lowest):**
1. Policy `session_table` field (from matched rule)
2. `--session-table` CLI flag
3. `SENTINEL_SESSION_TABLE` environment variable
4. Empty (no session tracking - will fail if require_server_session)

The policy-specified table overrides CLI and environment settings, ensuring security policies
can enforce specific tables for compliance or multi-table architectures.

**Use case:**
Enforce that all production access is:
1. Per-request policy evaluated (server mode)
2. Trackable in DynamoDB (for revocation and audit)
3. Visible in `sentinel server-sessions` output

**Example:**

```yaml
version: "1"
rules:
  # Production requires server mode with full session tracking
  - name: prod-requires-tracked-sessions
    effect: require_server_session
    conditions:
      profiles: [production]
    reason: Production requires tracked server sessions for compliance
    session_table: sentinel-sessions

  # Staging requires server mode only (no session tracking)
  - name: staging-requires-server
    effect: require_server
    conditions:
      profiles: [staging]
    reason: Staging requires server mode for instant revocation

  # Development allows any mode
  - name: dev-allow
    effect: allow
    conditions:
      profiles: [development]
```

**Comparison with require_server:**

| Effect | Server Mode | Session Table | Use Case |
|--------|-------------|---------------|----------|
| `require_server` | Required | Optional | Instant revocation via policy changes |
| `require_server_session` | Required | Required | Full tracking with revocation and audit trail |

**Note:** Like `require_server`, `require_server_session` denials cannot be bypassed by approval workflows or break-glass.

### Complete Example

```yaml
version: "1"
rules:
  # Allow dev team access to dev profile
  - name: dev-team-access
    effect: allow
    conditions:
      profiles:
        - dev
      users:
        - alice
        - bob
        - charlie
    reason: Development team access

  # Allow staging access during business hours
  - name: staging-business-hours
    effect: allow
    conditions:
      profiles:
        - staging
      users:
        - alice
        - bob
      time:
        days:
          - monday
          - tuesday
          - wednesday
          - thursday
          - friday
        hours:
          start: "09:00"
          end: "18:00"
        timezone: "America/New_York"
    reason: Staging access during business hours

  # Require approval for production
  - name: prod-requires-approval
    effect: require_approval
    conditions:
      profiles:
        - prod
    reason: Production access requires approval

  # Deny all other access
  - name: default-deny
    effect: deny
    conditions: {}
    reason: No matching rule - access denied
```

### Time Window Fields

**days** - Weekdays when the rule applies:
- `monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday`, `sunday`
- Empty list means any day

**hours** - Time of day when the rule applies:
- `start`: Beginning of window (inclusive), 24-hour format
- `end`: End of window (exclusive), 24-hour format
- Omit for any time of day

**timezone** - IANA timezone for time evaluation:
- Examples: `America/New_York`, `Europe/London`, `UTC`
- Omit to use local system timezone

### mode

The `mode` condition restricts when a rule applies based on how credentials are being requested. This enables different policies for server mode (per-request evaluation) versus CLI mode (one-time evaluation).

**Valid modes:**
- `server` - Credentials served via credential server (`sentinel exec --server`)
- `cli` - Credentials served via exec command (`sentinel exec` without `--server`)
- `credential_process` - Credentials served via credential_process (`sentinel credentials`)

**Omit for wildcard:** If `mode` is not specified, the rule matches any mode (equivalent to specifying all three modes).

**Examples:**

```yaml
# Only allow server mode (for real-time revocation control)
rules:
  - name: prod-server-only
    effect: allow
    conditions:
      profiles: [production]
      mode: [server]

# Allow both CLI and credential_process (one-time evaluation modes)
rules:
  - name: dev-one-time
    effect: allow
    conditions:
      profiles: [development]
      mode: [cli, credential_process]

# Allow any mode (omit mode condition)
rules:
  - name: staging-any-mode
    effect: allow
    conditions:
      profiles: [staging]
      # No mode condition = matches any mode
```

**Security considerations:**

Server mode enables real-time policy enforcement because each credential request is evaluated against the current policy. This provides:

1. **Instant revocation**: Change policy and new credential requests are immediately affected
2. **Per-request audit**: Every credential fetch is logged with policy decision
3. **Short-lived credentials**: Server can enforce shorter credential TTLs

For sensitive profiles requiring instant revocation capability, use `mode: [server]` to ensure credentials are only issued through the credential server.

---

## Approval Policy

Approval policies define who can approve requests and conditions for auto-approval.

### Schema

```yaml
version: "1"
rules:
  - name: string              # Rule identifier
    profiles: [string]        # Matching profiles (empty = any)
    approvers: [string]       # Users who can approve (required)
    auto_approve:             # Auto-approval conditions (optional)
      users: [string]         # Users who can self-approve (empty = any)
      time:                   # Time window for auto-approve
        days: [string]
        hours:
          start: "HH:MM"
          end: "HH:MM"
        timezone: string
      max_duration: duration  # Max duration for auto-approve (e.g., "1h")
```

### Complete Example

```yaml
version: "1"
rules:
  # Production access - requires specific approvers
  - name: prod-approval
    profiles:
      - prod
    approvers:
      - security-team
      - ops-lead
    auto_approve:
      users:
        - ops-lead
      time:
        days:
          - monday
          - tuesday
          - wednesday
          - thursday
          - friday
        hours:
          start: "09:00"
          end: "17:00"
        timezone: "America/New_York"
      max_duration: 1h

  # Staging access - team leads can approve
  - name: staging-approval
    profiles:
      - staging
    approvers:
      - team-lead-alice
      - team-lead-bob

  # Default rule - any manager can approve
  - name: default-approval
    profiles: []  # Matches any profile
    approvers:
      - engineering-manager
      - security-team
```

### Auto-Approve Conditions

Auto-approve allows requests to be automatically approved when all conditions match:

| Field | Description | Default |
|-------|-------------|---------|
| `users` | Users who can self-approve | Empty = any user |
| `time` | Time window for auto-approval | Omit = any time |
| `max_duration` | Maximum request duration | Omit = no limit |

All conditions must match for auto-approval to trigger.

---

## Break-Glass Policy

Break-glass policies control who can invoke emergency access and under what conditions.

### Schema

```yaml
version: "1"
rules:
  - name: string                    # Rule identifier
    profiles: [string]              # Matching profiles (empty = any)
    users: [string]                 # Authorized users (required)
    allowed_reason_codes: [string]  # Allowed reasons (empty = any)
    time:                           # Time restrictions (optional)
      days: [string]
      hours:
        start: "HH:MM"
        end: "HH:MM"
      timezone: string
    max_duration: duration          # Max break-glass duration
```

### Reason Codes

| Code | Description |
|------|-------------|
| `incident` | Production incident response |
| `maintenance` | Emergency maintenance |
| `security` | Security incident response |
| `recovery` | Disaster recovery |
| `other` | Other emergency (requires detailed justification) |

### Complete Example

```yaml
version: "1"
rules:
  # On-call engineers can break-glass for incidents
  - name: oncall-incident-access
    profiles:
      - prod
    users:
      - oncall-alice
      - oncall-bob
      - oncall-charlie
    allowed_reason_codes:
      - incident
      - security
      - recovery
    max_duration: 4h

  # Security team - full break-glass
  - name: security-team-access
    profiles: []  # Any profile
    users:
      - security-admin
      - security-lead
    allowed_reason_codes: []  # Any reason
    max_duration: 4h

  # DBAs - maintenance only during off-hours
  - name: dba-maintenance
    profiles:
      - prod-database
    users:
      - dba-alice
      - dba-bob
    allowed_reason_codes:
      - maintenance
    time:
      days:
        - saturday
        - sunday
      hours:
        start: "00:00"
        end: "06:00"
      timezone: "America/New_York"
    max_duration: 2h
```

---

## Rate Limit Policy

Rate limit policies prevent break-glass abuse by enforcing cooldowns and quotas.

### Schema

```yaml
version: "1"
rules:
  - name: string              # Rule identifier
    profiles: [string]        # Matching profiles (empty = any)
    cooldown: duration        # Min time between events
    max_per_user: int         # Max events per user in quota_window
    max_per_profile: int      # Max events per profile in quota_window
    quota_window: duration    # Time window for quota counting
    escalation_threshold: int # Trigger escalation notification
```

### Complete Example

```yaml
version: "1"
rules:
  # Production rate limits
  - name: prod-rate-limits
    profiles:
      - prod
    cooldown: 30m             # 30 minutes between break-glass events
    max_per_user: 3           # Max 3 per user per day
    max_per_profile: 10       # Max 10 per profile per day
    quota_window: 24h         # Count over 24-hour window
    escalation_threshold: 2   # Escalate after 2 events

  # Staging - less restrictive
  - name: staging-rate-limits
    profiles:
      - staging
    cooldown: 10m
    max_per_user: 5
    quota_window: 24h

  # Default rate limits
  - name: default-rate-limits
    profiles: []
    cooldown: 15m
    max_per_user: 5
    max_per_profile: 20
    quota_window: 24h
    escalation_threshold: 3
```

### Rate Limit Fields

| Field | Description | Required |
|-------|-------------|----------|
| `cooldown` | Minimum time between break-glass events for same user+profile | At least one limit |
| `max_per_user` | Maximum events per user within quota_window | At least one limit |
| `max_per_profile` | Maximum events per profile within quota_window | At least one limit |
| `quota_window` | Time window for counting max_per_user/max_per_profile | Required if quotas set |
| `escalation_threshold` | Trigger escalated notification when exceeded | No |

At least one of `cooldown`, `max_per_user`, or `max_per_profile` must be set.

---

## Duration Format

Duration values use Go duration format:

| Format | Meaning |
|--------|---------|
| `30m` | 30 minutes |
| `1h` | 1 hour |
| `2h30m` | 2 hours 30 minutes |
| `24h` | 24 hours |

### Limits

| Context | Maximum Duration |
|---------|------------------|
| Access request | 8 hours |
| Break-glass event | 4 hours |
| Session duration | Configurable per command |

---

## Policy Evaluation

### Access Policy Evaluation

1. Rules are evaluated in order (first match wins)
2. All conditions in a rule must match
3. If no rule matches, access is denied (implicit deny)

```
Request: {user: "alice", profile: "prod", time: "Monday 10:00"}

Rule 1: profiles=["dev"], users=["alice"]     → No match (wrong profile)
Rule 2: profiles=["prod"], users=["alice"]    → Match! → apply effect
```

### Condition Matching

| Condition | Empty Value | Non-Empty Value |
|-----------|-------------|-----------------|
| `profiles` | Matches any profile | Matches if profile in list |
| `users` | Matches any user | Matches if user in list |
| `mode` | Matches any mode | Matches if mode in list |
| `time` | Matches any time | Matches if within window |

### Example Evaluation

```yaml
rules:
  - name: dev-access
    effect: allow
    conditions:
      profiles: [dev]
      users: [alice, bob]
```

| Request | Result |
|---------|--------|
| alice + dev | Allow (matches rule) |
| alice + prod | Continue (profile doesn't match) |
| charlie + dev | Continue (user doesn't match) |

---

## Validation Errors

### Access Policy

| Error | Cause |
|-------|-------|
| "rule at index N missing name" | Rule lacks `name` field |
| "invalid effect" | Effect not one of: allow, deny, require_approval, require_server, require_server_session |
| "invalid weekday" | Day not one of: monday-sunday |
| "invalid timezone" | Timezone not recognized by system |
| "invalid credential mode" | Mode not one of: server, cli, credential_process |

### Approval Policy

| Error | Cause |
|-------|-------|
| "must have at least one rule" | Empty rules list |
| "rule must have at least one approver" | No approvers specified |
| "auto_approve must have at least one condition" | auto_approve block with no conditions |

### Break-Glass Policy

| Error | Cause |
|-------|-------|
| "must have at least one rule" | Empty rules list |
| "rule must have at least one user" | No authorized users |
| "invalid reason code" | Reason not one of: incident, maintenance, security, recovery, other |
| "max_duration exceeds maximum" | Duration greater than 4h |

### Rate Limit Policy

| Error | Cause |
|-------|-------|
| "must have at least one rule" | Empty rules list |
| "must have at least one limit" | No cooldown, max_per_user, or max_per_profile |
| "missing quota_window" | max_per_user/max_per_profile set without quota_window |
