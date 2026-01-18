# Core Concepts

Understanding how Sentinel evaluates policies and manages access.

## Policy Evaluation Flow

When a user requests credentials, Sentinel follows this evaluation flow:

```
┌─────────────────┐
│ Credential      │
│ Request         │
│ (user, profile) │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Load Policy     │
│ from SSM        │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ Evaluate Rules  │
│ (first match)   │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    v         v
┌───────┐  ┌───────┐
│ Match │  │  No   │
│ Found │  │ Match │
└───┬───┘  └───┬───┘
    │          │
    v          v
┌───────┐  ┌───────┐
│ Apply │  │ Deny  │
│ Effect│  │(default)│
└───────┘  └───────┘
```

### First-Match-Wins

Rules are evaluated in order. The first rule whose conditions match determines the outcome.

```yaml
rules:
  - name: rule-1        # Checked first
    effect: allow
    conditions:
      users: [alice]

  - name: rule-2        # Checked second (only if rule-1 doesn't match)
    effect: deny
    conditions:
      users: [alice]    # Never reached for alice - rule-1 already matched
```

### Default Deny

If no rule matches, access is denied. Always include a catch-all deny rule for explicit documentation:

```yaml
rules:
  # ... your allow rules ...

  - name: default-deny
    effect: deny
    conditions: {}      # Empty conditions match any request
    reason: No matching rule
```

## Effects

Each rule specifies an effect that determines the outcome when matched.

### allow

Grant access immediately. Sentinel issues credentials and logs the decision.

```yaml
- name: dev-access
  effect: allow
  conditions:
    profiles: [dev]
    users: [alice, bob]
```

### deny

Reject access immediately. No credentials are issued.

```yaml
- name: block-contractors
  effect: deny
  conditions:
    users: [contractor-1, contractor-2]
  reason: Contractors not allowed direct access
```

### require_approval

Access requires human approval before credentials are issued.

```yaml
- name: prod-approval-required
  effect: require_approval
  conditions:
    profiles: [prod]
  reason: Production access requires approval
```

When matched:
1. User must submit an access request
2. Designated approver reviews and approves/denies
3. If approved, credentials can be issued

## Conditions

Conditions specify when a rule matches. All conditions in a rule must match (AND logic).

### profiles

Match requests for specific AWS profiles:

```yaml
conditions:
  profiles:
    - dev
    - staging
```

- Empty list `[]` or omitted: matches any profile
- Non-empty list: matches if requested profile is in the list

### users

Match requests from specific users:

```yaml
conditions:
  users:
    - alice
    - bob
    - charlie
```

- Empty list `[]` or omitted: matches any user
- Non-empty list: matches if requesting user is in the list
- Username is determined by the OS (output of `whoami`)

### time

Match requests within a time window:

```yaml
conditions:
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
```

**days** - Which days of the week:
- Valid values: `monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday`, `sunday`
- Empty or omitted: matches any day

**hours** - Time of day range:
- `start`: Beginning of window (inclusive)
- `end`: End of window (exclusive)
- Format: 24-hour `HH:MM`
- Omitted: matches any time

**timezone** - IANA timezone:
- Examples: `America/New_York`, `Europe/London`, `UTC`
- Omitted: uses system local timezone

## SourceIdentity Fingerprinting

Every session issued by Sentinel is stamped with a unique fingerprint for audit purposes.

### Format

```
sentinel:<username>:<request-id>
```

Example: `sentinel:alice:a1b2c3d4`

### Components

| Part | Description | Example |
|------|-------------|---------|
| `sentinel` | Fixed prefix identifying Sentinel-issued credentials | `sentinel` |
| `username` | Sanitized OS username (alphanumeric, max 20 chars) | `alice` |
| `request-id` | 8-character hex identifier (unique per request) | `a1b2c3d4` |

### Properties

**Immutable**: Set once on AssumeRole, cannot be changed for session lifetime.

**Propagating**: Follows through role chaining automatically. If you assume role A with Sentinel, then role A assumes role B, the SourceIdentity remains.

**Auditable**: Appears in every CloudTrail event from that session.

### CloudTrail Appearance

```json
{
  "userIdentity": {
    "type": "AssumedRole",
    "sourceIdentity": "sentinel:alice:a1b2c3d4"
  },
  "eventName": "DescribeInstances"
}
```

## Decision Logging

Sentinel logs every access decision for audit and compliance.

### Log Format

JSON Lines format with one entry per decision:

```json
{
  "timestamp": "2026-01-17T10:30:00Z",
  "user": "alice",
  "profile": "production",
  "effect": "allow",
  "rule": "prod-access",
  "rule_index": 2,
  "reason": "Production access allowed",
  "policy_path": "/sentinel/policies/prod",
  "request_id": "a1b2c3d4",
  "source_identity": "sentinel:alice:a1b2c3d4",
  "role_arn": "arn:aws:iam::123456789012:role/ProductionRole",
  "session_duration_seconds": 3600
}
```

### Fields

| Field | Type | Description | Present |
|-------|------|-------------|---------|
| `timestamp` | string | ISO8601 timestamp | Always |
| `user` | string | Requesting username | Always |
| `profile` | string | Requested AWS profile | Always |
| `effect` | string | `allow` or `deny` | Always |
| `rule` | string | Matched rule name (empty if no match) | Always |
| `rule_index` | int | Position of matched rule (-1 if none) | Always |
| `reason` | string | Rule reason or "no matching rule" | Always |
| `policy_path` | string | SSM parameter path | Always |
| `request_id` | string | 8-char hex identifier | Allow only |
| `source_identity` | string | Full SourceIdentity value | Allow only |
| `role_arn` | string | Assumed role ARN | Allow only |
| `session_duration_seconds` | int | Session duration | Allow only |

### Enabling Logging

**To file:**
```bash
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev --log-file /var/log/sentinel/decisions.log
```

**To stderr:**
```bash
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev --log-stderr
```

**Both:**
```bash
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev --log-file /var/log/sentinel/decisions.log --log-stderr
```

## Access Override Mechanisms

Sentinel provides two mechanisms to override normal policy decisions.

### Approved Requests

For `require_approval` effect, access is granted after human approval:

1. User submits request with justification
2. Designated approver reviews
3. Approver approves (or denies)
4. User can now obtain credentials

The approved request ID is logged with credential issuance for audit correlation.

### Break-Glass Access

For emergency situations, break-glass bypasses policy evaluation:

1. User invokes break-glass with reason code and justification
2. Sentinel records the event with full audit trail
3. Credentials are issued immediately
4. Session is time-limited and logged

Break-glass events are independently auditable and can trigger security alerts.

## Trust Policy Enforcement

To make Sentinel usage mandatory (not just advisory), configure IAM trust policies.

### How It Works

IAM trust policies can require the `sts:SourceIdentity` condition:

```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringLike": {
      "sts:SourceIdentity": "sentinel:*"
    }
  }
}
```

With this trust policy:
- Sentinel-issued credentials can assume the role (SourceIdentity matches)
- Non-Sentinel credentials are rejected (no SourceIdentity or wrong format)

### Enforcement Levels

| Level | Mechanism | Scope |
|-------|-----------|-------|
| Advisory | Sentinel logs only | No enforcement |
| Per-Role | Trust policy condition | Individual roles |
| Organization | Service Control Policy | All roles in OU/org |

See [Enforcement Patterns](../ENFORCEMENT.md) for complete configuration.

## Policy Caching

Sentinel caches policies to reduce SSM API calls and latency.

### Behavior

- Policies are cached for 5 minutes
- Cache is per-process (not shared across invocations)
- Cache key is the SSM parameter path

### Implications

- Policy changes take up to 5 minutes to take effect
- Credential processes start fresh (no persistent cache)
- Long-running `exec` sessions use cached policy

### Forcing Refresh

For immediate policy updates:
1. Exit any running `exec` sessions
2. New credential requests will load fresh policy
