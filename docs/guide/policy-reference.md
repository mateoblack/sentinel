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
    effect: string            # allow | deny | require_approval
    conditions:               # All conditions must match
      profiles: [string]      # AWS profile names (empty = any)
      users: [string]         # Usernames (empty = any)
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
| "invalid effect" | Effect not one of: allow, deny, require_approval |
| "invalid weekday" | Day not one of: monday-sunday |
| "invalid timezone" | Timezone not recognized by system |

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
