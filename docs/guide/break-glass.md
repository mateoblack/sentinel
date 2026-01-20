# Break-Glass Access

Emergency access for incident response and critical situations.

## Overview

Break-glass access allows authorized users to bypass normal policy evaluation during emergencies. It provides:

- Immediate credential issuance
- Mandatory justification
- Full audit trail
- Rate limiting to prevent abuse
- Post-incident review capabilities

```
┌─────────────────┐
│  Emergency!     │
│  Need immediate │
│  access         │
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Invoke         │
│  Break-Glass    │
│  + reason code  │
│  + justification│
└────────┬────────┘
         │
         v
┌─────────────────┐
│  Rate Limit     │
│  Check          │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    v         v
┌───────┐  ┌───────┐
│ Pass  │  │ Fail  │
└───┬───┘  └───┬───┘
    │          │
    v          v
┌───────┐  ┌───────┐
│Access │  │Denied │
│Granted│  │(wait) │
└───────┘  └───────┘
```

## When to Use Break-Glass

Break-glass is for genuine emergencies:

| Scenario | Use Break-Glass? |
|----------|------------------|
| Production outage impacting customers | Yes |
| Security incident requiring investigation | Yes |
| Scheduled maintenance outside business hours | Yes (with maintenance reason) |
| "I forgot to submit a request earlier" | No - use approval workflow |
| Testing break-glass functionality | No - use dev/staging |

## Prerequisites

### DynamoDB Table

Create a DynamoDB table for storing break-glass events:

```bash
aws dynamodb create-table \
  --table-name sentinel-breakglass \
  --attribute-definitions \
    AttributeName=pk,AttributeType=S \
    AttributeName=sk,AttributeType=S \
    AttributeName=gsi1pk,AttributeType=S \
    AttributeName=gsi1sk,AttributeType=S \
  --key-schema \
    AttributeName=pk,KeyType=HASH \
    AttributeName=sk,KeyType=RANGE \
  --global-secondary-indexes \
    '[
      {
        "IndexName": "gsi1",
        "KeySchema": [
          {"AttributeName": "gsi1pk", "KeyType": "HASH"},
          {"AttributeName": "gsi1sk", "KeyType": "RANGE"}
        ],
        "Projection": {"ProjectionType": "ALL"}
      }
    ]' \
  --billing-mode PAY_PER_REQUEST
```

### IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelBreakGlassTable",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/sentinel-breakglass",
        "arn:aws:dynamodb:*:*:table/sentinel-breakglass/index/*"
      ]
    }
  ]
}
```

## Reason Codes

Every break-glass invocation requires a reason code:

| Code | Description | When to Use |
|------|-------------|-------------|
| `incident` | Production incident response | Customer-impacting outage, service degradation |
| `maintenance` | Emergency maintenance | Critical patches, urgent infrastructure changes |
| `security` | Security incident response | Active attack, breach investigation |
| `recovery` | Disaster recovery | Data restoration, failover procedures |
| `other` | Other emergency | Requires detailed justification |

## Invoking Break-Glass

### Basic Usage

```bash
sentinel breakglass \
  --profile prod \
  --reason-code incident \
  --justification "Production database outage affecting all customers. INC-2026-0117. Need immediate access to investigate replication lag." \
  --breakglass-table sentinel-breakglass
```

### With Custom Duration

```bash
sentinel breakglass \
  --profile prod \
  --reason-code maintenance \
  --justification "Emergency kernel patch for CVE-2026-5678. Maintenance window approved by security team." \
  --duration 2h \
  --breakglass-table sentinel-breakglass
```

### Output

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

The `request_id` is the SourceIdentity request ID for CloudTrail correlation.

## Justification Requirements

Break-glass requires detailed justification:

| Requirement | Value |
|-------------|-------|
| Minimum length | 20 characters |
| Maximum length | 1000 characters |

### Good Justifications

- "Production database outage affecting all customers. INC-2026-0117. Need immediate access to investigate replication lag."
- "Security alert from SOC. Suspected unauthorized access to S3 bucket logs. Need to review CloudTrail immediately."
- "Emergency kernel patch for CVE-2026-5678. Approved in CHANGE-1234. Applying during low-traffic window."

### Bad Justifications

- "emergency" (too short)
- "need access now" (no context)
- "testing" (not a valid emergency)

## Managing Break-Glass Events

### List Events

```bash
# Your events
sentinel breakglass-list --breakglass-table sentinel-breakglass

# Active events only
sentinel breakglass-list --breakglass-table sentinel-breakglass --status active

# Events for a specific profile
sentinel breakglass-list --breakglass-table sentinel-breakglass --profile prod
```

### Check Event Details

```bash
sentinel breakglass-check a1b2c3d4e5f67890 --breakglass-table sentinel-breakglass
```

### Close an Event Early

When the emergency is resolved, close the event:

```bash
sentinel breakglass-close a1b2c3d4e5f67890 \
  --reason "Incident resolved. Database replication restored. Confirmed no data loss." \
  --breakglass-table sentinel-breakglass
```

### Using SSO Profiles

If your AWS credentials come from an SSO profile, use `--aws-profile`:

```bash
sentinel breakglass-list --breakglass-table sentinel-breakglass --aws-profile admin-sso
sentinel breakglass-check a1b2c3d4e5f67890 --breakglass-table sentinel-breakglass --aws-profile admin-sso
sentinel breakglass-close a1b2c3d4e5f67890 --reason "Resolved" --breakglass-table sentinel-breakglass --aws-profile admin-sso
```

## Event Lifecycle

### States

| Status | Description | Transitions To |
|--------|-------------|----------------|
| `active` | Emergency access in effect | closed, expired |
| `closed` | Manually closed by invoker/security | - (terminal) |
| `expired` | Duration elapsed | - (terminal) |

### Duration Limits

| Limit | Value |
|-------|-------|
| Default duration | 1 hour |
| Maximum duration | 4 hours |

Break-glass access is intentionally time-limited to encourage prompt incident resolution.

## Rate Limiting

Rate limits prevent break-glass abuse while allowing legitimate emergency access.

### Configuration

```yaml
version: "1"
rules:
  - name: prod-rate-limits
    profiles:
      - prod
    cooldown: 30m           # 30 min between events
    max_per_user: 3         # Max 3 per user per day
    max_per_profile: 10     # Max 10 per profile per day
    quota_window: 24h       # Count over 24 hours
    escalation_threshold: 2 # Alert after 2 events
```

### Rate Limit Fields

| Field | Description |
|-------|-------------|
| `cooldown` | Minimum time between break-glass events for same user+profile |
| `max_per_user` | Maximum events per user within quota_window |
| `max_per_profile` | Maximum events per profile within quota_window |
| `quota_window` | Time window for counting quotas |
| `escalation_threshold` | Trigger alert when exceeded |

### Rate Limit Errors

If rate limited:

```json
{
  "error": "rate_limit_exceeded",
  "message": "Cooldown active. Next allowed at 2026-01-17T11:00:00Z",
  "retry_after": "2026-01-17T11:00:00Z"
}
```

## Break-Glass Policy

Control who can invoke break-glass and under what conditions.

### Configuration

```yaml
version: "1"
rules:
  - name: oncall-incident-access
    profiles:
      - prod
    users:
      - oncall-primary
      - oncall-secondary
      - incident-commander
    allowed_reason_codes:
      - incident
      - security
      - recovery
    max_duration: 4h

  - name: dba-maintenance
    profiles:
      - prod-database
    users:
      - dba-alice
      - dba-bob
    allowed_reason_codes:
      - maintenance
    time:
      days: [saturday, sunday]
      hours:
        start: "00:00"
        end: "06:00"
      timezone: "America/New_York"
    max_duration: 2h
```

### Policy Fields

| Field | Description |
|-------|-------------|
| `profiles` | Which profiles this rule applies to (empty = any) |
| `users` | Authorized users |
| `allowed_reason_codes` | Which reason codes are allowed (empty = any) |
| `time` | Time window restrictions |
| `max_duration` | Maximum duration for this rule |

## Post-Incident Review

After an incident, review break-glass usage:

### List Recent Events

```bash
sentinel breakglass-list \
  --breakglass-table sentinel-breakglass \
  --status closed
```

### Audit Checklist

- [ ] Was break-glass necessary? Could approval workflow have worked?
- [ ] Was justification adequate?
- [ ] Was duration appropriate?
- [ ] What actions were taken during the session?
- [ ] Should rate limits be adjusted?
- [ ] Are there process improvements to reduce future break-glass needs?

### CloudTrail Correlation

Find all actions taken during break-glass:

```bash
# Get the request_id from the break-glass event
sentinel breakglass-check a1b2c3d4e5f67890 --breakglass-table sentinel-breakglass

# Search CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="sentinel:alice:b2c3d4e5" \
  --start-time "2026-01-17T10:30:00Z" \
  --end-time "2026-01-17T11:30:00Z"
```

## Notifications

### Break-Glass Alerts

Configure alerts for break-glass events:

```yaml
notifications:
  sns:
    topic_arn: "arn:aws:sns:us-east-1:123456789012:security-alerts"
    events:
      - breakglass_invoked
      - breakglass_escalation

  webhook:
    url: "https://your-service.com/security-webhook"
    events:
      - breakglass_invoked
```

### Escalation

When a user exceeds the escalation threshold:

```json
{
  "event_type": "breakglass_escalation",
  "user": "alice",
  "profile": "prod",
  "count": 3,
  "threshold": 2,
  "message": "User exceeded break-glass escalation threshold"
}
```

## Best Practices

### Justification Quality

- Include incident/ticket numbers (INC-1234, CHANGE-5678)
- Describe the specific emergency
- Reference relevant approvals or communications

### Duration Selection

- Use the minimum duration needed
- Default 1 hour is often sufficient for initial investigation
- Extend only if work is ongoing

### Closing Events

- Always close events when done (don't let them expire)
- Include resolution summary in close reason
- Helps with post-incident review

### Monitoring

- Alert on all break-glass invocations
- Review break-glass frequency weekly
- Investigate patterns (frequent break-glass = process problem)

### Testing

- Test break-glass in non-production first
- Include break-glass in incident response drills
- Verify rate limits work as expected
