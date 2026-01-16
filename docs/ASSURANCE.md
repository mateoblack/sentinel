# Assurance Guide

How to verify Sentinel is actually enforced in your AWS environment.

## Overview

Sentinel assurance operates at three levels:

1. **Deployment verification** - Are trust policies correctly configured?
2. **Runtime verification** - Is Sentinel actually being used?
3. **Continuous monitoring** - Are there any bypass attempts or drift?

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Sentinel Assurance                               │
├─────────────────────┬─────────────────────┬─────────────────────────────┤
│ Deployment          │ Runtime             │ Continuous                  │
│                     │                     │                             │
│ sentinel enforce    │ sentinel audit      │ Scheduled audit +           │
│ plan                │ verify              │ --require-sentinel          │
│                     │                     │                             │
│ "Is enforcement     │ "Is Sentinel        │ "Alert on drift or          │
│  configured?"       │  being used?"       │  bypass attempts"           │
└─────────────────────┴─────────────────────┴─────────────────────────────┘
```

## Deployment Verification

Verify that IAM trust policies are correctly configured for Sentinel enforcement.

### Check Role Enforcement Status

Use `sentinel enforce plan` to analyze trust policies:

```bash
# Single role
sentinel enforce plan --role=arn:aws:iam::123456789012:role/ProductionAdmin

# Multiple roles
sentinel enforce plan \
  --role=arn:aws:iam::123456789012:role/ProductionAdmin \
  --role=arn:aws:iam::123456789012:role/ProductionReadOnly \
  --role=arn:aws:iam::123456789012:role/DataEngineering
```

**Interpreting Results:**

| Status | Meaning | Action |
|--------|---------|--------|
| FULL | All trust policy statements require Sentinel SourceIdentity | No action needed |
| PARTIAL | Some statements require Sentinel, others don't | Review and update trust policy |
| NONE | No Sentinel enforcement | Apply trust policy with conditions |
| ERROR | Failed to analyze | Check IAM permissions |

**JSON Output for Scripting:**

```bash
sentinel enforce plan --role=arn:aws:iam::123456789012:role/MyRole --json
```

```json
[
  {
    "role_arn": "arn:aws:iam::123456789012:role/MyRole",
    "analysis": {
      "status": "full",
      "level": "trust-policy",
      "issues": [],
      "recommendations": ["Role is fully enforced for Sentinel access"]
    }
  }
]
```

### Generate Compliant Trust Policies

Use `sentinel enforce generate trust-policy` to create enforcement-ready policies.

**Pattern A: Any Sentinel Credentials**

```bash
sentinel enforce generate trust-policy \
  --pattern=any-sentinel \
  --principal=arn:aws:iam::123456789012:root
```

**Pattern B: Specific Users via Sentinel**

```bash
sentinel enforce generate trust-policy \
  --pattern=specific-users \
  --principal=arn:aws:iam::123456789012:root \
  --users=alice --users=bob --users=charlie
```

**Pattern C: Migration Mode (Sentinel OR Legacy)**

```bash
sentinel enforce generate trust-policy \
  --pattern=migration \
  --principal=arn:aws:iam::123456789012:root \
  --legacy-principal=arn:aws:iam::123456789012:role/LegacyServiceRole
```

### Bulk Verification Script

Check all roles in your environment:

```bash
#!/bin/bash
# verify-enforcement.sh - Check Sentinel enforcement for all roles

# List all roles (filter to your naming convention)
ROLES=$(aws iam list-roles --query 'Roles[?starts_with(RoleName, `Production`)].Arn' --output text)

# Check each role
for role in $ROLES; do
  echo "Checking: $role"
  sentinel enforce plan --role="$role" --json | jq -r '.[0] | "\(.analysis.status): \(.role_arn)"'
done
```

**Example output:**

```
Checking: arn:aws:iam::123456789012:role/ProductionAdmin
full: arn:aws:iam::123456789012:role/ProductionAdmin
Checking: arn:aws:iam::123456789012:role/ProductionReadOnly
partial: arn:aws:iam::123456789012:role/ProductionReadOnly
Checking: arn:aws:iam::123456789012:role/ProductionDataPipeline
none: arn:aws:iam::123456789012:role/ProductionDataPipeline
```

## Runtime Verification

Verify that Sentinel is actually being used for AWS access by auditing CloudTrail.

### CloudTrail Session Audit

Use `sentinel audit verify` to check recent sessions:

```bash
# Last hour
sentinel audit verify \
  --start=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ) \
  --end=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Last 24 hours
sentinel audit verify \
  --start=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ) \
  --end=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Specific time window
sentinel audit verify \
  --start=2026-01-15T00:00:00Z \
  --end=2026-01-16T00:00:00Z
```

**Command Reference:**

| Flag | Description | Required |
|------|-------------|----------|
| `--start` | Start of time window (RFC3339 format) | Yes |
| `--end` | End of time window (RFC3339 format) | Yes |
| `--role` | Filter by specific role ARN | No |
| `--user` | Filter by username | No |
| `--region` | AWS region for CloudTrail operations | No |
| `--json` | Machine-readable JSON output | No |

**Human-Readable Output:**

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

[WARNING] Session assumed role without Sentinel SourceIdentity
  Event ID: def456...
  Time: 2026-01-15T16:45:00Z

...

Result: 4 issue(s) found
```

**Interpreting Results:**

| Metric | Meaning | Target |
|--------|---------|--------|
| Pass Rate | % of sessions with Sentinel SourceIdentity | 100% after full enforcement |
| Non-Sentinel Sessions | Sessions without Sentinel fingerprint | 0 after full enforcement |
| Issues | Specific sessions that bypass Sentinel | Investigate each |

**JSON Output for Scripting:**

```bash
sentinel audit verify \
  --start=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ) \
  --end=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --json
```

```json
{
  "start_time": "2026-01-15T00:00:00Z",
  "end_time": "2026-01-16T00:00:00Z",
  "total_sessions": 42,
  "sentinel_sessions": 38,
  "non_sentinel_sessions": 4,
  "issues": [
    {
      "severity": "warning",
      "message": "Session assumed role without Sentinel SourceIdentity",
      "session_info": {
        "event_id": "abc123...",
        "event_time": "2026-01-15T14:32:00Z"
      }
    }
  ]
}
```

**Exit Codes:**

| Code | Meaning | Use Case |
|------|---------|----------|
| 0 | All sessions verified | Success - no issues |
| 1 | Issues found | Alert - investigate sessions |
| Non-zero | Other error | Check stderr for details |

### Drift Detection at Credential Time

Enable drift warnings for proactive detection:

```ini
# ~/.aws/config
[profile production]
credential_process = sentinel credentials --profile production --policy-parameter /sentinel/policies/default --require-sentinel
```

**Warning output (stderr):**

```
Warning: Role arn:aws:iam::123456789012:role/MyRole has partial Sentinel enforcement (Some statements allow access without Sentinel SourceIdentity)
```

**Decision log entry:**

```json
{
  "timestamp": "2026-01-16T10:30:00Z",
  "user": "alice",
  "profile": "production",
  "effect": "allow",
  "drift_status": "partial",
  "drift_message": "Some statements allow access without Sentinel SourceIdentity"
}
```

## Continuous Monitoring

Set up automated verification for ongoing assurance.

### Periodic Audit Script

Create a cron job for daily verification:

```bash
#!/bin/bash
# /opt/sentinel/daily-audit.sh

# Configuration
SLACK_WEBHOOK="${SLACK_WEBHOOK_URL}"
LOG_DIR="/var/log/sentinel"
THRESHOLD=95  # Alert if pass rate drops below 95%

# Run audit for last 24 hours
RESULT=$(sentinel audit verify \
  --start=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ) \
  --end=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --json)

# Parse results
TOTAL=$(echo "$RESULT" | jq -r '.total_sessions')
SENTINEL=$(echo "$RESULT" | jq -r '.sentinel_sessions')
ISSUES=$(echo "$RESULT" | jq -r '.issues | length')

# Calculate pass rate
if [ "$TOTAL" -gt 0 ]; then
  PASS_RATE=$(echo "scale=1; $SENTINEL * 100 / $TOTAL" | bc)
else
  PASS_RATE="100"
fi

# Log result
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) total=$TOTAL sentinel=$SENTINEL issues=$ISSUES rate=$PASS_RATE%" >> "$LOG_DIR/audit-history.log"

# Alert if below threshold
if [ "$(echo "$PASS_RATE < $THRESHOLD" | bc)" -eq 1 ]; then
  curl -X POST "$SLACK_WEBHOOK" -H 'Content-type: application/json' \
    --data "{\"text\":\"Sentinel Alert: Pass rate $PASS_RATE% (below $THRESHOLD% threshold). $ISSUES non-Sentinel sessions in last 24h.\"}"
fi
```

Add to crontab:

```cron
# Run Sentinel audit daily at 6 AM UTC
0 6 * * * /opt/sentinel/daily-audit.sh
```

### Alert Integration

**Exit Code for Scripting:**

```bash
# In CI/CD or monitoring scripts
if sentinel audit verify --start=... --end=... --json > /dev/null 2>&1; then
  echo "All sessions verified"
else
  echo "Issues found - check audit results"
  exit 1
fi
```

**PagerDuty Integration:**

```bash
#!/bin/bash
# Alert on non-zero exit code
if ! sentinel audit verify --start=... --end=... 2>&1; then
  curl -X POST https://events.pagerduty.com/v2/enqueue \
    -H 'Content-Type: application/json' \
    -d '{
      "routing_key": "YOUR_ROUTING_KEY",
      "event_action": "trigger",
      "payload": {
        "summary": "Sentinel: Non-Sentinel sessions detected",
        "severity": "warning",
        "source": "sentinel-audit"
      }
    }'
fi
```

**Slack Webhook:**

```bash
#!/bin/bash
RESULT=$(sentinel audit verify --start=... --end=... --json 2>&1)
ISSUES=$(echo "$RESULT" | jq -r '.issues | length')

if [ "$ISSUES" -gt 0 ]; then
  curl -X POST "$SLACK_WEBHOOK_URL" \
    -H 'Content-type: application/json' \
    --data "{\"text\":\"Sentinel Audit Alert: $ISSUES non-Sentinel sessions detected\"}"
fi
```

### Dashboard Queries

Use Amazon Athena to query CloudTrail logs for Sentinel assurance metrics.

**Pass Rate Over Time:**

```sql
SELECT
    DATE(eventtime) AS day,
    COUNT(*) AS total_sessions,
    COUNT(CASE WHEN useridentity.sourceidentity LIKE 'sentinel:%' THEN 1 END) AS sentinel_sessions,
    ROUND(100.0 * COUNT(CASE WHEN useridentity.sourceidentity LIKE 'sentinel:%' THEN 1 END) / COUNT(*), 1) AS pass_rate
FROM cloudtrail_logs
WHERE eventname = 'AssumeRole'
    AND eventtime >= DATE_ADD('day', -30, CURRENT_DATE)
GROUP BY DATE(eventtime)
ORDER BY day DESC;
```

**Issues by Role:**

```sql
SELECT
    requestparameters.rolearn AS role_arn,
    COUNT(*) AS non_sentinel_sessions
FROM cloudtrail_logs
WHERE eventname = 'AssumeRole'
    AND (useridentity.sourceidentity IS NULL OR useridentity.sourceidentity NOT LIKE 'sentinel:%')
    AND eventtime >= DATE_ADD('day', -7, CURRENT_DATE)
GROUP BY requestparameters.rolearn
ORDER BY non_sentinel_sessions DESC
LIMIT 20;
```

**Sessions by User:**

```sql
SELECT
    REGEXP_EXTRACT(useridentity.sourceidentity, 'sentinel:([^:]+):', 1) AS sentinel_user,
    COUNT(*) AS session_count,
    COUNT(DISTINCT DATE(eventtime)) AS active_days
FROM cloudtrail_logs
WHERE useridentity.sourceidentity LIKE 'sentinel:%'
    AND eventtime >= DATE_ADD('day', -30, CURRENT_DATE)
GROUP BY 1
ORDER BY session_count DESC;
```

## Verification Checklist

Use this checklist when adopting Sentinel enforcement:

### Initial Deployment

- [ ] Run `sentinel enforce plan` on all target roles
- [ ] Document roles with NONE or PARTIAL enforcement
- [ ] Generate trust policies with `sentinel enforce generate trust-policy`
- [ ] Apply trust policies to target roles
- [ ] Verify with `sentinel enforce plan` (all should show FULL)

### Runtime Validation (First 24 Hours)

- [ ] Run `sentinel audit verify` over 24-hour window
- [ ] Investigate any non-Sentinel sessions
- [ ] Verify pass rate is at target level (aim for 100%)
- [ ] Check decision logs for drift warnings

### Ongoing Assurance

- [ ] Enable `--require-sentinel` for proactive drift detection
- [ ] Set up scheduled audit script (daily or hourly)
- [ ] Configure alerts for pass rate drops
- [ ] Review drift status in decision logs
- [ ] Monitor CloudTrail for bypass attempts

### Incident Response

- [ ] Audit specific time windows: `sentinel audit verify --start=... --end=...`
- [ ] Filter by role: `sentinel audit verify --role=...`
- [ ] Export JSON for investigation: `sentinel audit verify --json > incidents.json`
- [ ] Cross-reference with Sentinel decision logs

## Troubleshooting

### "Zero sessions found"

**Cause:** No AssumeRole events in the time window or CloudTrail not configured.

**Resolution:**
1. Verify the time window is correct (RFC3339 format)
2. Check CloudTrail is enabled in the region
3. Ensure role filter matches actual role ARNs
4. Wait for CloudTrail delivery delay (up to 15 minutes)

### "Unknown enforcement status"

**Cause:** IAM permissions missing or role doesn't exist.

**Resolution:**
1. Verify the role ARN is correct
2. Check IAM permissions include `iam:GetRole`
3. Ensure role exists in the account

### "High percentage of non-Sentinel sessions"

**Cause:** Users bypassing Sentinel or migration incomplete.

**Resolution:**
1. Review non-Sentinel sessions in audit output
2. Check if credentials are being obtained outside Sentinel
3. Update trust policies to require Sentinel SourceIdentity
4. Consider SCP enforcement for organization-wide control

### "Drift detection shows partial/none but trust policy is configured"

**Cause:** Trust policy may have additional statements without Sentinel condition.

**Resolution:**
1. Run `sentinel enforce plan --role=... --json` for detailed analysis
2. Review trust policy for statements without `sts:SourceIdentity` condition
3. Update or remove legacy statements

## Related Documentation

- [Enforcement Patterns](ENFORCEMENT.md) - Trust policies and SCPs for mandatory Sentinel usage
- [CloudTrail Correlation](CLOUDTRAIL.md) - Correlating Sentinel logs with AWS activity
- [Bootstrap Guide](BOOTSTRAP.md) - Setting up Sentinel policy infrastructure
