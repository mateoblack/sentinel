# The AWS Credentials Problem Nobody Talks About

## The Scenario

Your senior developer runs this at 2am:
```bash
aws rds delete-db-instance --db-instance-identifier prod-primary
```

In the morning, you check CloudTrail:
```json
{
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AIDAI...:alice",
    "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/alice"
  },
  "eventTime": "2025-06-15T02:13:45Z",
  "eventName": "DeleteDBInstance"
}
```

**She has admin permissions. She's a senior dev. She's SUPPOSED to have this access.**

**But you still can't answer basic questions:**
- What was the business justification?
- Did she follow proper process or bypass controls?
- Was this an emergency, or did she fat-finger prod instead of dev?
- How did she get the credentials - SSO? Stored keys? Assumed role directly?

**CloudTrail shows you WHAT happened. It doesn't show you WHY it was allowed or HOW access was granted.**

## The Gap in AWS Security

**AWS IAM:** Defines what you *can* do

**AWS SSO:** Proves who you are

**CloudTrail:** Records what you did

**What's missing:** Intent, justification, and process.

Existing tools don't fill this gap:

| Tool | Secure Storage | Policy Evaluation | Provable Intent | Open Source |
|------|---------------|-------------------|-----------------|-------------|
| **aws-vault** | Yes | No | No | Yes |
| **AWS IAM** | - | Yes (what) | No (why) | - |
| **Granted** | Yes | Yes | No | Partial |
| **Teleport** | Yes | Yes | Yes | No ($$) |
| **Sentinel** | Yes | Yes | Yes | Yes |

## How Sentinel Works

Sentinel sits between you and AWS credentials, evaluating policy **before** credentials exist:

```
Developer requests access
        |
        v
Sentinel evaluates policy (before AWS sees anything)
        |
        v
Policy allows? --> Issue short-lived STS credentials with SourceIdentity
Policy denies? --> No credentials issued, no access
Policy requires approval? --> Wait for second human
        |
        v
Every action in CloudTrail shows: sentinel:alice:a1b2c3d4
```

**Three-layer defense:**

1. **Policy evaluation** - Access control before credentials exist
2. **SourceIdentity stamping** - Every action traceable to specific request
3. **Trust policy enforcement** - AWS rejects bypass attempts

### Example Access Policy

```yaml
version: "1"
rules:
  # Normal work - open access with audit
  - name: dev-default
    effect: allow
    conditions:
      profiles:
        - dev
        - staging
    reason: Development access

  # Production requires approval
  - name: prod-approval
    effect: require_approval
    conditions:
      profiles:
        - prod
    reason: Production access requires approval

  # Catch-all deny
  - name: default-deny
    effect: deny
    conditions: {}
    reason: No matching rule
```

### What Gets Logged

**Sentinel decision log:**
```json
{
  "timestamp": "2025-06-15T02:13:45Z",
  "user": "alice",
  "profile": "prod",
  "effect": "allow",
  "rule": "break-glass",
  "reason": "database locked, customers can't login",
  "request_id": "a1b2c3d4",
  "source_identity": "sentinel:alice:a1b2c3d4",
  "duration": "1h"
}
```

**CloudTrail shows:**
```json
{
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/alice",
    "sessionContext": {
      "sessionIssuer": {
        "sourceIdentity": "sentinel:alice:a1b2c3d4"
      }
    }
  }
}
```

**Now you can answer every question:**
- How: Break-glass emergency access
- Why: "database locked, customers can't login"
- When: 02:13 with 1-hour auto-expiry
- Process: Followed proper emergency protocol

## Enforcement at the AWS Level

Trust policies can require Sentinel:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringLike": {
        "sts:SourceIdentity": "sentinel:*"
      }
    }
  }]
}
```

**Direct AssumeRole calls fail. AWS itself enforces it.**

SCPs can require Sentinel for dangerous actions:

```json
{
  "Effect": "Deny",
  "Action": [
    "rds:DeleteDBInstance",
    "ec2:TerminateInstances",
    "s3:DeleteBucket"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "sts:SourceIdentity": "sentinel:*"
    }
  }
}
```

**No Sentinel = no destructive actions. Enforced organization-wide.**

## Real-World Use Cases

### Prevent accidents

```bash
# Wrong profile? Policy denies before credentials exist
sentinel exec --profile prod --policy-parameter /sentinel/policies/prod \
  -- aws s3 rm s3://prod-data --recursive
# Error: access denied by policy - require_approval effect matched
```

### Emergency access with accountability

```bash
sentinel breakglass \
  --profile prod \
  --reason-code incident \
  --justification "database locked, customers can't login" \
  --breakglass-table sentinel-breakglass \
  --duration 1h

# Returns credentials with:
# - Full audit trail created
# - SNS alert fired to security team
# - Auto-expires in 1 hour
# - SourceIdentity stamped: sentinel:alice:a1b2c3d4
```

### Time-boxed access with time windows

```yaml
rules:
  - name: business-hours-only
    effect: allow
    conditions:
      profiles:
        - staging
      time:
        days: [monday, tuesday, wednesday, thursday, friday]
        hours:
          start: "09:00"
          end: "18:00"
        timezone: America/New_York
    reason: Business hours access only
```

### AI-assisted operations

```bash
# AI tools use a restricted profile
export AWS_PROFILE=dev-readonly

# Policy limits what AI can access
# SourceIdentity still shows who is accountable
```

### Compliance audits

```bash
# Verify CloudTrail sessions have Sentinel enforcement
sentinel audit verify \
  --start 2025-01-01T00:00:00Z \
  --end 2025-01-31T23:59:59Z

# Correlate Sentinel logs with CloudTrail
grep "sentinel:alice" sentinel-decisions.log
```

## Policy Effects

Sentinel supports three policy effects:

| Effect | Behavior |
|--------|----------|
| `allow` | Issue credentials immediately |
| `deny` | Reject request, no credentials |
| `require_approval` | Submit for human approval first |

### Approval Workflow

When `require_approval` matches, the request enters a state machine:

```
pending --> approved --> credentials issued
        \-> denied
        \-> expired (TTL)
        \-> cancelled
```

Approvers are defined in a separate approval policy:

```yaml
version: "1"
rules:
  - name: prod-approvers
    profiles:
      - prod
    approvers:
      - security-lead
      - platform-oncall
    auto_approve:
      users:
        - senior-dev
      max_duration: 30m
      time:
        days: [monday, tuesday, wednesday, thursday, friday]
        hours:
          start: "09:00"
          end: "18:00"
```

### Break-Glass

For emergencies that can't wait for approval:

```bash
sentinel breakglass \
  --profile prod \
  --reason-code incident \
  --justification "Production outage, need immediate database access" \
  --breakglass-table sentinel-breakglass
```

Break-glass provides:
- Immediate access (no approval wait)
- Mandatory justification (20-1000 characters)
- Reason codes: `incident`, `maintenance`, `security`, `recovery`, `other`
- Maximum 4-hour duration
- Rate limiting to prevent abuse
- Automatic notifications to security team

## Why Open Source?

For security tooling, transparency isn't optional.

**You need to trust this with your AWS credentials.** The only way to earn that trust is to show the code.

- Security teams can audit every line
- Community finds bugs faster than any QA team
- No vendor lock-in
- Free forever

Open source has been the standard for credential tools (aws-vault, terraform, aws-cli). Sentinel follows that tradition.

## Get Started

**Install from source:**
```bash
go install github.com/byteness/aws-vault/v7/cmd/sentinel@latest
```

**Bootstrap a policy:**
```bash
# Preview what will be created
sentinel init bootstrap --profile dev --plan

# Create the SSM parameter
sentinel init bootstrap --profile dev

# Check status
sentinel init status
```

**Use it:**
```bash
# Via exec
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev \
  -- aws sts get-caller-identity

# Via credential_process in ~/.aws/config
[profile dev]
credential_process = sentinel credentials --profile dev --policy-parameter /sentinel/policies/dev
```

**Learn more:**
- [Getting Started Guide](guide/getting-started.md)
- [CLI Reference](guide/commands.md)
- [Policy Reference](guide/policy-reference.md)
- [Enforcement Patterns](ENFORCEMENT.md)

---

**The problem:** CloudTrail shows what happened.
**The solution:** Sentinel shows why it was allowed.
