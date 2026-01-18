# Approval Workflows

Configure and use approval workflows for sensitive access.

## Overview

Approval workflows add human review before granting access. When a policy rule has `effect: require_approval`, users must:

1. Submit an access request with justification
2. Wait for an authorized approver to review
3. Receive approval (or denial)
4. Use credentials within the approved time window

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  User Requests  │────>│  Pending         │────>│  Approver       │
│  Access         │     │  Request         │     │  Reviews        │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                              ┌────────────────────┬──────┴──────┐
                              v                    v             v
                        ┌───────────┐       ┌───────────┐  ┌───────────┐
                        │  Approved │       │  Denied   │  │  Expired  │
                        │           │       │           │  │  (TTL)    │
                        └─────┬─────┘       └───────────┘  └───────────┘
                              │
                              v
                        ┌───────────┐
                        │  User     │
                        │  Accesses │
                        └───────────┘
```

## Prerequisites

### DynamoDB Table

Create a DynamoDB table for storing access requests:

```bash
aws dynamodb create-table \
  --table-name sentinel-requests \
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

Users need permissions to interact with the requests table:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelRequestTable",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/sentinel-requests",
        "arn:aws:dynamodb:*:*:table/sentinel-requests/index/*"
      ]
    }
  ]
}
```

## Configuring Approval Requirements

### Access Policy

Configure profiles that require approval:

```yaml
version: "1"
rules:
  - name: prod-requires-approval
    effect: require_approval
    conditions:
      profiles:
        - prod
        - prod-admin
    reason: Production access requires approval

  - name: dev-access
    effect: allow
    conditions:
      profiles:
        - dev
```

### Approval Policy

Define who can approve requests:

```yaml
version: "1"
rules:
  - name: prod-approval
    profiles:
      - prod
      - prod-admin
    approvers:
      - security-team
      - ops-lead
      - engineering-manager

  - name: default
    profiles: []  # Matches any
    approvers:
      - security-team
```

## Request Workflow

### Step 1: Submit Request

```bash
sentinel request \
  --profile prod \
  --justification "Deploy critical security patch for CVE-2026-1234" \
  --duration 2h \
  --request-table sentinel-requests
```

**Output:**
```json
{
  "request_id": "a1b2c3d4e5f67890",
  "profile": "prod",
  "status": "pending",
  "expires_at": "2026-01-17T18:30:00Z",
  "auto_approved": false
}
```

### Step 2: Check Status

Wait for approval, or check status:

```bash
sentinel check a1b2c3d4e5f67890 --request-table sentinel-requests
```

**Output:**
```json
{
  "id": "a1b2c3d4e5f67890",
  "requester": "alice",
  "profile": "prod",
  "justification": "Deploy critical security patch for CVE-2026-1234",
  "duration": "2h",
  "status": "pending",
  "created_at": "2026-01-17T10:30:00Z",
  "updated_at": "2026-01-17T10:30:00Z",
  "expires_at": "2026-01-17T18:30:00Z"
}
```

### Step 3: Approver Reviews

Approver lists pending requests:

```bash
sentinel list --request-table sentinel-requests --status pending
```

Approver reviews and approves:

```bash
sentinel approve a1b2c3d4e5f67890 \
  --request-table sentinel-requests \
  --comment "Verified CVE ticket, approved for 2h window"
```

### Step 4: Access Granted

Once approved, the user can obtain credentials:

```bash
sentinel exec --profile prod --policy-parameter /sentinel/policies/prod
```

Sentinel checks for an approved request and issues credentials if found.

## Denying Requests

Approvers can deny requests with a reason:

```bash
sentinel deny a1b2c3d4e5f67890 \
  --request-table sentinel-requests \
  --comment "Please use staging environment for testing first"
```

## Listing Requests

### List Your Requests

```bash
sentinel list --request-table sentinel-requests
```

### List Pending Requests (All Users)

```bash
sentinel list --request-table sentinel-requests --status pending
```

### List Requests for a Profile

```bash
sentinel list --request-table sentinel-requests --profile prod
```

## Auto-Approval

Auto-approval allows certain requests to be automatically approved without human intervention.

### Configuration

```yaml
version: "1"
rules:
  - name: prod-approval
    profiles:
      - prod
    approvers:
      - security-team
      - ops-lead
    auto_approve:
      users:
        - ops-lead
        - senior-engineer
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
```

### How It Works

When a request is submitted, if all auto-approve conditions match:
1. Request is created with status `approved`
2. No human review required
3. User can immediately access credentials

### Conditions

All conditions must match for auto-approval:

| Condition | Description |
|-----------|-------------|
| `users` | Requester must be in this list (empty = any) |
| `time` | Request time must be within window (omit = any) |
| `max_duration` | Requested duration must be <= this value |

### Example

```bash
# ops-lead requests 1h during business hours → auto-approved
sentinel request \
  --profile prod \
  --justification "Routine maintenance" \
  --duration 1h \
  --request-table sentinel-requests
```

```json
{
  "request_id": "b2c3d4e5f6789012",
  "profile": "prod",
  "status": "approved",
  "expires_at": "2026-01-17T18:30:00Z",
  "auto_approved": true
}
```

## Request Lifecycle

### States

| Status | Description | Transitions To |
|--------|-------------|----------------|
| `pending` | Awaiting approval | approved, denied, expired |
| `approved` | Access granted | expired |
| `denied` | Access rejected | - (terminal) |
| `expired` | TTL elapsed | - (terminal) |
| `cancelled` | Requester cancelled | - (terminal) |

### Expiration

Requests have a Time-To-Live (TTL) of 8 hours by default. If not approved/denied within this window, the request expires automatically.

The `expires_at` field shows when the request will expire.

### Duration Limits

| Limit | Value |
|-------|-------|
| Maximum request duration | 8 hours |
| Default request duration | 1 hour |
| Request TTL (time to approve) | 8 hours |

## Notifications

### Webhook Notifications

Configure webhooks to notify on request events:

```yaml
notifications:
  webhook:
    url: "https://your-service.com/sentinel-webhook"
    events:
      - request_created
      - request_approved
      - request_denied
```

### SNS Notifications

```yaml
notifications:
  sns:
    topic_arn: "arn:aws:sns:us-east-1:123456789012:sentinel-requests"
    events:
      - request_created
      - request_approved
```

## Integration with credential_process

When using `credential_process`, Sentinel automatically checks for approved requests:

```ini
[profile prod]
credential_process = sentinel credentials --profile prod --policy-parameter /sentinel/policies/prod
```

If:
1. Policy evaluates to `deny` (or `require_approval`)
2. An approved request exists for the user+profile
3. The approved request hasn't expired

Then credentials are issued based on the approved request.

## Audit Trail

All approval events are logged:

```json
{
  "timestamp": "2026-01-17T10:35:00Z",
  "event_type": "request_approved",
  "request_id": "a1b2c3d4e5f67890",
  "profile": "prod",
  "requester": "alice",
  "approver": "bob",
  "comment": "Verified CVE ticket"
}
```

Enable logging with `--log-file` or `--log-stderr` flags.

## Best Practices

### Justification Requirements

Require meaningful justifications (minimum 10 characters):
- Good: "Deploy security patch for CVE-2026-1234"
- Bad: "need access"

### Approver Selection

- Assign at least 2 approvers per profile for availability
- Include both technical leads and security team
- Consider time zones for global teams

### Auto-Approval Guidelines

- Use sparingly for sensitive profiles
- Limit to trusted users only
- Cap duration (e.g., 1h max)
- Consider business hours only

### Monitoring

- Alert on high request volume
- Review denied requests for patterns
- Track approval latency
