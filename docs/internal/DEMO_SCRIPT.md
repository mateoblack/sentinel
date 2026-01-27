# Sentinel Demo Script

Executable demo script showing common Sentinel workflows. Target: 15-minute full demo.

## Prerequisites

Before starting the demo, ensure:

- AWS credentials configured (SSO, IAM user, or environment)
- Sentinel binary built: `go build -o sentinel .`
- AWS CLI installed for verification commands
- DynamoDB tables provisioned (for session/approval demos)

```bash
# Build Sentinel
go build -o sentinel .

# Verify build
./sentinel --version
```

## Demo 1: Basic Credential Flow (2 min)

Demonstrates the core Sentinel workflow: policy evaluation before credential issuance.

```bash
# 1. Validate configuration
./sentinel config validate
```
**Expected output:**
```
Configuration validation: PASSED
- AWS config file: ~/.aws/config
- Profiles found: 5
- SSM Parameter Store: accessible
```

```bash
# 2. Check identity - shows who Sentinel thinks you are
./sentinel whoami
```
**Expected output:**
```
Identity: arn:aws:iam::123456789012:user/john.doe
Account: 123456789012
Username: john.doe
```

```bash
# 3. Get credentials with policy evaluation
./sentinel credentials --profile staging --policy-parameter /sentinel/policies/staging
```
**Expected output (on success):**
```json
{
  "Version": 1,
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "SessionToken": "...",
  "Expiration": "2026-01-27T23:00:00Z"
}
```

```bash
# 4. Exec with credentials - runs command with policy-controlled access
./sentinel exec staging --policy-parameter /sentinel/policies/staging -- aws sts get-caller-identity
```
**Expected output:**
```json
{
    "UserId": "AROA...:sentinel:john.doe:abc123",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/StagingRole/sentinel:john.doe:abc123"
}
```

**Key points to highlight:**
- SourceIdentity stamping: `sentinel:john.doe:abc123` format
- Policy evaluated before credentials issued
- If policy denies, no credentials are returned

## Demo 2: Policy Management (3 min)

Shows the policy lifecycle: pull, validate, diff, push.

```bash
# 1. Pull current policy from SSM
./sentinel policy pull staging > staging-policy.yaml
```
**Expected output:** Policy YAML written to file

```bash
# 2. View the policy
cat staging-policy.yaml
```
**Expected output:**
```yaml
version: "1"
rules:
  - name: allow-developers
    effect: allow
    users:
      - john.doe
      - jane.smith
    profiles:
      - staging
    time_windows:
      - weekdays: [monday, tuesday, wednesday, thursday, friday]
        start_hour: 9
        end_hour: 18
```

```bash
# 3. Validate policy locally (no AWS credentials needed)
./sentinel policy validate staging-policy.yaml
```
**Expected output:**
```
Policy validation: PASSED
- Version: 1 (current)
- Rules: 2
- No warnings
```

```bash
# 4. Lint for issues
./sentinel policy lint staging-policy.yaml
```
**Expected output:**
```
Linting staging-policy.yaml...
[PASS] allow-before-deny: Allow rules precede deny rules
[PASS] no-unreachable-rules: All rules are reachable
[PASS] no-overlapping-time-windows: Time windows don't overlap
No issues found.
```

```bash
# 5. Make a change, then diff against SSM
# (Edit staging-policy.yaml to add a user)
./sentinel policy diff staging staging-policy.yaml
```
**Expected output:**
```diff
--- SSM: /sentinel/policies/staging
+++ Local: staging-policy.yaml
@@ -4,6 +4,7 @@
     users:
       - john.doe
       - jane.smith
+      - new.user
     profiles:
```

```bash
# 6. Push changes (with confirmation)
./sentinel policy push staging staging-policy.yaml
```
**Expected output:**
```
Uploading policy to /sentinel/policies/staging...
Changes detected. Continue? [y/N]: y
Policy uploaded successfully.
```

## Demo 3: Server Mode with Session Tracking (3 min)

Demonstrates real-time credential revocation capability.

**Terminal 1:**
```bash
# 1. Start server mode with session tracking
./sentinel exec staging --server --session-table sentinel-sessions -- bash
```
**Expected output:**
```
Starting Sentinel server mode...
Session ID: sess_abc123def456
Server listening on unix:///tmp/sentinel-abc123.sock
Launching subprocess...
```

**Terminal 2:**
```bash
# 2. List active sessions
./sentinel server-sessions list --table sentinel-sessions
```
**Expected output:**
```
Active Sessions:
ID                   User        Profile   Started              Expires
sess_abc123def456    john.doe    staging   2026-01-27 14:30:00  2026-01-27 14:45:00
```

```bash
# 3. Revoke the session
./sentinel server-sessions revoke --table sentinel-sessions --id sess_abc123def456
```
**Expected output:**
```
Session sess_abc123def456 revoked.
```

**Terminal 1 (observe):**
```bash
# 4. Next AWS command in the subprocess fails
aws s3 ls
```
**Expected output:**
```
Error: Session revoked. Please re-authenticate.
```

**Key points to highlight:**
- Real-time revocation without killing the process
- Session tracked in DynamoDB
- Fail-closed: revoked session = no credentials

## Demo 4: Approval Workflow (3 min)

Shows the request/approve flow for sensitive access.

```bash
# 1. Request access to production
./sentinel request production --duration 1h --reason "Deploy v2.0"
```
**Expected output:**
```
Request submitted: req_xyz789
Profile: production
Duration: 1 hour
Reason: Deploy v2.0
Status: pending

Awaiting approval from: security-team@example.com
```

```bash
# 2. Check request status
./sentinel request list
```
**Expected output:**
```
Request ID      Profile      Status    Submitted            Expires
req_xyz789      production   pending   2026-01-27 14:35:00  2026-01-27 15:35:00
```

**As approver:**
```bash
# 3. Approve the request
./sentinel approve req_xyz789
```
**Expected output:**
```
Request req_xyz789 approved.
User john.doe can now access production for 1 hour.
```

**As requester:**
```bash
# 4. Access with approval
./sentinel credentials --profile production --policy-parameter /sentinel/policies/production
```
**Expected output:** Credentials returned (approval was valid)

## Demo 5: Break-Glass Emergency Access (2 min)

Demonstrates emergency access bypass with audit trail.

```bash
# 1. Invoke break-glass
./sentinel breakglass-invoke production --reason incident --justification "P1 outage - database connectivity"
```
**Expected output:**
```
Break-glass access granted.
Event ID: bg_emergency123
Profile: production
Duration: 4 hours (maximum)
Reason: incident
Justification: P1 outage - database connectivity

WARNING: This access is logged and will be reviewed.
```

```bash
# 2. List active break-glass events
./sentinel breakglass-list
```
**Expected output:**
```
Event ID          Profile      Invoker     Started              Expires              Status
bg_emergency123   production   john.doe    2026-01-27 14:40:00  2026-01-27 18:40:00  active
```

```bash
# 3. Close event after incident resolved
./sentinel breakglass-close bg_emergency123
```
**Expected output:**
```
Break-glass event bg_emergency123 closed.
Duration: 45 minutes
Post-incident review required.
```

**Key points to highlight:**
- Bypasses normal policy but with full audit trail
- Rate limited to prevent abuse
- Must be closed after incident

## Demo 6: Device Posture (2 min)

Shows device-bound sessions and MDM integration.

```bash
# 1. Show device info
./sentinel devices list
```
**Expected output:**
```
Device ID: d8a7b6c5e4f3...
Platform: darwin
MDM Status: compliant (Jamf Pro)
Encryption: enabled
Last Check: 2026-01-27 14:42:00
```

```bash
# 2. Show device-bound sessions
./sentinel device-sessions --device-id d8a7b6c5e4f3... --table sentinel-sessions
```
**Expected output:**
```
Sessions for device d8a7b6c5e4f3...:
Session ID           User        Profile   Status
sess_abc123def456    john.doe    staging   active
sess_def456ghi789    john.doe    dev       expired
```

**Key points to highlight:**
- Device ID is hardware-bound (HMAC of machine ID)
- Sessions can be queried by device
- MDM integration validates device posture before credential issuance

## Demo 7: Audit and Compliance (2 min)

Demonstrates audit capabilities for security teams.

```bash
# 1. Verify audit log integrity
./sentinel audit verify-logs /var/log/sentinel.log --key-parameter /sentinel/hmac-key
```
**Expected output:**
```
Verifying audit log integrity...
Log entries: 1,247
Valid signatures: 1,247
Tampered entries: 0
Result: PASSED
```

```bash
# 2. Check session compliance
./sentinel audit session-compliance --since 24h
```
**Expected output:**
```
Session Compliance Report (last 24 hours):
Profile      Required Mode    Compliant Sessions    Total Sessions    Compliance
staging      any              45                    45                100%
production   server_session   12                    12                100%
dev          any              89                    89                100%

Overall Compliance: 100%
```

```bash
# 3. Find untracked sessions (CloudTrail correlation)
./sentinel audit untracked-sessions --since 24h
```
**Expected output:**
```
Untracked Sessions Report:
Checking CloudTrail for sessions not tracked by Sentinel...

Found 0 untracked sessions.
All AWS sessions in the last 24 hours were issued by Sentinel.
```

**Key points to highlight:**
- HMAC-signed logs prevent tampering
- Session compliance validates policy enforcement
- CloudTrail correlation detects policy bypass

## Demo 8: Infrastructure Status (1 min)

Quick health check of Sentinel deployment.

```bash
# Check deployment status
./sentinel init status --check-tables --region us-east-1
```
**Expected output:**
```
Sentinel Deployment Status:
- SSM Parameters: 5 policies configured
- DynamoDB Tables:
  - sentinel-approvals: OK (encryption: AWS managed)
  - sentinel-breakglass: OK (encryption: AWS managed)
  - sentinel-sessions: OK (encryption: AWS managed)
- KMS Key: alias/sentinel-policy-signing (active)

Status: Healthy
```

## Troubleshooting Commands

If demos fail, use these commands to diagnose:

```bash
# Debug mode - verbose logging
./sentinel --debug exec staging -- aws sts get-caller-identity

# Check AWS connectivity
./sentinel whoami

# Validate policy syntax
./sentinel policy validate policy.yaml

# Check permissions
./sentinel permissions check --auto-detect
```

## Demo Tips

1. **Prepare policies in advance** - Have staging/production policies ready in SSM
2. **Pre-create approval requests** - Approval demo needs request already pending
3. **Use a separate test account** - Avoid affecting production during demos
4. **Show the decision logs** - `tail -f /var/log/sentinel.log` during exec
5. **Highlight SourceIdentity** - Show CloudTrail correlation after exec

---

*Last updated: 2026-01-27*
*Target audience: Engineers demonstrating Sentinel to stakeholders*
