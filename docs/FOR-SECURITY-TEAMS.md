# For Security Teams: The Sentinel Opportunity

## TL;DR

Sentinel is an open-source credential gateway that adds **intent and justification** to every AWS access decision.

- Every session stamped with traceable SourceIdentity
- Decision logs capture *why* access was granted, not just *what* happened
- Break-glass requires written justification
- Sessions revocable in seconds
- Policies defined as code, reviewable in Git

**The result:** Self-service access with stronger audit controls than traditional least-privilege alone — because least-privilege doesn't help when the privileged account is the target.

---

## The Opportunity

Security teams have always faced a tough limitation: **CloudTrail shows actions, not intent.**

When Alice deletes a bucket at 2am, CloudTrail tells you she did it. But it can't tell you:
- Was this planned maintenance or a mistake?
- Did she follow the runbook?
- Was it an emergency? Who knew about it?

Without that context, security teams had to compensate with process — tickets, approvals, waiting periods. Not because they didn't trust their colleagues, but because they didn't have the tools to verify after the fact.

**Sentinel changes that.**

---

## What Sentinel Adds

| Capability | What You Get |
|------------|--------------|
| **SourceIdentity stamping** | Every CloudTrail event traces to exact user + request ID |
| **Decision logs** | Why access was granted — rule name, conditions matched, justification |
| **Break-glass audit trail** | Emergency access requires written justification, fully logged |
| **Instant revocation** | Kill a session in seconds, not hours |
| **Policy-as-code** | Review access rules in Git, version controlled, PR-approved |

This isn't about replacing security review — it's about giving you **better data** to make faster decisions with confidence.

---

## The Trade: Better for Everyone

```
Security teams get:               Engineering teams get:
──────────────────────────────────────────────────────────
Complete audit trail (WHO + WHY)  Faster onboarding
Break-glass justifications        Broader access when needed
Time-based restrictions           More autonomy
Instant revocation capability     Less friction
Policy-as-code to review          Self-service access
```

**Win-win.** More visibility enables more trust enables more speed.

---

## The Security Story

### Open Source & Auditable

Sentinel is fully open-source. You can:
- Read every line of code
- Audit the policy evaluation logic
- Fork and customize if needed
- Self-host with zero vendor lock-in

### Built on aws-vault's Battle-Tested Security

Sentinel inherits [aws-vault](https://github.com/99designs/aws-vault)'s credential security:

- **Keychain encryption** — Credentials stored in OS keychain (macOS Keychain, Windows Credential Manager, Linux secret-service)
- **Never touch disk unencrypted** — Credentials exist only in memory during use
- **Hardware-backed where available** — Secure Enclave on macOS, TPM on Windows

The encryption? You'd need quantum computing to crack it. And by then? **The credentials already expired.**

Default session: 1 hour. Break-glass max: 4 hours. Server mode: 15 minutes.

Even theoretical future attacks can't touch credentials that no longer exist.

### Fail-Closed Design

Sentinel is **additive security**. It doesn't replace IAM — it adds a layer:

- If Sentinel is down → access denied (fail-closed)
- If policy doesn't match → access denied
- If credentials expire → access denied

IAM is still the enforcement layer. Sentinel just decides whether to *ask* IAM for credentials.

### Enforcement Options

Want to ensure nobody bypasses Sentinel? Two options:

1. **Trust Policy** — Role requires `sts:SourceIdentity` starting with `sentinel:`
2. **SCP** — Org-wide policy blocks sensitive actions without SourceIdentity

Bypass attempts show up in CloudTrail as **access denied**. You'll see them immediately.

---

## What the Data Enables

Once Sentinel is running, you have structured data that didn't exist before:

### Today

| Data | Use Case |
|------|----------|
| Decision logs | Compliance reporting, audit trails |
| Break-glass events | Incident correlation, post-mortems |
| Request/approval history | Access reviews, attestation |
| Session tracking | Real-time visibility |

### Tomorrow

| Capability | Description |
|------------|-------------|
| **Dashboards** | Real-time access visualization |
| **Anomaly Alerts** | Unusual patterns, break-glass spikes |
| **AI Analysis** | "Summarize access patterns for Q4" |
| **Compliance Automation** | Auto-generated SOC2/SOX evidence |
| **Geo-Anomaly Detection** | Impossible travel alerts |
| **Access Reviews** | One SQL query instead of spreadsheets |

The foundation is there. Build what you need.

---

## Before & After

### Before Sentinel

```
CloudTrail Event:
  User: arn:aws:sts::123456789012:assumed-role/DevRole/alice
  Action: s3:DeleteBucket
  Time: 2026-01-19 02:47:33 UTC

  ❓ Why did Alice have access at 2am?
  ❓ Was this an emergency?
  ❓ Who authorized it?
  ❓ Can we revoke access?
```

### After Sentinel

```
CloudTrail Event:
  User: arn:aws:sts::123456789012:assumed-role/DevRole/alice
  SourceIdentity: sentinel:alice:direct:a1b2c3d4
  Action: s3:DeleteBucket
  Time: 2026-01-19 02:47:33 UTC

Sentinel Decision Log (request_id: a1b2c3d4):
  user: alice
  profile: prod
  effect: allow
  rule: break-glass-incident
  justification: "INC-4521 - database corruption, runbook step 7"
  duration: 1h

  ✅ Why 2am? Break-glass for incident INC-4521
  ✅ Emergency? Yes, with justification logged
  ✅ Authorization? Break-glass policy, auto-approved
  ✅ Revocation? Available instantly via server-revoke
```

Same action. Complete context.

---

---

## FAQ

### What if Sentinel locks everyone out?

Policy changes to assumed roles are themselves gated by Sentinel — it's turtles all the way down.

**Recommended model:**

```yaml
# Only admins can change policies, and only during business hours
- name: policy-admin-access
  effect: allow
  conditions:
    profiles: [policy-admin]
    users: [security-team]
    time:
      days: [monday, tuesday, wednesday, thursday, friday]
      hours:
        start: "09:00"
        end: "17:00"
      timezone: America/New_York
  reason: Policy administration - business hours only

# Emergency access - no server mode requirement
# (because what if AWS services are down during the emergency?)
- name: emergency-admin
  effect: allow
  conditions:
    profiles: [emergency-admin]
  reason: Emergency access - MFA required at role level
```

**Layered defense:**

| Scenario | Access Path |
|----------|-------------|
| Normal work | Standard Sentinel policy |
| Policy changes | Admin role, business hours only |
| Emergency | MFA role, simple allow (no extra dependencies) |
| True disaster | Root account (alerts everywhere) |

The emergency role uses a simple `allow` — no `require_server`. Why? Because if AWS services are failing during an emergency, you still need a way in. The MFA requirement is enforced at the IAM role level, and usage triggers immediate alerts. It's the escape hatch that has to work.

### What if AWS services go down?

Sentinel depends on AWS services (SSM for policies, optionally DynamoDB for approvals/sessions). Regional failures shouldn't cause total outage.

**Multi-region deployment:**

| Component | Resilience Strategy |
|-----------|---------------------|
| SSM policies | Replicate to multiple regions |
| DynamoDB tables | Global tables for cross-region replication |
| Client config | Failover region in `--region` flag or config |

If us-east-1 goes down, Sentinel clients failover to us-west-2. Same policies, same access.

**If all regions fail** (rare but possible): use the emergency MFA role — that's what it's for.

**Disabling Sentinel entirely** (removing trust policy requirements or SCPs) is the nuclear option. That action should:

- Trigger immediate alerts
- Require out-of-band approval
- Be treated as potential account compromise

This is intentional. Disabling Sentinel is the "pull the fire alarm" action — everyone should know it happened. If an attacker compromises an admin and tries to disable Sentinel to cover their tracks, that action becomes the alert.

### Why does Sentinel fail-closed?

Sentinel uses AWS `credential_process`, which requires valid JSON credentials on stdout. If anything fails — network timeout, SSM unreachable, policy parse error, STS failure, process crash — Sentinel exits non-zero with no output. The AWS SDK treats this as failure and issues no credentials.

There's no code path that issues credentials on error. The protocol itself makes "fail-open" impossible.

### What if a legitimate admin needs access during a failure?

That's what the emergency MFA role is for. It's a separate IAM role that:
- Doesn't require SourceIdentity in its trust policy (bypasses Sentinel enforcement)
- Requires MFA at the IAM level
- Triggers immediate alerts on use
- Has a short session duration

Legitimate use: Sentinel is down, admin uses emergency role, fixes the issue, alerts fire, incident is documented.

Malicious use: Attacker tries emergency role, doesn't have MFA, access denied. Or has compromised MFA, alerts fire, security responds.

The emergency role exists precisely for this scenario. It's not a backdoor — it's a documented, monitored, MFA-protected escape hatch.

### What if someone tries to bypass Sentinel?

Trust policies and SCPs can require SourceIdentity. Bypass attempts show up as CloudTrail denials. You'll see them.

### Do we have to review every policy change?

Up to you. Options:
- Require PR approval for policy changes
- Review once, trust the system, audit periodically
- Set up alerts for specific policy patterns

### Does this affect compliance?

Positively. Sentinel *improves* compliance posture:
- Audit trails answer "why" not just "what"
- Break-glass has mandatory justification
- Access reviews become queries, not spreadsheets
- Evidence generation can be automated

---

## Summary

| Traditional Model | Sentinel Model |
|-------------------|----------------|
| CloudTrail: what happened | CloudTrail + logs: what + why |
| Break-glass: informal | Break-glass: justified + audited |
| Revocation: wait for expiry | Revocation: instant |
| Policy: tribal knowledge | Policy: code in Git |
| Access reviews: manual | Access reviews: SQL queries |

**Sentinel doesn't replace security oversight — it gives you better tools for it.**

More visibility. More confidence. More speed.

And it's open-source, battle-tested, and quantum-proof (because the credentials expire first 😄).

Let's build something great together.
