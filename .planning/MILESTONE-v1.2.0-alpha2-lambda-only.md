# Milestone: v1.2.0 - Sentinel Alpha 2 (Lambda-Only)

## 🎯 Goal
Remove all client-side security controls that can be bypassed. Ship server-side enforcement only.

**Version:** v1.2.0 - Sentinel Alpha 2  
**Current:** v1.21 - Sentinel Alpha 1

## 🚨 The Problem

**Classic mode is fundamentally insecure:**
- User can modify binary to bypass policy
- Device posture checks are client-side (fakeable)
- MDM verification happens on client (spoofable)
- SourceIdentity can be set by modified client
- "Trust the client" model = not zero trust

**One CVE = project credibility destroyed**

### The CVE Scenario
```
Sentinel v1.21 ships with classic mode
    ↓
Security researcher: "I can bypass device posture"
    ↓
CVE-2025-XXXX: Sentinel Device Posture Bypass
    ↓
Headline: "AWS Zero Trust Tool Trivially Bypassed"
    ↓
Trust = gone
Adoption = dead
Credibility = damaged
```

## ✅ What Ships in v1.2.0 (Alpha 2)

### Core Architecture
- **Lambda TVM only** - No local credential mode
- **Server-side policy evaluation** - Client cannot bypass
- **Server-side MDM checks** - Query Intune/Jamf from Lambda
- **Server-side device posture** - Trust boundary is Lambda, not client
- **DynamoDB required** - Sessions, approvals, break-glass

### User Experience
```bash
# 1. Deploy infrastructure (one-time)
sentinel deploy --region us-west-2

# 2. Bootstrap policy
sentinel init bootstrap --profile prod

# 3. Use it (Lambda enforces everything)
sentinel exec --profile prod -- aws s3 ls
# → Calls Lambda
# → Lambda evaluates policy
# → Lambda checks MDM (if required)
# → Lambda returns creds OR denies
# → Client never gets direct AWS access
```

## ❌ What Gets Removed

### Classic Mode
```bash
# REMOVED in v1.2.0:
sentinel exec --profile prod -- aws s3 ls         # Local policy eval
sentinel credentials --profile prod                # Direct creds to client
--no-server flag                                   # No option to skip Lambda
```

### Client-Side Security
- ❌ Local policy evaluation
- ❌ Client-side MDM checks  
- ❌ Device posture on client
- ❌ Any "trust the client" logic
- ❌ Local credential issuance

### Optional Features Become Required
- ❌ DynamoDB now required (was optional)
- ❌ Lambda deployment required (was optional with `--server`)
- ❌ Internet connectivity required (was optional)

## 🔧 Breaking Changes

### For Users

**BEFORE (v1.21 Alpha 1):**
```bash
# Just install and run (insecure)
sentinel exec --profile dev -- aws s3 ls
```

**AFTER (v1.2.0 Alpha 2):**
```bash
# Must deploy infrastructure first (secure)
sentinel deploy --region us-west-2
sentinel init bootstrap --profile dev

# Then use (calls Lambda)
sentinel exec --profile dev -- aws s3 ls
```

### For Developers

**Files to Remove/Deprecate:**
- `cli/credentials.go` - Direct credential issuance (remove local path)
- `cli/exec.go` - Local policy evaluation path (remove)
- `vault/` package - Direct AWS credential access (refactor for Lambda-only)
- Local MDM check implementations (client-side)

**Files to Keep/Refactor:**
- `lambda/handler.go` - This becomes the core
- `cli/exec.go` - Refactor to call Lambda only
- Server mode becomes the only mode
- `sentinel/` package - Lambda-side policy evaluation

## 📋 Implementation Plan

### Phase 1: v1.21 (Current) - Deprecation Warnings
```bash
# Add warnings to classic mode
sentinel exec --profile prod -- aws s3 ls
# WARNING: Classic mode is insecure and will be removed in v1.2.0 (Alpha 2).
# Deploy Lambda for secure server-side enforcement:
#   sentinel deploy --region us-west-2
```

### Phase 2: v1.2.0 (Alpha 2) - Lambda-Only
```bash
# Remove classic mode entirely
sentinel exec --profile prod -- aws s3 ls
# ERROR: Sentinel requires Lambda deployment.
# Run: sentinel deploy --region us-west-2

# After deployment:
sentinel exec --profile prod -- aws s3 ls
# ✅ Calls Lambda, server-side enforcement
```

### Code Changes Required

**1. Remove Classic Execution Path:**
```go
// cli/exec.go - REMOVE
func executeLocal(ctx context.Context, input ExecInput) error {
    // Local policy evaluation - DELETE THIS
}

// cli/exec.go - KEEP (modify to Lambda-only)
func Execute(ctx context.Context, input ExecInput) error {
    // Always call Lambda
    return executeViaLambda(ctx, input)
}
```

**2. Remove Direct Credential Commands:**
```bash
# REMOVE these commands:
sentinel credentials --profile prod
sentinel export --profile prod
```

**3. Update Bootstrap:**
```bash
# v1.21: Optional Lambda
sentinel init bootstrap --profile prod [--with-all]

# v1.2.0: Lambda required
sentinel init bootstrap --profile prod  # Always deploys Lambda
```

**4. Update README:**
```markdown
# OLD Quick Start (v1.21)
sentinel exec --profile dev -- aws s3 ls

# NEW Quick Start (v1.2.0)
sentinel deploy --region us-west-2
sentinel init bootstrap --profile dev
sentinel exec --profile dev -- aws s3 ls
```

## 🎯 Success Criteria

### Security
- ✅ No client-side policy evaluation
- ✅ No client-side device checks
- ✅ Modified binary cannot bypass policy
- ✅ Zero CVEs related to client-side bypass
- ✅ All security enforcement in Lambda

### User Experience
- ✅ Clear deployment guide
- ✅ One-command infrastructure setup (`sentinel deploy`)
- ✅ Migration path from v1.21
- ✅ Error messages guide users to Lambda setup
- ✅ Setup takes < 5 minutes

### Documentation
- ✅ README clearly states Lambda-only
- ✅ Security model documented
- ✅ No confusion about "modes"
- ✅ Comparison with competitors (we're server-side only)
- ✅ Migration guide from v1.21

## 📣 Messaging

### v1.21 → v1.2.0 Communication
> "Sentinel Alpha 2 (v1.2.0) removes client-side security controls.
> All enforcement now happens in Lambda where it can't be bypassed.
> This is a breaking change - classic mode is removed."

### v1.2.0 Launch Message
> "Sentinel Alpha 2: Server-side only. Client-side security isn't."

### Competitive Positioning
> "Sentinel is the only AWS credential gateway that enforces policy
> server-side by default. No client-side bypass possible. 
> That's what zero trust means."

## 🚀 Timeline

- **v1.21 (Jan 2026)**: Sentinel Alpha 1 - Classic mode with deprecation warnings
- **v1.2.0 (Feb 2026)**: Sentinel Alpha 2 - Lambda-only, classic removed
- **v1.3.0 (Mar 2026)**: Beta 1 - Production-ready with full documentation

## ⚠️ Risks & Mitigation

### Risk: Users resist infrastructure requirement
**Mitigation:** 
- One-command deploy (`sentinel deploy`)
- CloudFormation template included
- Cost calculator: "~$5/month for small teams"
- Clear messaging: "Security has infrastructure cost"

### Risk: Cold start latency
**Mitigation:**
- Provisioned concurrency option for prod
- Document expected latency (~100-500ms)
- Credential caching on client (reduces Lambda calls)
- "Latency is security tax - we're honest about it"

### Risk: Cost concerns
**Mitigation:**
- Free tier sufficient for development
- Production cost: ~$5-50/month depending on usage
- "Compare to cost of one security incident"
- Optional cost alerts in deployment

### Risk: Offline usage impossible
**Mitigation:**
- Document as expected behavior
- "Server-side verification requires server"
- Emergency break-glass documented for true outages
- "If you're offline, AWS is too"

### Risk: Complexity for new users
**Mitigation:**
- `sentinel deploy` handles all CloudFormation
- Auto-creates DynamoDB tables
- One command for full setup
- Video walkthrough documentation

## 📝 Migration Guide (v1.21 → v1.2.0)

```bash
# Step 1: Deploy Lambda infrastructure
sentinel deploy --region us-west-2
# This creates:
# - Lambda function (sentinel-tvm)
# - DynamoDB tables (if --with-all used)
# - IAM roles
# - API Gateway (optional)

# Step 2: Update bootstrap (adds Lambda endpoint to policy)
sentinel init bootstrap --profile prod
# Policy now includes Lambda endpoint reference

# Step 3: Test it
sentinel exec --profile prod -- aws sts get-caller-identity
# Should show Lambda-issued credentials

# Step 4: Remove old configs
rm -rf ~/.sentinel/cache/  # Local policy cache no longer used

# Step 5: Update scripts/aliases
# OLD: sentinel exec --profile prod
# NEW: sentinel exec --profile prod  # Same command, Lambda backend
```

### What Breaks

**These commands are removed:**
```bash
sentinel credentials --profile prod  # REMOVED
sentinel export --profile prod       # REMOVED
--no-server flag                     # REMOVED
```

**These patterns still work (Lambda backend):**
```bash
sentinel exec --profile prod -- aws s3 ls           # ✅ Works (calls Lambda)
sentinel whoami --profile prod                      # ✅ Works
sentinel policy pull/push prod                      # ✅ Works
```

## 🎯 Definition of Done

### Code
- [ ] Remove `executeLocal()` from `cli/exec.go`
- [ ] Remove `credentials` command
- [ ] Remove `--no-server` flag
- [ ] Update `sentinel deploy` to be required step
- [ ] Add clear error when Lambda not deployed
- [ ] Remove client-side MDM check code
- [ ] Update all tests for Lambda-only

### Documentation  
- [ ] Update README Quick Start
- [ ] Migration guide written
- [ ] Security model documented
- [ ] Lambda deployment guide
- [ ] Cost estimation doc
- [ ] Troubleshooting guide

### Release
- [ ] CHANGELOG.md updated with breaking changes
- [ ] Migration script provided
- [ ] Announcement blog post draft
- [ ] Security positioning statement
- [ ] Comparison doc vs. competitors

## 📊 Metrics to Track

### Pre-Release (v1.21)
- Classic mode usage vs. Lambda mode
- User feedback on deprecation warnings
- Deploy command usage

### Post-Release (v1.2.0)
- Setup completion rate
- Time to first successful exec
- Lambda invocation latency
- User complaints about complexity
- CVE count (target: 0)

## 🎯 The One-Liner

> **"Alpha 2: Server-side only. Because client-side security isn't."**

---

## Decision Record

**Decision:** Remove classic mode in v1.2.0 (Sentinel Alpha 2)

**Rationale:** Client-side security controls are bypassable. One CVE destroys project credibility. Server-side enforcement is the only real zero trust.

**Trade-offs Accepted:**
- Setup complexity increases (requires Lambda deploy)
- Offline usage not possible
- Latency increases (~100-500ms per call)
- Cost increases (~$5-50/month)

**Security Benefit:** Eliminates entire class of bypass vulnerabilities.

**Approved:** ✅  
**Target Date:** v1.2.0 - Feb 2026  
**Breaking Change:** YES

---

**Ship clean. Be the standard. No CVEs. 🎯**
