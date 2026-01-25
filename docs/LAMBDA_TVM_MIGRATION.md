# Lambda TVM Migration Guide

This guide helps you choose between CLI server mode and Lambda TVM, and provides a migration path for transitioning to server-side credential vending.

## Overview

Sentinel offers two modes for per-request policy evaluation:

| Mode | Description | Trust Boundary |
|------|-------------|----------------|
| **CLI Server Mode** | Local metadata server on developer workstation | Client-side |
| **Lambda TVM** | Centralized AWS Lambda + API Gateway deployment | Server-side |

**CLI Server Mode** (`sentinel exec --server`) runs a local HTTP server that evaluates policy on every credential request. This enables real-time revocation but relies on the client to use the server.

**Lambda TVM** (`sentinel exec --remote-server`) moves credential vending to AWS infrastructure. Protected roles trust ONLY the Lambda execution role, making policy bypass architecturally impossible.

## Decision Matrix

| Factor | CLI Server Mode | Lambda TVM |
|--------|----------------|------------|
| **Trust boundary** | Client-side | Server-side |
| **Bypass prevention** | Relies on client behavior | Enforced via IAM + SCP |
| **Deployment** | Per-developer workstation | Centralized AWS infrastructure |
| **Session revocation** | Local server restart | Instant via DynamoDB |
| **Latency** | ~10ms (local) | ~100-200ms (network) |
| **Cost** | None (local compute) | Lambda + API Gateway charges |
| **Scaling** | Single user | Organizational scale |
| **Audit trail** | Local logs | CloudWatch Logs |
| **Setup complexity** | Minimal | AWS infrastructure required |
| **Maintenance** | None | Lambda updates, IAM policies |

## When to Use CLI Server Mode

CLI server mode is appropriate when:

1. **Individual developers testing locally** - Quick setup, no infrastructure required
2. **Development environments** - Bypass prevention isn't critical for non-production
3. **Low-latency requirements** - Local ~10ms vs network ~100-200ms
4. **Teams not ready for AWS deployment** - Stepping stone to full TVM adoption
5. **Evaluating Sentinel** - Try real-time revocation without infrastructure commitment

**Example use case:** A developer wants to test Sentinel's server mode features before recommending organization-wide adoption.

```bash
# Quick start with CLI server mode
sentinel exec --server --profile dev -- terraform plan
```

## When to Use Lambda TVM

Lambda TVM is essential when:

1. **Production environments requiring enforcement** - Protected roles trust only the Lambda, preventing bypass
2. **Organizational deployment** - Centralized control across teams and accounts
3. **SCP enforcement needed** - Block direct AssumeRole to protected roles
4. **Compliance requirements** - Audit trails in CloudWatch Logs
5. **Multi-team environments** - Consistent policy enforcement across organization
6. **Server-side trust boundary** - Clients cannot access protected roles without TVM approval

**Example use case:** An organization deploys Lambda TVM to ensure all production role access goes through Sentinel policy evaluation.

```bash
# Connect to Lambda TVM
sentinel exec --remote-server https://API_ID.execute-api.us-east-1.amazonaws.com --profile production -- aws s3 ls
```

## Migration Path: CLI Server to Lambda TVM

### Prerequisites

Before migrating, ensure you have:

- [ ] AWS account with permissions for Lambda, API Gateway, IAM, and SSM
- [ ] Sentinel policies working in CLI server mode
- [ ] Understanding of protected role patterns (`SentinelProtected-*`)

### Step 1: Deploy Lambda TVM Infrastructure

Choose your deployment method:

**Terraform:**
```bash
cd terraform/sentinel-tvm
terraform init
terraform plan -var="policy_parameter=/sentinel/policies/production"
terraform apply
```

**CDK:**
```bash
cd cdk/sentinel-tvm
npm install
cdk deploy
```

**Manual:** Follow [LAMBDA_TVM_DEPLOYMENT.md](LAMBDA_TVM_DEPLOYMENT.md)

Capture the API Gateway endpoint URL from deployment output.

### Step 2: Configure Protected Roles

Protected roles must trust ONLY the Lambda execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    }
  ]
}
```

Use the Terraform module for protected roles:
```bash
cd terraform/sentinel-protected-role
terraform apply -var="role_name=SentinelProtected-Production" -var="tvm_role_arn=arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole"
```

**Critical:** Remove any other principals from the trust policy. Direct AssumeRole must be blocked.

### Step 3: Update Client IAM Policies

Clients need permission to invoke the API Gateway endpoint:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeTVM",
      "Effect": "Allow",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:REGION:ACCOUNT:API_ID/*"
    }
  ]
}
```

### Step 4: Deploy Service Control Policies (SCPs)

SCPs ensure clients cannot bypass the TVM:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDirectAssumeRole",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelProtected-*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole"
        }
      }
    }
  ]
}
```

See [LAMBDA_TVM_SCP.md](LAMBDA_TVM_SCP.md) for complete patterns.

### Step 5: Switch Clients to Remote Server

Update client commands from `--server` to `--remote-server`:

**Before (CLI server mode):**
```bash
sentinel exec --server --profile production -- aws sts get-caller-identity
```

**After (Lambda TVM):**
```bash
sentinel exec --remote-server https://API_ID.execute-api.REGION.amazonaws.com --profile production -- aws sts get-caller-identity
```

### Step 6: Verify Migration

1. **Test TVM connectivity:**
   ```bash
   curl -X GET "https://API_ID.execute-api.REGION.amazonaws.com/profiles" \
     --aws-sigv4 "aws:amz:REGION:execute-api"
   ```

2. **Test credential issuance:**
   ```bash
   sentinel exec --remote-server https://API_ID.execute-api.REGION.amazonaws.com \
     --profile production -- aws sts get-caller-identity
   ```

3. **Verify SCP blocking:**
   ```bash
   # This should fail with AccessDenied
   aws sts assume-role \
     --role-arn arn:aws:iam::ACCOUNT:role/SentinelProtected-Production \
     --role-session-name direct-test
   ```

## Gradual Rollout Strategy

For large organizations, migrate incrementally:

### Phase 1: Deploy TVM Alongside Existing Access

1. Deploy Lambda TVM infrastructure
2. Create new protected roles with `SentinelProtected-` prefix
3. Keep existing roles unchanged
4. Early adopters test with `--remote-server`

**Duration:** 1-2 weeks

### Phase 2: Audit-Only SCP

1. Deploy CloudTrail metric filter for direct AssumeRole:
   ```bash
   aws logs put-metric-filter \
     --log-group-name CloudTrail/logs \
     --filter-name DirectAssumeRole \
     --filter-pattern '{ $.eventName = "AssumeRole" && $.requestParameters.roleArn = "*SentinelProtected*" && $.userIdentity.arn != "*SentinelTVMExecutionRole*" }' \
     --metric-transformations metricName=DirectAssumeRoleCount,metricNamespace=Sentinel,metricValue=1
   ```

2. Create alarm for violations
3. Review who's calling AssumeRole directly
4. Work with teams to migrate to TVM

**Duration:** 2-4 weeks

### Phase 3: Enable Blocking SCP for Test Roles

1. Select non-critical protected roles
2. Apply deny SCP to those roles only
3. Verify TVM works, direct access blocked
4. Address any issues

**Duration:** 1-2 weeks

### Phase 4: Full Enforcement

1. Apply deny SCP to all protected roles
2. Monitor CloudWatch for violations
3. Provide rollback documentation to teams
4. Celebrate successful migration

**Duration:** Ongoing

## Rollback Plan

If issues arise, rollback is straightforward:

### Disable SCPs

1. **Remove SCP from OU:**
   ```bash
   aws organizations detach-policy \
     --policy-id p-XXXXXXXXX \
     --target-id ou-XXXXXXXX
   ```

2. **Or modify SCP to allow direct access:**
   Change `StringNotEquals` condition to include additional principals.

### Re-enable Direct AssumeRole

1. **Update protected role trust policies:**
   Add back the principals that should have direct access.

2. **Update client commands:**
   Switch back to `--server` mode:
   ```bash
   sentinel exec --server --profile production -- aws sts get-caller-identity
   ```

### When Rollback is Appropriate

- TVM latency causing operational issues
- Critical automation broken by SCP enforcement
- Urgent access needed during TVM outage
- Bugs discovered in TVM credential vending

**Note:** Rollback reduces security posture. Schedule migration completion as soon as issues are resolved.

## Comparison Summary

| Aspect | CLI Server Mode | Lambda TVM |
|--------|----------------|------------|
| **Best for** | Development, evaluation | Production, compliance |
| **Security** | Client-dependent | Server-enforced |
| **Operational cost** | Developer workstation | AWS infrastructure |
| **Migration effort** | None | Medium (IAM, SCP, deployment) |
| **Organizational scale** | Individual | Enterprise |

## Related Documentation

- [LAMBDA_TVM_DEPLOYMENT.md](LAMBDA_TVM_DEPLOYMENT.md) - Full deployment guide
- [LAMBDA_TVM_COSTS.md](LAMBDA_TVM_COSTS.md) - Cost optimization guide
- [LAMBDA_TVM_SCP.md](LAMBDA_TVM_SCP.md) - SCP enforcement patterns
- [QUICKSTART.md](QUICKSTART.md) - CLI server mode setup
