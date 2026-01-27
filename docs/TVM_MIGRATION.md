# Migrating to TVM-Only Mode (v2.1)

> **v2.1 Breaking Change:** Sentinel v2.1 removes "classic mode" (direct credential injection). All credential vending now requires Lambda TVM for server-verified security.

## Why Classic Mode Was Removed

Sentinel v2.1 removes "classic mode" (direct credential injection) because:

1. **Client-side is fakeable**: Device posture checks on the client can be bypassed by a malicious client
2. **Credentials escape**: Once injected via `credential_process` or environment variables, credentials can be captured, cached, and reused
3. **No per-request policy**: Classic mode evaluates policy once at credential issuance, not on every SDK call
4. **Server-side is verified**: Lambda TVM puts the trust boundary in AWS infrastructure where clients cannot bypass it

**The Lambda isn't overhead. It's where the intelligence lives.**

No Lambda = no threat intel = just another fakeable CLI tool.

## What Changed

| Before (v2.0) | After (v2.1) | Why |
|---------------|--------------|-----|
| `sentinel exec profile -- cmd` | `sentinel exec --remote-server <url> profile -- cmd` | Policy evaluation moved server-side |
| `sentinel credentials --profile profile` | **Removed** | Credentials to stdout are capturable |
| `sentinel exec --server profile -- cmd` | **Removed** | Local server is client-controlled |

## Migration Steps

### 1. Deploy Lambda TVM

If you haven't already deployed Lambda TVM, do so now:

```bash
# Option A: Terraform (recommended)
cd terraform/sentinel-tvm
terraform init
terraform apply -var="region=us-east-1"

# Save the outputs
export TVM_URL=$(terraform output -raw api_gateway_url)

# Option B: CDK
cd cdk/sentinel-tvm
npm install
npx cdk deploy

# Option C: Manual (see docs/LAMBDA_TVM_DEPLOYMENT.md)
```

Note the API Gateway URL from the deployment output (e.g., `https://abc123.execute-api.us-east-1.amazonaws.com`).

### 2. Update Your Commands

Replace direct exec with remote-server:

```bash
# Before (v2.0) - no longer works
sentinel exec production -- aws s3 ls

# After (v2.1) - requires TVM
sentinel exec --remote-server https://abc123.execute-api.us-east-1.amazonaws.com production -- aws s3 ls
```

You can set the TVM URL as an environment variable to avoid repeating it:

```bash
# Add to ~/.bashrc or ~/.zshrc
export SENTINEL_TVM_URL="https://abc123.execute-api.us-east-1.amazonaws.com"

# Then use
sentinel exec --remote-server "$SENTINEL_TVM_URL" production -- aws s3 ls
```

### 3. Update credential_process (if used)

If you used `sentinel credentials` in `~/.aws/config`, this no longer works:

```ini
# Before (no longer works in v2.1)
[profile production]
credential_process = sentinel credentials --profile production
```

**Migration options:**

**Option A: Use container credentials (recommended)**

Configure your SDK to use container credentials from TVM:

```bash
# Set container credentials URL
export AWS_CONTAINER_CREDENTIALS_FULL_URI="https://abc123.execute-api.us-east-1.amazonaws.com/credentials?profile=production"

# AWS SDKs will automatically use this
aws s3 ls
```

**Option B: Use sentinel exec wrapper**

Replace credential_process with exec:

```bash
# Instead of credential_process
sentinel exec --remote-server "$SENTINEL_TVM_URL" production -- aws s3 ls
```

### 4. Update CI/CD Pipelines

Replace direct credential injection with TVM calls:

```yaml
# Before (GitHub Actions - no longer works)
- name: Get AWS Credentials
  run: |
    eval $(sentinel credentials --profile production --stdout)
    aws s3 ls

# After (v2.1)
- name: Get AWS Credentials via TVM
  env:
    AWS_CONTAINER_CREDENTIALS_FULL_URI: "https://abc123.execute-api.us-east-1.amazonaws.com/credentials?profile=production"
  run: |
    aws s3 ls
```

### 5. Update Shell Functions

If you used `sentinel shell init`:

```bash
# Before - generated functions used local exec
sentinel-production() {
  sentinel exec production -- "$@"
}

# After - functions need TVM URL
sentinel-production() {
  sentinel exec --remote-server "$SENTINEL_TVM_URL" production -- "$@"
}
```

Regenerate your shell functions with the TVM URL:

```bash
# Regenerate shell init with TVM
eval "$(sentinel shell init --remote-server "$SENTINEL_TVM_URL")"
```

## FAQ

### Q: Why can't I use classic mode?

**A:** Classic mode is fakeable. Device posture and policy are evaluated client-side, meaning attackers can bypass them by modifying the client. TVM enforces security server-side in AWS infrastructure where it cannot be bypassed.

### Q: Is TVM more complex?

**A:** Initial setup requires deploying Lambda (~5 min with Terraform). After that, usage is nearly identical. The security improvement is substantial.

### Q: What about latency?

**A:** TVM adds ~50-100ms per credential refresh (every 15 min by default). For interactive use, this is imperceptible. For high-frequency automation, credentials are cached.

### Q: Can I still use SSO/IAM Identity Center?

**A:** Yes. TVM supports SSO profiles. The Lambda assumes the role using your SSO session. Your authentication method doesn't change, only where credentials are vended.

### Q: What if Lambda is down?

**A:** No credentials are issued. This is fail-closed security by design. For high availability, deploy TVM to multiple regions or use AWS Lambda's built-in availability.

### Q: How do I verify TVM is working?

**A:** Use `sentinel whoami` with the TVM URL:

```bash
sentinel whoami --remote-server "$SENTINEL_TVM_URL" --profile production
```

This will show your AWS identity as seen by TVM.

## Security Benefits

By moving to TVM-only, you gain:

1. **Policy enforcement at trust boundary**: Clients cannot bypass policy
2. **Device posture verification**: MDM checks happen server-side
3. **Session tracking**: All credentials are tracked and revocable
4. **Audit completeness**: CloudTrail shows all TVM-issued credentials
5. **SourceIdentity stamping**: Every credential traced to specific request

## Troubleshooting

### "Error: --remote-server is required"

You're running v2.1+ without specifying the TVM URL. Either:
- Set `SENTINEL_TVM_URL` environment variable
- Pass `--remote-server <url>` explicitly

### "Error: Not authenticated"

TVM requires IAM authentication. Ensure you have valid AWS credentials for calling the TVM endpoint.

### "Error: Policy denies access"

TVM is enforcing your policy. Check:
1. Your policy allows the profile you're requesting
2. Your device meets posture requirements (if configured)
3. Time window conditions are satisfied

### "Connection refused" or "timeout"

TVM endpoint is unreachable. Verify:
1. The URL is correct
2. Your network allows HTTPS to API Gateway
3. The Lambda function is deployed and healthy

## Related Documentation

- [Lambda TVM Deployment](LAMBDA_TVM_DEPLOYMENT.md) - How to deploy TVM
- [Lambda TVM Costs](LAMBDA_TVM_COSTS.md) - Cost analysis
- [Lambda TVM Testing](LAMBDA_TVM_TESTING.md) - Testing your deployment
- [SCP Reference](SCP_REFERENCE.md) - Enforce TVM-only access via SCPs

---

*Migration guide for Sentinel v2.1 TVM-Only mode*
