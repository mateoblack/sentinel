# Troubleshooting

Common issues, debugging techniques, and frequently asked questions.

## Debugging with --debug

Enable verbose output for any command:

```bash
sentinel --debug exec --profile dev --policy-parameter /sentinel/policies/dev
```

Debug output includes:
- AWS SDK calls and responses
- Policy evaluation details
- SSM parameter lookups
- AssumeRole requests

## Common Errors

### "NoCredentialProviders: no valid providers in chain"

**Symptom:** Sentinel fails to start with credential provider error.

**Cause:** No AWS credentials available for Sentinel's initial SSM lookup.

**Solutions:**

1. **Set environment variables:**
   ```bash
   export AWS_ACCESS_KEY_ID=AKIA...
   export AWS_SECRET_ACCESS_KEY=...
   ```

2. **Use aws-vault for initial credentials:**
   ```bash
   aws-vault exec admin -- sentinel exec --profile dev --policy-parameter /sentinel/policies/dev
   ```

3. **Configure credentials file:**
   ```ini
   # ~/.aws/credentials
   [default]
   aws_access_key_id = AKIA...
   aws_secret_access_key = ...
   ```

4. **Use IAM role (EC2, Lambda, ECS):**
   - Ensure instance/task role has SSM read permissions

---

### "AccessDeniedException" on SSM GetParameter

**Symptom:** Sentinel reports access denied when loading policy.

**Cause:** IAM permissions missing for SSM read.

**Solutions:**

1. **Check IAM policy attached:**
   ```bash
   aws iam get-policy-document --policy-arn arn:aws:iam::...:policy/SentinelPolicyReader
   ```

2. **Verify resource ARN matches:**
   - Policy specifies `/sentinel/policies/*`
   - You're requesting `/sentinel/policies/dev`
   - ARN must match

3. **Check for SCPs blocking access:**
   - Service Control Policies can deny SSM access
   - Check organization policies

4. **Verify region:**
   - SSM parameters are regional
   - Use `--region` flag if needed

---

### "ParameterNotFound"

**Symptom:** Policy parameter doesn't exist.

**Cause:** SSM parameter not bootstrapped or wrong path.

**Solutions:**

1. **Bootstrap the parameter:**
   ```bash
   sentinel init bootstrap --profile dev
   ```

2. **Check status:**
   ```bash
   sentinel init status
   ```

3. **Verify parameter path:**
   - Default: `/sentinel/policies/dev`
   - Custom root: `/myorg/sentinel/policies/dev`

4. **Check region:**
   ```bash
   sentinel init status --region us-west-2
   ```

---

### "access denied" on Policy Evaluation

**Symptom:** Sentinel evaluates policy but denies access.

**Cause:** Policy rules don't match the request.

**Solutions:**

1. **Enable logging:**
   ```bash
   sentinel exec --profile dev --policy-parameter /sentinel/policies/dev --log-stderr
   ```

2. **Check log output:**
   ```json
   {
     "effect": "deny",
     "rule": "",
     "rule_index": -1,
     "reason": "no matching rule"
   }
   ```

3. **Review policy:**
   - Is your username in the allowed list?
   - Is the profile name correct?
   - Is there a time window restriction?

4. **Check username:**
   ```bash
   whoami
   ```
   - Sentinel uses OS username for matching

---

### "AccessDenied" on AssumeRole

**Symptom:** Policy allows access but AssumeRole fails.

**Cause:** IAM role trust policy or permissions issue.

**Solutions:**

1. **Check trust policy:**
   ```bash
   aws iam get-role --role-name MyRole --query 'Role.AssumeRolePolicyDocument'
   ```

2. **Verify principal:**
   - Trust policy must allow your IAM entity

3. **Check for SourceIdentity restriction:**
   - If trust policy requires `sentinel:*`, Sentinel must be issuing the request
   - Check trust policy conditions

4. **Verify role exists:**
   ```bash
   aws iam get-role --role-name MyRole
   ```

---

### "ValidationException" on DynamoDB

**Symptom:** Request/break-glass commands fail with DynamoDB error.

**Cause:** Table doesn't exist or schema mismatch.

**Solutions:**

1. **Verify table exists:**
   ```bash
   aws dynamodb describe-table --table-name sentinel-requests
   ```

2. **Check table name:**
   - `--request-table sentinel-requests`
   - `--breakglass-table sentinel-breakglass`

3. **Verify region:**
   - DynamoDB tables are regional
   - Use `--region` flag

4. **Create table if needed:**
   - See [Deployment Guide](deployment.md) for table creation

---

### "justification too short"

**Symptom:** Request or break-glass rejected for justification length.

**Cause:** Justification doesn't meet minimum length.

**Requirements:**

| Context | Minimum | Maximum |
|---------|---------|---------|
| Access request | 10 chars | 500 chars |
| Break-glass | 20 chars | 1000 chars |

**Solution:** Provide more detailed justification:

```bash
# Too short
sentinel request --justification "need access"

# Adequate
sentinel request --justification "Deploy hotfix for production issue INC-2026-0117"
```

---

### "rate limit exceeded"

**Symptom:** Break-glass fails with rate limit error.

**Cause:** Cooldown active or quota exceeded.

**Solutions:**

1. **Wait for cooldown:**
   - Check `retry_after` in error message
   - Default cooldown varies by policy

2. **Check quota:**
   ```bash
   sentinel breakglass-list --breakglass-table sentinel-breakglass --invoker $(whoami)
   ```

3. **Contact security team:**
   - If legitimate emergency, security may be able to reset limits

---

### "invalid timezone"

**Symptom:** Policy validation fails with timezone error.

**Cause:** Timezone not recognized by system.

**Solutions:**

1. **Use IANA timezone format:**
   - Correct: `America/New_York`, `Europe/London`, `UTC`
   - Incorrect: `EST`, `PST`, `Eastern`

2. **Check system timezone database:**
   ```bash
   # Linux
   ls /usr/share/zoneinfo/America/

   # macOS
   ls /var/db/timezone/zoneinfo/America/
   ```

---

### "request not found"

**Symptom:** Check/approve/deny fails with request not found.

**Cause:** Invalid request ID or request expired.

**Solutions:**

1. **Verify request ID:**
   ```bash
   sentinel list --request-table sentinel-requests
   ```

2. **Check if expired:**
   - Requests expire after 8 hours (TTL)
   - Expired requests are still in table but may not be actionable

3. **Check table name:**
   - Ensure using correct table

---

## Policy Evaluation Issues

### Rule Not Matching

**Debug steps:**

1. Add logging:
   ```bash
   sentinel exec --profile dev --policy-parameter /sentinel/policies/dev --log-stderr 2>&1 | jq
   ```

2. Check log output for:
   - `rule`: Which rule matched (empty if none)
   - `rule_index`: Position of matched rule (-1 if none)
   - `reason`: Explanation

3. Common mismatches:
   - Username case sensitivity
   - Profile name typo
   - Time window not active

### Wrong Rule Matching

**Cause:** Rules are evaluated first-match-wins. An earlier rule is matching.

**Solution:** Reorder rules - more specific rules should come first:

```yaml
rules:
  # Specific deny first
  - name: block-contractors
    effect: deny
    conditions:
      users: [contractor-1]

  # Then general allow
  - name: dev-access
    effect: allow
    conditions:
      profiles: [dev]
```

### Time Window Issues

**Debug steps:**

1. Check current time in specified timezone:
   ```bash
   TZ=America/New_York date
   ```

2. Verify day of week:
   ```bash
   date +%A | tr '[:upper:]' '[:lower:]'
   ```

3. Check policy time configuration:
   - `start` is inclusive
   - `end` is exclusive
   - Format is 24-hour `HH:MM`

---

## DynamoDB Connectivity

### Table Not Found

```bash
# List tables in current region
aws dynamodb list-tables

# Check specific region
aws dynamodb list-tables --region us-east-1
```

### Permission Issues

Required actions:
- `dynamodb:GetItem`
- `dynamodb:PutItem`
- `dynamodb:UpdateItem`
- `dynamodb:Query`

Check with:
```bash
aws sts get-caller-identity
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::...:user/myuser \
  --action-names dynamodb:GetItem \
  --resource-arns arn:aws:dynamodb:...:table/sentinel-requests
```

---

## SSM Permission Errors

### GetParameter Denied

Required actions:
- `ssm:GetParameter`
- `ssm:GetParameters`
- `ssm:GetParametersByPath`

Check with:
```bash
aws ssm get-parameter --name /sentinel/policies/dev
```

### Custom Policy Root

If using custom policy root, update IAM policy resource:

```json
"Resource": [
  "arn:aws:ssm:*:*:parameter/myorg/sentinel/policies/*"
]
```

---

## FAQ

### Q: Can I use Sentinel with aws-vault?

Yes. Configure `credential_process` in your profile, and aws-vault will use Sentinel for that profile.

### Q: How do I test policies without affecting production?

1. Use a separate policy parameter for testing
2. Configure a test profile pointing to the test parameter
3. Test policy changes before updating production

### Q: Can multiple users share the same machine?

Yes. Sentinel uses OS username (`whoami`) for user identification. Each user's requests are tracked separately.

### Q: How long are credentials valid?

Default is 1 hour. Customize with `--duration`:
- `credentials`: Use `-d` flag
- `exec`: Use `-d` flag
- Maximum depends on role's max session duration

### Q: Can I use Sentinel in CI/CD?

Yes. Options:
1. Configure `credential_process` in the CI environment
2. Use an IAM role that allows Sentinel users
3. Set up auto-approval for CI user during deployment windows

### Q: What happens if SSM is unavailable?

Sentinel will fail to issue credentials. Consider:
- Multi-region SSM replication
- Break-glass procedures for SSM outages
- Local policy caching (not currently implemented)

### Q: How do I migrate from another credential tool?

1. Bootstrap Sentinel parameters
2. Configure policies to match current access patterns
3. Update one profile at a time to use `credential_process`
4. Monitor decision logs for unexpected denials
5. Gradually enable enforcement

### Q: Can I audit who accessed what?

Yes. Combine:
1. Sentinel decision logs (who requested, allow/deny)
2. CloudTrail (what actions were taken)
3. SourceIdentity correlation between the two

See [CloudTrail Correlation](../CLOUDTRAIL.md) for details.

---

## Getting Help

- **Debug mode:** `sentinel --debug <command>`
- **Decision logs:** `--log-stderr` or `--log-file`
- **GitHub Issues:** Report bugs or request features
