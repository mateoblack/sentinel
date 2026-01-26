# Policy Signing Guide

KMS-based cryptographic signing for Sentinel policy integrity verification.

## Overview

Policy signing prevents attackers from tampering with Sentinel policies stored in AWS SSM Parameter Store. Without signing, an attacker who compromises IAM credentials with SSM write access could modify policies to grant themselves elevated permissions.

### Threat Model

**Attacks prevented by policy signing:**

| Attack | Description | How Signing Prevents It |
|--------|-------------|-------------------------|
| Cache poisoning | Attacker modifies policy in SSM to add permissive rules | Lambda TVM rejects policies without valid KMS signature |
| SSM parameter tampering | Attacker with SSM:PutParameter access modifies policies | Signature verification fails because attacker lacks KMS signing key |
| Man-in-the-middle | Policy content modified during SSM read | Signature computed over original content won't match |
| Insider threat | Rogue admin modifies policies directly | KMS key access is separate from SSM access; requires both to inject malicious policies |

### Trust Model

```
                                  +-------------------+
                                  |   KMS Signing     |
                                  |       Key         |
                                  +--------+----------+
                                           |
                    Sign with kms:Sign     |    Verify with kms:Verify
                           +---------------+---------------+
                           |                               |
                           v                               v
+------------------+   +--------+-------+      +-----------+----------+
|  Policy Author   |-->|     SSM       |----->|    Lambda TVM        |
|  (trusted)       |   | Parameter     |      |  VerifyingLoader     |
+------------------+   | Store         |      +----------------------+
                       +---------------+               |
                                                       v
                                              +--------+--------+
                                              |  Credentials    |
                                              |  (if valid)     |
                                              +-----------------+
```

**Key principle:** Only principals with `kms:Sign` access to the signing key can create valid policy signatures. Lambda TVM verifies signatures before issuing credentials.

### Fail-Closed Security

When signature verification is enabled:

- **Invalid signature:** Credentials denied, error logged
- **Missing signature:** Credentials denied (when enforcement enabled)
- **KMS verification error:** Credentials denied, error logged

No credentials are ever issued for policies that fail signature verification.

## Prerequisites

- AWS account with KMS permissions
- Sentinel v1.18 or later
- For Lambda TVM: permissions to update function environment variables
- For CI/CD signing: IAM role with `kms:Sign` permission

## Creating a KMS Signing Key

The signing key must be an asymmetric RSA key with SIGN_VERIFY usage. Sentinel uses the `RSASSA_PSS_SHA_256` algorithm.

### AWS Console

1. Open the KMS console at https://console.aws.amazon.com/kms
2. Choose **Customer managed keys** > **Create key**
3. Configure:
   - Key type: **Asymmetric**
   - Key usage: **Sign and verify**
   - Key spec: **RSA_4096** (recommended) or RSA_2048
4. Add an alias: `alias/sentinel-policy-signing`
5. Define key administrators and users

### AWS CLI

```bash
# Create asymmetric signing key
aws kms create-key \
  --key-spec RSA_4096 \
  --key-usage SIGN_VERIFY \
  --description "Sentinel policy signing key" \
  --tags TagKey=Purpose,TagValue=sentinel-policy-signing

# Note the KeyId from the output
# Example: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

# Create alias for easier reference
aws kms create-alias \
  --alias-name alias/sentinel-policy-signing \
  --target-key-id 12345678-1234-1234-1234-123456789012
```

### Terraform

```hcl
resource "aws_kms_key" "sentinel_policy_signing" {
  description              = "Sentinel policy signing key"
  key_usage               = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_4096"

  # Enable key rotation is not available for asymmetric keys
  # Rotate by creating a new key and updating references

  tags = {
    Purpose = "sentinel-policy-signing"
  }
}

resource "aws_kms_alias" "sentinel_policy_signing" {
  name          = "alias/sentinel-policy-signing"
  target_key_id = aws_kms_key.sentinel_policy_signing.key_id
}

# IAM policy for signing (CI/CD pipelines, policy authors)
data "aws_iam_policy_document" "sentinel_policy_signer" {
  statement {
    sid    = "AllowPolicySigning"
    effect = "Allow"
    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.sentinel_policy_signing.arn]
  }
}

# IAM policy for verification (Lambda TVM execution role)
data "aws_iam_policy_document" "sentinel_policy_verifier" {
  statement {
    sid    = "AllowPolicyVerification"
    effect = "Allow"
    actions = [
      "kms:Verify",
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.sentinel_policy_signing.arn]
  }
}

resource "aws_iam_policy" "sentinel_policy_signer" {
  name   = "SentinelPolicySigner"
  policy = data.aws_iam_policy_document.sentinel_policy_signer.json
}

resource "aws_iam_policy" "sentinel_policy_verifier" {
  name   = "SentinelPolicyVerifier"
  policy = data.aws_iam_policy_document.sentinel_policy_verifier.json
}
```

### IAM Permissions

**For policy signers (CI/CD, policy authors):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPolicySigning",
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
    }
  ]
}
```

**For policy verifiers (Lambda TVM):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPolicyVerification",
      "Effect": "Allow",
      "Action": [
        "kms:Verify",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
    }
  ]
}
```

## Signing Policies Locally

### Sign a Policy

Use `sentinel policy sign` to create a detached signature:

```bash
# Sign and output to stdout
sentinel policy sign policy.yaml --key-id alias/sentinel-policy-signing

# Sign and save to file
sentinel policy sign policy.yaml --key-id alias/sentinel-policy-signing -o policy.sig

# Sign with explicit region
sentinel policy sign policy.yaml \
  --key-id arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
  --region us-east-1
```

**Output format (JSON):**

```json
{
  "signature": "base64-encoded-signature...",
  "metadata": {
    "key_id": "alias/sentinel-policy-signing",
    "algorithm": "RSASSA_PSS_SHA_256",
    "signed_at": "2026-01-26T10:30:00Z",
    "policy_hash": "a1b2c3d4e5f67890..."
  }
}
```

The signature file contains:
- `signature`: Base64-encoded KMS signature bytes
- `metadata.key_id`: KMS key identifier used for signing
- `metadata.algorithm`: Signing algorithm (always `RSASSA_PSS_SHA_256`)
- `metadata.signed_at`: UTC timestamp of signature creation
- `metadata.policy_hash`: SHA-256 hash of the policy content (hex-encoded)

### Verify a Signature

Verify a policy against its signature locally:

```bash
# Verify signature
sentinel policy verify policy.yaml --key-id alias/sentinel-policy-signing -s policy.sig

# Output on success: "Signature valid"
# Output on failure: "Signature invalid" with details
```

**Exit codes:**
- `0`: Signature is valid
- `1`: Signature is invalid or verification error

### Push Signed Policies

Upload a policy with its signature to SSM:

```bash
# Sign and push in one command
sentinel policy push myprofile policy.yaml --sign --key-id alias/sentinel-policy-signing

# This creates two SSM parameters:
# /sentinel/policies/myprofile     - the policy YAML
# /sentinel/signatures/myprofile   - the signature JSON
```

**Alternative: separate sign and push:**

```bash
# Sign locally
sentinel policy sign policy.yaml --key-id alias/sentinel-policy-signing -o policy.sig

# Push policy
sentinel policy push myprofile policy.yaml

# Push signature (manual SSM put)
aws ssm put-parameter \
  --name /sentinel/signatures/myprofile \
  --type String \
  --value "$(cat policy.sig)" \
  --overwrite
```

### SSM Parameter Structure

Signed policies use paired parameters:

| Parameter | Content | Example Path |
|-----------|---------|--------------|
| Policy | YAML policy content | `/sentinel/policies/production` |
| Signature | JSON signature envelope | `/sentinel/signatures/production` |

The signature parameter path is derived by replacing `/policies/` with `/signatures/` in the policy path.

## Lambda TVM Signature Verification

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SENTINEL_POLICY_SIGNING_KEY` | KMS key ARN or alias for verifying signatures | (none) |
| `SENTINEL_ENFORCE_POLICY_SIGNING` | Set to `"true"` to reject unsigned policies | `"true"` when signing key is set |

### Configuration Workflow

**1. Add to existing Lambda TVM:**

```bash
aws lambda update-function-configuration \
  --function-name sentinel-tvm \
  --environment "Variables={
    SENTINEL_POLICY_PARAMETER=/sentinel/policies/production,
    SENTINEL_POLICY_SIGNING_KEY=alias/sentinel-policy-signing,
    SENTINEL_ENFORCE_POLICY_SIGNING=true
  }"
```

**2. Grant KMS verify permission to Lambda execution role:**

```bash
aws iam attach-role-policy \
  --role-name SentinelTVMExecutionRole \
  --policy-arn arn:aws:iam::ACCOUNT:policy/SentinelPolicyVerifier
```

### Terraform Configuration

```hcl
module "sentinel_tvm" {
  source = "./terraform/sentinel-tvm"

  # ... other configuration ...

  # Policy signing
  policy_signing_key_arn     = aws_kms_key.sentinel_policy_signing.arn
  enforce_policy_signing     = true
}
```

Or directly on the Lambda resource:

```hcl
resource "aws_lambda_function" "sentinel_tvm" {
  # ... other configuration ...

  environment {
    variables = {
      SENTINEL_POLICY_PARAMETER       = "/sentinel/policies/production"
      SENTINEL_POLICY_SIGNING_KEY     = aws_kms_key.sentinel_policy_signing.arn
      SENTINEL_ENFORCE_POLICY_SIGNING = "true"
    }
  }
}

# Attach KMS verify permission to execution role
resource "aws_iam_role_policy_attachment" "tvm_policy_verifier" {
  role       = aws_iam_role.sentinel_tvm_execution.name
  policy_arn = aws_iam_policy.sentinel_policy_verifier.arn
}
```

### Loader Chain

When signature verification is enabled, the Lambda TVM policy loader chain is:

```
SSM Parameter Store
        |
        v
+-------+--------+
| LoaderWithRaw  |  (fetches raw policy YAML)
+-------+--------+
        |
        v
+-------+--------+
| VerifyingLoader|  (verifies KMS signature)
+-------+--------+
        |
        v
+-------+--------+
| CachedLoader   |  (caches valid policies)
+-------+--------+
        |
        v
   Policy Object
```

The `VerifyingLoader`:
1. Loads policy YAML from `/sentinel/policies/X`
2. Loads signature JSON from `/sentinel/signatures/X`
3. Verifies signature using KMS
4. Returns policy only if signature is valid

### Enforcement Modes

| `SENTINEL_POLICY_SIGNING_KEY` | `SENTINEL_ENFORCE_POLICY_SIGNING` | Behavior |
|-------------------------------|-----------------------------------|----------|
| Not set | Not set | Signature verification disabled |
| Set | Not set (defaults to `true`) | Unsigned policies rejected |
| Set | `"true"` | Unsigned policies rejected |
| Set | `"false"` | Unsigned policies allowed with warning log |

**Recommended:** Set both `SENTINEL_POLICY_SIGNING_KEY` and `SENTINEL_ENFORCE_POLICY_SIGNING=true` for fail-closed security.

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: Policy Deployment

on:
  push:
    paths:
      - 'policies/**'
    branches:
      - main

jobs:
  validate-and-deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Setup Sentinel
        run: |
          go install github.com/byteness/aws-vault/v7/cmd/sentinel@latest

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/PolicyDeploymentRole
          aws-region: us-east-1

      - name: Validate policies
        run: |
          for policy in policies/*.yaml; do
            sentinel policy validate "$policy" -q
          done

      - name: Check for changes
        id: diff
        run: |
          CHANGED=false
          for policy in policies/*.yaml; do
            PROFILE=$(basename "$policy" .yaml)
            if ! sentinel policy diff "$PROFILE" "$policy" --no-color > /dev/null 2>&1; then
              echo "Changes detected in $PROFILE"
              CHANGED=true
            fi
          done
          echo "changed=$CHANGED" >> $GITHUB_OUTPUT

      - name: Deploy signed policies
        if: steps.diff.outputs.changed == 'true'
        run: |
          for policy in policies/*.yaml; do
            PROFILE=$(basename "$policy" .yaml)
            # Sign and push
            sentinel policy push "$PROFILE" "$policy" \
              --sign \
              --key-id alias/sentinel-policy-signing \
              --force
          done
```

### Pre-Push Validation Script

```bash
#!/bin/bash
# scripts/validate-policy.sh
# Run before pushing policy changes

set -e

POLICY_FILE=${1:-policy.yaml}
PROFILE=${2:-production}
KEY_ID=${3:-alias/sentinel-policy-signing}

echo "=== Validating policy: $POLICY_FILE ==="

# Step 1: Validate syntax locally (no AWS needed)
echo "1. Validating syntax..."
sentinel policy validate "$POLICY_FILE" -q
echo "   Syntax valid"

# Step 2: Check diff against current policy
echo "2. Checking changes..."
if sentinel policy diff "$PROFILE" "$POLICY_FILE" --no-color > /tmp/policy-diff.txt 2>&1; then
  echo "   No changes detected"
  exit 0
fi
echo "   Changes detected:"
cat /tmp/policy-diff.txt

# Step 3: Sign the policy
echo "3. Signing policy..."
sentinel policy sign "$POLICY_FILE" --key-id "$KEY_ID" -o /tmp/policy.sig
echo "   Signed successfully"

# Step 4: Verify signature
echo "4. Verifying signature..."
sentinel policy verify "$POLICY_FILE" --key-id "$KEY_ID" -s /tmp/policy.sig
echo "   Signature verified"

echo ""
echo "=== Validation complete ==="
echo "Ready to push with:"
echo "  sentinel policy push $PROFILE $POLICY_FILE --sign --key-id $KEY_ID"
```

### Approval Gates for Policy Changes

For organizations requiring approval before policy deployment:

```yaml
name: Policy Change Request

on:
  pull_request:
    paths:
      - 'policies/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate all policies
        run: |
          for policy in policies/*.yaml; do
            sentinel policy validate "$policy"
          done

      - name: Show policy diff
        run: |
          for policy in policies/*.yaml; do
            PROFILE=$(basename "$policy" .yaml)
            echo "=== $PROFILE ==="
            sentinel policy diff "$PROFILE" "$policy" || true
          done

  require-approval:
    runs-on: ubuntu-latest
    needs: validate
    environment: policy-review  # Requires manual approval in GitHub
    steps:
      - run: echo "Policy changes approved"
```

## Troubleshooting

### Common Errors

**Error: `policy signature verification failed`**

The signature doesn't match the policy content.

**Causes:**
- Policy was modified after signing
- Wrong signature file
- Signature created with different KMS key

**Resolution:**
```bash
# Re-sign the policy
sentinel policy sign policy.yaml --key-id alias/sentinel-policy-signing -o policy.sig

# Push both policy and signature
sentinel policy push myprofile policy.yaml --sign --key-id alias/sentinel-policy-signing
```

---

**Error: `policy signature missing`**

No signature parameter exists for the policy.

**Causes:**
- Policy pushed without `--sign` flag
- Signature parameter deleted
- Wrong signature parameter path

**Resolution:**
```bash
# Check if signature exists
aws ssm get-parameter --name /sentinel/signatures/myprofile

# Push with signing
sentinel policy push myprofile policy.yaml --sign --key-id alias/sentinel-policy-signing
```

---

**Error: `policy not signed (signature enforcement enabled)`**

Signature enforcement is enabled but the policy has no signature.

**Causes:**
- Policy was pushed without signing
- `SENTINEL_ENFORCE_POLICY_SIGNING=true` is set

**Resolution:**
Sign and push the policy:
```bash
sentinel policy push myprofile policy.yaml --sign --key-id alias/sentinel-policy-signing
```

---

**Error: `AccessDeniedException` on KMS operations**

IAM permissions missing for KMS Sign or Verify.

**Resolution for signing:**
```bash
# Add kms:Sign permission to your role/user
aws iam attach-role-policy \
  --role-name YourRole \
  --policy-arn arn:aws:iam::ACCOUNT:policy/SentinelPolicySigner
```

**Resolution for Lambda TVM:**
```bash
# Add kms:Verify permission to Lambda execution role
aws iam attach-role-policy \
  --role-name SentinelTVMExecutionRole \
  --policy-arn arn:aws:iam::ACCOUNT:policy/SentinelPolicyVerifier
```

---

**Error: `KMSInvalidKeyUsageException`**

The KMS key is not configured for signing.

**Causes:**
- Key usage is `ENCRYPT_DECRYPT` instead of `SIGN_VERIFY`
- Key is symmetric instead of asymmetric

**Resolution:**
Create a new asymmetric signing key:
```bash
aws kms create-key \
  --key-spec RSA_4096 \
  --key-usage SIGN_VERIFY \
  --description "Sentinel policy signing key"
```

### Log Messages

Lambda TVM logs signature verification status:

| Log Message | Meaning |
|-------------|---------|
| `INFO: Policy signature verification enabled (key: ..., enforce: true)` | Signature verification active |
| `INFO: Policy signature verification disabled (SENTINEL_POLICY_SIGNING_KEY not set)` | Verification not configured |
| `WARNING: policy X has no signature, loading without verification` | Unsigned policy (enforcement disabled) |

### Debugging with `policy verify`

Test signature verification locally:

```bash
# Verify against specific key
sentinel policy verify policy.yaml \
  --key-id alias/sentinel-policy-signing \
  -s policy.sig

# Output shows validation result and any mismatches
```

### Checking SSM Parameters

Verify both policy and signature are in SSM:

```bash
# List policy parameters
aws ssm get-parameters-by-path --path /sentinel/policies --recursive

# List signature parameters
aws ssm get-parameters-by-path --path /sentinel/signatures --recursive

# Get specific signature
aws ssm get-parameter --name /sentinel/signatures/production --query 'Parameter.Value' --output text | jq .
```

## Security Considerations

### Key Rotation

KMS asymmetric keys cannot be automatically rotated. To rotate:

1. Create a new signing key
2. Re-sign all policies with the new key
3. Update Lambda TVM `SENTINEL_POLICY_SIGNING_KEY` to new key
4. Delete old key after verification period

### Least Privilege

- **Signing (kms:Sign):** Grant only to CI/CD pipelines and authorized policy authors
- **Verification (kms:Verify):** Grant only to Lambda TVM execution role
- **Key administration:** Separate from signing/verification permissions

### Audit Trail

- KMS logs all Sign and Verify operations to CloudTrail
- SSM logs parameter access
- Lambda TVM logs signature verification results

### Disaster Recovery

Keep offline backup of:
- KMS key ID/ARN
- Current policies and signatures (from SSM)
- IAM policies for key access

In case of key deletion, you'll need to:
1. Create new signing key
2. Re-sign all policies
3. Update all Lambda TVM configurations
