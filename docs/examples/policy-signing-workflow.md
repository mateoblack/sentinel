# Policy Signing Workflow Example

This example shows the complete workflow for signing and deploying a Sentinel policy.

## Prerequisites

- KMS signing key created (see POLICY_SIGNING.md)
- `kms:Sign` permission for CI/CD or policy author
- Lambda TVM with `kms:Verify` permission

## Workflow

### 1. Create or Edit Policy

```yaml
# production-policy.yaml
version: "1"
rules:
  - name: prod-access
    effect: allow
    conditions:
      profiles: [production]
      device:
        require_mdm: true
    reason: Production access from managed device
```

### 2. Validate Locally

```bash
sentinel policy validate production-policy.yaml
```

### 3. Diff Against Current

```bash
sentinel policy diff production production-policy.yaml
```

### 4. Sign and Push

```bash
# Sign and push in one command
sentinel policy push production production-policy.yaml \
  --sign --key-id alias/sentinel-policy-signing

# This creates:
# /sentinel/policies/production - policy YAML
# /sentinel/signatures/production - signature JSON
```

### 5. Verify Deployment

```bash
# Pull and verify the deployed policy
sentinel policy pull production -o deployed.yaml
sentinel policy verify deployed.yaml \
  --key-id alias/sentinel-policy-signing \
  -s /tmp/sig.json
```

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Sign and Deploy Policy
  run: |
    sentinel policy validate policy.yaml
    sentinel policy push production policy.yaml \
      --sign --key-id alias/sentinel-policy-signing \
      --force
  env:
    AWS_REGION: us-east-1
```
