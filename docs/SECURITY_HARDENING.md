# Security Hardening Guide

Comprehensive security hardening features introduced in Sentinel v1.16, covering timing attack mitigation, secrets management, rate limiting, error sanitization, and encryption.

## Overview

Version 1.16 addresses findings from a comprehensive security audit with targeted hardening measures across all credential endpoints and infrastructure components.

### Hardening Areas

| Area | Description | Components |
|------|-------------|------------|
| Timing Attack Mitigation | Constant-time token comparison | Credential servers |
| Secrets Management | AWS Secrets Manager integration | Lambda TVM |
| Rate Limiting | Request throttling with RFC 7231 compliance | Lambda TVM, credential servers |
| Error Sanitization | Generic client responses, detailed internal logs | All credential endpoints |
| DynamoDB Encryption | AWS-managed KMS encryption | All Sentinel tables |
| CI/CD Scanning | Automated security scanning | GitHub Actions |

### When to Apply

Apply these hardening features for:

- **Production deployments:** All production Sentinel deployments should implement all hardening features
- **Regulated environments:** SOC 2, HIPAA, PCI-DSS, and other compliance frameworks benefit from documented security controls
- **Security-conscious organizations:** Organizations with security teams or dedicated security review processes

## Threat Model

### Attacks Prevented

| Attack | Description | How Hardening Prevents It |
|--------|-------------|---------------------------|
| Timing oracle on bearer tokens | Attacker measures response times to extract token bytes | `crypto/subtle.ConstantTimeCompare()` ensures constant-time comparison regardless of token match position |
| Credential stuffing | Automated attempts to brute-force credentials | Rate limiting blocks excessive requests with configurable windows and burst limits |
| Information leakage via errors | Attacker extracts internal paths, ARNs, or configuration from error messages | Error sanitization logs details internally, returns generic messages to clients |
| Unencrypted data at rest | Attacker with storage access reads sensitive data | DynamoDB KMS encryption protects all stored data |
| Secret exposure in environment | Attacker reads Lambda environment variables to extract API tokens | Secrets Manager stores sensitive tokens with IAM-controlled access |

### Defense in Depth

```
Client Request
      |
      v
+-----+------+
| Rate Limit |  <-- Block excessive requests (100 req/min default)
+-----+------+
      |
      v
+-----+-------+
| Token Auth  |  <-- Constant-time comparison (timing-safe)
+-----+-------+
      |
      v
+-----+--------+
| Policy Eval  |  <-- SSM policy with optional signature verification
+-----+--------+
      |
      v
+-----+-----------+
| Credential Fetch|  <-- Secrets from Secrets Manager (not env vars)
+-----+-----------+
      |
      v
+-----+------+
| Audit Log  |  <-- Sanitized errors (no internal details)
+-----+------+
      |
      v
+-----+-------+
| Response    |  <-- Credentials (if allowed) or generic error
+-----+-------+
```

### Fail-Closed vs Fail-Open Decisions

| Component | Behavior | Rationale |
|-----------|----------|-----------|
| Policy signature verification | Fail-closed | Invalid signatures deny credentials; security cannot be bypassed |
| Rate limiting | Fail-open | DynamoDB errors allow requests; availability prioritized over abuse prevention |
| Secrets Manager | Fail-closed | Missing secrets deny requests; credentials cannot be issued without proper configuration |

Rate limiting fails open to prevent denial of service: an attacker cannot cause outages by overwhelming the rate limit backend.

## Timing Attack Mitigation

### The Threat

Standard string comparison (`==`) in most programming languages uses early exit optimization - it returns `false` as soon as it finds the first mismatched byte. This creates a timing oracle:

```go
// VULNERABLE - returns early on first mismatch
if token == expectedToken {
    // ...
}
```

An attacker can measure response times to determine how many leading bytes of their guess match the actual token. By iterating through byte values and measuring response times, they can extract the entire token byte-by-byte.

### The Solution

Sentinel uses `crypto/subtle.ConstantTimeCompare()` for all bearer token comparisons:

```go
import "crypto/subtle"

// SECURE - constant-time comparison
if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1 {
    // Token is valid
}
```

This function compares all bytes regardless of where mismatches occur, making timing analysis ineffective.

### Affected Components

| Component | File | Function |
|-----------|------|----------|
| Sentinel credential server | `sentinel/server.go` | `withAuthorizationCheck()` |
| ECS credential server | `server/ecsserver.go` | `withAuthorizationCheck()` |

### Code Pattern

The secure pattern used in both servers:

```go
// withAuthorizationCheck is middleware that validates the Authorization header.
// SECURITY: Uses constant-time comparison to prevent timing attacks on bearer tokens.
func withAuthorizationCheck(authToken string, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // SECURITY: Use constant-time comparison to prevent timing attacks.
        // Direct string comparison (!=) returns early on first mismatched byte,
        // leaking timing information that allows attackers to extract the token
        // byte-by-byte by measuring response times.
        if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(authToken)) != 1 {
            writeErrorMessage(w, "invalid Authorization token", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    }
}
```

### Verification

Security regression tests validate timing-safe comparison using AST analysis:

```bash
# Run security tests
go test ./... -run Security

# Specific timing attack tests
go test ./sentinel -run TestTimingSafe
go test ./server -run TestTimingSafe
```

The tests verify that:
1. Token comparison uses `crypto/subtle.ConstantTimeCompare`
2. Direct string comparison (`==`, `!=`) is not used for tokens
3. Comparison is performed on byte slices, not strings

## Secrets Manager Integration

### Why Use Secrets Manager

Environment variables are visible in:
- Lambda console configuration tab
- CloudWatch Logs (if accidentally logged)
- Process environment dumps
- Container inspection

AWS Secrets Manager provides:
- IAM-controlled access
- Automatic rotation support
- Audit trail via CloudTrail
- Encryption at rest

### How It Works

The `CachedSecretsLoader` provides in-process caching with configurable TTL:

```go
// CachedSecretsLoader wraps AWS Secrets Manager with caching
type CachedSecretsLoader struct {
    client secretsManagerAPI
    ttl    time.Duration
    cache  map[string]*cachedSecret
}

// Default TTL is 1 hour - optimized for Lambda cold starts
const DefaultSecretsCacheTTL = 1 * time.Hour
```

### Configuration Steps

**Step 1: Create secret in AWS Secrets Manager**

```bash
aws secretsmanager create-secret \
  --name sentinel/mdm-api-token \
  --description "MDM API token for Sentinel device posture verification" \
  --secret-string "your-api-token-here"
```

**Step 2: Grant Lambda/server IAM role permission**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSecretsManagerRead",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:sentinel/*"
    }
  ]
}
```

**Step 3: Set environment variable pointing to secret**

```bash
aws lambda update-function-configuration \
  --function-name sentinel-tvm \
  --environment "Variables={MDM_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:sentinel/mdm-api-token}"
```

### Terraform Example

```hcl
# Create the secret
resource "aws_secretsmanager_secret" "mdm_token" {
  name        = "sentinel/mdm-api-token"
  description = "MDM API token for Sentinel device posture verification"
}

resource "aws_secretsmanager_secret_version" "mdm_token" {
  secret_id     = aws_secretsmanager_secret.mdm_token.id
  secret_string = var.mdm_api_token
}

# Grant Lambda access
resource "aws_iam_role_policy" "tvm_secrets_access" {
  name = "SentinelTVMSecretsAccess"
  role = aws_iam_role.sentinel_tvm_execution.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowSecretsManagerRead"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.mdm_token.arn
      }
    ]
  })
}

# Configure Lambda
resource "aws_lambda_function" "sentinel_tvm" {
  # ... other configuration ...

  environment {
    variables = {
      MDM_SECRET_ARN = aws_secretsmanager_secret.mdm_token.arn
    }
  }
}
```

### Cache Behavior

| Behavior | Default | Configurable |
|----------|---------|--------------|
| TTL | 1 hour | Yes, via `WithTTL()` |
| Cache scope | In-process (per Lambda instance) | No |
| Cache invalidation | TTL-based expiry | No manual invalidation |
| Cold start behavior | First request fetches from Secrets Manager | N/A |

**Customizing TTL:**

```go
loader, err := NewCachedSecretsLoader(awsCfg, WithTTL(30*time.Minute))
```

### Backward Compatibility

For migration, the Secrets Manager integration falls back to environment variables:

1. Check `MDM_SECRET_ARN` environment variable
2. If set, load secret from Secrets Manager
3. If not set or load fails, fall back to `MDM_API_TOKEN` environment variable
4. Log deprecation warning when using environment variable fallback

```
WARN: Using MDM_API_TOKEN environment variable (deprecated).
      Migrate to Secrets Manager: set MDM_SECRET_ARN instead.
```

## Rate Limiting Configuration

Sentinel provides two rate limiting implementations for different deployment scenarios.

### Memory-Based (Single Instance)

**Use case:** Local credential server, development environments, single-instance deployments.

```go
import "github.com/byteness/aws-vault/v7/ratelimit"

limiter, err := ratelimit.NewMemoryRateLimiter(ratelimit.Config{
    RequestsPerWindow: 100,      // Max requests per window
    Window:            time.Minute,  // Time window duration
    BurstSize:         10,       // Allow short bursts above rate
})
```

**Configuration options:**

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `RequestsPerWindow` | int | Maximum requests allowed in window | Required |
| `Window` | time.Duration | Time window for counting requests | Required |
| `BurstSize` | int | Burst allowance above base rate | `RequestsPerWindow` |

### DynamoDB-Based (Distributed)

**Use case:** Lambda TVM, multiple credential servers, distributed deployments.

```go
import "github.com/byteness/aws-vault/v7/ratelimit"

limiter, err := ratelimit.NewDynamoDBRateLimiter(
    dynamoClient,           // AWS SDK DynamoDB client
    "sentinel-ratelimit",   // Table name
    ratelimit.Config{
        RequestsPerWindow: 100,
        Window:            time.Minute,
    },
)
```

**Table schema:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `PK` | String | Partition key: `"RL#" + key` (e.g., `RL#arn:aws:iam::123456789:user/alice`) |
| `WindowStart` | String | ISO8601 timestamp of current window start |
| `Count` | Number | Request count in current window |
| `TTL` | Number | Unix timestamp for DynamoDB TTL (auto-cleanup) |

**Atomic operations:**

The DynamoDB rate limiter uses `UpdateItem` with condition expressions for atomic increment:

```go
// Atomic increment or window reset
UpdateExpression: "SET #count = if_not_exists(#count, :zero) + :one, #ws = if_not_exists(#ws, :ws), #ttl = :ttl"
ConditionExpression: "attribute_not_exists(#ws) OR #ws = :ws"
```

**Fail-open behavior:**

DynamoDB errors log a warning and allow the request:

```go
if err != nil {
    log.Printf("ratelimit: DynamoDB error (failing open): %v", err)
    return true, 0, err  // Allow request despite error
}
```

### Response Headers

Rate limit responses include RFC 7231 compliant headers:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 45

{"Message": "Rate limit exceeded"}
```

The `Retry-After` header indicates seconds until the client should retry.

### Integration Example

**Sentinel credential server:**

```go
config := SentinelServerConfig{
    // ... other config ...
    RateLimitConfig: &ratelimit.Config{
        RequestsPerWindow: 100,
        Window:            time.Minute,
        BurstSize:         10,
    },
}

server, err := NewSentinelServer(ctx, config, authToken, port)
```

**Lambda TVM with DynamoDB:**

```go
dynamoClient := dynamodb.NewFromConfig(awsCfg)
limiter, err := ratelimit.NewDynamoDBRateLimiter(
    dynamoClient,
    os.Getenv("RATE_LIMIT_TABLE"),
    ratelimit.Config{
        RequestsPerWindow: 100,
        Window:            time.Minute,
    },
)
```

## Error Sanitization Pattern

### The Principle

**Log detailed errors internally, return generic messages to clients.**

Internal logs enable debugging and incident response. Client responses prevent information leakage to potential attackers.

### What's Sanitized

| Internal Detail | Client Response |
|-----------------|-----------------|
| SSM parameter paths (`/sentinel/policies/prod`) | `"internal error"` |
| ARN parsing errors | `"internal error"` |
| MDM provider failures | `"device verification failed"` |
| Credential retrieval errors | `"Failed to retrieve credentials"` |
| DynamoDB errors | `"internal error"` |
| Policy loading failures | `"Failed to load policy"` |

### What's Preserved

Some information is intentionally returned to clients:

| Information | Rationale |
|-------------|-----------|
| Rate limit `Retry-After` | Enables proper client backoff behavior |
| Policy deny reasons | Intentional user-facing feedback (e.g., "Production requires server mode") |
| Authentication failures | Generic "invalid Authorization token" is safe |

### Code Pattern

```go
// Internal logging with full details
log.Printf("ERROR: failed to load policy from %s: %v", ssmPath, err)

// External response with generic message
writeErrorMessage(w, "internal error", http.StatusInternalServerError)
```

**Do NOT do this:**

```go
// WRONG - leaks internal details to client
writeErrorMessage(w, fmt.Sprintf("failed to load policy from %s: %v", ssmPath, err), 500)
```

### Verification

Security tests validate error sanitization:

```bash
go test ./... -run Sanitiz
```

Tests verify that:
1. Error responses do not contain SSM paths
2. Error responses do not contain ARNs
3. Error responses do not contain stack traces
4. Internal details are present in logs but not responses

## DynamoDB Encryption

All Sentinel DynamoDB tables use AWS-managed KMS encryption by default.

### Encrypted Tables

| Table | Purpose | Encryption |
|-------|---------|------------|
| Approval requests | Stores access request workflow state | AWS-managed KMS |
| Break-glass events | Stores emergency access audit trail | AWS-managed KMS |
| Server sessions | Tracks active credential server sessions | AWS-managed KMS |
| Rate limit counters | Stores distributed rate limit state | AWS-managed KMS |

### Encryption Configuration

The `infrastructure/schema.go` package defines encryption options:

```go
// EncryptionType represents the encryption type for DynamoDB tables.
type EncryptionType string

const (
    // EncryptionDefault uses AWS owned encryption (default for DynamoDB).
    EncryptionDefault EncryptionType = "DEFAULT"
    // EncryptionKMS uses AWS managed KMS key for encryption.
    EncryptionKMS EncryptionType = "KMS"
    // EncryptionCustomerKey uses a customer-provided CMK ARN.
    EncryptionCustomerKey EncryptionType = "CUSTOMER_KEY"
)
```

**Configuration struct:**

```go
type EncryptionConfig struct {
    Type      EncryptionType
    KMSKeyARN string  // Only for EncryptionCustomerKey
}
```

### Terraform Example

**AWS-managed KMS (recommended default):**

```hcl
resource "aws_dynamodb_table" "sessions" {
  name         = "sentinel-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled = true  # Uses AWS-managed KMS key
  }
}
```

**Customer-managed CMK:**

```hcl
resource "aws_kms_key" "sentinel" {
  description = "Sentinel DynamoDB encryption key"
}

resource "aws_dynamodb_table" "sessions" {
  name         = "sentinel-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.sentinel.arn
  }
}
```

### Table Schema Functions

The `infrastructure` package provides pre-configured schemas with encryption:

```go
// All table schema functions return schemas with AWS-managed KMS encryption
schema := infrastructure.ApprovalTableSchema("sentinel-requests")
schema := infrastructure.BreakGlassTableSchema("sentinel-breakglass")
schema := infrastructure.SessionTableSchema("sentinel-sessions")

// Each schema includes:
// Encryption: DefaultEncryptionKMS()
```

## CI/CD Security Scanning

### Integrated Tools

| Tool | Purpose | Trigger |
|------|---------|---------|
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | Go vulnerability database scanning | PR, Push, Weekly |
| [gosec](https://github.com/securego/gosec) | Static application security testing (SAST) | PR, Push, Weekly |
| [Trivy](https://github.com/aquasecurity/trivy) | Container and filesystem vulnerability scanning | PR, Push, Weekly |

### Local Scanning Commands

Run security scans locally before committing:

```bash
# Go vulnerability database scan
govulncheck ./...

# Static application security testing
gosec ./...

# Filesystem scanning
trivy fs .
```

### Installing Scan Tools

```bash
# govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# trivy (macOS)
brew install trivy

# trivy (Linux)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

### GitHub Actions Integration

Security scans run automatically on:
- Pull requests (block merge on findings)
- Push to main (alert on findings)
- Weekly schedule (catch newly disclosed vulnerabilities)

Results are uploaded to GitHub Security tab for centralized tracking.

## Security Regression Tests

### Purpose

Security regression tests prevent reintroduction of previously fixed security issues. They validate:

1. **Timing-safe comparison:** AST analysis verifies `crypto/subtle` usage
2. **Rate limiter bypass resistance:** Concurrent access tests
3. **Error sanitization:** Response inspection for leaked details
4. **Memory bounds:** Rate limiters don't grow unbounded

### Running Tests

```bash
# All security tests
go test ./... -run Security

# Specific categories
go test ./sentinel -run TestTimingSafe
go test ./server -run TestTimingSafe
go test ./ratelimit -run TestConcurrent
go test ./... -run TestErrorSanitiz
```

### Test File Locations

Security tests are located in `*_security_test.go` files:

| Package | Test File | Tests |
|---------|-----------|-------|
| `sentinel` | `server_security_test.go` | Timing-safe token comparison |
| `server` | `ecsserver_security_test.go` | Timing-safe token comparison |
| `ratelimit` | `ratelimit_security_test.go` | Bypass resistance, memory bounds |
| `lambda` | `lambda_security_test.go` | Error sanitization |

### Test Coverage

Security regression tests are part of the CI/CD pipeline. The test suite includes:

- 153 security regression tests across 13 packages
- AST verification for security-critical code patterns
- Concurrent access testing for race conditions
- Memory profiling for resource exhaustion prevention

## Troubleshooting

### Rate Limit Triggered Unexpectedly

**Symptoms:**
- Receiving `429 Too Many Requests` during normal usage
- `Retry-After` header in responses

**Causes:**
- Window configuration too restrictive
- DynamoDB latency causing retry storms
- Burst size not accounting for normal usage patterns

**Resolution:**

1. Check current configuration:
   ```bash
   # Lambda TVM
   aws lambda get-function-configuration --function-name sentinel-tvm \
     --query 'Environment.Variables' | grep RATE
   ```

2. Adjust rate limit settings:
   ```bash
   aws lambda update-function-configuration \
     --function-name sentinel-tvm \
     --environment "Variables={
       RATE_LIMIT_REQUESTS=200,
       RATE_LIMIT_WINDOW=60s,
       RATE_LIMIT_BURST=20
     }"
   ```

3. Check DynamoDB latency in CloudWatch metrics

### Secrets Manager Access Denied

**Symptoms:**
- `AccessDeniedException` when Lambda starts
- Credentials not being vended

**Causes:**
- IAM permissions missing `secretsmanager:GetSecretValue`
- Secret ARN format incorrect
- Secret doesn't exist or is in different region

**Resolution:**

1. Verify secret exists:
   ```bash
   aws secretsmanager describe-secret --secret-id sentinel/mdm-api-token
   ```

2. Verify IAM permissions:
   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole \
     --action-names secretsmanager:GetSecretValue \
     --resource-arns arn:aws:secretsmanager:REGION:ACCOUNT:secret:sentinel/mdm-api-token
   ```

3. Check secret ARN format:
   - Correct: `arn:aws:secretsmanager:us-east-1:123456789012:secret:sentinel/mdm-api-token`
   - With suffix: `arn:aws:secretsmanager:us-east-1:123456789012:secret:sentinel/mdm-api-token-AbCdEf` (auto-generated)

### Security Test Failures

**Symptoms:**
- `TestTimingSafe` failing
- Security regression test failures in CI

**Causes:**
- Token comparison not using `crypto/subtle.ConstantTimeCompare`
- Direct string comparison (`==`, `!=`) used for tokens

**Resolution:**

1. Review the failing test output for specific line numbers

2. Ensure all token comparisons use constant-time comparison:
   ```go
   // CORRECT
   if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1 {

   // INCORRECT - will fail security tests
   if token == expected {
   ```

3. Run the specific test with verbose output:
   ```bash
   go test ./sentinel -run TestTimingSafe -v
   ```

### DynamoDB Encryption Verification

**Verifying encryption is enabled:**

```bash
aws dynamodb describe-table --table-name sentinel-sessions \
  --query 'Table.SSEDescription'
```

Expected output for AWS-managed KMS:
```json
{
  "Status": "ENABLED",
  "SSEType": "KMS",
  "KMSMasterKeyArn": "arn:aws:kms:us-east-1:123456789012:key/..."
}
```

**If encryption is not enabled:**

DynamoDB tables created before v1.16 may not have encryption enabled. To enable:

```bash
aws dynamodb update-table \
  --table-name sentinel-sessions \
  --sse-specification Enabled=true
```
