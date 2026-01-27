# Architecture Research: Server-Side Credential Vending

**Domain:** AWS Lambda TVM for Sentinel CLI tool
**Researched:** 2026-01-24
**Confidence:** HIGH

## Executive Summary

A Lambda-based Token Vending Machine (TVM) for Sentinel should be architected as a **shared-code monorepo** with two separate build targets: the existing CLI binary and a new Lambda handler binary. Both executables share the core Sentinel packages (policy, session, identity, logging) but have different entrypoints and deployment models.

**Critical constraint:** The Lambda function IS the trust boundary. Only the Lambda execution role can call AssumeRole on protected roles - client applications must call the Lambda endpoint (via API Gateway) to obtain credentials.

## Code Reuse Strategy

### Recommended Approach: Monorepo with Multiple Binaries

**Pattern:** Sentinel already follows Go monorepo best practices with `cmd/sentinel/main.go` for CLI and shared packages under the project root. The Lambda handler follows the same pattern.

**Structure:**
```
sentinel/
├── cmd/
│   ├── sentinel/          # Existing CLI binary
│   │   └── main.go
│   └── lambda-tvm/        # NEW: Lambda TVM binary
│       └── main.go
├── policy/                # Shared package
├── session/               # Shared package
├── identity/              # Shared package
├── logging/               # Shared package
├── request/               # Shared package
├── breakglass/            # Shared package
└── lambda/                # NEW: Lambda-specific handler logic
    ├── handler.go         # HTTP API Gateway handler
    ├── types.go           # Request/response types
    └── credentials.go     # Credential vending logic
```

**Build targets:**
- `go build ./cmd/sentinel` → CLI binary (existing)
- `GOOS=linux GOARCH=amd64 go build -o bootstrap ./cmd/lambda-tvm` → Lambda binary (new)

**Why this works:**
- Go compiles only used code - Lambda binary doesn't include CLI-only packages (kingpin, vault keyring, prompt)
- Existing Makefile patterns support multiple GOOS/GOARCH targets (already builds 9 target platforms)
- No code duplication - both binaries import the same policy/session/identity packages
- Single go.mod for dependency management

**Confidence:** HIGH - This pattern is explicitly recommended in Go Lambda documentation and monorepo best practices. Source: [Building Lambda functions with Go - AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/lambda-golang.html)

### What Gets Shared

**Core evaluation logic (100% reuse):**
- `policy.Evaluate()` - Policy evaluation engine
- `policy.PolicyLoader` - SSM policy loading with caching
- `session.Store` - DynamoDB session tracking
- `identity.GenerateSourceIdentity()` - SourceIdentity stamping
- `identity.GetAWSUsername()` - User extraction from STS
- `logging.Logger` - Decision logging
- `request.Store` - Approval workflow checking
- `breakglass.Store` - Break-glass checking

**Lambda-specific code (new):**
- HTTP API Gateway handler wrapper
- API Gateway request/response marshaling
- Lambda execution role credential retrieval
- AssumeRole invocation with SourceIdentity
- Error response formatting for HTTP

**CLI-specific code (not shared):**
- kingpin command parsing
- aws-vault keyring integration
- Interactive prompts
- Local credential server

## New Components

### 1. Lambda Handler Package (`lambda/`)

**Purpose:** Bridge between API Gateway HTTP events and Sentinel's core credential vending logic.

**Key files:**

`lambda/handler.go`:
```go
package lambda

import (
    "context"
    "github.com/aws/aws-lambda-go/events"
    "github.com/byteness/aws-vault/v7/policy"
    "github.com/byteness/aws-vault/v7/session"
    "github.com/byteness/aws-vault/v7/identity"
)

type Handler struct {
    PolicyLoader    policy.PolicyLoader
    SessionStore    session.Store
    RequestStore    request.Store
    BreakGlassStore breakglass.Store
    Logger          logging.Logger
    Region          string
}

func (h *Handler) HandleCredentialRequest(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
    // 1. Extract user identity from API Gateway authorizer context
    // 2. Parse profile from request path/body
    // 3. Load policy via PolicyLoader
    // 4. Evaluate policy
    // 5. Check approval/break-glass if denied
    // 6. AssumeRole with SourceIdentity
    // 7. Track session if SessionStore configured
    // 8. Return credentials in AWS SDK format
}
```

`lambda/types.go`:
```go
// Request/response types for API Gateway integration
type CredentialRequest struct {
    Profile         string `json:"profile"`
    SessionDuration int64  `json:"session_duration,omitempty"` // seconds
}

type CredentialResponse struct {
    AccessKeyId     string `json:"AccessKeyId"`
    SecretAccessKey string `json:"SecretAccessKey"`
    Token           string `json:"Token"`
    Expiration      string `json:"Expiration"` // ISO8601 format
}

type ErrorResponse struct {
    Message string `json:"message"`
    Code    string `json:"code,omitempty"`
}
```

`lambda/credentials.go`:
```go
// AssumeRole logic with SourceIdentity stamping
// Reuses identity.GenerateSourceIdentity() and existing patterns from sentinel.CredentialProvider
```

**Design rationale:**
- Handler follows existing `sentinel.SentinelServer.DefaultRoute()` pattern but adapted for API Gateway events
- Reuses all core Sentinel logic from existing packages
- Lambda-specific concerns isolated in lambda/ package

### 2. Lambda Entrypoint (`cmd/lambda-tvm/main.go`)

**Purpose:** Bootstrap Lambda runtime and wire dependencies.

```go
package main

import (
    "context"
    "os"

    "github.com/aws/aws-lambda-go/lambda"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/ssm"
    "github.com/aws/aws-sdk-go-v2/service/dynamodb"
    "github.com/byteness/aws-vault/v7/lambda"
    "github.com/byteness/aws-vault/v7/policy"
    "github.com/byteness/aws-vault/v7/session"
    "github.com/byteness/aws-vault/v7/logging"
)

func main() {
    ctx := context.Background()

    // Load AWS config from Lambda execution role
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        panic(err)
    }

    // Initialize dependencies
    policyLoader := policy.NewLoader(ssm.NewFromConfig(cfg))
    var sessionStore session.Store
    if tableName := os.Getenv("SESSION_TABLE"); tableName != "" {
        sessionStore = session.NewDynamoDBStore(cfg, tableName)
    }

    handler := &lambda.Handler{
        PolicyLoader: policyLoader,
        SessionStore: sessionStore,
        Region:       cfg.Region,
        Logger:       logging.NewStdoutLogger(), // Lambda CloudWatch Logs
    }

    lambda.Start(handler.HandleCredentialRequest)
}
```

**Design rationale:**
- Environment variables for configuration (Lambda best practice)
- Reuses existing SDK client constructors (NewFromConfig patterns)
- No CLI-specific code (kingpin, prompts, keyring)

### 3. API Gateway Configuration

**Authentication:** IAM authentication (AWS_IAM authorizer)

**Why IAM:**
- Caller identity flows to Lambda via `requestContext.identity.userArn`
- Enables SigV4 signing from client SDKs
- No custom authorizer Lambda needed
- Follows AWS best practices for service-to-service authentication

**Endpoint design:**
```
POST /credentials
Body: {
  "profile": "prod-admin",
  "session_duration": 3600  // optional
}

Response 200: {
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-01-24T19:00:00Z"
}

Response 403: {
  "message": "Policy denied access",
  "code": "PolicyDenied"
}
```

**API Gateway resource policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "execute-api:Invoke",
    "Resource": "arn:aws:execute-api:{region}:{account}:{api-id}/*",
    "Condition": {
      "IpAddress": {
        "aws:SourceIp": ["10.0.0.0/8"]  // VPC-only or corporate IP ranges
      }
    }
  }]
}
```

**Confidence:** HIGH - IAM authentication with API Gateway is the standard pattern for internal AWS service-to-service calls. Sources: [Control access to a REST API with IAM permissions](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html), [AWS Security Best Practices: IAM for Service-to-Service Authentication](https://www.ranthebuilder.cloud/post/aws-security-best-practices-leveraging-iam-for-service-to-service-authentication-and-authorization)

### 4. Lambda Execution Role (Trust Boundary)

**Trust policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Service": "lambda.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

**Permissions policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeProtectedRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/sentinel-protected-*"
    },
    {
      "Sid": "ReadPolicy",
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
    },
    {
      "Sid": "SessionTracking",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/sentinel-sessions",
        "arn:aws:dynamodb:*:*:table/sentinel-sessions/index/*"
      ]
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/sentinel-tvm:*"
    }
  ]
}
```

**Critical constraint enforcement:**
Protected roles MUST trust ONLY the Lambda execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:role/sentinel-lambda-execution-role"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "aws:SourceAccount": "123456789012"
      }
    }
  }]
}
```

**Why this enforces the trust boundary:**
- Only Lambda can assume protected roles
- Client applications cannot bypass the Lambda by calling AssumeRole directly
- Policy evaluation happens before AssumeRole is called
- SourceIdentity stamping provides audit trail

**Confidence:** HIGH - This is the core TVM pattern. Sources: [Implement SaaS tenant isolation with AWS Lambda TVM](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/implement-saas-tenant-isolation-for-amazon-s3-by-using-an-aws-lambda-token-vending-machine.html)

## Integration Points

### Existing Sentinel Packages Used by Lambda

| Package | Usage in Lambda | Reuse Level |
|---------|----------------|-------------|
| `policy` | Load policy from SSM, evaluate requests | 100% - Exact same Evaluate() logic |
| `session` | Track Lambda-issued sessions in DynamoDB | 100% - Same Store interface |
| `identity` | Generate SourceIdentity for stamping | 100% - Same GenerateSourceIdentity() |
| `logging` | Log decisions to CloudWatch | 100% - Same Logger interface |
| `request` | Check for approved requests | 100% - Same FindApprovedRequest() |
| `breakglass` | Check for active break-glass | 100% - Same FindActiveBreakGlass() |
| `iso8601` | Format expiration timestamps | 100% - Same Format() function |

### Key Integration Pattern

The Lambda handler follows the **exact same decision flow** as `sentinel.SentinelServer.DefaultRoute()`:

```go
// EXISTING: sentinel/server.go DefaultRoute()
1. Build policy.Request
2. Load policy via PolicyLoader
3. Evaluate policy
4. Check approval/break-glass if denied
5. Check session revocation if tracked
6. Apply duration capping
7. Get credentials via CredentialProvider
8. Log decision
9. Touch session

// NEW: lambda/handler.go HandleCredentialRequest()
1. Build policy.Request (from API Gateway authorizer context)
2. Load policy via PolicyLoader                    // SHARED
3. Evaluate policy                                 // SHARED
4. Check approval/break-glass if denied           // SHARED
5. Check session revocation if tracked            // SHARED
6. Apply duration capping                         // SHARED
7. AssumeRole with SourceIdentity (Lambda-specific implementation)
8. Log decision                                   // SHARED
9. Track session                                  // SHARED
```

**What changes:**
- User identity extraction: API Gateway `requestContext.identity.userArn` instead of STS GetCallerIdentity at startup
- Credential retrieval: Lambda calls `sts.AssumeRole` directly instead of delegating to vault/CLI credential providers
- HTTP response format: API Gateway response objects instead of ECS credential server format

**What stays the same:**
- Policy evaluation logic (policy.Evaluate)
- Session tracking (session.Store)
- Approval checking (request.Store)
- Break-glass checking (breakglass.Store)
- SourceIdentity generation (identity.GenerateSourceIdentity)
- Decision logging (logging.Logger)

### Modified Components

**None.** The Lambda does not require modifications to existing Sentinel packages. All integration points use existing exported interfaces and functions.

### New vs Modified

| Component | Status | Notes |
|-----------|--------|-------|
| `policy/` | UNCHANGED | Lambda uses existing Evaluate() and PolicyLoader |
| `session/` | UNCHANGED | Lambda uses existing Store interface |
| `identity/` | UNCHANGED | Lambda uses existing GenerateSourceIdentity() |
| `logging/` | UNCHANGED | Lambda uses existing Logger interface |
| `request/` | UNCHANGED | Lambda uses existing FindApprovedRequest() |
| `breakglass/` | UNCHANGED | Lambda uses existing FindActiveBreakGlass() |
| `sentinel/server.go` | UNCHANGED | CLI server continues working as-is |
| `cmd/sentinel/main.go` | UNCHANGED | CLI binary unchanged |
| `cmd/lambda-tvm/main.go` | NEW | Lambda entrypoint |
| `lambda/handler.go` | NEW | API Gateway handler |
| `lambda/types.go` | NEW | API Gateway request/response types |
| `lambda/credentials.go` | NEW | AssumeRole with SourceIdentity |

## Deployment Model

### Infrastructure as Code Options

**Recommendation: Start with Terraform, offer CDK examples**

**Rationale:**
- Terraform is multi-cloud and more widely adopted in enterprises (2026 market share)
- CDK has tighter AWS integration but creates vendor lock-in
- CDKTF was deprecated by HashiCorp in 2025 - don't rely on "best of both worlds"
- Sentinel is infrastructure-agnostic (works with any IaC tool)

**Deployment artifacts to provide:**

1. **Terraform module** (`infrastructure/terraform/lambda-tvm/`)
   - Lambda function resource
   - API Gateway HTTP API
   - IAM execution role
   - CloudWatch log group
   - Example protected role trust policy

2. **CDK example** (`infrastructure/cdk-examples/lambda-tvm/`)
   - Same resources as Terraform
   - TypeScript example only (most popular CDK language)
   - Document as "example" not "official module"

3. **CloudFormation template** (`infrastructure/cloudformation/lambda-tvm.yaml`)
   - Generated from CDK example using `cdk synth`
   - Enables console-based deployment for GUI users

**Confidence:** MEDIUM - Based on 2026 IaC landscape research. Organizations have strong preferences, so providing multiple options maximizes adoption. Sources: [AWS CDK vs Terraform: Complete 2026 Comparison](https://dev.to/aws-builders/aws-cdk-vs-terraform-the-complete-2026-comparison-3b4p), [Infrastructure as Code: Complete AWS Guide](https://towardsthecloud.com/blog/infrastructure-as-code)

### How Organizations Deploy the TVM

**Deployment topology options:**

1. **Single-account, single-region** (Simplest)
   - Lambda in same account as protected roles
   - API Gateway internal endpoint (VPC)
   - Client applications in same VPC

2. **Hub-and-spoke multi-account** (Recommended)
   - Lambda in central "security" account
   - Protected roles in spoke accounts
   - Cross-account AssumeRole via trust policies
   - API Gateway with IAM authentication from all accounts

3. **Multi-region active-active** (High availability)
   - Lambda in multiple regions
   - Route 53 health checks
   - SSM Parameter Store cross-region replication for policies

**Configuration approach:**

**Environment variables** (Lambda best practice):
```bash
POLICY_PARAMETER=/sentinel/policies/default
SESSION_TABLE=sentinel-sessions
REQUEST_TABLE=sentinel-requests
BREAKGLASS_TABLE=sentinel-breakglass
LOG_LEVEL=info
```

**Why not SSM Parameter Store for config:**
- Lambda cold start latency (SSM call adds 50-100ms)
- Environment variables sufficient for Lambda-specific config
- Policy content still loaded from SSM (cached by PolicyLoader)

### Client Integration Pattern

**How applications call the TVM:**

```go
// Client-side code (application in AWS)
import (
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// 1. Load AWS credentials (from IAM role, instance profile, etc.)
cfg, _ := config.LoadDefaultConfig(ctx)

// 2. Create SigV4-signed HTTP client
client := aws.NewDefaultsResolver()

// 3. Call TVM endpoint
resp, err := client.Post(
    "https://tvm.example.com/credentials",
    "application/json",
    bytes.NewBuffer([]byte(`{"profile":"prod-admin"}`))
)

// 4. Parse credentials
var creds CredentialResponse
json.NewDecoder(resp.Body).Decode(&creds)

// 5. Use credentials to create AWS SDK client
cfg := aws.Config{
    Credentials: credentials.StaticCredentialsProvider{
        Value: aws.Credentials{
            AccessKeyID:     creds.AccessKeyId,
            SecretAccessKey: creds.SecretAccessKey,
            SessionToken:    creds.Token,
        },
    },
}
```

**SDK support:**
- Any AWS SDK can call the TVM (Python, Java, Node.js, Go, etc.)
- SigV4 signing built into all AWS SDKs
- No Sentinel-specific client library needed

**Confidence:** HIGH - This is standard AWS SDK integration pattern. Any service calling an IAM-authenticated API Gateway follows this flow.

## Build Order

### Phase 1: Foundation (Core Lambda Handler)

**Goal:** Lambda function that can evaluate policy and return mock credentials.

**Components:**
1. `lambda/types.go` - Request/response types
2. `lambda/handler.go` - Basic handler skeleton
3. `cmd/lambda-tvm/main.go` - Entrypoint
4. Makefile target for Lambda build
5. Unit tests for handler request parsing

**Integration test:** Deploy Lambda that returns allow/deny based on mock policy.

**Duration estimate:** 1 phase (1-2 plans)

### Phase 2: Credential Vending (AssumeRole Integration)

**Goal:** Lambda actually vends real credentials via AssumeRole.

**Components:**
1. `lambda/credentials.go` - AssumeRole with SourceIdentity
2. Integration with existing `identity.GenerateSourceIdentity()`
3. Lambda execution role IAM policy
4. Protected role trust policy template
5. End-to-end test: Lambda → AssumeRole → credentials

**Integration test:** Deploy Lambda, call with test profile, verify credentials work.

**Duration estimate:** 1 phase (2-3 plans)

### Phase 3: Session Tracking & Approval/Break-Glass

**Goal:** Lambda uses existing session/request/breakglass stores.

**Components:**
1. Wire `session.Store` in Lambda handler
2. Wire `request.Store` in Lambda handler
3. Wire `breakglass.Store` in Lambda handler
4. Environment variable configuration
5. Integration tests with DynamoDB

**Integration test:** Create approved request → Lambda vends credentials.

**Duration estimate:** 1 phase (2-3 plans)

### Phase 4: API Gateway Integration

**Goal:** Expose Lambda via API Gateway with IAM authentication.

**Components:**
1. API Gateway HTTP API resource
2. IAM authorizer configuration
3. Integration request/response mapping
4. Resource policy for VPC/IP restriction
5. Client integration example code

**Integration test:** Call API Gateway endpoint with SigV4 → get credentials.

**Duration estimate:** 1 phase (2-3 plans)

### Phase 5: Infrastructure as Code

**Goal:** Provide IaC templates for deployment.

**Components:**
1. Terraform module with all resources
2. CDK example (TypeScript)
3. CloudFormation template (generated from CDK)
4. Deployment documentation
5. Protected role trust policy generator

**Deliverable:** Organizations can `terraform apply` to deploy TVM.

**Duration estimate:** 1 phase (2-3 plans)

### Phase 6: Testing & Documentation

**Goal:** Production-ready TVM with comprehensive testing.

**Components:**
1. Integration test suite (Lambda → API Gateway → AssumeRole)
2. Load testing (benchmark API Gateway → Lambda latency)
3. Security regression tests (policy bypass attempts)
4. Deployment guide (LAMBDA_TVM.md)
5. Migration guide (CLI server → Lambda TVM)

**Quality gate:** >80% code coverage, <200ms p99 latency.

**Duration estimate:** 2 phases (4-5 plans)

**Total estimated duration:** 7-8 phases, 14-18 plans (~40-60 min)

## Suggested Build Order Rationale

**Why this order:**

1. **Foundation first** - Establish Lambda build pipeline and basic handler logic before AWS integration
2. **Credential vending second** - Core TVM functionality (AssumeRole) before session tracking
3. **Session tracking third** - Reuse existing stores once credential flow works
4. **API Gateway fourth** - Expose via HTTP after Lambda logic is solid
5. **IaC fifth** - Automate deployment once all components work
6. **Testing last** - Comprehensive testing of complete system

**Dependencies:**
- Phase 2 depends on Phase 1 (handler must parse requests before vending credentials)
- Phase 3 depends on Phase 2 (session tracking requires credential flow)
- Phase 4 depends on Phase 3 (API Gateway exposes Lambda handler)
- Phase 5 depends on Phase 4 (IaC templates deploy API Gateway)
- Phase 6 depends on Phase 5 (testing requires deployed infrastructure)

**Risk mitigation:**
- Early integration tests (end of Phase 2) prove AssumeRole flow works
- Incremental complexity (policy → credentials → sessions → API Gateway)
- Each phase has testable deliverable (no "big bang" integration at end)

## Architecture Patterns

### Key Pattern: Policy Evaluation at Trust Boundary

```
Client App             Lambda TVM              Protected Role
    |                       |                        |
    | 1. POST /credentials  |                        |
    |---------------------->|                        |
    |                       | 2. Load policy (SSM)   |
    |                       | 3. Evaluate policy     |
    |                       | 4. Check approval      |
    |                       | 5. Check break-glass   |
    |                       |                        |
    |                       | 6. AssumeRole          |
    |                       |----------------------->|
    |                       |<-----------------------|
    |                       | 7. Stamp SourceIdentity|
    |                       | 8. Track session       |
    |<----------------------|                        |
    | Credentials           |                        |
```

**Trust boundary enforcement:**
- Protected role trusts ONLY Lambda execution role
- Client app cannot call AssumeRole directly
- Policy evaluation happens BEFORE AssumeRole
- SourceIdentity proves credential came from Lambda

### Anti-Pattern: Client-Side Policy Evaluation

**DON'T DO THIS:**
```
Client App             Lambda TVM              Protected Role
    |                       |                        |
    | 1. Evaluate policy    |                        |
    |    (client-side)      |                        |
    | 2. POST /credentials  |                        |
    |---------------------->|                        |
    |                       | 3. AssumeRole (no check)|
```

**Why this is wrong:**
- Client can bypass policy by skipping evaluation
- Lambda becomes credential proxy, not trust boundary
- No centralized audit log

**Prevention:**
- Lambda MUST evaluate policy, not trust client claims
- API Gateway passes only authenticated identity, not policy decisions

### Pattern: Stateless Lambda with External State

**Lambda handler is stateless:**
- No in-memory caching (every invocation is independent)
- All state in DynamoDB (sessions, approvals, break-glass)
- Policy cache in PolicyLoader (but each Lambda invocation loads fresh)

**Why stateless:**
- Lambda cold starts mean in-memory cache is lost
- Multiple Lambda instances would have cache inconsistency
- DynamoDB provides consistent state across instances

**Trade-off:**
- Higher latency (DynamoDB query on every request)
- Better consistency (no stale cache)
- Acceptable for TVM use case (p99 latency <200ms target)

### Pattern: Fail-Closed for Security, Fail-Open for Availability

**Following existing Sentinel patterns:**

```go
// Revocation check: Fail-closed for security
if revoked, err := session.IsSessionRevoked(ctx, store, sessionID); err != nil {
    log.Printf("Warning: failed to check revocation: %v", err)
    // Continue serving credentials (fail-open for availability)
} else if revoked {
    return ErrorResponse{Message: "Session revoked"}, http.StatusForbidden
    // Deny credentials immediately (fail-closed for security)
}
```

**Lambda follows same pattern:**
- Policy load failure → deny credentials (fail-closed)
- Session revocation detected → deny credentials (fail-closed)
- DynamoDB connectivity error → allow credentials but log warning (fail-open)

## Scalability Considerations

### At 100 requests/second

**Architecture:**
- Single Lambda function, auto-scaling
- API Gateway in single region
- DynamoDB on-demand billing mode
- SSM Parameter Store caching in PolicyLoader

**Estimated costs:**
- Lambda: $0.20/million requests × 8.64M/day = ~$1.73/day
- API Gateway: $1.00/million requests × 8.64M/day = ~$8.64/day
- DynamoDB: ~$0.01/day (minimal storage, on-demand reads)
- Total: ~$10.40/day or $312/month

### At 1,000 requests/second

**Architecture changes needed:**
- Multi-region Lambda (active-active)
- API Gateway with Route 53 health checks
- DynamoDB global tables (cross-region replication)
- CloudFront for request routing

**Estimated costs:**
- Lambda: $0.20/million requests × 86.4M/day = ~$17.28/day
- API Gateway: $1.00/million requests × 86.4M/day = ~$86.40/day
- DynamoDB: ~$0.50/day (replication costs)
- CloudFront: ~$10/day (data transfer)
- Total: ~$114/day or $3,420/month

**Bottlenecks:**
- SSM Parameter Store (1,000 TPS standard, 10,000 TPS high-throughput)
- DynamoDB write capacity (handle with provisioned capacity + auto-scaling)
- Lambda cold starts (mitigate with provisioned concurrency)

### At 10,000 requests/second

**Architecture changes needed:**
- Provisioned concurrency for Lambda (eliminate cold starts)
- DynamoDB provisioned capacity with auto-scaling
- SSM high-throughput parameters
- Multiple API Gateway endpoints (shard by profile)

**Estimated costs:**
- Lambda: $17.28/day (requests) + ~$500/day (provisioned concurrency)
- API Gateway: ~$864/day
- DynamoDB: ~$50/day (provisioned capacity + global tables)
- Total: ~$1,431/day or $42,930/month

**Note:** At this scale, consider custom implementation without API Gateway (ALB → Lambda direct integration for lower cost).

## Sources

### Token Vending Machine Patterns
- [Implement SaaS tenant isolation with AWS Lambda TVM - AWS Prescriptive Guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/implement-saas-tenant-isolation-for-amazon-s3-by-using-an-aws-lambda-token-vending-machine.html)
- [TVM Explained - AWS Workshop](https://momento.awsworkshop.io/9_live-updates/tvm_explained.html)
- [Isolate tenant data on AWS S3 via AWS Lambda TVM - Picus Security Engineering](https://medium.com/picus-security-engineering/isolate-your-tenant-data-on-aws-s3-via-aws-lambda-token-vending-machine-e5c7f4254ed4)

### AWS Lambda Best Practices
- [Building Lambda functions with Go - AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/lambda-golang.html)
- [Define Lambda function handlers in Go - AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/golang-handler.html)
- [Defining Lambda function permissions with an execution role - AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)

### API Gateway IAM Authentication
- [Control access to a REST API with IAM permissions - Amazon API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html)
- [AWS Security Best Practices: IAM for Service-to-Service Authentication](https://www.ranthebuilder.cloud/post/aws-security-best-practices-leveraging-iam-for-service-to-service-authentication-and-authorization)
- [IAM Integration with AWS Lambda - API Gateway Authorization](https://moldstud.com/articles/p-iam-integration-with-aws-lambda-streamlining-api-gateway-authorization-effortlessly)

### Go Monorepo Architecture
- [Shared Go Packages in a Monorepo - 1Password](https://passage.1password.com/post/shared-go-packages-in-a-monorepo)
- [Building a Monorepo in Golang - Earthly Blog](https://earthly.dev/blog/golang-monorepo/)
- [Go Monorepos for Growing Teams](https://jamescun.com/posts/golang-monorepo-structure/)

### Infrastructure as Code (2026)
- [AWS CDK vs Terraform: Complete 2026 Comparison - DEV Community](https://dev.to/aws-builders/aws-cdk-vs-terraform-the-complete-2026-comparison-3b4p)
- [Infrastructure as Code: Complete AWS Guide to IaC Tools [2026]](https://towardsthecloud.com/blog/infrastructure-as-code)
- [AWS CDK vs Terraform Comparison - Towards The Cloud](https://towardsthecloud.com/blog/aws-cdk-vs-terraform)

### Security & Trust Boundaries
- [SEC02-BP02 Use temporary credentials - AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_unique.html)
- [Lambda Function Permissions - Security Best Practices](https://reintech.io/blog/securing-aws-lambda-functions-iam-roles-policies)
- [Locking AWS Lambda Execution Roles - Josh Armitage](https://medium.com/@josh.armitage/locking-aws-lambda-execution-roles-a03b92449f22)
