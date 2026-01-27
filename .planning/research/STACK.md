# Stack Research: Server-Side Credential Vending

**Project:** Sentinel v1.14 - Lambda TVM
**Researched:** 2026-01-24
**Confidence:** HIGH

## Executive Summary

Server-side credential vending requires Lambda function + API Gateway with IAM authentication. Go 1.25 is well-suited for this with sub-100ms cold starts. Use HTTP API (not REST API) for cost savings and simplicity - IAM auth works identically. Container credentials format is already implemented in ecsserver.go and can be reused directly.

**Key decision:** Deployment tooling matters. Terraform recommended over SAM/CDK for consistency with likely existing infrastructure patterns.

## Lambda Runtime

### Recommended: provided.al2023

| Component | Version | Purpose | Rationale |
|-----------|---------|---------|-----------|
| Go Runtime | `provided.al2023` | OS-only runtime for Lambda | Current best practice, supported until Jun 2029. `go1.x` is deprecated. |
| Go Version | 1.25 | Language version | Already in use (go.mod), no upgrade needed |
| aws-lambda-go | v1.52.0 | Lambda programming model | Latest stable (Jan 2026), provides `lambda.Start()` and event types |

**Key requirements:**
- Compile to binary named `bootstrap` for provided.al2023 runtime
- Use `GOOS=linux GOARCH=amd64` (or arm64 for Graviton2)
- No code changes from existing Go codebase needed

**Cold start performance:**
- Go provides sub-100ms cold starts (fastest compiled language option)
- Lazy initialization critical: avoid heavy init() blocks in imported packages
- Memory allocation affects CPU: 512MB = 40% faster cold start than 128MB
- SnapStart NOT available for Go (only Java/Python/.NET as of 2026)

### Core Library: github.com/aws/aws-lambda-go

```go
import (
    "github.com/aws/aws-lambda-go/lambda"
    "github.com/aws/aws-lambda-go/events"
)
```

**Key packages:**
- `lambda` - Entry point via `lambda.Start(handler)`
- `events` - Event type definitions for API Gateway, ALB, etc.
- `lambdacontext` - Access Lambda execution context
- `lambdaurl` - Lambda Function URL support (not needed for API Gateway)

**Already in go.mod:** No new dependencies required for basic Lambda. Existing aws-sdk-go-v2 works as-is.

## API Gateway

### Recommended: HTTP API with IAM Authorization

| Decision | Choice | Rationale |
|----------|--------|-----------|
| API Type | HTTP API (v2) | Lower cost, simpler, sufficient for IAM auth + Lambda |
| Authorization | IAM (AWS_IAM) | Enforces SigV4 signing, extracts caller identity from request context |
| Integration | Lambda proxy | Standard pattern, automatic request/response transformation |

### REST API vs HTTP API Comparison

| Feature | REST API | HTTP API | Impact |
|---------|----------|----------|--------|
| IAM Authorization | Yes | Yes | Both work identically for SigV4 auth |
| Resource Policies | Yes | No | Not needed (IAM is sufficient) |
| Cost | Higher | ~71% cheaper | HTTP API wins |
| Latency | Standard | Lower | HTTP API optimized |
| Request Validation | Yes | No | Handle in Lambda code |
| API Keys | Yes | No | Not needed for IAM auth |

**Verdict:** HTTP API saves cost without losing required functionality. Resource policies (REST-only feature) are unnecessary when using IAM authorization.

### Event Type for HTTP API

Use `events.APIGatewayV2HTTPRequest` (not APIGatewayProxyRequest):

```go
func handler(ctx context.Context, request events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
    // request.RequestContext.Authorizer contains IAM identity info
    // request.RequestContext.Authorizer.IAM.UserArn
    // request.RequestContext.Authorizer.IAM.AccessKey
}
```

**Key fields:**
- `RequestContext.Authorizer.IAM` - Caller's IAM identity (UserArn, AccountID, etc.)
- `Body` - Request payload
- `Headers` - HTTP headers
- `PathParameters`, `QueryStringParameters` - URL components

**Response format:**

```go
return events.APIGatewayV2HTTPResponse{
    StatusCode: 200,
    Headers: map[string]string{
        "Content-Type": "application/json",
    },
    Body: jsonString,
}, nil
```

## Container Credentials Format

### Already Implemented in ecsserver.go

**CRITICAL FINDING:** Sentinel already implements container credentials format in `server/ecsserver.go:39-49`. This code can be reused directly:

```go
func writeCredsToResponse(creds aws.Credentials, w http.ResponseWriter) {
    err := json.NewEncoder(w).Encode(map[string]string{
        "AccessKeyId":     creds.AccessKeyID,
        "SecretAccessKey": creds.SecretAccessKey,
        "Token":           creds.SessionToken,
        "Expiration":      iso8601.Format(creds.Expires),
    })
}
```

**Response schema (required fields):**

```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "IQoJ...",
  "Expiration": "2026-01-24T12:34:56Z"
}
```

**Optional field (not needed for Sentinel):**
- `RoleArn` - ECS includes this, but AWS SDKs don't require it

**SDK compatibility:**
- All AWS SDKs (v2, v3, boto3, etc.) recognize this format
- SDKs refresh credentials automatically before expiration
- Default refresh: 5 minutes before expiration timestamp
- Requires `AWS_CONTAINER_CREDENTIALS_FULL_URI` environment variable set to Lambda endpoint

## SDK Integration Points

### Existing Code Reuse

From `server/ecsserver.go`:
- ✅ Credential response formatting (lines 39-49)
- ✅ Authorization token validation (lines 29-37) - adapt for SigV4
- ✅ AssumeRole provider caching (lines 121-138) - reuse pattern
- ✅ Error response formatting (lines 21-27)

**Adaptation needed:**
- Replace header-based auth token with SigV4 verification
- Extract caller identity from `request.RequestContext.Authorizer.IAM` instead of token
- Use Lambda event types instead of http.Request

### Dependencies Already Satisfied

From go.mod, already available:
- `github.com/aws/aws-sdk-go-v2/service/sts` v1.41.6 - AssumeRole calls
- `github.com/aws/aws-sdk-go-v2/credentials` v1.19.7 - Credentials types
- `github.com/byteness/aws-vault/v7/iso8601` - Date formatting
- `github.com/aws/smithy-go` v1.24.0 - AWS SDK primitives

**New dependency required:**
- `github.com/aws/aws-lambda-go` v1.52.0 - Lambda runtime only

## Deployment

### Recommended: Terraform

| Tool | Pros | Cons | Verdict |
|------|------|------|---------|
| Terraform | Multi-resource support, state management, likely already in use | Verbose for simple Lambda | ✅ Recommended |
| AWS SAM | Optimized for serverless, local testing, simple syntax | AWS-only, limited to serverless resources | Use if team prefers |
| AWS CDK | Programmatic (Go support available), type-safe | Complexity overhead, synthesizes to CloudFormation | Overkill for this |

**Rationale for Terraform:**
- Sentinel likely has existing infrastructure (DynamoDB, SSM parameters)
- Terraform manages Lambda + API Gateway + IAM roles in single state
- Community modules available: terraform-aws-modules/lambda/aws
- Multi-environment support (dev/staging/prod)

**Alternative (SAM):** Valid if team wants CloudFormation-native deployment with local testing via `sam local start-api`

### Required Terraform Resources

Minimal viable deployment:

```hcl
# Lambda function
resource "aws_lambda_function" "sentinel_tvm"
resource "aws_iam_role" "lambda_exec"
resource "aws_iam_role_policy_attachment" "lambda_logs"
resource "aws_iam_policy" "lambda_sentinel" # SSM, DynamoDB, STS access

# API Gateway HTTP API
resource "aws_apigatewayv2_api" "sentinel"
resource "aws_apigatewayv2_stage" "sentinel"
resource "aws_apigatewayv2_integration" "lambda"
resource "aws_apigatewayv2_route" "default"
resource "aws_apigatewayv2_authorizer" "iam" # IAM authorization

# Lambda permission for API Gateway
resource "aws_lambda_permission" "api_gateway"
```

**Key configuration:**
- Authorization type: `AWS_IAM` on route
- Payload format version: `2.0` for HTTP API
- Lambda timeout: 30s (credential vending should be fast)
- Memory: 512MB (balance cost vs cold start)

### Build Process

Standard Go Lambda build:

```bash
GOOS=linux GOARCH=amd64 go build -o bootstrap ./cmd/lambda-tvm
zip function.zip bootstrap
```

**Optimization flags:**
- `-ldflags="-s -w"` - Strip debug info, reduce binary size
- `-tags lambda.norpc` - Disable RPC if not needed

**Architecture consideration:**
- x86_64: Compatible, widely tested
- arm64 (Graviton2): 20% cheaper, same performance for Go
- **Recommendation:** Start x86_64, migrate to arm64 post-MVP

## NOT Adding

### Libraries to Avoid

| Library | Why NOT | What Instead |
|---------|---------|--------------|
| github.com/awslabs/aws-lambda-go-api-proxy | Unnecessary complexity, designed for porting HTTP frameworks (Gin, Echo) | Use events.APIGatewayV2HTTPRequest directly |
| Lambda layers | Adds cold start overhead, Go binaries are self-contained | Single binary deployment |
| API Gateway REST API | Higher cost, unnecessary features | HTTP API with IAM auth |
| Container image deployment | Slower cold starts (vs zip), larger artifacts | Zip file with bootstrap binary |
| Provisioned concurrency | Ongoing cost, not needed for TVM workload | Accept cold starts (sub-100ms acceptable) |

### Features to Defer

**Lambda SnapStart:** Not available for Go runtime (only Java/Python/.NET). Traditional cold start optimization sufficient.

**Lambda Function URLs:** Could replace API Gateway for simplicity, but:
- No built-in SigV4 verification in Lambda runtime (must implement manually)
- API Gateway provides IAM.UserArn extraction automatically
- Keep API Gateway for identity handling convenience

**Request validation:** HTTP API doesn't support built-in validation (REST API feature). Handle in Lambda code - acceptable tradeoff for cost savings.

## Installation

### New Dependencies

```bash
# Lambda runtime only - already have aws-sdk-go-v2
go get github.com/aws/aws-lambda-go@v1.52.0
```

### Existing Dependencies (Reuse)

```go
// Already in go.mod, no upgrade needed
github.com/aws/aws-sdk-go-v2 v1.41.1
github.com/aws/aws-sdk-go-v2/service/sts v1.41.6
github.com/aws/aws-sdk-go-v2/credentials v1.19.7
```

## Integration Summary

**Client-side changes:**
1. Set `AWS_CONTAINER_CREDENTIALS_FULL_URI=https://[api-gateway-url]/credentials`
2. Set `AWS_CONTAINER_AUTHORIZATION_TOKEN=[optional-auth-header]` (if adding additional auth layer)
3. AWS SDK automatically uses container credentials provider

**Server-side implementation:**
1. Lambda handler receives APIGatewayV2HTTPRequest
2. Extract caller identity from `request.RequestContext.Authorizer.IAM`
3. Load Sentinel policy from SSM (existing code)
4. Evaluate policy (existing sentinel package)
5. Call STS AssumeRole (existing vault.AssumeRoleProvider pattern)
6. Return credentials in container format (existing ecsserver.writeCredsToResponse)

**Key insight:** 80% of required code already exists in Sentinel codebase. Lambda layer is thin adapter between API Gateway events and existing Sentinel logic.

## Sources

### Official Documentation (HIGH Confidence)
- [Building Lambda functions with Go](https://docs.aws.amazon.com/lambda/latest/dg/lambda-golang.html)
- [AWS Lambda Go GitHub](https://github.com/aws/aws-lambda-go)
- [API Gateway REST vs HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-vs-rest.html)
- [Container Credentials Provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
- [STS AssumeRole API Reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Lambda Proxy Integrations](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html)
- [aws-lambda-go events package](https://pkg.go.dev/github.com/aws/aws-lambda-go/events)

### Community Resources (MEDIUM Confidence)
- [Go Lambda Cold Start Optimization 2025](https://zircon.tech/blog/aws-lambda-cold-start-optimization-in-2025-what-actually-works/)
- [Terraform Lambda API Gateway Tutorial](https://developer.hashicorp.com/terraform/tutorials/aws/lambda-api-gateway)
- [AWS Lambda SnapStart Documentation](https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html) (confirms no Go support)
- [SAM vs CDK vs Terraform Comparison 2026](https://dev.to/aws-builders/aws-cdk-vs-terraform-the-complete-2026-comparison-3b4p)

### Verified Findings
- Container credentials format: Confirmed via ECS task metadata endpoint documentation and existing Sentinel implementation
- Go Lambda runtime: Verified as provided.al2023 (go1.x deprecated)
- API Gateway IAM auth: Both REST and HTTP APIs support IAM identically
- aws-lambda-go version: v1.52.0 latest as of Jan 2026
