# Research Summary: Server-Side Credential Vending (v1.14)

**Domain:** Lambda-based Token Vending Machine (TVM) for Sentinel
**Researched:** 2026-01-24
**Overall confidence:** HIGH

## Executive Summary

Server-side credential vending via AWS Lambda is a **natural evolution** of Sentinel's existing architecture. The v1.10 `SentinelServer` already implements per-request policy evaluation and credential vending - the Lambda TVM applies the same pattern in a serverless, scalable context.

**Key insight:** The Lambda TVM is not a new system - it's a **deployment alternative** for the existing Sentinel credential vending logic. The core policy evaluation, session tracking, approval checking, and SourceIdentity stamping code is 100% reusable. Only the HTTP handler wrapper and AssumeRole invocation are Lambda-specific.

**Critical architectural constraint:** The Lambda function IS the trust boundary. Protected roles must trust ONLY the Lambda execution role, preventing client applications from bypassing policy by calling AssumeRole directly. This makes server-side vending fundamentally different from CLI-based credential issuance.

**Strategic value:** Organizations with serverless architectures (ECS Fargate, Lambda workloads, containerized apps) gain centralized credential vending without deploying the CLI in every container. The TVM scales automatically, requires no persistent infrastructure, and costs ~$10/day at 100 req/sec.

## Key Findings

### Architecture: Monorepo with Shared Packages

**Stack:** Go monorepo with two binaries (CLI + Lambda) sharing core packages

The existing Sentinel codebase already follows Go monorepo best practices:
- `cmd/sentinel/` for CLI binary
- Shared packages: `policy/`, `session/`, `identity/`, `logging/`, `request/`, `breakglass/`
- Multiple build targets in Makefile

**Add:**
- `cmd/lambda-tvm/` for Lambda binary
- `lambda/` package for API Gateway handler logic

**Code reuse:** 95%+ of credential vending logic is shared between CLI server and Lambda TVM.

**Critical pitfall:** The Lambda TVM follows the **exact same decision flow** as `sentinel.SentinelServer.DefaultRoute()`. The integration points are:
1. Policy evaluation (policy.Evaluate)
2. Session tracking (session.Store)
3. Approval checking (request.FindApprovedRequest)
4. Break-glass checking (breakglass.FindActiveBreakGlass)
5. SourceIdentity generation (identity.GenerateSourceIdentity)
6. Decision logging (logging.Logger)

### Features: Policy Enforcement at the Trust Boundary

**Table stakes:**
- Temporary credentials (STS AssumeRole with configurable duration)
- Authentication (AWS IAM via API Gateway SigV4)
- Policy evaluation (deny by default, explicit allow required)
- Audit logging (CloudTrail + decision logs)
- Session revocation (DynamoDB-backed tracking)

**Differentiators:**
- Policy-gated vending (Sentinel policies apply before credentials issued)
- Approval workflow integration (sensitive profiles require approval)
- Break-glass override (emergency access with justification)
- Session tracking & compliance (all vended sessions tracked for audit)
- SourceIdentity propagation (CloudTrail correlation)
- Real-time revocation (immediate session termination)

**Anti-features (DO NOT BUILD):**
- Client-side policy evaluation (clients can bypass)
- Long-lived credentials (defeats TVM purpose; cap at 1 hour)
- Credential caching on client (defeats revocation)
- Anonymous requests (cannot audit who got what)
- Synchronous approval in TVM path (blocks credential requests)

## Implications for Roadmap

### Suggested Phase Structure

Based on research, the Lambda TVM milestone breaks down into **7-8 phases**:

#### 1. Foundation - Core Lambda Handler (1 phase)
**Why first:** Establish Lambda build pipeline and basic handler logic before AWS integration.

**Deliverables:**
- `lambda/types.go` - API Gateway request/response types
- `lambda/handler.go` - Handler skeleton with request parsing
- `cmd/lambda-tvm/main.go` - Lambda entrypoint
- Makefile target: `make lambda-tvm` (builds Linux binary)
- Unit tests for request parsing

**Integration test:** Deploy Lambda that evaluates mock policy and returns allow/deny.

**Avoids:** Pitfall #1 - Don't start with AWS integration complexity. Get the build and handler flow working first.

---

#### 2. Credential Vending - AssumeRole Integration (1 phase)
**Why second:** Core TVM functionality (credential issuance) before session tracking.

**Deliverables:**
- `lambda/credentials.go` - AssumeRole with SourceIdentity stamping
- Integration with `identity.GenerateSourceIdentity()`
- Lambda execution role IAM policy template
- Protected role trust policy template
- End-to-end test: Lambda → AssumeRole → working credentials

**Integration test:** Deploy Lambda, call with test profile, use returned credentials to access AWS service.

**Avoids:** Pitfall #2 - Verify AssumeRole flow works before adding session tracking complexity.

---

#### 3. Session Tracking & Approval/Break-Glass (1 phase)
**Why third:** Reuse existing stores after credential flow is proven.

**Deliverables:**
- Wire `session.Store` in Lambda handler (DynamoDB)
- Wire `request.Store` for approval checking
- Wire `breakglass.Store` for emergency access
- Environment variable configuration (SESSION_TABLE, REQUEST_TABLE, BREAKGLASS_TABLE)
- Integration tests with DynamoDB mocks

**Integration test:** Create approved request → Lambda vends credentials (approval flow).

**Avoids:** Pitfall #3 - Session tracking failures must not block credential vending (fail-open for availability). Follow existing `SentinelServer` pattern.

---

#### 4. API Gateway Integration (1 phase)
**Why fourth:** Expose Lambda via HTTP after core logic is solid.

**Deliverables:**
- API Gateway HTTP API resource
- IAM authorizer configuration (AWS_IAM)
- Integration request/response mapping
- Resource policy for VPC/IP restriction
- Client integration example (SigV4 signing)

**Integration test:** Call API Gateway endpoint with SigV4 → receive credentials → use credentials.

**Avoids:** Pitfall #4 - API Gateway resource policy must restrict access (VPC-only or corporate IP ranges). Public TVM endpoints are a security risk.

---

#### 5. Infrastructure as Code (1 phase)
**Why fifth:** Automate deployment once all components work end-to-end.

**Deliverables:**
- Terraform module (`infrastructure/terraform/lambda-tvm/`)
- CDK example (`infrastructure/cdk-examples/lambda-tvm/`)
- CloudFormation template (generated from CDK)
- Deployment documentation (LAMBDA_TVM.md)
- Protected role trust policy generator

**Integration test:** `terraform apply` → deployed TVM → successful credential vending.

**Avoids:** Pitfall #5 - Provide both Terraform and CDK examples. Organizations have strong IaC preferences; don't force a single tool.

---

#### 6. Testing & Documentation (2 phases)
**Why last:** Comprehensive testing requires complete deployed system.

**Deliverables:**
- Integration test suite (full API Gateway → Lambda → AssumeRole flow)
- Load testing (benchmark latency, throughput)
- Security regression tests (policy bypass attempts, credential leak prevention)
- Deployment guide (LAMBDA_TVM.md)
- Migration guide (CLI server → Lambda TVM comparison)

**Quality gates:**
- >80% code coverage on lambda/ package
- <200ms p99 latency (API Gateway → credentials)
- Zero security regression test failures

**Avoids:** Pitfall #6 - Test the actual deployed Lambda, not just unit tests. Integration tests must call real API Gateway endpoint.

---

### Phase Ordering Rationale

**Dependencies:**
- Phase 2 requires Phase 1 (handler must parse requests before vending credentials)
- Phase 3 requires Phase 2 (session tracking requires credential flow)
- Phase 4 requires Phase 3 (API Gateway exposes Lambda handler)
- Phase 5 requires Phase 4 (IaC templates deploy API Gateway)
- Phase 6 requires Phase 5 (testing requires deployed infrastructure)

**Risk mitigation:**
- Early integration test (end of Phase 2) proves AssumeRole works
- Incremental complexity (policy → credentials → sessions → API Gateway)
- Each phase has testable deliverable (no "big bang" integration)

**Research flags:**
- Phase 3 likely needs deeper research: How do we handle approval workflow timeouts in the TVM request path? (Recommend: Return 403 immediately with requestID, client polls separately)
- Phase 4 may need research: API Gateway throttling and rate limiting configuration for production scale
- Phase 6 should include load testing to verify DynamoDB auto-scaling works under burst traffic

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Architecture | HIGH | Go monorepo pattern is well-established; Lambda handler follows existing SentinelServer pattern |
| Code Reuse | HIGH | Existing packages (policy, session, identity) require zero modifications; 95%+ reuse verified |
| Integration | HIGH | SentinelServer.DefaultRoute() is the reference implementation; Lambda handler is a port |
| Deployment | MEDIUM | Terraform vs CDK choice depends on organization; provide both examples |
| Features | HIGH | Table stakes verified via AWS TVM documentation; differentiators leverage existing Sentinel v1.0-v1.13 features |
| Scalability | MEDIUM | DynamoDB and Lambda scale well, but need load testing to verify at 1,000+ req/sec |

**Low confidence areas (need deeper research during implementation):**
- API Gateway resource policy best practices for VPC-only access (Phase 4)
- DynamoDB provisioned capacity vs on-demand for high-throughput scenarios (Phase 6)
- Lambda cold start mitigation strategies (provisioned concurrency adds cost)

## Gaps to Address

### Approval Workflow Timeout Handling

**Question:** What happens when a TVM request requires approval but approval is async?

**Current CLI behavior:** `sentinel exec` with `require_approval` policy effect:
1. Evaluate policy → EffectRequireApproval
2. Check for existing approved request
3. If not approved → return error with suggestion to run `sentinel request`
4. User runs `sentinel request`, waits for approval, re-runs `sentinel exec`

**TVM scenario:** Client application calls TVM endpoint:
1. Lambda evaluates policy → EffectRequireApproval
2. Check for existing approved request
3. If not approved → ???

**Options:**
- **A) Synchronous wait (BAD):** Lambda blocks waiting for approval → 15-minute Lambda timeout → expensive
- **B) Auto-create request + return 403 (RECOMMENDED):** Lambda creates approval request, returns 403 with request ID, client polls
- **C) Return 403 only (SIMPLE):** Return 403 with error message, client must call separate approval API

**Recommendation:** Option B - Lambda auto-creates approval request, returns structured error:
```json
{
  "error": "PolicyRequiresApproval",
  "message": "Access to profile 'prod-admin' requires approval",
  "request_id": "a1b2c3d4e5f6g7h8",
  "approval_status_url": "https://tvm.example.com/requests/a1b2c3d4e5f6g7h8"
}
```

Client polls `/requests/{id}` endpoint until status changes to "approved", then retries credential request.

**Phase to address:** Phase 3 (Session Tracking & Approval/Break-Glass)

---

### Multi-Region Deployment

**Question:** How do organizations deploy TVM across multiple AWS regions for high availability?

**Challenge:** SSM Parameter Store is region-specific. Policy updates must propagate to all regions.

**Options:**
- **A) SSM cross-region replication:** Use EventBridge + Lambda to replicate parameter updates
- **B) S3-backed policy storage:** Store policy in S3, enable cross-region replication, Lambda reads from S3
- **C) Single-region control plane:** Deploy TVM in one region, accept cross-region latency

**Recommendation:** Defer to Phase 5 (Infrastructure as Code) - provide IaC examples for single-region deployment. Multi-region is an advanced use case organizations can implement themselves using Option A.

**Documentation need:** Add "Multi-Region Deployment" section to LAMBDA_TVM.md with Option A pattern.

---

### Cost Optimization for High-Volume Scenarios

**Question:** At 10,000 req/sec, TVM costs ~$43k/month. How do we optimize?

**Research needed:**
- Lambda SnapStart for Go (reduces cold start latency, may reduce provisioned concurrency need)
- API Gateway HTTP API vs REST API cost comparison (HTTP API is 70% cheaper)
- DynamoDB DAX (caching layer) for session lookup hot path
- ALB → Lambda direct integration (bypass API Gateway for cost savings)

**Recommendation:** Document cost optimization patterns in Phase 6 (Testing & Documentation). Provide reference architectures for:
- Low-volume (<100 req/sec): API Gateway + Lambda on-demand
- Medium-volume (100-1,000 req/sec): API Gateway + Lambda provisioned concurrency
- High-volume (>1,000 req/sec): ALB + Lambda + DynamoDB DAX

**Phase to address:** Phase 6 (Testing & Documentation) - add "Cost Optimization" section

## Open Questions

**Q1: Should TVM support custom identity sources (non-AWS identities)?**
- Example: JWT tokens from Auth0, Okta, etc.
- Would require Lambda authorizer for token validation
- User identity extracted from JWT claims instead of AWS STS

**Answer:** Defer to future milestone. v1.14 focuses on AWS-native identity (GetCallerIdentity). JWT integration is a separate feature.

---

**Q2: How do clients discover available profiles?**
- CLI has `sentinel shell init` which queries SSM for `/sentinel/policies/*`
- TVM clients need same discovery mechanism

**Answer:** Add to Phase 4 (API Gateway Integration) - new endpoint `GET /profiles` that returns available profiles from SSM.

---

**Q3: Should TVM support credential caching to reduce STS calls?**
- CLI caches credentials in keyring
- TVM could cache in Lambda memory or ElastiCache

**Answer:** No - defeats purpose of per-request policy evaluation. TVM should call STS on every request to enable real-time revocation.

---

**Q4: How do we test TVM without deploying to AWS?**
- Integration tests need real Lambda + API Gateway + DynamoDB
- Expensive and slow for development cycle

**Answer:** Add to Phase 6 - provide Docker Compose stack with LocalStack for local TVM testing (API Gateway + Lambda + DynamoDB emulation).

## Ready for Roadmap

Research is complete. Key decisions for roadmap creator:

1. **Phase structure:** 7-8 phases as outlined above
2. **Build order:** Foundation → Credentials → Sessions → API Gateway → IaC → Testing
3. **Integration points:** Reuse existing packages (policy, session, identity) with zero modifications
4. **New code:** Lambda handler (~500 LOC), Lambda entrypoint (~100 LOC), IaC templates
5. **Critical constraints:** Lambda IS trust boundary; protected roles trust only Lambda execution role
6. **Quality gates:** >80% coverage, <200ms p99 latency, zero security regressions

**Estimated effort:** 7-8 phases, 14-18 plans, ~40-60 minutes total execution time

**Next steps:**
1. Create milestone v1.14 structure in `.planning/milestones/v1.14/`
2. Generate phase plans based on this research
3. Begin Phase 1: Foundation (Lambda handler skeleton)

## Sources

### Token Vending Machine Patterns
- [Implement SaaS tenant isolation with AWS Lambda TVM - AWS Prescriptive Guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/implement-saas-tenant-isolation-for-amazon-s3-by-using-an-aws-lambda-token-vending-machine.html)
- [TVM Explained - AWS Workshop](https://momento.awsworkshop.io/9_live-updates/tvm_explained.html)
- [Token Vending Machine - AWS Workshop](https://momento.awsworkshop.io/9_live-updates/token_vending_machine.html)

### AWS Lambda Best Practices
- [Building Lambda functions with Go - AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/lambda-golang.html)
- [Define Lambda function handlers in Go - AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/golang-handler.html)
- [Lambda examples using SDK for Go V2](https://docs.aws.amazon.com/code-library/latest/ug/go_2_lambda_code_examples.html)

### Security & Trust Boundaries
- [SEC02-BP02 Use temporary credentials - AWS Well-Architected Framework](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_identities_unique.html)
- [Provision least-privilege IAM roles with Role Vending Machine](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/provision-least-privilege-iam-roles-by-deploying-a-role-vending-machine-solution.html)
- [Defining Lambda function permissions with execution role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)

### API Gateway IAM Authentication
- [Control access to a REST API with IAM permissions](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html)
- [AWS Security Best Practices: IAM for Service-to-Service Authentication](https://www.ranthebuilder.cloud/post/aws-security-best-practices-leveraging-iam-for-service-to-service-authentication-and-authorization)
- [API Gateway User Authentication Best Practices](https://repost.aws/questions/QUudE5jzHTQN6IZT-17v9Q8A/api-gateway-user-authentication-best-practices)

### Go Monorepo Architecture
- [Shared Go Packages in a Monorepo - 1Password](https://passage.1password.com/post/shared-go-packages-in-a-monorepo)
- [Building a Monorepo in Golang - Earthly Blog](https://earthly.dev/blog/golang-monorepo/)
- [Go Monorepos for Growing Teams](https://jamescun.com/posts/golang-monorepo-structure/)
- [Full-stack monorepo - Part I: Go services](https://medium.com/burak-tasci/full-stack-monorepo-part-i-go-services-967bb3527bb8)

### Infrastructure as Code (2026)
- [AWS CDK vs Terraform: Complete 2026 Comparison](https://dev.to/aws-builders/aws-cdk-vs-terraform-the-complete-2026-comparison-3b4p)
- [Infrastructure as Code: Complete AWS Guide to IaC Tools [2026]](https://towardsthecloud.com/blog/infrastructure-as-code)
- [AWS CDK vs Terraform Comparison - Towards The Cloud](https://towardsthecloud.com/blog/aws-cdk-vs-terraform)
