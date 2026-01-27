# Pitfalls Research: Server-Side Credential Vending

**Researched:** 2026-01-24
**Domain:** Lambda-based Token Vending Machines with API Gateway + IAM authentication
**Confidence:** MEDIUM-HIGH (web research verified with multiple sources, AWS-specific patterns identified)

## Research Summary

Investigated common security and operational pitfalls when building Lambda-based credential vending machines (TVMs) integrated with API Gateway and IAM authentication. The TVM is the security boundary — if compromised or misconfigured, attackers obtain AWS credentials with potentially broad permissions.

**Critical insight:** Lambda TVMs are commonly targeted for credential theft and lateral movement. The attack surface includes overly permissive Lambda execution roles, API Gateway authentication bypass, cold start credential caching, error message information leakage, and STS AssumeRole privilege escalation chains.

**Primary recommendation:** Treat Lambda execution role permissions as the blast radius for TVM compromise. Follow least privilege rigorously, implement fail-closed security for session revocation, prevent credential exposure in logs/errors, and enforce SCP boundaries org-wide.

---

## Security Pitfalls

### CRITICAL: Overly Permissive Lambda Execution Role

**What goes wrong:** Lambda execution role has admin privileges or wildcard permissions (`*`), enabling attackers who compromise the TVM to access/modify/delete resources across the entire AWS account.

**Why it happens:**
- Default AWS managed policies (e.g., `AdministratorAccess`) used for convenience during development
- Execution role shared across multiple Lambda functions with different permission requirements
- Incremental feature additions grant broader permissions without review

**Consequences:**
- **Credential theft:** Attackers extract environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) via command injection or SSRF vulnerabilities
- **Lateral movement:** Compromised TVM credentials used to assume other roles, access DynamoDB tables, read SSM parameters, etc.
- **Privilege escalation:** With `iam:PassRole` + `lambda:CreateFunction`, attackers create new Lambda functions with admin roles

**Prevention:**
1. **Principle of least privilege:** Grant only permissions required for TVM operation:
   - `sts:AssumeRole` on specific role ARNs (not `*`)
   - `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:UpdateItem` on specific session table ARN
   - `ssm:GetParameter` on specific policy parameter path
   - `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` for CloudWatch
2. **Separate execution roles:** Never share execution roles between Lambda functions
3. **Deny admin policies:** Add explicit deny for `iam:*`, `organizations:*`, `sts:AssumeRole` on admin roles
4. **Resource-based conditions:** Use `Condition` blocks to restrict `sts:AssumeRole` to specific source ARNs
5. **SCP enforcement:** Apply service control policies to prevent TVM from accessing sensitive actions

**Warning signs:**
- Lambda execution role has policies with `"Resource": "*"` or `"Effect": "Allow", "Action": "*"`
- Multiple Lambda functions share the same execution role
- IAM policy simulator shows permissions beyond TVM requirements
- CloudTrail shows TVM role accessing resources outside normal operation

**Phase:** Phase 1 (Infrastructure Setup) — execution role must be defined before Lambda deployment

---

### CRITICAL: IAM Authentication Bypass via API Gateway

**What goes wrong:** API Gateway configured with IAM authentication but allows unauthenticated requests due to misconfiguration, enabling credential vending to anonymous callers.

**Why it happens:**
- Resource policy uses `"Principal": "*"` without `Condition` blocks
- API Gateway method authorization set to `NONE` instead of `AWS_IAM`
- CORS configuration allows pre-flight OPTIONS requests without authentication
- Multiple authorization types configured, allowing fallback to open method

**Consequences:**
- **Anonymous credential access:** Anyone can call TVM API and obtain temporary AWS credentials
- **Credential abuse:** Attackers script credential requests for maximum duration, bypassing all policy enforcement
- **Denial of service:** Unlimited credential requests exhaust STS quota or DynamoDB capacity

**Prevention:**
1. **Enforce AWS_IAM authorization:** Set `authorizationType: AWS_IAM` on all API Gateway methods
2. **Resource policy deny-by-default:** Use explicit `Deny` statements for unauthenticated access:
   ```json
   {
     "Effect": "Deny",
     "Principal": "*",
     "Action": "execute-api:Invoke",
     "Resource": "arn:aws:execute-api:*:*:*",
     "Condition": {
       "StringNotEquals": {
         "aws:PrincipalType": ["User", "AssumedRole"]
       }
     }
   }
   ```
3. **SigV4 signature validation:** API Gateway automatically validates SigV4 signatures; never disable
4. **Test unauthenticated access:** Attempt API calls without credentials to verify denial
5. **CloudWatch metrics:** Monitor `4xx` errors (should be high for unauthenticated attempts)

**Warning signs:**
- API Gateway access logs show requests without `user` field (unauthenticated)
- CloudTrail shows `AssumeRole` calls with unexpected `principalId` or `sourceIPAddress`
- Sudden spike in API requests from unknown IP ranges
- DynamoDB session table contains sessions with missing or invalid `user` fields

**Phase:** Phase 2 (API Gateway Setup) — authentication must be configured before public deployment

**References:**
- [API Gateway Security Best Practices](https://www.practical-devsecops.com/api-gateway-security-best-practices/)
- [IAM Authentication Bypass via Wildcard Expansion](https://0xn3va.gitbook.io/cheat-sheets/cloud/aws/api-gateway)

---

### CRITICAL: STS AssumeRole Privilege Escalation Chains

**What goes wrong:** TVM has permission to assume roles with broader privileges than the TVM itself, enabling attackers to "hop" through roles until reaching administrative access.

**Why it happens:**
- TVM execution role granted `sts:AssumeRole` on `*` resources
- Target roles have overly permissive trust policies (`"Principal": "*"` with weak conditions)
- No external ID or session name validation in trust policies
- TVM can assume roles in other AWS accounts without restrictions

**Consequences:**
- **Multi-hop escalation:** Attacker assumes Role A (limited), uses Role A to assume Role B (broader), uses Role B to assume Admin Role
- **Cross-account compromise:** TVM credentials used to assume roles in production accounts
- **Persistent access:** Attacker creates new roles with long-lived credentials

**Prevention:**
1. **Restrict AssumeRole targets:** Execution role should only assume roles matching specific naming pattern:
   ```json
   {
     "Effect": "Allow",
     "Action": "sts:AssumeRole",
     "Resource": "arn:aws:iam::ACCOUNT_ID:role/sentinel-vended-*"
   }
   ```
2. **Trust policy conditions:** Require specific `sts:SourceIdentity` or `sts:ExternalId`:
   ```json
   {
     "Effect": "Allow",
     "Principal": {
       "AWS": "arn:aws:iam::ACCOUNT_ID:role/sentinel-tvm-execution-role"
     },
     "Action": "sts:AssumeRole",
     "Condition": {
       "StringEquals": {
         "sts:ExternalId": "sentinel-tvm-unique-id"
       }
     }
   }
   ```
3. **Deny privilege escalation:** Use permission boundaries on TVM execution role to prevent assuming admin roles
4. **SCP enforcement:** Apply SCP denying `sts:AssumeRole` on admin roles except from trusted principals
5. **Session name validation:** Require `RoleSessionName` matching pattern (e.g., `sentinel-*`)

**Warning signs:**
- CloudTrail shows `AssumeRole` calls from TVM to unexpected roles
- Execution role policy has `"Resource": "arn:aws:iam::*:role/*"` (overly broad)
- Trust policies on vended roles have `"Principal": "*"` or weak conditions
- Session names in CloudTrail don't match expected patterns

**Phase:** Phase 1 (Infrastructure Setup) — role chaining prevention must be designed into IAM policies

**References:**
- [AWS IAM Privilege Escalation Methods](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/)
- [Lambda Privilege Escalation via PassRole](https://makosecblog.com/aws-pentest/lambda-privesc/)

---

### HIGH: Cold Start Credential Caching in Global Scope

**What goes wrong:** TVM Lambda caches credentials or policy state in global variables during cold start, causing credentials to persist across invocations and leak between tenants/users.

**Why it happens:**
- Credentials loaded during Lambda initialization (outside handler function)
- Global variables used to cache policy evaluations or session state
- SDK clients initialized at module level with long-lived credentials
- Lambda container reuse causes previous invocation's data to remain in memory

**Consequences:**
- **Credential leakage:** User A's credentials returned to User B on subsequent request
- **Stale policy enforcement:** Policy changes not reflected until container cold start
- **Session confusion:** Session tracking state mixed between users

**Prevention:**
1. **No global credential caching:** Load credentials only inside handler function:
   ```python
   # BAD: Global cache persists across invocations
   policy_cache = {}

   def handler(event, context):
       if 'profile' in policy_cache:
           policy = policy_cache['profile']  # WRONG: may be for different user

   # GOOD: Per-request scope
   def handler(event, context):
       policy = load_policy(event['profile'])  # Fresh load each request
   ```
2. **Handler-scoped state only:** All user-specific state must be local variables in handler
3. **Refresh ephemeral data:** Even with caching, refresh credentials/policy before using:
   ```python
   def handler(event, context):
       if hasattr(handler, 'policy_cache'):
           # Check expiration even if cached
           if time.time() > handler.policy_cache['expiry']:
               handler.policy_cache = load_policy()
       else:
           handler.policy_cache = load_policy()
   ```
4. **AWS Parameters and Secrets Extension:** Use Lambda extension for SSM/Secrets Manager with TTL expiry
5. **Test container reuse:** Simulate warm Lambda by invoking multiple times with different users

**Warning signs:**
- DynamoDB shows sessions attributed to wrong users
- Credentials returned have wrong `SourceIdentity`
- Policy changes take 5-15 minutes to apply (Lambda container TTL)
- Logs show same policy loaded for all requests despite different profiles

**Phase:** Phase 3 (Lambda Handler Implementation) — handler must be designed without global state

**References:**
- [Lambda Cold Start Security Vulnerabilities](https://medium.com/@rizqimulkisrc/serverless-security-aws-lambda-cold-start-vulnerabilities-84461bb7b51a)
- [Lambda Environment Lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html)

---

### HIGH: Error Message Information Leakage

**What goes wrong:** Lambda returns detailed error messages exposing internal system structure, credential formats, IAM role ARNs, DynamoDB table names, or policy logic.

**Why it happens:**
- Unhandled exceptions bubble stack traces to API response
- Error messages include AWS SDK error details (ARNs, account IDs)
- Debug logging enabled in production Lambda
- CloudWatch logs set to verbose mode without data protection

**Consequences:**
- **Reconnaissance:** Attackers learn internal architecture from error messages
- **Credential format disclosure:** Error shows expected credential structure for replay attacks
- **Account enumeration:** Error messages leak AWS account ID and region
- **Policy bypass hints:** Error messages reveal which policy rules are evaluated

**Prevention:**
1. **Generic error responses:** Return sanitized errors to API clients:
   ```python
   try:
       credentials = vend_credentials(user, profile)
   except Exception as e:
       logger.error(f"Credential vending failed: {e}")  # Detailed log
       return {
           "statusCode": 500,
           "body": json.dumps({"error": "Internal server error"})  # Generic response
       }
   ```
2. **CloudWatch data protection:** Use managed identifiers to mask credentials in logs:
   - Mask `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
   - Redact email addresses, ARNs, account IDs
3. **API Gateway logging configuration:** Set `dataTraceEnabled: false` for production
4. **Structured error codes:** Return error codes (e.g., `INVALID_PROFILE`, `POLICY_DENIED`) without details
5. **Test error paths:** Trigger errors and verify responses don't leak internal details

**Warning signs:**
- API responses contain stack traces or file paths
- Error messages include AWS resource ARNs or account IDs
- CloudWatch logs show credentials in plaintext
- Error responses differ between valid/invalid inputs (timing attacks)

**Phase:** Phase 3 (Lambda Handler Implementation) — error handling must sanitize all responses

**References:**
- [Lambda Information Leakage via Errors](https://medium.com/r3d-buck3t/vulnerable-lambda-leaks-aws-account-information-c613837377ad)
- [CloudWatch Data Protection for Sensitive Logs](https://aws.amazon.com/blogs/mt/handling-sensitive-log-data-using-amazon-cloudwatch/)

---

### MEDIUM: SCP Enforcement Gaps

**What goes wrong:** Service control policies intended to restrict credential usage have gaps, allowing TVM-vended credentials to access forbidden resources.

**Why it happens:**
- SCPs don't affect management account, TVM deployed in wrong account
- SCP conditions use `aws:PrincipalArn` which doesn't match role session ARNs
- SCP exempts roles matching TVM execution role pattern but doesn't distinguish vended sessions
- EC2 instance credential restrictions not applied to Lambda credentials

**Consequences:**
- **Policy bypass:** Users obtain credentials via TVM but SCP doesn't restrict usage
- **Untracked access:** Credentials used outside intended VPC or IP range
- **Compliance failure:** Audit shows credentials accessing forbidden services (e.g., `s3:DeleteBucket`)

**Prevention:**
1. **Test SCP with vended credentials:** Assume role via TVM and verify SCPs apply
2. **SourceIdentity-based SCPs:** Enforce restrictions based on `sts:SourceIdentity`:
   ```json
   {
     "Effect": "Deny",
     "Action": "s3:DeleteBucket",
     "Resource": "*",
     "Condition": {
       "StringNotLike": {
         "aws:userid": "AIDAI*:sentinel:*"
       }
     }
   }
   ```
3. **VPC endpoint restrictions:** If vended credentials should only work from specific VPCs, enforce via SCP:
   ```json
   {
     "Effect": "Deny",
     "Action": "*",
     "Resource": "*",
     "Condition": {
       "StringNotEquals": {
         "aws:SourceVpc": "vpc-12345678"
       }
     }
   }
   ```
4. **Member account deployment:** Deploy TVM in member account (not management account) where SCPs apply
5. **Session tags:** Pass session tags via `AssumeRole` and use in SCP conditions

**Warning signs:**
- CloudTrail shows vended credentials performing unexpected actions
- SCP metrics show low denial rate despite restrictive policies
- Credentials work from disallowed IP addresses or VPCs
- Manual testing shows SCP not blocking actions as expected

**Phase:** Phase 1 (Infrastructure Setup) — SCP design must account for TVM session patterns

**References:**
- [Service Control Policy Examples](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html)
- [EC2 Credential Vending Controls](https://aws.amazon.com/blogs/security/how-to-use-policies-to-restrict-where-ec2-instance-credentials-can-be-used-from/)

---

## Integration Pitfalls

### CRITICAL: Sentinel Policy Evaluation Bypass via Direct Lambda Invocation

**What goes wrong:** API Gateway enforces IAM authentication but Lambda function allows direct invocation via `lambda:InvokeFunction`, bypassing API Gateway and skipping Sentinel policy evaluation.

**Why it happens:**
- Lambda resource policy allows `lambda:InvokeFunction` from `Principal: "*"`
- Lambda function doesn't validate request came through API Gateway
- No `aws:SourceArn` condition on Lambda resource policy

**Consequences:**
- **Complete policy bypass:** Attackers directly invoke Lambda and obtain credentials without policy check
- **No audit trail:** API Gateway access logs miss direct Lambda invocations
- **Session tracking bypass:** Direct invocation skips DynamoDB session creation

**Prevention:**
1. **Restrict Lambda invocation:** Lambda resource policy should only allow API Gateway:
   ```json
   {
     "Effect": "Allow",
     "Principal": {
       "Service": "apigateway.amazonaws.com"
     },
     "Action": "lambda:InvokeFunction",
     "Resource": "arn:aws:lambda:REGION:ACCOUNT:function:sentinel-tvm",
     "Condition": {
       "ArnLike": {
         "AWS:SourceArn": "arn:aws:execute-api:REGION:ACCOUNT:API_ID/*/*"
       }
     }
   }
   ```
2. **Request validation:** Lambda handler checks `requestContext.apiId` and `requestContext.stage` are present
3. **Deny direct invocation IAM policy:** SCP denies `lambda:InvokeFunction` on TVM except from API Gateway
4. **Test direct invocation:** Attempt `aws lambda invoke` and verify access denied

**Warning signs:**
- CloudTrail shows `lambda:Invoke` events without matching API Gateway logs
- Session table shows entries without API request IDs
- Credentials vended without policy evaluation logs

**Phase:** Phase 2 (API Gateway Setup) — Lambda resource policy must be configured with API Gateway

---

### HIGH: Credential Refresh Failure Handling

**What goes wrong:** AWS SDK auto-refresh fails when credentials expire, causing long-running processes to lose access mid-operation without graceful degradation.

**Why it happens:**
- TVM doesn't implement credential refresh endpoint (only initial vend)
- SDK credential expiration occurs 5 minutes before STS expiry, but TVM unreachable
- Network partition or API Gateway throttling prevents refresh
- Credential expiration time set too short (e.g., 15 minutes for multi-hour Terraform apply)

**Consequences:**
- **Terraform apply failures:** Long-running infrastructure changes fail halfway through
- **Partial resource creation:** CloudFormation stacks stuck in `CREATE_IN_PROGRESS`
- **User frustration:** Developers restart operations from scratch

**Prevention:**
1. **Implement refresh endpoint:** API Gateway path `/refresh` extends existing session credentials
2. **SDK auto-refresh support:** Return credentials in ECS container credential format with `Expiration`:
   ```json
   {
     "AccessKeyId": "ASIA...",
     "SecretAccessKey": "...",
     "Token": "...",
     "Expiration": "2026-01-24T12:00:00Z"
   }
   ```
3. **Adequate credential duration:** Default to 1 hour for `--server` mode, allow policy override for longer operations
4. **Exponential backoff retries:** SDK retries refresh with backoff; ensure API Gateway has sufficient throttle limits
5. **Fallback to re-authentication:** If refresh fails, SDK should trigger full re-authentication flow

**Warning signs:**
- Users report "ExpiredToken" errors during long operations
- CloudWatch shows 429 throttling errors on refresh endpoint
- SDK logs show "credentials refreshed too close to expiration"

**Phase:** Phase 4 (Credential Refresh Implementation) — refresh logic separate from initial vend

**References:**
- [Credential Refresh Expiry Issues](https://github.com/aws/aws-sdk-go-v2/issues/2135)
- [ECS Credential Refresh Timing](https://github.com/aws/aws-sdk-net/issues/2498)

---

### MEDIUM: DynamoDB Session Table Race Conditions

**What goes wrong:** Concurrent credential requests create duplicate sessions in DynamoDB or allow session revocation bypass due to race conditions.

**Why it happens:**
- `PutItem` without condition expression allows duplicates
- Session revocation check uses eventually consistent read
- Two Lambda invocations process same user simultaneously
- Session expiry check uses stale cached data

**Consequences:**
- **Session duplication:** User has multiple active sessions for same profile
- **Revocation bypass:** Revoked session still serves credentials due to read lag
- **Quota bypass:** Rate limiting based on active sessions undercounts

**Prevention:**
1. **Conditional writes for session creation:**
   ```python
   dynamodb.put_item(
       TableName='sentinel-sessions',
       Item={'sessionId': session_id, ...},
       ConditionExpression='attribute_not_exists(sessionId)'  # Atomic check
   )
   ```
2. **Strongly consistent reads for revocation:**
   ```python
   response = dynamodb.get_item(
       TableName='sentinel-sessions',
       Key={'sessionId': session_id},
       ConsistentRead=True  # Not eventually consistent
   )
   ```
3. **Optimistic locking with version attribute:**
   ```python
   dynamodb.update_item(
       TableName='sentinel-sessions',
       Key={'sessionId': session_id},
       UpdateExpression='SET #status = :new_status, #version = #version + :inc',
       ConditionExpression='#version = :expected_version',  # Version check
       ExpressionAttributeNames={'#status': 'status', '#version': 'version'},
       ExpressionAttributeValues={':new_status': 'revoked', ':expected_version': current_version, ':inc': 1}
   )
   ```
4. **TransactWriteItems for atomic operations:** Use transactions when creating session + updating quota counter

**Warning signs:**
- DynamoDB shows multiple sessions with same `user` + `profile` + overlapping times
- Revoked sessions continue returning credentials for 1-2 seconds
- ConditionalCheckFailedException errors in CloudWatch (normal for atomic checks)

**Phase:** Phase 5 (Session Management Implementation) — session store must use conditional writes

**References:**
- [DynamoDB Race Conditions](https://awsfundamentals.com/blog/understanding-and-handling-race-conditions-at-dynamodb)
- [Optimistic Locking in DynamoDB](https://codewithmukesh.com/blog/handle-concurrency-in-amazon-dynamodb-with-optimistic-locking/)

---

### MEDIUM: Container Credential Format Compatibility

**What goes wrong:** SDK fails to parse credentials returned by TVM due to format mismatch with AWS container credential specification.

**Why it happens:**
- TVM returns STS `AssumeRole` response directly instead of container format
- Field names don't match SDK expectations (e.g., `AccessKey` vs `AccessKeyId`)
- `Expiration` timestamp format incorrect (not RFC3339)
- Missing `RoleArn` field causes SDK to reject credentials

**Consequences:**
- **SDK parsing errors:** Clients receive 200 OK but fail to extract credentials
- **Auth failures:** Tools report "unable to load credentials" despite successful vend
- **Compatibility issues:** Works with AWS CLI but fails with boto3/SDK

**Prevention:**
1. **Follow ECS container credential format exactly:**
   ```json
   {
     "AccessKeyId": "ASIA...",
     "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
     "Token": "IQoJb3JpZ2luX2VjEH...",
     "Expiration": "2026-01-24T12:34:56Z",
     "RoleArn": "arn:aws:iam::123456789012:role/vended-role"
   }
   ```
2. **RFC3339 timestamp format:** Use `time.Now().UTC().Format(time.RFC3339)` for `Expiration`
3. **Test with multiple SDKs:** Verify with AWS CLI, boto3, aws-sdk-go, aws-sdk-java
4. **Response content-type:** Set `Content-Type: application/json` header
5. **Reference aws-vault implementation:** Sentinel already has container credential server in `server/ecsserver.go`

**Warning signs:**
- SDK logs show "unable to parse credentials" or "invalid timestamp"
- Works with `curl` but fails with SDK
- Different SDKs have different failure modes

**Phase:** Phase 3 (Lambda Handler Implementation) — response format must match ECS spec

**References:**
- [Container Credential Provider Spec](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
- [Sentinel ECS Server Implementation](https://github.com/byteness/aws-vault/blob/main/server/ecsserver.go)

---

## Operational Pitfalls

### HIGH: Lambda Deployment Downtime During Updates

**What goes wrong:** Deploying new Lambda code causes credential vending downtime as API Gateway switches from old version to new version.

**Why it happens:**
- Lambda function updated in-place without versioning
- API Gateway integration points directly at `$LATEST` version
- No provisioned concurrency, all containers cold start after deployment
- Developers rename handler function or binary during deployment

**Consequences:**
- **Credential vending outage:** Users receive 5xx errors during deployment window
- **Failed automation:** CI/CD pipelines fail when TVM unavailable mid-deployment
- **Extended outage:** Cold start times increase outage from seconds to minutes

**Prevention:**
1. **Use Lambda versioning + aliases:**
   - Deploy to new version (e.g., `v42`)
   - Switch alias (`prod`) from `v41` to `v42`
   - API Gateway points to `sentinel-tvm:prod` (alias, not `$LATEST`)
2. **Provisioned concurrency:** Pre-warm containers for `prod` alias to eliminate cold starts
3. **Blue/green deployment:**
   - Create second API Gateway stage (`blue`, `green`)
   - Deploy to inactive stage, test, then switch traffic
4. **Gradual traffic shifting:** Use CodeDeploy Lambda deployment with `Linear10PercentEvery1Minute`
5. **Rollback plan:** Keep previous version alias (`prod-prev`) for instant rollback

**Warning signs:**
- CloudWatch shows spike in 5xx errors during deployment
- API Gateway metrics show latency increase to 10+ seconds (cold start)
- Users report "service unavailable" during deployment windows

**Phase:** Phase 6 (Deployment Strategy) — deployment must be designed for zero downtime

**References:**
- [Zero Downtime Lambda Deployments](https://moiadev.medium.com/when-lambda-deployments-arent-zero-downtime-and-how-to-fix-it-e53e37f1c17)
- [Blue/Green Deployments with API Gateway](https://aws.amazon.com/blogs/compute/zero-downtime-blue-green-deployments-with-amazon-api-gateway/)

---

### MEDIUM: CloudWatch Logs Cost Explosion

**What goes wrong:** CloudWatch Logs accumulates gigabytes of data per day due to verbose Lambda logging, causing unexpected costs.

**Why it happens:**
- Debug logging enabled in production
- Every credential request logs full event payload (including credentials)
- No log retention policy, logs kept indefinitely
- Log group set to never expire

**Consequences:**
- **Cost overrun:** CloudWatch Logs charges $0.50/GB ingestion + $0.03/GB storage
- **Performance impact:** Large log volumes slow CloudWatch Insights queries
- **Compliance risk:** Credentials accidentally logged in plaintext

**Prevention:**
1. **Set log retention:** Configure 7-day or 30-day retention for Lambda log groups
2. **Structured logging levels:** Use `INFO` for production, `DEBUG` only for troubleshooting
3. **Filter sensitive data:** Redact credentials before logging:
   ```python
   logger.info(f"Vended credentials for user={user}, profile={profile}")  # Good
   logger.debug(f"Full event: {event}")  # BAD: may contain credentials
   ```
4. **CloudWatch data protection:** Apply managed identifiers to mask credentials automatically
5. **Metric filters instead of logs:** Track counters (requests, denials) as CloudWatch metrics, not logs
6. **Log sampling:** Log 1% of successful requests, 100% of failures

**Warning signs:**
- CloudWatch Logs bill exceeds $100/month for single Lambda
- Log groups grow by gigabytes per day
- CloudWatch Insights queries time out
- Compliance audit finds credentials in logs

**Phase:** Phase 3 (Lambda Handler Implementation) — logging strategy must be defined early

**References:**
- [Lambda Logging Best Practices](https://edgedelta.com/company/knowledge-center/lambda-logging)
- [Data Masking in CloudWatch Logs](https://dev.to/mlnrt/data-masking-of-aws-lambda-function-logs-37mc)

---

### MEDIUM: Monitoring Blind Spots for Security Events

**What goes wrong:** TVM compromise or abuse goes undetected because CloudWatch alarms and metrics don't cover security-critical events.

**Why it happens:**
- Monitoring focuses on availability (5xx errors) but not security (policy denials)
- No alerts for unusual credential request patterns
- CloudTrail analysis not integrated with real-time monitoring
- No dashboard for TVM security posture

**Consequences:**
- **Delayed incident response:** Credential theft discovered days later via CloudTrail audit
- **Abuse undetected:** Attacker makes thousands of credential requests without triggering alerts
- **Policy bypass unnoticed:** Configuration error allows unrestricted credential vending

**Prevention:**
1. **CloudWatch alarms for security events:**
   - High rate of policy denials (potential attack)
   - Credential requests from unexpected IP ranges
   - Spike in error responses (misconfiguration)
   - Session revocations (security incident indicator)
2. **Custom metrics from Lambda:**
   ```python
   cloudwatch.put_metric_data(
       Namespace='Sentinel/TVM',
       MetricData=[
           {
               'MetricName': 'PolicyDenials',
               'Value': 1,
               'Dimensions': [{'Name': 'Profile', 'Value': profile}]
           }
       ]
   )
   ```
3. **CloudWatch dashboard:** Track TVM health in single view (request rate, error rate, denial rate)
4. **EventBridge rules:** Trigger SNS/Lambda on high-value CloudTrail events (e.g., `AssumeRole` by TVM)
5. **Daily security reports:** Lambda function aggregates previous day's security events

**Warning signs:**
- Security incident discovered retroactively via CloudTrail
- No alerts fired despite ongoing attack
- Monitoring dashboard shows green during actual outage

**Phase:** Phase 7 (Monitoring & Alerting) — security monitoring separate from availability monitoring

---

### LOW: API Gateway Throttling During Traffic Spikes

**What goes wrong:** API Gateway throttles credential requests during traffic spikes (e.g., CI/CD pipeline burst), causing widespread authentication failures.

**Why it happens:**
- Default API Gateway throttle limits (10,000 req/sec account-wide)
- Burst limit exhausted by parallel Terraform applies
- No reserved capacity for TVM API

**Consequences:**
- **CI/CD failures:** Deployment pipelines fail with 429 Too Many Requests
- **User impact:** Developers unable to assume roles during peak hours
- **Cascading failures:** Retries amplify load, making throttling worse

**Prevention:**
1. **Request throttle limits increase:** Contact AWS support to raise account-level limits
2. **Usage plans with quotas:** Create API Gateway usage plan with higher throttle for CI/CD
3. **Client-side backoff:** SDK automatically retries with exponential backoff
4. **Reserved concurrency:** Configure Lambda reserved concurrency to prevent over-provisioning
5. **Burst capacity planning:** Size API Gateway for 2x expected peak load

**Warning signs:**
- CloudWatch shows 429 errors during deployment windows
- API Gateway throttle metrics exceed 80% of limit
- Users report intermittent "rate exceeded" errors

**Phase:** Phase 6 (Deployment Strategy) — capacity planning before production rollout

---

## Prevention Matrix

| Pitfall | Warning Signs | Prevention | Phase |
|---------|---------------|------------|-------|
| **Overly Permissive Execution Role** | Execution role has `Resource: "*"` or admin policies | Least privilege IAM policy; separate roles per function; deny admin actions | Phase 1: Infrastructure |
| **IAM Auth Bypass** | API Gateway logs show requests without `user` field | Enforce `AWS_IAM` authorization; resource policy deny unauthenticated | Phase 2: API Gateway |
| **AssumeRole Privilege Escalation** | CloudTrail shows unexpected role assumptions from TVM | Restrict `sts:AssumeRole` to specific role ARNs; trust policy conditions | Phase 1: Infrastructure |
| **Cold Start Credential Caching** | Credentials with wrong `SourceIdentity`; policy changes delayed | No global state; handler-scoped variables only; test container reuse | Phase 3: Lambda Handler |
| **Error Message Leakage** | Stack traces or ARNs in API responses | Generic error codes; CloudWatch data protection; sanitize exceptions | Phase 3: Lambda Handler |
| **SCP Enforcement Gaps** | Vended credentials access forbidden services | Test SCPs with vended creds; `sts:SourceIdentity` conditions; member account deployment | Phase 1: Infrastructure |
| **Policy Evaluation Bypass** | CloudTrail shows `lambda:Invoke` without API Gateway logs | Lambda resource policy restricts to API Gateway only; request context validation | Phase 2: API Gateway |
| **Credential Refresh Failure** | "ExpiredToken" errors during long operations | Implement `/refresh` endpoint; 1hr default duration; SDK retry config | Phase 4: Refresh Logic |
| **DynamoDB Race Conditions** | Duplicate sessions for same user+profile | Conditional writes; strongly consistent reads; optimistic locking | Phase 5: Session Management |
| **Container Format Incompatibility** | SDK parses credentials but auth fails | Follow ECS format exactly; RFC3339 timestamps; test multiple SDKs | Phase 3: Lambda Handler |
| **Deployment Downtime** | 5xx errors during deployment; 10+ second latency | Lambda versioning + aliases; provisioned concurrency; blue/green deployment | Phase 6: Deployment |
| **CloudWatch Cost Explosion** | Logs grow by GB/day; unexpected CloudWatch bills | 7-day retention; filter sensitive data; metric filters; log sampling | Phase 3: Lambda Handler |
| **Monitoring Blind Spots** | Security incidents discovered retroactively | CloudWatch alarms for denials/errors; custom security metrics; daily reports | Phase 7: Monitoring |
| **API Gateway Throttling** | 429 errors during CI/CD; throttle metrics at 80% | Request limit increase; usage plans; burst capacity planning | Phase 6: Deployment |

---

## Integration-Specific Recommendations

### Integrating with Existing Sentinel

Based on Sentinel's current architecture (v1.13 with 114,891 LOC Go, server mode, session tracking), specific integration points:

1. **Policy Evaluation Reuse:** Lambda TVM should call Sentinel policy engine via shared library, not duplicate policy logic
   - **Pitfall risk:** Policy logic divergence between CLI and TVM
   - **Prevention:** Extract `policy` package into shared module; TVM imports same package

2. **Session Table Compatibility:** TVM should write to same DynamoDB session table as `sentinel exec --server`
   - **Pitfall risk:** Schema mismatch causes session tracking to break
   - **Prevention:** Use `session.ServerSession` struct from existing codebase; write integration tests

3. **SourceIdentity Format Consistency:** TVM-vended credentials must use same `sentinel:<user>:<request-id>` format
   - **Pitfall risk:** CloudTrail correlation breaks; audit verify fails
   - **Prevention:** Import `identity` package; use `identity.NewSourceIdentity()` function

4. **Credential Duration Alignment:** TVM should respect `MaxServerDuration` from policy
   - **Pitfall risk:** Policy caps ignored; credentials vended for longer than allowed
   - **Prevention:** Policy evaluation must return duration cap; Lambda enforces minimum of (requested, policy_cap)

5. **Decision Logging Compatibility:** TVM should write to same JSON Lines decision log format
   - **Pitfall risk:** Audit trails fragmented; `sentinel audit session-compliance` misses TVM sessions
   - **Prevention:** Use `logging.LogDecision()` function; write to CloudWatch Logs in same format

---

## Sources

### Primary (HIGH confidence)
- [Serverless Security Risks 2026 - Qualys](https://blog.qualys.com/product-tech/2026/01/15/serverless-security-risks-identity-ssrf-rce)
- [AWS Lambda Privilege Escalation Methods](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/)
- [Lambda Cold Start Security Vulnerabilities](https://medium.com/@rizqimulkisrc/serverless-security-aws-lambda-cold-start-vulnerabilities-84461bb7b51a)
- [API Gateway Security Best Practices 2026](https://www.practical-devsecops.com/api-gateway-security-best-practices/)
- [DynamoDB Conditional Writes for Race Conditions](https://awsfundamentals.com/blog/understanding-and-handling-race-conditions-at-dynamodb)
- [Container Credential Provider - AWS Docs](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)

### Secondary (MEDIUM confidence)
- [Lambda Functions Should Not Share Admin Roles - Trend Micro](https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/Lambda/functions-dont-share-role-with-admin-privileges.html)
- [Information Leakage via Lambda Errors](https://medium.com/r3d-buck3t/vulnerable-lambda-leaks-aws-account-information-c613837377ad)
- [STS AssumeRole Security Pitfalls](https://medium.com/picus-security-engineering/isolate-your-tenant-data-on-aws-s3-via-aws-lambda-token-vending-machine-e5c7f4254ed4)
- [Zero Downtime Lambda Deployments](https://moiadev.medium.com/when-lambda-deployments-arent-zero-downtime-and-how-to-fix-it-e53e37f1c17)
- [CloudWatch Data Protection for Logs](https://aws.amazon.com/blogs/mt/handling-sensitive-log-data-using-amazon-cloudwatch/)

### Tertiary (LOW confidence - patterns observed)
- API Gateway wildcard ARN expansion issues (documented in community cheat sheets)
- EC2 credential vending controls adapted for Lambda context
- Blue/green deployment patterns adapted from API Gateway blog

### Verification Notes
- **Lambda execution role anti-patterns:** Verified across multiple security sources (Qualys, Trend Micro, AWS Security Hub)
- **API Gateway IAM bypass:** Historical vulnerabilities (2023) documented; current best practices from 2026 sources
- **STS privilege escalation:** Well-documented attack paths in offensive security resources (Hacking the Cloud, RhinoSecurity)
- **Cold start caching:** Confirmed via AWS Lambda lifecycle documentation + security research
- **DynamoDB race conditions:** AWS patterns documented; optimistic locking is standard approach
- **Container credential format:** AWS SDK reference documentation is authoritative

---

## Metadata

**Research scope:**
- Security pitfalls: Lambda execution role, API Gateway auth, STS chains, credential caching, error leakage, SCP gaps
- Integration pitfalls: Policy bypass, credential refresh, session races, format compatibility
- Operational pitfalls: Deployment downtime, logging costs, monitoring gaps, throttling

**Confidence breakdown:**
- Security pitfalls: MEDIUM-HIGH (web research from authoritative security sources, patterns verified across multiple vendors)
- Integration pitfalls: HIGH (based on Sentinel's existing architecture and AWS SDK specifications)
- Operational pitfalls: MEDIUM (AWS best practices documented, but deployment patterns vary by org)
- Sentinel integration: HIGH (based on codebase analysis of ARCHITECTURE.md and PROJECT.md)

**Research date:** 2026-01-24
**Valid until:** 2026-02-24 (30 days - security landscape evolves quickly)

**Key gaps identified:**
- No AWS-published TVM reference architecture with security hardening guide (LOW confidence for TVM-specific patterns)
- Limited documentation on SigV4 replay attack prevention mechanisms beyond timestamp validation
- No standardized testing framework for SCP enforcement validation with vended credentials

---

*Phase: Server-Side Credential Vending (Milestone v1.14)*
*Research completed: 2026-01-24*
*Ready for roadmap creation: Yes*
