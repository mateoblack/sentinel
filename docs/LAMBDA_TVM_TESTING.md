# Lambda TVM Testing Guide

This guide covers testing the Sentinel Lambda Token Vending Machine (TVM) at all levels: unit, integration, security, and load testing.

## Overview

The Lambda TVM is a security-critical component. Comprehensive testing ensures:

- Policy enforcement cannot be bypassed
- SourceIdentity is always stamped on credentials
- Session tracking works correctly
- Approval and break-glass overrides function properly
- Performance meets target latencies

## 1. Unit Test Coverage

The `lambda/` package has extensive unit test coverage (~2,800 lines of tests).

### Running Unit Tests

```bash
# Run all lambda tests
go test ./lambda/...

# Run with verbose output
go test -v ./lambda/...

# Run with race detector (recommended for CI)
go test -race ./lambda/...

# Run specific test by name
go test -v -run TestHandleRequest_Success ./lambda/...

# Run security regression tests specifically
go test -v -run TestSecurityRegression ./lambda/...
```

### Generating Coverage Reports

```bash
# Generate coverage profile
go test -coverprofile=coverage.out ./lambda/...

# View coverage summary
go tool cover -func=coverage.out

# Generate HTML coverage report
go tool cover -html=coverage.out -o coverage.html

# Open in browser
open coverage.html
```

### Test Categories

| Test File | Coverage Area |
|-----------|---------------|
| `handler_test.go` | Handler request/response, policy evaluation, duration validation |
| `vend_test.go` | Credential vending, SourceIdentity formatting, STS calls |
| `security_test.go` | Security regression tests for bypass prevention |
| `router_test.go` | API routing and profile discovery |
| `session_test.go` | Session creation, revocation, tracking |

## 2. Integration Testing

### Local Testing with Mock API Gateway Events

The tests use mock API Gateway v2 HTTP events. You can also test locally using the handler directly:

```go
package main

import (
    "context"
    "fmt"
    "github.com/aws/aws-lambda-go/events"
    "github.com/byteness/aws-vault/v7/lambda"
)

func main() {
    // Create test request
    req := events.APIGatewayV2HTTPRequest{
        QueryStringParameters: map[string]string{
            "profile": "arn:aws:iam::123456789012:role/test-role",
        },
        RequestContext: events.APIGatewayV2HTTPRequestContext{
            Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
                IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
                    AccountID: "123456789012",
                    UserARN:   "arn:aws:iam::123456789012:user/testuser",
                    UserID:    "AIDAEXAMPLE",
                },
            },
        },
    }

    // Handle request
    handler := lambda.NewHandler()
    resp, err := handler.HandleRequest(context.Background(), req)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Status: %d\nBody: %s\n", resp.StatusCode, resp.Body)
}
```

### Testing Deployed Lambda with AWS CLI

After deployment, test the Lambda directly:

```bash
# Create test event file
cat > test-event.json << 'EOF'
{
  "queryStringParameters": {
    "profile": "arn:aws:iam::123456789012:role/SentinelProtected-Production"
  },
  "requestContext": {
    "authorizer": {
      "iam": {
        "accountId": "123456789012",
        "userArn": "arn:aws:iam::123456789012:user/testuser",
        "userId": "AIDAIOSFODNN7EXAMPLE"
      }
    }
  }
}
EOF

# Invoke Lambda directly
aws lambda invoke \
  --function-name sentinel-tvm \
  --payload file://test-event.json \
  --cli-binary-format raw-in-base64-out \
  response.json

# Check response
cat response.json | jq .
```

### Testing API Gateway Endpoint with SigV4

The API Gateway endpoint requires IAM authorization (SigV4 signing):

```bash
# Using AWS CLI (automatically signs with SigV4)
API_ENDPOINT="https://API_ID.execute-api.REGION.amazonaws.com"

# Test credential vending
aws apigatewayv2 invoke-api \
  --api-id API_ID \
  --stage '$default' \
  --body '{"profile":"production"}'

# Or use curl with AWS SigV4 signing (requires awscurl or similar)
pip install awscurl
awscurl --service execute-api \
  --region us-east-1 \
  "${API_ENDPOINT}/?profile=production"

# Or use the sentinel CLI
sentinel exec --remote-server "${API_ENDPOINT}" \
  --profile production \
  -- aws sts get-caller-identity
```

### Testing Profile Discovery Endpoint

```bash
# List available profiles
awscurl --service execute-api \
  --region us-east-1 \
  "${API_ENDPOINT}/profiles"

# Expected response:
# {
#   "profiles": [
#     {"name": "dev", "policy_path": "/sentinel/policies/dev"},
#     {"name": "production", "policy_path": "/sentinel/policies/production"}
#   ],
#   "root": "/sentinel/policies"
# }
```

## 3. Security Testing Checklist

Before production deployment, verify each security control:

### Direct AssumeRole Blocked by SCP

```bash
# This should FAIL with AccessDenied (SCP blocks direct access)
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/SentinelProtected-Production \
  --role-session-name test-direct \
  2>&1 | grep -E "(AccessDenied|Explicit Deny)"

# Expected: An error occurred (AccessDenied)
```

### TVM Can Assume Protected Roles

```bash
# This should SUCCEED (TVM is allowed by SCP and trust policy)
awscurl --service execute-api \
  "${API_ENDPOINT}/?profile=production"

# Expected: JSON with AccessKeyId, SecretAccessKey, Token, Expiration
```

### Policy Deny Returns 403

```bash
# Test with a policy that denies your user
# Modify the Sentinel policy to deny your user, then:
awscurl --service execute-api \
  "${API_ENDPOINT}/?profile=production"

# Expected: HTTP 403 with {"Code":"POLICY_DENY","Message":"Policy denied: ..."}
```

### Invalid Duration Returns 400

```bash
# Duration too short (< 900 seconds)
awscurl --service execute-api \
  "${API_ENDPOINT}/?profile=production&duration=600"

# Expected: HTTP 400 with {"Code":"INVALID_DURATION",...}

# Duration too long (> 43200 seconds)
awscurl --service execute-api \
  "${API_ENDPOINT}/?profile=production&duration=50000"

# Expected: HTTP 400 with {"Code":"INVALID_DURATION",...}
```

### Session Revocation Blocks Credentials

```bash
# 1. Get credentials and note the session ID
awscurl --service execute-api \
  "${API_ENDPOINT}/?profile=production" | jq .

# 2. Revoke the session in DynamoDB
aws dynamodb update-item \
  --table-name sentinel-sessions \
  --key '{"id":{"S":"SESSION_ID_HERE"}}' \
  --update-expression "SET #s = :revoked" \
  --expression-attribute-names '{"#s":"status"}' \
  --expression-attribute-values '{":revoked":{"S":"revoked"}}'

# 3. Try to get new credentials (same session)
awscurl --service execute-api \
  "${API_ENDPOINT}/?profile=production"

# Expected: HTTP 403 with {"Code":"SESSION_REVOKED",...}
```

### SourceIdentity Present in CloudTrail

```bash
# After successful credential vending, check CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --max-results 5 | \
  jq '.Events[].CloudTrailEvent | fromjson | select(.sourceIdentity != null) | {sourceIdentity, eventTime}'

# Expected: sourceIdentity starts with "sentinel:"
```

## 4. Load Testing

### Target Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| P99 Latency | < 200ms | Cold starts excluded |
| P50 Latency | < 50ms | Warm Lambda |
| Error Rate | < 0.1% | Excluding policy denies |
| Throughput | Auto-scales | Lambda handles concurrency |

### Lambda Power Tuning

Use AWS Lambda Power Tuning to find optimal memory size:

```bash
# Deploy power tuning state machine (one-time setup)
aws cloudformation create-stack \
  --stack-name lambda-power-tuning \
  --template-url https://s3.amazonaws.com/aws-lambda-power-tuning/latest/lambda-power-tuning.yaml \
  --capabilities CAPABILITY_IAM

# Run power tuning
aws stepfunctions start-execution \
  --state-machine-arn "arn:aws:states:REGION:ACCOUNT:stateMachine:powerTuningStateMachine" \
  --input '{
    "lambdaARN": "arn:aws:lambda:REGION:ACCOUNT:function:sentinel-tvm",
    "powerValues": [128, 256, 512, 1024, 2048],
    "num": 50,
    "payload": "{\"queryStringParameters\":{\"profile\":\"production\"},\"requestContext\":{\"authorizer\":{\"iam\":{\"accountId\":\"123456789012\",\"userArn\":\"arn:aws:iam::123456789012:user/testuser\",\"userId\":\"AIDAEXAMPLE\"}}}}"
  }'
```

### Load Testing with Artillery

Create `artillery-config.yml`:

```yaml
config:
  target: "https://API_ID.execute-api.REGION.amazonaws.com"
  phases:
    - duration: 60
      arrivalRate: 10
      name: Warm up
    - duration: 120
      arrivalRate: 50
      name: Sustained load
    - duration: 60
      arrivalRate: 100
      name: Peak load
  plugins:
    expect: {}
  processor: "./artillery-processor.js"

scenarios:
  - name: "Credential Vending"
    flow:
      - function: "signRequest"
      - get:
          url: "/?profile=production"
          expect:
            - statusCode: 200
            - contentType: application/json
```

Create `artillery-processor.js`:

```javascript
const AWS = require('aws-sdk');
const aws4 = require('aws4');

module.exports = {
  signRequest: function(requestParams, ctx, ee, next) {
    const credentials = AWS.config.credentials;
    const opts = {
      host: new URL(ctx.vars.target).host,
      path: '/?profile=production',
      service: 'execute-api',
      region: 'us-east-1',
    };
    aws4.sign(opts, {
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey,
      sessionToken: credentials.sessionToken,
    });
    requestParams.headers = opts.headers;
    return next();
  }
};
```

Run the load test:

```bash
# Install dependencies
npm install artillery aws-sdk aws4

# Run load test
artillery run artillery-config.yml

# Generate HTML report
artillery run --output report.json artillery-config.yml
artillery report report.json
```

### Load Testing with k6

Create `k6-test.js`:

```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';
import { AWSConfig, SignatureV4 } from 'k6/x/aws';

export const options = {
  stages: [
    { duration: '1m', target: 10 },   // Warm up
    { duration: '2m', target: 50 },   // Sustained load
    { duration: '1m', target: 100 },  // Peak load
    { duration: '1m', target: 0 },    // Cool down
  ],
  thresholds: {
    http_req_duration: ['p(99)<200'], // 99% of requests under 200ms
    http_req_failed: ['rate<0.01'],   // Error rate under 1%
  },
};

const awsConfig = new AWSConfig({
  region: 'us-east-1',
  accessKeyId: __ENV.AWS_ACCESS_KEY_ID,
  secretAccessKey: __ENV.AWS_SECRET_ACCESS_KEY,
  sessionToken: __ENV.AWS_SESSION_TOKEN,
});

const signer = new SignatureV4({
  service: 'execute-api',
  region: awsConfig.region,
  credentials: awsConfig.credentials,
});

export default function () {
  const url = 'https://API_ID.execute-api.us-east-1.amazonaws.com/?profile=production';
  const signedRequest = signer.sign({
    method: 'GET',
    url: url,
  });

  const res = http.get(url, { headers: signedRequest.headers });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has AccessKeyId': (r) => JSON.parse(r.body).AccessKeyId !== undefined,
  });

  sleep(0.1);
}
```

Run with k6:

```bash
k6 run k6-test.js
```

### Monitoring During Load Tests

Watch these CloudWatch metrics:

```bash
# Create dashboard command
aws cloudwatch put-dashboard \
  --dashboard-name "TVM-LoadTest" \
  --dashboard-body '{
    "widgets": [
      {
        "type": "metric",
        "properties": {
          "metrics": [
            ["AWS/Lambda", "Duration", "FunctionName", "sentinel-tvm", {"stat": "p99"}],
            ["AWS/Lambda", "Duration", "FunctionName", "sentinel-tvm", {"stat": "p50"}]
          ],
          "title": "Lambda Duration"
        }
      },
      {
        "type": "metric",
        "properties": {
          "metrics": [
            ["AWS/Lambda", "ConcurrentExecutions", "FunctionName", "sentinel-tvm"],
            ["AWS/Lambda", "Invocations", "FunctionName", "sentinel-tvm"]
          ],
          "title": "Concurrency & Invocations"
        }
      },
      {
        "type": "metric",
        "properties": {
          "metrics": [
            ["AWS/Lambda", "Errors", "FunctionName", "sentinel-tvm"]
          ],
          "title": "Errors"
        }
      }
    ]
  }'
```

## 5. Troubleshooting Common Issues

### "POLICY_DENY" Error

**Symptom:** HTTP 403 with `{"Code":"POLICY_DENY","Message":"Policy denied: ..."}`

**Diagnosis:**
```bash
# Check the policy in SSM
aws ssm get-parameter \
  --name /sentinel/policies/production \
  --with-decryption | jq -r '.Parameter.Value'

# Verify your user matches policy rules
sentinel credentials --profile production --verbose
```

**Common causes:**
- User not in allowed list
- Time outside allowed hours
- Missing required labels

### "CREDENTIAL_ERROR" Error

**Symptom:** HTTP 500 with `{"Code":"CREDENTIAL_ERROR","Message":"Failed to vend credentials"}`

**Diagnosis:**
```bash
# Check Lambda logs
aws logs tail /aws/lambda/sentinel-tvm --since 10m

# Verify trust policy on protected role
aws iam get-role --role-name SentinelProtected-Production | jq '.Role.AssumeRolePolicyDocument'

# Verify Lambda execution role has permission
aws iam list-role-policies --role-name SentinelTVMExecutionRole
```

**Common causes:**
- Protected role doesn't trust Lambda execution role
- Lambda execution role can't assume protected role
- Missing SourceIdentity condition in trust policy

### Cold Start Latency

**Symptom:** First request after idle period takes >500ms

**Solution:** Use Provisioned Concurrency:
```bash
# Enable provisioned concurrency
aws lambda put-provisioned-concurrency-config \
  --function-name sentinel-tvm \
  --qualifier '$LATEST' \
  --provisioned-concurrent-executions 5

# Alternatively, use Application Auto Scaling
aws application-autoscaling register-scalable-target \
  --service-namespace lambda \
  --resource-id "function:sentinel-tvm:$LATEST" \
  --scalable-dimension lambda:function:ProvisionedConcurrency \
  --min-capacity 1 \
  --max-capacity 100
```

### Session Table Not Found

**Symptom:** Error creating/looking up sessions

**Diagnosis:**
```bash
# Check environment variable
aws lambda get-function-configuration \
  --function-name sentinel-tvm | \
  jq '.Environment.Variables.SENTINEL_SESSION_TABLE'

# Verify table exists
aws dynamodb describe-table --table-name sentinel-sessions

# Check Lambda has DynamoDB permissions
aws iam list-attached-role-policies \
  --role-name SentinelTVMExecutionRole
```

### "IAM_AUTH_REQUIRED" Error

**Symptom:** HTTP 403 with `{"Code":"IAM_AUTH_REQUIRED",...}`

**Diagnosis:**
- Request not signed with SigV4
- API Gateway IAM authorization not configured

**Solution:**
```bash
# Verify API Gateway route has IAM auth
aws apigatewayv2 get-route \
  --api-id API_ID \
  --route-id ROUTE_ID | jq '.AuthorizationType'

# Should return "AWS_IAM"
```

## See Also

- [LAMBDA_TVM_DEPLOYMENT.md](LAMBDA_TVM_DEPLOYMENT.md) - Full deployment guide
- [LAMBDA_TVM_SCP.md](LAMBDA_TVM_SCP.md) - SCP enforcement patterns
- [LAMBDA_TVM_COST.md](LAMBDA_TVM_COST.md) - Cost optimization guide
