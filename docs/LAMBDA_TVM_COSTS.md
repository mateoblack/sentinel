# Lambda TVM Cost Optimization Guide

Cost guidance for production deployments of the Sentinel Lambda Token Vending Machine.

## Overview

The Lambda TVM incurs costs from four AWS services:

| Service | Pricing Component | Notes |
|---------|------------------|-------|
| Lambda | Requests + Duration | Per-request and compute time |
| API Gateway | HTTP API requests | $1.00 per million |
| DynamoDB | Read/Write capacity | On-demand or provisioned |
| CloudWatch | Log ingestion + storage | Decision audit trail |

## Cost Breakdown

### Lambda

- **Requests:** $0.20 per 1 million requests
- **Duration:** $0.0000166667 per GB-second (x86_64)
- **ARM64 (Graviton2):** $0.0000133334 per GB-second (20% cheaper)

Typical TVM invocation at 256MB for 100ms = $0.000000417 per request.

### API Gateway HTTP API

- **Requests:** $1.00 per 1 million requests
- Much cheaper than REST API ($3.50 per million)

### DynamoDB (On-Demand)

- **Write:** $1.25 per million Write Capacity Units (WCU)
- **Read:** $0.25 per million Read Capacity Units (RCU)
- **Storage:** $0.25 per GB/month

Each credential request with session tracking: ~2 WCU + 1 RCU.

### CloudWatch Logs

- **Ingestion:** $0.50 per GB
- **Storage:** $0.03 per GB/month
- Each decision log entry: ~500 bytes

## Volume Patterns

### Low Volume (<100K requests/month)

**Estimated cost:** <$5/month

| Component | Cost |
|-----------|------|
| Lambda (100K @ 256MB, 100ms) | $0.02 |
| API Gateway | $0.10 |
| DynamoDB (on-demand) | $0.30 |
| CloudWatch Logs (50MB) | $0.03 |
| **Total** | **~$0.50** |

**Configuration:**
- Default Lambda settings (256MB memory)
- On-demand DynamoDB capacity
- Standard log retention (30 days)

**Use cases:** Small teams, development environments, POC deployments.

### Medium Volume (100K-1M requests/month)

**Estimated cost:** $5-50/month

| Component | Monthly Cost |
|-----------|-------------|
| Lambda (1M @ 256MB, 100ms) | $0.42 |
| API Gateway | $1.00 |
| DynamoDB (on-demand) | $3.00 |
| CloudWatch Logs (500MB) | $0.25 |
| **Total** | **~$5** |

**Configuration:**
- Default Lambda settings
- On-demand DynamoDB (acceptable for variable traffic)
- Consider 7-day log retention for cost savings

**Use cases:** Mid-size organizations, staging environments.

### High Volume (>1M requests/month)

**Estimated cost:** $50-500/month depending on volume

At 10M requests/month:

| Component | Monthly Cost |
|-----------|-------------|
| Lambda (10M @ 256MB, 100ms) | $4.17 |
| API Gateway | $10.00 |
| DynamoDB (provisioned) | $15.00 |
| CloudWatch Logs (5GB) | $2.50 |
| **Total** | **~$32** |

**Configuration:**
- Consider provisioned concurrency for latency-sensitive workloads
- Provisioned DynamoDB capacity (25% cheaper than on-demand)
- Use ARM64 architecture for 20% Lambda cost reduction
- Aggressive log retention (7 days) or export to S3

**Use cases:** Large enterprises, production workloads.

## Optimization Tips

### 1. Use ARM64 Architecture (Graviton2)

~20% cost reduction on Lambda compute:

```hcl
module "sentinel_tvm" {
  source = "./terraform/sentinel-tvm"

  architecture = "arm64"  # Default is x86_64
  # ...
}
```

### 2. Right-Size Lambda Memory

256MB is sufficient for most workloads. Higher memory may reduce duration but increases per-second cost.

Test with different memory settings:
- 128MB: Minimum viable, may increase duration
- 256MB: Recommended default
- 512MB: For complex policies or high-concurrency

### 3. Enable API Gateway Caching

Cache `/profiles` endpoint responses:

```bash
aws apigatewayv2 update-route \
  --api-id $API_ID \
  --route-id $ROUTE_ID \
  --operation-name GetProfiles
```

Note: Caching not recommended for credential vending endpoint (security).

### 4. DynamoDB Capacity Modes

**On-demand:** Best for unpredictable traffic
- No capacity planning required
- Pay per request
- Scales automatically

**Provisioned:** 25% cheaper for predictable workloads
- Requires capacity planning
- Set WCU/RCU based on expected traffic
- Enable auto-scaling for variable loads

### 5. CloudWatch Log Optimization

- Set retention policy (7 days for dev, 30 days for prod)
- Export to S3 for long-term retention at lower cost
- Use log insights queries sparingly (billed per GB scanned)

### 6. Lambda Reserved Concurrency

Free to configure, prevents runaway scaling:

```hcl
resource "aws_lambda_function" "tvm" {
  reserved_concurrent_executions = 100  # Max concurrent
}
```

## Provisioned Concurrency

Eliminates cold starts but adds fixed cost.

**Cost:** ~$0.015 per provisioned GB-hour

**Example: 2 instances at 256MB**

```
2 instances × 0.256 GB × 730 hours/month × $0.015 = $5.50/month
```

**When to use:**
- Consistent low-latency requirements (<50ms p99)
- Cold start sensitivity in credential flows
- High-frequency automated callers

**When to skip:**
- Variable traffic patterns
- Cost-sensitive deployments
- Acceptable cold start latency (100-300ms)

## DynamoDB Capacity Planning

### On-Demand (Recommended for Variable Traffic)

No planning required. Cost scales with usage.

### Provisioned (For Predictable Workloads)

Calculate based on expected requests:

| Requests/sec | WCU (sessions) | RCU (sessions) | Monthly Cost |
|--------------|----------------|----------------|--------------|
| 1 | 3 | 2 | $2.50 |
| 10 | 30 | 20 | $25.00 |
| 100 | 300 | 200 | $250.00 |

Enable auto-scaling for burst handling:

```hcl
resource "aws_appautoscaling_target" "sessions_read" {
  max_capacity       = 1000
  min_capacity       = 5
  resource_id        = "table/sentinel-sessions"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}
```

## Quick Reference

| Traffic | Architecture | DynamoDB | Est. Monthly Cost |
|---------|--------------|----------|-------------------|
| <100K | x86_64 | On-demand | <$1 |
| <100K | ARM64 | On-demand | <$1 |
| 100K-1M | x86_64 | On-demand | $5-15 |
| 100K-1M | ARM64 | On-demand | $4-12 |
| 1M-10M | ARM64 | Provisioned | $30-150 |
| >10M | ARM64 + Provisioned Concurrency | Provisioned | $100-500 |

## Cost Monitoring

Set up CloudWatch alarms:

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name sentinel-tvm-high-cost \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 86400 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold
```

Use AWS Cost Explorer tags to track TVM costs separately:

```hcl
tags = {
  Application = "sentinel-tvm"
  CostCenter  = "security"
}
```
