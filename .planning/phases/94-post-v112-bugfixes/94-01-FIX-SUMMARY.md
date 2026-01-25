# Fix Summary: 94-01-FIX

## Status: Complete

## Issues Fixed

| ID | Issue | Severity |
|----|-------|----------|
| UAT-001 | DynamoDB Reserved Keyword Bug | Major |
| UAT-002 | Missing --aws-profile on request | Minor |
| UAT-003 | Missing --aws-profile on credentials | Minor |
| UAT-004 | Missing --aws-profile on breakglass | Minor |
| UAT-005 | Missing --aws-profile on exec | Minor |
| UAT-006 | require_approval Effect Not Enforced | Critical |
| UAT-007 | Missing --request-table/--breakglass-table | Major |

---

### UAT-001: DynamoDB Reserved Keyword Bug (Major)
**File:** `request/dynamodb.go`

**Problem:** The `queryByIndex` function used attribute names directly in `KeyConditionExpression`. When querying by status (`sentinel list --status pending`), it failed because `status` is a DynamoDB reserved keyword.

**Error:**
```
ValidationException: Invalid KeyConditionExpression: Attribute name is a reserved keyword; reserved keyword: status
```

**Fix:** Updated `queryByIndex` to use expression attribute names (`#pk` placeholder) that DynamoDB substitutes with the actual attribute name:

```go
// Use expression attribute names for reserved words (e.g., "status")
keyCondition := "#pk = :v"
exprAttrNames := map[string]string{
    "#pk": keyAttr,
}

output, err := s.client.Query(ctx, &dynamodb.QueryInput{
    // ...
    KeyConditionExpression:   aws.String(keyCondition),
    ExpressionAttributeNames: exprAttrNames,
    // ...
})
```

This pattern matches `breakglass/dynamodb.go` lines 334-338.

---

### UAT-002: Missing --aws-profile on request Command (Minor)
**File:** `cli/request.go`

**Problem:** Users authenticating via SSO need `--aws-profile` to specify which profile's credentials to use for DynamoDB/STS calls. The `request` command lacked this flag, making it inconsistent with other approval workflow commands (approve, deny, list, check, breakglass-*).

**Fix:** Added `--aws-profile` flag following the pattern from `cli/approve.go`:

1. Added `AWSProfile` field to `RequestCommandInput` struct
2. Added `--aws-profile` flag in `ConfigureRequestCommand`
3. Updated `RequestCommand` to use `AWSProfile` for credential loading if specified, otherwise fall back to `--profile`

```go
// Use --aws-profile for credentials if specified, otherwise use --profile
credentialProfile := input.AWSProfile
if credentialProfile == "" {
    credentialProfile = input.ProfileName
}
awsCfgOpts := []func(*config.LoadOptions) error{
    config.WithSharedConfigProfile(credentialProfile),
}
```

---

### UAT-003, UAT-004, UAT-005: Missing --aws-profile on other commands (Minor)

**Files:** `cli/credentials.go`, `cli/breakglass.go`, `cli/sentinel_exec.go`

**Problem:** Discovered during testing that additional commands were also missing the `--aws-profile` flag, creating the same SSO user issue as UAT-002.

**Fix:** Applied identical pattern to all three commands:
1. Added `AWSProfile` field to input struct
2. Added `--aws-profile` flag in Configure function
3. Updated AWS config loading to use `AWSProfile` if specified

---

### UAT-006: require_approval Effect Not Enforced (Critical Security)
**Files:** `cli/credentials.go`, `cli/sentinel_exec.go`

**Problem:** The `require_approval` policy effect was not being enforced. Both commands only checked for approved requests when `decision.Effect == policy.EffectDeny`, allowing `require_approval` to fall through to credential issuance without any check.

**Fix:** Changed the condition from:
```go
if decision.Effect == policy.EffectDeny {
```
to:
```go
if decision.Effect == policy.EffectDeny || decision.Effect == policy.EffectRequireApproval {
```

This ensures that both `deny` and `require_approval` effects trigger the approval/break-glass check before issuing credentials.

---

### UAT-007: Missing --request-table/--breakglass-table (Major)
**Files:** `cli/credentials.go`, `cli/sentinel_exec.go`

**Problem:** Even with UAT-006 fixed, approval checking couldn't work because there was no way to specify the DynamoDB table names. The `Store` and `BreakGlassStore` fields were only populated via test injection.

**Fix:** Added `--request-table` and `--breakglass-table` CLI flags to both commands. When provided, DynamoDB stores are created:

```go
// 3.5. Create approval stores if configured (and not injected for testing)
if input.Store == nil && input.RequestTable != "" {
    input.Store = request.NewDynamoDBStore(awsCfg, input.RequestTable)
}
if input.BreakGlassStore == nil && input.BreakGlassTable != "" {
    input.BreakGlassStore = breakglass.NewDynamoDBStore(awsCfg, input.BreakGlassTable)
}
```

---

## Files Modified

| File | Change |
|------|--------|
| `request/dynamodb.go` | Added ExpressionAttributeNames to queryByIndex |
| `cli/request.go` | Added --aws-profile flag |
| `cli/credentials.go` | Added --aws-profile, --request-table, --breakglass-table; Fixed require_approval |
| `cli/breakglass.go` | Added --aws-profile flag |
| `cli/sentinel_exec.go` | Added --aws-profile, --request-table, --breakglass-table; Fixed require_approval |

## Verification

- [x] `gofmt -e` passes on all modified files
- [x] No syntax errors introduced
- [x] queryByIndex uses ExpressionAttributeNames pattern
- [x] All commands with dual profile usage now have --aws-profile flag

## Backward Compatibility

All fixes maintain full backward compatibility:
- UAT-001: No API changes, just internal DynamoDB query format
- UAT-002 to UAT-005: `--aws-profile` is optional; defaults to `--profile` if not specified
