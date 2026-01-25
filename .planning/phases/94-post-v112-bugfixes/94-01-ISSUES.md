# UAT Issues: Post v1.12 Bug Fixes

## UAT-001: DynamoDB Reserved Keyword Bug (Major)

**Location:** `request/dynamodb.go:310`
**Command:** `sentinel list --status pending`

**Issue:** The `queryByIndex` function uses attribute names directly in `KeyConditionExpression` without escaping. When querying by status, it fails because `status` is a DynamoDB reserved keyword.

**Error:**
```
ValidationException: Invalid KeyConditionExpression: Attribute name is a reserved keyword; reserved keyword: status
```

**Root Cause:** Line 310 uses:
```go
KeyConditionExpression: aws.String(fmt.Sprintf("%s = :v", keyAttr))
```

When `keyAttr` is `"status"`, this produces `status = :v` which fails because `status` is reserved.

**Fix:** Use expression attribute names (`#pk` mapped to the actual attribute name) like `breakglass/dynamodb.go` does at lines 335-338.

**Acceptance Criteria:**
- [x] `sentinel list --status pending` works without error
- [x] `sentinel list --status approved` works without error
- [x] Other GSI queries (by requester, by profile) continue to work

---

## UAT-002: Missing --aws-profile on request Command (Minor)

**Commands that support --aws-profile:**
- approve, deny, list, check
- breakglass, breakglass-close, breakglass-check, breakglass-list

**Commands that DON'T support --aws-profile:**
- request

**Issue:** Users authenticating via SSO need `--aws-profile` to specify which profile's credentials to use for DynamoDB/STS calls. The `request` command lacks this flag, making it inconsistent with the approval workflow commands.

**Root Cause:** `cli/request.go` uses `--profile` for both:
1. The target profile being requested (semantic meaning)
2. The AWS credentials profile for API calls

Other commands (approve, deny, etc.) have separate flags:
- `--profile` or positional arg: the target resource
- `--aws-profile`: the AWS credentials for API calls

**Fix:** Add `--aws-profile` flag to the request command, following the pattern from approve.go. Use `--aws-profile` for AWS credential loading if specified, otherwise fall back to `--profile`.

**Acceptance Criteria:**
- [x] `sentinel request --profile prod --aws-profile sso-dev ...` works with SSO credentials
- [x] Backward compatible: `sentinel request --profile prod ...` still works (uses prod for credentials)
- [x] Help text explains when `--aws-profile` is needed

---

## UAT-003: Missing --aws-profile on credentials Command (Minor)

**Command:** `sentinel credentials`

**Issue:** Same as UAT-002 - users authenticating via SSO need `--aws-profile` to specify which profile's credentials to use for SSM/STS calls.

**Fix:** Added `--aws-profile` flag following the same pattern.

**Acceptance Criteria:**
- [x] `sentinel credentials --profile prod --aws-profile sso-dev ...` works with SSO credentials
- [x] Backward compatible

---

## UAT-004: Missing --aws-profile on breakglass Command (Minor)

**Command:** `sentinel breakglass`

**Issue:** Same as UAT-002 - users authenticating via SSO need `--aws-profile` to specify which profile's credentials to use for DynamoDB/STS calls.

**Fix:** Added `--aws-profile` flag following the same pattern.

**Acceptance Criteria:**
- [x] `sentinel breakglass --profile prod --aws-profile sso-dev ...` works with SSO credentials
- [x] Backward compatible

---

## UAT-005: Missing --aws-profile on exec Command (Minor)

**Command:** `sentinel exec`

**Issue:** Same as UAT-002 - users authenticating via SSO need `--aws-profile` to specify which profile's credentials to use for SSM/STS calls.

**Fix:** Added `--aws-profile` flag following the same pattern.

**Acceptance Criteria:**
- [x] `sentinel exec --profile prod --aws-profile sso-dev ...` works with SSO credentials
- [x] Backward compatible

---

## UAT-006: require_approval Effect Not Enforced (Critical Security)

**Commands:** `sentinel credentials`, `sentinel exec`

**Issue:** The `require_approval` policy effect is not being enforced. When a policy rule has `effect: require_approval`, the credentials/exec commands only check for approved requests when the effect is `deny`, not `require_approval`. This allows users to bypass approval requirements entirely.

**Root Cause:** Both `cli/credentials.go:237` and `cli/sentinel_exec.go:259` only check:
```go
if decision.Effect == policy.EffectDeny {
    // Check for approved request or break-glass
}
```

The `EffectRequireApproval` case falls through to credential issuance without any approval check.

**Fix:** Change the condition to:
```go
if decision.Effect == policy.EffectDeny || decision.Effect == policy.EffectRequireApproval {
```

**Acceptance Criteria:**
- [x] `require_approval` rules trigger approval check
- [x] Credentials are denied without approved request when `require_approval` is in effect
- [x] Approved requests still work to bypass `require_approval`

---

## UAT-007: Missing --request-table/--breakglass-table on credentials/exec (Major)

**Commands:** `sentinel credentials`, `sentinel exec`

**Issue:** Even after fixing UAT-006, the `require_approval` enforcement still fails because there's no way to tell `credentials` or `exec` where to look for approved requests. The `input.Store` field exists for testing but has no corresponding CLI flag.

**Fix:** Added `--request-table` and `--breakglass-table` flags to both commands. When these flags are provided, DynamoDB stores are created to enable approval workflow and break-glass checking.

**Acceptance Criteria:**
- [x] `sentinel credentials --request-table sentinel-requests ...` creates store and checks approvals
- [x] `sentinel exec --request-table sentinel-requests ...` creates store and checks approvals
- [x] `--breakglass-table` works for break-glass override checking
- [x] Backward compatible (flags are optional)

---

## Summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| UAT-001 | DynamoDB Reserved Keyword Bug | Major | Fixed |
| UAT-002 | Missing --aws-profile on request | Minor | Fixed |
| UAT-003 | Missing --aws-profile on credentials | Minor | Fixed |
| UAT-004 | Missing --aws-profile on breakglass | Minor | Fixed |
| UAT-005 | Missing --aws-profile on exec | Minor | Fixed |
| UAT-006 | require_approval Effect Not Enforced | Critical | Fixed |
| UAT-007 | Missing --request-table/--breakglass-table on credentials/exec | Major | Fixed |
