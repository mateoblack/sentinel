# UAT Issues: Phase 88 Plan 03

**Tested:** 2026-01-22
**Source:** .planning/phases/88-approval-table-provisioning/88-03-SUMMARY.md
**Tester:** User via /gsd:verify-work

## Open Issues

### UAT-001: --plan flag requires DynamoDB permissions (should be dry-run)

**Discovered:** 2026-01-22
**Phase/Plan:** 88-03, 89-02, 90-02
**Severity:** Major
**Feature:** All init table commands --plan flag
**Description:** Running any `sentinel init {approvals|breakglass|sessions} --plan` command fails with "Access denied to DynamoDB table" error. The --plan flag is meant to show a dry-run preview of what would be created, but it's attempting to access DynamoDB.
**Expected:** --plan should display the table schema that would be created without requiring any DynamoDB permissions. Users need to see the plan BEFORE they have permissions set up.
**Actual:** All three commands fail with access denied error:
- `sentinel init approvals --plan` → "Access denied to DynamoDB table: sentinel-requests"
- `sentinel init breakglass --plan` → "Access denied to DynamoDB table: sentinel-breakglass"
- `sentinel init sessions --plan` → "Access denied to DynamoDB table: sentinel-sessions"
**Repro:**
1. Use an AWS profile without DynamoDB permissions
2. Run `sentinel init approvals --plan --region us-east-1 --aws-profile <profile>`
3. Observe access denied error
4. Same for breakglass and sessions

**Impact:** Users cannot preview infrastructure before setting up IAM permissions, which defeats the purpose of the --plan flag for onboarding.

**Root Cause (likely):** The `Plan()` method in `infrastructure/provisioner.go` calls `TableStatus()` which queries DynamoDB to check if the table exists. For a true dry-run, it should skip this check or handle access denied gracefully.

### UAT-002: init status --check-tables crashes on access denied instead of graceful handling

**Discovered:** 2026-01-22
**Phase/Plan:** 92-01
**Severity:** Major
**Feature:** Enhanced init status with --check-tables
**Description:** Running `sentinel init status --aws-profile dev --region us-east-1 --check-tables` fails completely with AccessDeniedException when the user lacks DynamoDB permissions.
**Expected:** The status command should gracefully handle access denied errors and display table status as "ACCESS_DENIED" or "UNKNOWN", still showing other information (SSM policies, suggestions).
**Actual:** Command fails entirely with raw AWS error message, providing no useful output.
**Repro:**
1. Use an AWS profile without DynamoDB DescribeTable permission
2. Run `sentinel init status --aws-profile dev --region us-east-1 --check-tables`
3. Command crashes with AccessDeniedException

**Impact:** Users cannot use status command to understand their setup state if they lack DynamoDB permissions - exactly when they need guidance most.

---

### UAT-003: --generate-iam-policies doesn't include DynamoDB policies with --with-* flags

**Discovered:** 2026-01-22
**Phase/Plan:** 91-02
**Severity:** Major
**Feature:** Combined IAM policy generation in unified bootstrap
**Description:** Running `sentinel init bootstrap --profile dev --with-approvals --generate-iam-policies --region us-east-1` only outputs SSM IAM policies (SentinelPolicyReader, SentinelPolicyAdmin). The DynamoDB table permissions are missing despite `--with-approvals` being specified.
**Expected:** When `--with-approvals` (or other `--with-*` flags) is combined with `--generate-iam-policies`, the output should include BOTH:
- SSM policies (SentinelPolicyReader, SentinelPolicyAdmin)
- DynamoDB policies (SentinelApprovalTableProvisioning, SentinelApprovalTableOperations)
**Actual:** Only SSM policies are shown. DynamoDB policies are completely absent.
**Repro:**
1. Run `sentinel init bootstrap --profile dev --with-approvals --generate-iam-policies --region us-east-1`
2. Observe output only shows SSM-related IAM policies
3. No DynamoDB table permissions included

**Workaround:** Use `sentinel init approvals --generate-iam --region us-east-1` separately to get DynamoDB IAM policies.

**Impact:** Users cannot get a complete IAM policy from a single command when setting up combined infrastructure.

**Note:** The output does show a Bootstrap Plan with "Do you want to apply these changes?" prompt - this suggests `--generate-iam-policies` may not be working as a standalone info flag but is mixed with plan mode.

## Resolved Issues

[None yet]

---

*Phase: 88-approval-table-provisioning*
*Plan: 03*
*Tested: 2026-01-22*
