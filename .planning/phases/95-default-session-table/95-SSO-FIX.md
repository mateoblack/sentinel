---
phase: 95-default-session-table
plan: SSO-FIX
type: fix
wave: 1
depends_on: []
files_modified: [cli/sentinel_exec.go, cli/sentinel_exec_test.go]
autonomous: true
---

<objective>
Fix server mode SSO credential profile resolution - adapter loses --aws-profile context.

**Bug Description:**
The `sentinelCredentialProviderAdapter` only stores the `Sentinel` struct but doesn't capture `input.AWSProfile`. When the server calls `GetCredentialsWithSourceIdentity`, it passes `req.ProfileName` (the policy target profile) for credential retrieval, but should use the SSO credential profile (`--aws-profile`).

**Impact:**
- User runs: `sentinel exec --aws-profile sso-dev --profile prod-policy --server -- aws s3 ls`
- Non-server mode: Uses `sso-dev` for credentials → works
- Server mode: Adapter uses `prod-policy` for credentials → fails (wrong profile for SSO login)

**Root Cause:**
Line 364 in cli/sentinel_exec.go:
```go
credProvider := &sentinelCredentialProviderAdapter{sentinel: s}
// Missing: credentialProfile not captured!
```

Purpose: Ensure --aws-profile flag is respected in server mode for SSO credential resolution.
Output: Fixed credential adapter with proper profile propagation.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md

@cli/sentinel_exec.go
@cli/sentinel_provider.go
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add credentialProfile field to sentinelCredentialProviderAdapter</name>
  <files>cli/sentinel_exec.go</files>
  <action>
  Modify the adapter to capture and use the credential profile.

  1. Update the struct definition (around line 506):
  ```go
  type sentinelCredentialProviderAdapter struct {
      sentinel          *Sentinel
      credentialProfile string  // SSO credential profile (from --aws-profile)
  }
  ```

  2. Update GetCredentialsWithSourceIdentity method (around line 511) to use credentialProfile:
  ```go
  func (a *sentinelCredentialProviderAdapter) GetCredentialsWithSourceIdentity(ctx context.Context, req sentinel.CredentialRequest) (*sentinel.CredentialResult, error) {
      // Use credentialProfile for credential retrieval, not req.ProfileName
      // req.ProfileName is the policy target, credentialProfile is the SSO source
      profileForCredentials := a.credentialProfile
      if profileForCredentials == "" {
          profileForCredentials = req.ProfileName
      }

      cliReq := SentinelCredentialRequest{
          ProfileName:     profileForCredentials,  // Use credential profile, not policy profile
          NoSession:       req.NoSession,
          SessionDuration: req.SessionDuration,
          Region:          req.Region,
          User:            req.User,
          RequestID:       req.RequestID,
          ApprovalID:      req.ApprovalID,
      }
      // ... rest unchanged
  }
  ```

  3. Update adapter construction (around line 364) to pass credentialProfile:
  ```go
  credProvider := &sentinelCredentialProviderAdapter{
      sentinel:          s,
      credentialProfile: credentialProfile,  // Pass the SSO credential profile
  }
  ```

  Note: `credentialProfile` is already computed on lines 186-189:
  ```go
  credentialProfile := input.AWSProfile
  if credentialProfile == "" {
      credentialProfile = input.ProfileName
  }
  ```
  </action>
  <verify>go build ./cli/... succeeds without errors</verify>
  <done>Adapter captures credentialProfile and uses it for credential retrieval</done>
</task>

<task type="auto">
  <name>Task 2: Add test for SSO profile in server mode</name>
  <files>cli/sentinel_exec_test.go</files>
  <action>
  Add test verifying that --aws-profile is properly used in server mode.

  Add test case in the appropriate test section:

  ```go
  t.Run("server mode uses credentialProfile from AWSProfile", func(t *testing.T) {
      // Verify adapter receives and uses the credential profile
      input := SentinelExecCommandInput{
          ProfileName:  "policy-target",    // Policy evaluation target
          AWSProfile:   "sso-credentials",  // SSO credential source
          StartServer:  true,
      }

      // Verify AWSProfile is distinct from ProfileName
      if input.AWSProfile == input.ProfileName {
          t.Error("Test setup error: AWSProfile should differ from ProfileName")
      }

      // Verify credentialProfile logic (from lines 186-189)
      credentialProfile := input.AWSProfile
      if credentialProfile == "" {
          credentialProfile = input.ProfileName
      }

      if credentialProfile != "sso-credentials" {
          t.Errorf("expected credentialProfile 'sso-credentials', got %q", credentialProfile)
      }
  })

  t.Run("server mode falls back to ProfileName when AWSProfile empty", func(t *testing.T) {
      input := SentinelExecCommandInput{
          ProfileName:  "my-profile",
          AWSProfile:   "",  // Not specified
          StartServer:  true,
      }

      credentialProfile := input.AWSProfile
      if credentialProfile == "" {
          credentialProfile = input.ProfileName
      }

      if credentialProfile != "my-profile" {
          t.Errorf("expected credentialProfile 'my-profile', got %q", credentialProfile)
      }
  })
  ```

  Add test for adapter field verification:

  ```go
  t.Run("sentinelCredentialProviderAdapter stores credentialProfile", func(t *testing.T) {
      adapter := &sentinelCredentialProviderAdapter{
          sentinel:          nil,  // Mock not needed for this test
          credentialProfile: "sso-profile",
      }

      if adapter.credentialProfile != "sso-profile" {
          t.Errorf("expected credentialProfile 'sso-profile', got %q", adapter.credentialProfile)
      }
  })
  ```
  </action>
  <verify>go test ./cli/... -run "server.*credential.*profile|sentinelCredentialProviderAdapter" -v passes</verify>
  <done>Tests verify SSO profile propagation to server mode adapter</done>
</task>

</tasks>

<verification>
Before declaring plan complete:
- [ ] go build ./... succeeds without errors
- [ ] go test ./cli/... -v passes
- [ ] go vet ./... reports no issues
</verification>

<success_criteria>
- sentinelCredentialProviderAdapter has credentialProfile field
- Adapter uses credentialProfile (not req.ProfileName) for credential retrieval
- Tests verify SSO profile propagation
- Server mode respects --aws-profile for SSO credentials
</success_criteria>

<output>
After completion, create `.planning/phases/95-default-session-table/95-SSO-FIX-SUMMARY.md`
</output>
