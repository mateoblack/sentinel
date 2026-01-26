---
phase: 126-policy-integrity
plan: 01
subsystem: security
tags: [kms, cryptography, signing, policy, sha256]

# Dependency graph
requires:
  - phase: 121-policy-schema
    provides: Policy types and parsing
provides:
  - KMSAPI interface for policy signing/verification
  - PolicySigner with Sign/Verify methods
  - SignedPolicy and SignatureMetadata types
  - Parameter naming conventions for policies and signatures
  - ComputePolicyHash for quick integrity checks
affects: [126-02, 126-03, 127-break-glass-audit]

# Tech tracking
tech-stack:
  added: [aws-sdk-go-v2/service/kms]
  patterns: [KMS asymmetric signing, SHA-256 content hashing]

key-files:
  created: [policy/signer.go, policy/signer_test.go, policy/signature.go, policy/signature_test.go]
  modified: [testutil/mock_aws.go]

key-decisions:
  - "Use MessageType RAW (not DIGEST) for signing - KMS handles hashing internally"
  - "Return (false, nil) for invalid signatures - not an error, just validation result"
  - "KMSInvalidSignatureException handled gracefully as (false, nil)"
  - "SHA-256 hex-encoded hash stored in metadata for quick tamper detection"

patterns-established:
  - "KMSAPI interface follows secretsManagerAPI pattern from lambda/secrets.go"
  - "MockKMSClient in testutil for consistent testing"
  - "Signature parameter path mirrors policy path (/sentinel/signatures/ prefix)"

issues-created: []

# Metrics
duration: 5min
completed: 2026-01-26
---

# Phase 126 Plan 01: KMS Policy Signing Infrastructure Summary

**KMS-based policy signing with KMSAPI interface, SignedPolicy types, and SHA-256 hash validation for preventing policy cache poisoning**

## Performance

- **Duration:** 5 min
- **Started:** 2026-01-26T02:47:12Z
- **Completed:** 2026-01-26T02:52:33Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Implemented PolicySigner with KMS Sign/Verify operations using RSASSA_PSS_SHA_256
- Created SignedPolicy and SignatureMetadata types for complete signing workflow
- Established parameter naming convention (policies -> signatures path mapping)
- Added ComputePolicyHash for quick tamper detection without KMS calls
- Added MockKMSClient to testutil for consistent testing patterns

## Task Commits

Each task was committed atomically:

1. **Task 1: Create KMS signer interface and implementation** - `8446c46` (feat)
2. **Task 2: Create signature types and storage schema** - `18a8caa` (feat)

## Files Created/Modified

- `policy/signer.go` - KMSAPI interface and PolicySigner implementation
- `policy/signer_test.go` - Comprehensive tests for Sign/Verify operations
- `policy/signature.go` - SignedPolicy, SignatureMetadata types and helpers
- `policy/signature_test.go` - Tests for parameter naming and hash validation
- `testutil/mock_aws.go` - Added MockKMSClient for KMS operation mocking

## Decisions Made

1. **MessageType RAW vs DIGEST**: Use RAW so KMS handles the hashing internally. This is simpler and matches how we'll call it with policy YAML bytes directly.

2. **Invalid signature handling**: Return (false, nil) for invalid signatures rather than returning an error. Invalid signatures are a normal validation outcome, not an infrastructure failure.

3. **KMSInvalidSignatureException**: Handle gracefully by converting to (false, nil). AWS KMS throws this exception for invalid signatures, but we normalize it to our boolean return pattern.

4. **SHA-256 hash in metadata**: Store hex-encoded SHA-256 hash in SignatureMetadata.PolicyHash for quick tamper detection without calling KMS. This is an optimization, not a replacement for cryptographic verification.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - execution was straightforward.

## Next Phase Readiness

- PolicySigner ready for integration with policy loading
- SignedPolicy types ready for cache storage
- MockKMSClient available for testing signature verification flows
- Ready for 126-02: Signed policy verification in loader

---
*Phase: 126-policy-integrity*
*Completed: 2026-01-26*
