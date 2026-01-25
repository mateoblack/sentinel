# Planning Constraints

These constraints apply to all planning and execution agents. Violating these constraints should block the plan.

---

## Device Posture: Server-Verified Only

**DO NOT implement local-only device posture checks.**

Local checks (FileVault status, OS version, firewall state collected by CLI) can be bypassed by modifying the binary. This creates a false sense of security.

### Required Approach

- Lambda TVM queries MDM/EDR APIs directly (server-side verification)
- CLI sends device identifier only, NOT posture claims
- TVM validates device state against Jamf/Intune/CrowdStrike/etc.
- Clients cannot fake compliance — server is source of truth

### Reject Plans That

- Collect posture locally and send claims to server
- Trust CLI-reported encryption/firewall/OS status
- Implement "local checks" as a foundation to build on
- Create `LocalCollector` or similar client-side posture gathering

### Accept Plans That

- Add MDM API integration to Lambda TVM
- Query device compliance server-side before issuing credentials
- Use hardware attestation (TPM/Secure Enclave) for device identity
- Implement device fingerprinting (ID only, not posture claims)

### Rationale

> "Local checks can be bypassed by a determined attacker with code access. Server-verified posture through MDM/EDR APIs is tamper-proof. Do it right or don't do it."

---

## General Constraints

### Security First

- Never trust client-provided claims for security decisions
- All enforcement happens server-side (Lambda TVM)
- Fail closed — deny access on verification failure

### Test Coverage

- New features require tests before merge
- Security-critical paths require regression tests
- Mock external dependencies in tests

---

*Last updated: 2026-01-25*
