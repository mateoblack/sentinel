# Requirements: Sentinel v2.0 Stable Release

**Defined:** 2026-01-27
**Core Value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.

## v2.0 Requirements

Stabilization requirements for production-ready release. Focus on testing, security hardening, and documentation completeness.

### Test Fixes & Coverage

- [ ] **TEST-01**: All existing test failures resolved (security, server, request packages)
- [ ] **TEST-02**: Test coverage targets met (security 80%, policy 90%, identity 85%)
- [ ] **TEST-03**: Race detector passes on full test suite
- [ ] **TEST-04**: Security regression tests cover 100% of STRIDE findings
- [ ] **TEST-05**: Integration tests exercise all CLI commands

### Device Posture

- [ ] **INTUNE-01**: Intune MDM provider implementation with Microsoft Graph API
- [ ] **INTUNE-02**: OAuth2 authentication with Azure AD
- [ ] **INTUNE-03**: Compliance status mapping to MDMDeviceInfo
- [ ] **INTUNE-04**: Rate limiting and pagination handling for Graph API
- [ ] **INTUNE-05**: Integration tests with mock Graph API responses

### Security Hardening

- [ ] **SEC-01**: SSM backup feature deprecated or encrypted with KMS
- [ ] **SEC-02**: SCP deployment command removed (replaced with template output)
- [ ] **SEC-03**: File permissions audited (0700 dirs, 0600 files)
- [ ] **SEC-04**: Input validation fuzz tests for all CLI inputs
- [ ] **SEC-05**: No unencrypted secrets written to disk

### Documentation

- [ ] **DOC-01**: Stale documentation cleaned up
- [ ] **DOC-02**: SECURITY.md updated with v2.0 threat model and known risks
- [ ] **DOC-03**: THREAT_MODEL.md references complete analysis
- [ ] **DOC-04**: README.md quick start guide updated
- [ ] **DOC-05**: IAM policy templates documented for all features
- [ ] **DOC-06**: SCP templates provided (not CLI deployment)
- [ ] **DOC-07**: All code examples in docs are testable (Example* tests)

### Release Preparation

- [ ] **REL-01**: CHANGELOG.md complete for v2.0
- [ ] **REL-02**: Version constants updated to 2.0.0
- [ ] **REL-03**: Git history clean (squash fixup commits if needed)
- [ ] **REL-04**: Release candidate tagged (v2.0.0-rc.1)

### Internal Documentation

- [ ] **INT-01**: Marshall document created for architecture overview
- [ ] **INT-02**: Demo script with common workflows
- [ ] **INT-03**: Architecture diagram showing all components

## Future Requirements

Deferred to v2.1 or later milestones.

### Advanced Features

- Web UI dashboard for policy management and approval workflows
- Multi-account policy federation
- Policy versioning and rollback
- Kubernetes integration (Pod Identity → Sentinel)
- Event-driven policy updates via EventBridge

## Out of Scope

Explicitly excluded from v2.0 stabilization.

| Feature | Reason |
|---------|--------|
| New major features | v2.0 is stabilization only, feature freeze |
| Breaking API changes | Maintain backward compatibility from v1.x |
| Multi-cloud support (Azure, GCP) | AWS-only for v2.0 |
| Automatic remediation | Commands require user confirmation |
| Real-time policy enforcement beyond sessions | SCP handles org-level enforcement |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| TEST-01 | Phase 150 | Pending |
| TEST-02 | Phase 150 | Pending |
| TEST-03 | Phase 150 | Pending |
| TEST-04 | Phase 150 | Pending |
| TEST-05 | Phase 150 | Pending |
| INTUNE-01 | Phase 151 | Pending |
| INTUNE-02 | Phase 151 | Pending |
| INTUNE-03 | Phase 151 | Pending |
| INTUNE-04 | Phase 151 | Pending |
| INTUNE-05 | Phase 151 | Pending |
| SEC-01 | Phase 152 | Pending |
| SEC-02 | Phase 152 | Pending |
| SEC-03 | Phase 152 | Pending |
| SEC-04 | Phase 152 | Pending |
| SEC-05 | Phase 152 | Pending |
| DOC-01 | Phase 153 | Pending |
| DOC-02 | Phase 153 | Pending |
| DOC-03 | Phase 153 | Pending |
| DOC-04 | Phase 153 | Pending |
| DOC-05 | Phase 153 | Pending |
| DOC-06 | Phase 153 | Pending |
| DOC-07 | Phase 153 | Pending |
| REL-01 | Phase 154 | Pending |
| REL-02 | Phase 154 | Pending |
| REL-03 | Phase 154 | Pending |
| REL-04 | Phase 154 | Pending |
| INT-01 | Phase 155 | Pending |
| INT-02 | Phase 155 | Pending |
| INT-03 | Phase 155 | Pending |

**Coverage:**
- v2.0 requirements: 27 total
- Mapped to phases: 27 (100% coverage)
- Unmapped: 0

---
*Requirements defined: 2026-01-27*
*Last updated: 2026-01-27 after initial definition*
