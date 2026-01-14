# Project Milestones: Sentinel

## v1.0 MVP (Shipped: 2026-01-14)

**Delivered:** Intent-aware access control layer for AWS credentials with policy evaluation, SSM-based policy storage, and integration via credential_process and exec commands.

**Phases completed:** 1-8 (16 plans total)

**Key accomplishments:**
- CLI foundation with kingpin framework and aws-vault credential provider integration
- Policy schema with YAML parsing, validation, and type-safe Effect/Weekday handling
- SSM Parameter Store policy loading with TTL-based caching
- Rule matching engine with time windows, timezone support, and first-match-wins semantics
- credential_process and exec commands with policy-gated credential issuance
- Structured JSON Lines decision logging with configurable destinations

**Stats:**
- 57 files created/modified
- 10,762 lines of Go
- 8 phases, 16 plans, ~40 tasks
- 1 day from start to ship

**Git range:** `feat(01-01)` → `feat(08-02)`

**What's next:** Consider approval workflows, break-glass mode, or additional policy features for v1.1

---
