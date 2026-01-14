# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-13)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** Phase 8 — Profile Compatibility

## Current Position

Phase: 8 of 8 (Profile Compatibility)
Plan: 1 of 2 in current phase
Status: In progress
Last activity: 2026-01-14 — Completed 08-01-PLAN.md

Progress: ███████████████████░ 94%

## Performance Metrics

**Velocity:**
- Total plans completed: 14
- Average duration: 2.4 min
- Total execution time: 34 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1-foundation | 2/2 | 6 min | 3 min |
| 2-policy-schema | 2/2 | 5 min | 2.5 min |
| 3-policy-loading | 2/2 | 3 min | 1.5 min |
| 4-policy-evaluation | 2/2 | 5 min | 2.5 min |
| 5-credential-process | 2/2 | 4 min | 2 min |
| 6-decision-logging | 2/2 | 7 min | 3.5 min |
| 7-exec-command | 2/2 | 3 min | 1.5 min |
| 8-profile-compatibility | 1/2 | 2 min | 2 min |

**Recent Trend:**
- Last 5 plans: 06-02 (4 min), 07-01 (2 min), 07-02 (1 min), 08-01 (2 min)
- Trend: Consistent

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

| Phase | Decision | Rationale |
|-------|----------|-----------|
| 01-01 | Use kingpin (not cobra) | Match existing aws-vault codebase patterns |
| 01-01 | Share aws-vault keyring service name | Allow sentinel to access same credential store |
| 01-02 | Follow exec.go vault.NewTempCredentialsProvider pattern | Consistent credential retrieval approach |
| 01-02 | Include CanExpire flag in result | Differentiate session vs long-lived credentials |
| 02-01 | String type aliases for Effect/Weekday | Type safety with IsValid() validation methods |
| 02-01 | Pointer for optional nested structs | Distinguish "not specified" from "empty" |
| 02-02 | Regex for hour format validation | Single-step HH:MM validation |
| 02-02 | time.LoadLocation for timezone | Leverage Go's timezone database |
| 02-02 | Require at least one condition per rule | Prevent overly broad rules |
| 03-01 | Caller provides aws.Config to Loader | Match vault.go pattern, no hidden config loading |
| 03-01 | WithDecryption: true always | Support SecureString parameters (no-op for String) |
| 03-01 | ErrPolicyNotFound wraps parameter name | Provide context in error messages |
| 03-02 | sync.RWMutex for cache (not Mutex) | Better read performance on cache hits |
| 03-02 | Errors not cached | Allow retries on transient failures |
| 03-02 | PolicyLoader interface abstraction | CachedLoader can wrap any loader implementation |
| 04-01 | Hour range [start, end) semantics | Inclusive start, exclusive end for intuitive business hours |
| 04-01 | Empty list = wildcard matching | Allow rules like "any user on staging" |
| 04-01 | Default deny on no match/nil input | Security-first approach |
| 05-01 | OS username for policy evaluation | Use os/user.Current().Username for identity |
| 05-01 | 5-minute cache TTL for policy | Balance API calls vs freshness |
| 06-01 | JSON Lines format for logs | Single-line JSON for log aggregation compatibility |
| 06-01 | Logger interface abstraction | Pluggable backends (file, network, etc.) |
| 06-01 | Logger nil by default | CLI flags added in plan 06-02 |
| 06-02 | Logger created from CLI flags at start | Before policy evaluation, after flag parsing |
| 06-02 | File logging uses O_APPEND mode | Accumulate entries across invocations |
| 06-02 | io.MultiWriter for multiple destinations | Standard library pattern for simultaneous outputs |
| 07-01 | SentinelExecCommand returns (int, error) | Exit code propagation for subprocess failure handling |
| 07-01 | Reuse exec.go helpers | getDefaultShell and createEnv for consistency |
| 08-01 | Fail-fast profile validation | Validate profile exists before policy loading |
| 08-01 | Helpful error messages with available profiles | User guidance when profile not found |

### Deferred Issues

None yet.

### Blockers/Concerns

None - Go is now available and builds succeed.

## Session Continuity

Last session: 2026-01-14
Stopped at: Completed 08-01-PLAN.md
Resume file: None
