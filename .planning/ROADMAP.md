# Roadmap: Sentinel

## Overview

Sentinel adds intent-aware access control to aws-vault, evaluating policy rules before issuing AWS credentials. The journey starts with CLI foundation and aws-vault integration, moves through policy schema design and SSM-based loading, implements the core decision engine, then exposes this through credential_process and exec commands with full logging and profile compatibility.

## Domain Expertise

None

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation** - Project setup, CLI scaffolding, aws-vault integration
- [x] **Phase 2: Policy Schema** - Define policy format and rule structure
- [ ] **Phase 3: Policy Loading** - SSM Parameter Store integration for policy fetch (In progress)
- [ ] **Phase 4: Policy Evaluation** - Core decision engine (allow/deny logic)
- [ ] **Phase 5: Credential Process** - credential_process output format and integration
- [ ] **Phase 6: Decision Logging** - Structured logging of access decisions
- [ ] **Phase 7: Exec Command** - sentinel exec for direct invocation
- [ ] **Phase 8: Profile Compatibility** - Seamless integration with existing aws-vault profiles

## Phase Details

### Phase 1: Foundation
**Goal**: CLI scaffolding with cobra, project structure, and aws-vault library integration
**Depends on**: Nothing (first phase)
**Research**: Unlikely (established patterns in existing codebase)
**Plans**: TBD

Plans:
- [x] 01-01: CLI skeleton with kingpin, main entry point
- [x] 01-02: aws-vault library integration, credential provider access

### Phase 2: Policy Schema
**Goal**: Define YAML/JSON policy format with rules for user, profile, time, and conditions
**Depends on**: Phase 1
**Research**: Unlikely (internal design decision)
**Plans**: TBD

Plans:
- [x] 02-01: Policy schema design and Go structs
- [x] 02-02: Policy parsing and validation

### Phase 3: Policy Loading
**Goal**: Fetch policies from SSM Parameter Store with caching
**Depends on**: Phase 2
**Research**: Likely (SSM Parameter Store API)
**Research topics**: aws-sdk-go-v2 SSM client patterns, parameter path conventions, caching strategies
**Plans**: TBD

Plans:
- [x] 03-01: SSM client setup and parameter fetch
- [ ] 03-02: Policy caching with TTL

### Phase 4: Policy Evaluation
**Goal**: Core decision engine that evaluates rules and returns allow/deny with matched rule
**Depends on**: Phase 3
**Research**: Unlikely (internal logic)
**Plans**: TBD

Plans:
- [ ] 04-01: Rule matching engine
- [ ] 04-02: Decision result with matched rule context

### Phase 5: Credential Process
**Goal**: `sentinel credentials --profile X` command with AWS credential_process JSON output
**Depends on**: Phase 4
**Research**: Likely (AWS credential_process spec)
**Research topics**: credential_process JSON format, expiration handling, error output conventions
**Plans**: TBD

Plans:
- [ ] 05-01: credentials command with policy evaluation
- [ ] 05-02: credential_process JSON output format

### Phase 6: Decision Logging
**Goal**: Structured logging of every access decision (user, profile, allow/deny, rule matched)
**Depends on**: Phase 5
**Research**: Unlikely (standard Go logging)
**Plans**: TBD

Plans:
- [ ] 06-01: Structured logger with decision fields
- [ ] 06-02: Log destination configuration

### Phase 7: Exec Command
**Goal**: `sentinel exec --profile X -- cmd` for direct command invocation with credentials
**Depends on**: Phase 5
**Research**: Unlikely (existing aws-vault exec patterns)
**Plans**: TBD

Plans:
- [ ] 07-01: exec command with subprocess spawning
- [ ] 07-02: Environment variable injection

### Phase 8: Profile Compatibility
**Goal**: Work transparently with existing ~/.aws/config profiles without modification
**Depends on**: Phase 7
**Research**: Unlikely (aws-vault config parsing exists)
**Plans**: TBD

Plans:
- [ ] 08-01: AWS config file parsing integration
- [ ] 08-02: Profile validation and error handling

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation | 2/2 | Complete | 2026-01-14 |
| 2. Policy Schema | 2/2 | Complete | 2026-01-14 |
| 3. Policy Loading | 1/2 | In progress | - |
| 4. Policy Evaluation | 0/2 | Not started | - |
| 5. Credential Process | 0/2 | Not started | - |
| 6. Decision Logging | 0/2 | Not started | - |
| 7. Exec Command | 0/2 | Not started | - |
| 8. Profile Compatibility | 0/2 | Not started | - |
