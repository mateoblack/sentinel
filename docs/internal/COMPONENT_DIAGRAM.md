# Sentinel Component Architecture

ASCII diagrams showing Sentinel's architecture and component interactions.

## System Architecture Overview

```
+-----------------------------------------------------------------------------+
|                              USER INTERFACE                                  |
+-----------------------------------------------------------------------------+
|  CLI Commands (cli/)                                                         |
|  +------------+ +------------+ +------------+ +------------+ +------------+  |
|  |credentials | |    exec    | |   policy   | |  request   | | breakglass |  |
|  +-----+------+ +-----+------+ +-----+------+ +-----+------+ +-----+------+  |
|        |              |              |              |              |         |
+--------+--------------+--------------+--------------+--------------+---------+
         |              |              |              |              |
         v              v              v              v              v
+-----------------------------------------------------------------------------+
|                           POLICY EVALUATION                                  |
+-----------------------------------------------------------------------------+
|  +-------------------+    +-------------------+    +-------------------+     |
|  |   PolicyLoader    |--->|   PolicyEngine    |--->|   Decision Log    |     |
|  |   (SSM + Cache)   |    |   (First Match)   |    |   (JSON Lines)    |     |
|  +-------------------+    +-------------------+    +-------------------+     |
|           |                       |                                          |
|           v                       v                                          |
|  +-------------------+    +-------------------+                              |
|  |   KMS Verifier    |    |  Device Posture   |                              |
|  |   (Signatures)    |    |   (MDM Lookup)    |                              |
|  +-------------------+    +-------------------+                              |
+-----------------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------------+
|                         CREDENTIAL PROVIDERS                                 |
+-----------------------------------------------------------------------------+
|  +-------------+  +-------------+  +-------------+  +-------------+          |
|  |   Keyring   |  |     SSO     |  | AssumeRole  |  |   Cached    |          |
|  |   Provider  |  |   Provider  |  |   Provider  |  |   Session   |          |
|  +------+------+  +------+------+  +------+------+  +------+------+          |
|         +----------------+----------------+----------------+                  |
|                                   |                                          |
|                                   v                                          |
|                    +-----------------------------+                           |
|                    |      SourceIdentity         |                           |
|                    |  (sentinel:user:request-id) |                           |
|                    +-----------------------------+                           |
+-----------------------------------------------------------------------------+
                                    |
                    +---------------+---------------+
                    v                               v
+-----------------------------------+  +-----------------------------------+
|         LOCAL SERVERS             |  |          LAMBDA TVM               |
+-----------------------------------+  +-----------------------------------+
|  +-------------+  +-------------+ |  |  +-------------+  +-------------+ |
|  |  EC2 Meta   |  |  ECS Creds  | |  |  |   Lambda    |  |   API GW    | |
|  |   Server    |  |   Server    | |  |  |   Handler   |  |  HTTP API   | |
|  +-------------+  +-------------+ |  |  +-------------+  +-------------+ |
|                                   |  |                                   |
|  +-----------------------------+  |  |  +-----------------------------+ |
|  |     Unix Socket Auth        |  |  |  |     IAM Auth (SigV4)        | |
|  |    (Process Credentials)    |  |  |  |     (Trust Boundary)        | |
|  +-----------------------------+  |  |  +-----------------------------+ |
+-----------------------------------+  +-----------------------------------+
                    |                               |
                    +---------------+---------------+
                                    v
+-----------------------------------------------------------------------------+
|                            STATE STORAGE                                     |
+-----------------------------------------------------------------------------+
|  +-------------+  +-------------+  +-------------+  +-------------+          |
|  |   Keyring   |  |  DynamoDB   |  |     SSM     |  |   Secrets   |          |
|  | (Credentials|  |  (Sessions  |  |  (Policies) |  |   Manager   |          |
|  |    Cache)   |  |  Approvals) |  |             |  |  (MDM Keys) |          |
|  +-------------+  +-------------+  +-------------+  +-------------+          |
+-----------------------------------------------------------------------------+
```

## Package Dependency Graph

```
main.go
   |
   +---> cli/
         |
         +---> sentinel/     (SentinelServer)
         |       |
         |       +---> policy/    (evaluation)
         |       +---> session/   (tracking)
         |       +---> mdm/       (device posture)
         |
         +---> vault/        (credential providers)
         |       |
         |       +---> server/    (EC2/ECS)
         |       +---> sso/       (SSO login)
         |
         +---> request/      (approval workflow)
         |       +---> notification/
         |
         +---> breakglass/   (emergency access)
         |       +---> ratelimit/
         |
         +---> infrastructure/ (provisioning)
                 +---> bootstrap/
```

## Data Flow: Credential Request

```
+----------+    +------------+    +---------------+    +-------------+
|   User   |--->|    CLI     |--->|    Policy     |--->|    Allow    |---> Credentials
|  Request |    |  Command   |    |    Engine     |    |    Deny     |---> Error
+----------+    +------------+    +---------------+    +-------------+
                     |                  |                    |
                     v                  v                    v
               +------------+    +---------------+    +-------------+
               |  Identity  |    |    Policy     |    |  Decision   |
               |   (STS)    |    |    (SSM)      |    |    Log      |
               +------------+    +---------------+    +-------------+
```

## Server Mode Architecture

```
+-----------------------------------------------------------------------+
|                        SENTINEL EXEC --SERVER                          |
+-----------------------------------------------------------------------+
|                                                                        |
|  +---------------------------+         +---------------------------+   |
|  |      User Process         |         |    Sentinel Server        |   |
|  |  (bash, python, etc.)     |         |                           |   |
|  |                           |         |  +---------------------+  |   |
|  |  AWS SDK makes request    |-------->|  | Credential Handler  |  |   |
|  |  via CREDENTIALS_FULL_URI |         |  +----------+----------+  |   |
|  |                           |         |             |             |   |
|  |                           |         |             v             |   |
|  |                           |         |  +---------------------+  |   |
|  |                           |         |  |  Policy Evaluation  |  |   |
|  |                           |         |  +----------+----------+  |   |
|  |                           |         |             |             |   |
|  |                           |         |             v             |   |
|  |                           |         |  +---------------------+  |   |
|  |                           |<--------|  | Session Tracking    |  |   |
|  |  Receives credentials     |         |  +---------------------+  |   |
|  +---------------------------+         +---------------------------+   |
|                                                     |                  |
|                                                     v                  |
|                                        +------------------------+      |
|                                        |       DynamoDB         |      |
|                                        |  (session state)       |      |
|                                        +------------------------+      |
+-----------------------------------------------------------------------+

Session Lifecycle:
  [Create] --> [Active] --> [Touch] --> [Revoke/Expire]
       |                        ^
       +------------------------+
              (heartbeat)
```

## Lambda TVM Architecture

```
+-----------------------------------------------------------------------+
|                         CLIENT SIDE                                    |
+-----------------------------------------------------------------------+
|                                                                        |
|  +---------------------------+                                         |
|  |   sentinel exec           |                                         |
|  |   --remote-server <url>   |                                         |
|  +-------------+-------------+                                         |
|                |                                                        |
|                v                                                        |
|  +---------------------------+                                         |
|  |    HTTP Request           |                                         |
|  |    POST /credentials      |                                         |
|  |    (SigV4 signed)         |                                         |
|  +-------------+-------------+                                         |
|                |                                                        |
+-----------------------------------------------------------------------+
                 |
                 v
+-----------------------------------------------------------------------+
|                         AWS CLOUD                                      |
+-----------------------------------------------------------------------+
|                                                                        |
|  +---------------------------+                                         |
|  |      API Gateway          |    Extract caller identity              |
|  |      (HTTP API)           |--> from IAM auth                        |
|  +-------------+-------------+                                         |
|                |                                                        |
|                v                                                        |
|  +---------------------------+                                         |
|  |      Lambda Function      |                                         |
|  |      (Sentinel TVM)       |                                         |
|  |                           |                                         |
|  |  1. Load policy (SSM)     |                                         |
|  |  2. Verify KMS signature  |                                         |
|  |  3. Evaluate policy       |                                         |
|  |  4. Check device posture  |  <--> [MDM API: Jamf/Intune]           |
|  |  5. AssumeRole with       |                                         |
|  |     SourceIdentity        |                                         |
|  |  6. Track session         |  <--> [DynamoDB]                        |
|  |  7. Return credentials    |                                         |
|  +-------------+-------------+                                         |
|                |                                                        |
|                v                                                        |
|  +---------------------------+                                         |
|  |    Protected IAM Role     |                                         |
|  |    (SentinelProtected-*)  |                                         |
|  |                           |                                         |
|  |  Trust Policy requires:   |                                         |
|  |  - TVM Lambda principal   |                                         |
|  |  - SourceIdentity present |                                         |
|  +---------------------------+                                         |
|                                                                        |
+-----------------------------------------------------------------------+

TRUST BOUNDARY: Lambda function enforces policy.
                Client cannot bypass evaluation.
```

## Policy Evaluation Flow

```
+-------------------------------------------------------------------------+
|                        POLICY EVALUATION                                 |
+-------------------------------------------------------------------------+
|                                                                          |
|   Request: { user: "john.doe", profile: "staging", timestamp: "..." }   |
|                                                                          |
|   +-------------------------------------------------------------------+  |
|   |                       Rule Matching                                |  |
|   |                                                                    |  |
|   |   Rule 1: allow for [alice, bob] on [prod]                        |  |
|   |           --> NO MATCH (user not in list)                         |  |
|   |                                                                    |  |
|   |   Rule 2: allow for [john.doe] on [staging, dev]                  |  |
|   |           with time_window: Mon-Fri 9-18                          |  |
|   |           --> MATCH! (user, profile, time all match)              |  |
|   |                                                                    |  |
|   |   Result: ALLOW (first match wins)                                 |  |
|   +-------------------------------------------------------------------+  |
|                                                                          |
|   If NO rules match --> DENY (default deny)                             |
|                                                                          |
+-------------------------------------------------------------------------+

Rule Evaluation Order:
  1. Check user list (empty = any user)
  2. Check profile list (empty = any profile)
  3. Check time windows (if specified)
  4. Check device conditions (if specified)
  5. Check credential mode (cli/server/credential_process)
  6. Return effect (allow/deny/require_approval/require_server)
```

## Approval Workflow State Machine

```
                    +------------+
                    |            |
                    |  PENDING   |
                    |            |
                    +-----+------+
                          |
         +----------------+----------------+
         |                |                |
         v                v                v
   +-----------+    +-----------+    +-----------+
   |           |    |           |    |           |
   | APPROVED  |    |  DENIED   |    |  EXPIRED  |
   |           |    |           |    |           |
   +-----------+    +-----------+    +-----------+
         |
         v
   +-----------+
   |           |
   | CANCELLED |
   | (optional)|
   |           |
   +-----------+

Transitions:
  PENDING -> APPROVED  (approver approves)
  PENDING -> DENIED    (approver denies)
  PENDING -> EXPIRED   (TTL reached)
  APPROVED -> CANCELLED (requester cancels)
```

## Break-Glass Flow

```
+-------------------------------------------------------------------------+
|                        BREAK-GLASS FLOW                                  |
+-------------------------------------------------------------------------+
|                                                                          |
|   Normal Flow:                                                           |
|   User --> Policy --> DENY --> Stop                                      |
|                                                                          |
|   Break-Glass Flow:                                                      |
|   User --> Policy --> DENY --> Break-Glass Request                       |
|                                       |                                  |
|                                       v                                  |
|                               +---------------+                          |
|                               | Rate Limiter  |                          |
|                               | 1. Cooldown   |                          |
|                               | 2. User quota |                          |
|                               | 3. Profile    |                          |
|                               |    quota      |                          |
|                               +-------+-------+                          |
|                                       |                                  |
|                                       v                                  |
|                               +---------------+                          |
|                               | Break-Glass   |                          |
|                               | Policy Check  |                          |
|                               +-------+-------+                          |
|                                       |                                  |
|                                       v                                  |
|                               +---------------+                          |
|                               | Create Event  |                          |
|                               | (DynamoDB)    |                          |
|                               +-------+-------+                          |
|                                       |                                  |
|                                       v                                  |
|                               +---------------+                          |
|                               |  Notify       |                          |
|                               | (SNS/Webhook) |                          |
|                               +-------+-------+                          |
|                                       |                                  |
|                                       v                                  |
|                               +---------------+                          |
|                               | Grant Access  |                          |
|                               | (time-bound)  |                          |
|                               +---------------+                          |
|                                                                          |
+-------------------------------------------------------------------------+
```

## Session Tracking

```
+-------------------------------------------------------------------------+
|                        SESSION TRACKING                                  |
+-------------------------------------------------------------------------+
|                                                                          |
|   DynamoDB Table: sentinel-sessions                                      |
|                                                                          |
|   +----------------------------------------------------------------+    |
|   |  SESSION#sess_abc123                                            |    |
|   |                                                                  |    |
|   |  source_identity: sentinel:john.doe:abc123                      |    |
|   |  device_id: d8a7b6c5e4f3...                                     |    |
|   |  profile: staging                                                |    |
|   |  created_at: 2026-01-27T14:30:00Z                               |    |
|   |  expires_at: 2026-01-27T14:45:00Z                               |    |
|   |  last_accessed: 2026-01-27T14:35:00Z                            |    |
|   |  status: active                                                  |    |
|   |  ttl: 1706370300 (Unix timestamp for DynamoDB TTL)              |    |
|   +----------------------------------------------------------------+    |
|                                                                          |
|   GSI1: SOURCE_IDENTITY#sentinel:john.doe:abc123                        |
|         (Query by SourceIdentity)                                        |
|                                                                          |
|   GSI2: DEVICE#d8a7b6c5e4f3...                                          |
|         (Query by DeviceID)                                              |
|                                                                          |
+-------------------------------------------------------------------------+

Revocation Check:
  On each credential request:
    1. Load session from DynamoDB
    2. Check status != revoked
    3. Check expires_at > now
    4. Update last_accessed (heartbeat)
    5. If revoked/expired --> DENY
```

## Component Legend

```
+-------------+    +- - - - - -+    +-------------+
|   Package   |    |  External |    |   Storage   |
|   (Go code) |    |  Service  |    |   (Persist) |
+-------------+    +- - - - - -+    +-------------+

----->  Data flow
---->   Control flow
<--->   Bidirectional

+-----------------------------------------------------------------------------+
|  Box: Component boundary or grouping                                         |
+-----------------------------------------------------------------------------+
```

## Key Interactions Summary

| Source | Target | Interaction |
|--------|--------|-------------|
| CLI | sentinel/ | Invoke credential operations |
| sentinel/ | policy/ | Load and evaluate policies |
| sentinel/ | session/ | Track server mode sessions |
| sentinel/ | mdm/ | Query device posture |
| policy/ | SSM | Load policy YAML |
| policy/ | KMS | Verify policy signature |
| session/ | DynamoDB | Persist session state |
| request/ | DynamoDB | Store approval requests |
| breakglass/ | DynamoDB | Track break-glass events |
| notification/ | SNS/Webhook | Send event notifications |
| lambda/ | STS | AssumeRole with SourceIdentity |
| vault/ | Keyring | Store/retrieve credentials |

---

*Last updated: 2026-01-27*
*Intended audience: Engineers understanding Sentinel internals*
