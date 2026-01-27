# Sentinel Architecture Overview

Internal documentation for Sentinel maintainers. Provides comprehensive architectural context for understanding the codebase.

## 1. System Overview

### Purpose
Sentinel is a policy-enforced credential access control layer for AWS. It sits between users/applications and AWS credentials, evaluating policy rules before issuing credentials.

### Core Principle
**"No policy match = no credentials"** (fail-closed)

When a credential request arrives, Sentinel evaluates it against policy rules. If no rule explicitly allows the request, access is denied. This is the default-deny security model.

### Integration Points
- **credential_process**: AWS SDK credential process integration for transparent credential injection
- **exec**: Direct command execution with credentials injected via environment or metadata server
- **Lambda TVM**: Server-side credential vending where Lambda IS the trust boundary

## 2. Package Organization

Sentinel contains 30+ packages organized by domain. Understanding these groupings helps navigate the codebase.

### Core Credential Flow

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `vault/` | AWS credential providers, keyring wrappers, config parsing | `TempCredentialsCreator`, `*Provider` implementations |
| `server/` | EC2/ECS metadata emulation, HTTP credential servers | `EC2Server`, `ECSServer` |
| `sentinel/` | Policy-aware SentinelServer for credential vending | `SentinelServer`, `SentinelProvider` |
| `lambda/` | Lambda TVM handler for server-side vending | `Handler`, `TVMConfig` |
| `sso/` | AWS SSO/IAM Identity Center integration | SSO login flow, token refresh |

### Policy Subsystem

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `policy/` | YAML schema, parsing, validation, signing (KMS) | `Policy`, `Rule`, `PolicySigner`, `VerifyingLoader` |
| `enforce/` | Trust policy analysis, SCP validation | `Analyzer`, `TrustPolicyGenerator` |
| `validate/` | Input validation, sanitization | Validation functions for policy inputs |

### Request/Response

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `request/` | Approval workflow state machine (DynamoDB) | `Request`, `Store`, `Checker` |
| `breakglass/` | Emergency access with rate limiting | `Event`, `Store`, `RateLimiter` |
| `session/` | Server-side session tracking and revocation | `Session`, `Store` |

### Security

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `security/` | Rate limiting, error sanitization | Security utilities |
| `ratelimit/` | Sliding window rate limiter | `Limiter`, DynamoDB atomic counters |
| `logging/` | HMAC-signed audit logs | `Logger`, `DecisionLogEntry`, `ApprovalLogEntry` |
| `mfa/` | Multi-factor authentication (TOTP, SMS) | `Verifier` interface |

### Infrastructure

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `bootstrap/` | SSM parameter setup | `Planner`, `Executor` |
| `infrastructure/` | DynamoDB table provisioning | `TableProvisioner` |
| `deploy/` | Deployment validation | Deployment checks |
| `config/` | Configuration validation | Config types |

### Device Posture

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `device/` | Device ID generation | `DeviceID`, `Collector` |
| `mdm/` | MDM provider interface (Jamf, Intune) | `Provider`, `JamfProvider`, `IntuneProvider` |

### CLI

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `cli/` | Command handlers (60+ commands) | Command handler functions |
| `prompt/` | MFA input drivers | Terminal, osascript, zenity, kdialog, ykman |
| `shell/` | Shell integration | Shell function generation |

### Supporting

| Package | Purpose | Key Types |
|---------|---------|-----------|
| `identity/` | AWS identity extraction, request ID generation | `Extractor`, `RequestID` |
| `notification/` | SNS/Webhook notifications | `Notifier`, `SNSNotifier`, `WebhookNotifier` |
| `errors/` | Structured error types | `SentinelError`, error codes |
| `permissions/` | IAM permission mapping | Feature-to-action mapping |
| `audit/` | CloudTrail integration | Audit commands |
| `testutil/` | Test utilities | Mock implementations |
| `iso8601/` | Timestamp formatting | AWS-compatible timestamps |

## 3. Key Data Flows

### Flow A: CLI Credential Process

The standard flow for CLI-based credential access via `credential_process` in `~/.aws/config`.

```
~/.aws/config: credential_process = sentinel credentials --profile staging
                                           |
                                           v
                              +-----------------------+
                              | cli/credentials.go    |
                              | Parse profile, load   |
                              | AWS config            |
                              +-----------------------+
                                           |
                                           v
                              +-----------------------+
                              | sentinel/SentinelServer|
                              | Load policy from SSM  |
                              | (with signature verify)|
                              +-----------------------+
                                           |
                                           v
                              +-----------------------+
                              | policy/Engine         |
                              | First-match-wins      |
                              | evaluation            |
                              +-----------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
           [Rule Match: allow]                           [No Match: deny]
                    |                                             |
                    v                                             v
           +-----------------------+                     [Exit with error]
           | vault/provider chain  |
           | Get credentials       |
           +-----------------------+
                    |
                    v
           +-----------------------+
           | sentinel/AssumeRole   |
           | Stamp SourceIdentity: |
           | sentinel:user:req-id  |
           +-----------------------+
                    |
                    v
           [Return aws.Credentials]
```

### Flow B: Exec with Server Mode

For long-running processes that need per-request policy evaluation.

```
sentinel exec staging --server --session-table sentinel-sessions -- bash
           |
           v
+-----------------------+
| cli/exec.go           |
| Start SentinelServer  |
| on localhost          |
+-----------------------+
           |
           v
+-----------------------+
| server/SentinelServer |
| Listen on socket/port |
| Set AWS_CONTAINER_... |
+-----------------------+
           |
           +---> [Subprocess starts with AWS_CONTAINER_CREDENTIALS_FULL_URI]
           |
           v
[Each credential request from subprocess]
           |
           v
+-----------------------+
| Per-request policy    |
| evaluation            |
+-----------------------+
           |
           v
+-----------------------+
| session/Store         |
| Create/touch session  |
| Track in DynamoDB     |
+-----------------------+
           |
           v
+-----------------------+
| Check for revocation  |
| on each request       |
+-----------------------+
           |
           v
[Credentials or denial]
```

### Flow C: Lambda TVM

Server-side credential vending where the Lambda function IS the trust boundary.

```
Client: sentinel exec staging --remote-server https://tvm.example.com/...
           |
           v
+-----------------------+
| API Gateway HTTP API  |
| IAM auth (SigV4)      |
| Extract caller ARN    |
+-----------------------+
           |
           v
+-----------------------+
| lambda/handler.go     |
| Parse request, load   |
| policy from SSM       |
+-----------------------+
           |
           v
+-----------------------+
| policy/VerifyingLoader|
| Verify KMS signature  |
| before evaluation     |
+-----------------------+
           |
           v
+-----------------------+
| policy/Engine         |
| Evaluate with caller  |
| identity from IAM     |
+-----------------------+
           |
           v
+-----------------------+
| mdm/Provider          |
| Optional: Query Jamf/ |
| Intune for device     |
+-----------------------+
           |
           v
+-----------------------+
| STS AssumeRole        |
| Stamp SourceIdentity: |
| sentinel:user:req-id  |
+-----------------------+
           |
           v
+-----------------------+
| session/Store         |
| Track session with    |
| DeviceID binding      |
+-----------------------+
           |
           v
[Return credentials via HTTP]
```

## 4. Security Boundaries

### Trust Boundaries

| Boundary | Location | Enforcement |
|----------|----------|-------------|
| **Lambda TVM** | AWS Lambda function | Clients cannot bypass policy - Lambda enforces before issuing credentials |
| **Policy Signature** | KMS-signed policies | Prevents tampering with policy YAML in SSM |
| **Session Binding** | DynamoDB sessions | DeviceID + SourceIdentity for attribution |

### Security Invariants

1. **Fail-closed**: No policy match = deny. The engine never fails open.

2. **Policy signing**: When enabled, policies must have valid KMS signatures. Unsigned/invalid policies are rejected.

3. **Session tracking**: Server mode sessions are tracked in DynamoDB with real-time revocation capability.

4. **SourceIdentity stamping**: All credentials include `sentinel:<user>:<request-id>` for CloudTrail correlation.

### Key Security Decisions

| Decision | Rationale |
|----------|-----------|
| Default deny | Security-first - explicit allow required |
| KMS signatures | Prevent cache poisoning and policy tampering |
| SourceIdentity format | 64-char AWS limit, unique per request |
| Session tracking | Enable real-time revocation |
| Rate limiting | Prevent credential abuse |
| Error sanitization | Log details internally, return generic messages |

## 5. State Storage

### Local State

| Store | Location | Contents |
|-------|----------|----------|
| **Keyring** | macOS Keychain, Linux keyctl, Windows Credential Manager | AWS credentials, cached sessions |
| **Config** | `~/.aws/config` | Profile definitions, credential_process setup |

### AWS State

| Service | Parameter Pattern | Contents |
|---------|-------------------|----------|
| **SSM Parameter Store** | `/sentinel/policies/<profile>` | Policy YAML |
| **SSM Parameter Store** | `/sentinel/policies/<profile>.sig` | Policy KMS signature |
| **DynamoDB** | `sentinel-approvals` | Approval workflow state |
| **DynamoDB** | `sentinel-breakglass` | Break-glass events |
| **DynamoDB** | `sentinel-sessions` | Server mode sessions |
| **Secrets Manager** | `sentinel/mdm/api-token` | MDM API credentials |

### DynamoDB Table Schemas

**Approvals Table:**
- PK: `REQUEST#<id>` (request ID)
- GSI1: `USER#<username>` for user queries
- GSI2: `PROFILE#<profile>` for profile queries
- TTL: Automatic expiration

**Sessions Table:**
- PK: `SESSION#<id>` (session ID)
- GSI1: `SOURCE_IDENTITY#<identity>` for source lookups
- GSI2: `DEVICE#<device-id>` for device queries
- TTL: Session expiration

**Break-Glass Table:**
- PK: `EVENT#<id>` (event ID)
- GSI1: `INVOKER#<username>` for invoker queries
- TTL: Event expiration

## 6. Extension Points

### Adding a New MDM Provider

1. Implement the `mdm.Provider` interface in `mdm/<provider>.go`:
   ```go
   type Provider interface {
       Name() string
       GetDevicePosture(ctx context.Context, deviceID string) (*DevicePosture, error)
   }
   ```

2. Add provider registration in `mdm/registry.go`

3. Add configuration support in `lambda/config.go` for TVM integration

4. Add tests in `mdm/<provider>_test.go`

### Adding a New CLI Command

1. Create command handler in `cli/<command>.go`:
   ```go
   func ConfigureMyCommand(app *kingpin.Application, globalConfig *GlobalConfig) {
       cmd := app.Command("my-command", "Description")
       // Add flags
       cmd.Action(func(c *kingpin.ParseContext) error {
           return runMyCommand(globalConfig)
       })
   }
   ```

2. Register in `main.go`:
   ```go
   cli.ConfigureMyCommand(app, &globalConfig)
   ```

3. Add tests in `cli/<command>_test.go`

4. Update documentation in `docs/commands.md`

### Adding a New Policy Condition

1. Extend the `policy.Condition` struct in `policy/types.go`:
   ```go
   type Condition struct {
       // Existing fields...
       NewCondition *string `yaml:"new_condition,omitempty"`
   }
   ```

2. Add evaluation logic in `policy/evaluate.go`

3. Add validation in `policy/validate.go`

4. Add tests in `policy/evaluate_test.go`

5. Update schema documentation in `docs/POLICY_SCHEMA.md`

### Adding a New Notification Type

1. Implement the `notification.Notifier` interface:
   ```go
   type Notifier interface {
       Notify(ctx context.Context, event Event) error
   }
   ```

2. Create implementation in `notification/<type>.go`

3. Add configuration in policy schema for the new notification type

4. Add tests in `notification/<type>_test.go`

## 7. Testing Strategy

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit tests | `*_test.go` (co-located) | Test individual functions/methods |
| Security regression | `*_security_test.go` | Validate denial paths, prevent regressions |
| Integration | `cli/*_test.go` | Test CLI command flows |
| Fuzz | `fuzz/` | Property-based testing for inputs |

### Mock Framework

Sentinel uses interface-based dependency injection for testability:

- `testutil/mock_*.go` - Mock implementations
- All AWS clients wrapped in interfaces (`SSMAPI`, `STSAPI`, `DynamoDBAPI`)
- Time abstraction via `time.Now` injection

### Running Tests

```bash
# All tests
go test ./...

# With race detector (requires CGO)
CGO_ENABLED=1 go test -race ./...

# Security tests only
go test -run TestSecurityRegression ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 8. Common Patterns

### Provider Chain

Credentials are resolved through a chain of providers:
```
KeyringProvider -> SSOProvider -> AssumeRoleProvider -> CachedSessionProvider
```

Each provider either returns credentials or delegates to the next.

### Interface-Based Design

All external dependencies are wrapped in interfaces for testability:
```go
type SSMAPI interface {
    GetParameter(ctx, *ssm.GetParameterInput) (*ssm.GetParameterOutput, error)
    PutParameter(ctx, *ssm.PutParameterInput) (*ssm.PutParameterOutput, error)
}
```

### Error Wrapping

Errors use `fmt.Errorf` with `%w` for chain compatibility:
```go
return fmt.Errorf("failed to load policy: %w", err)
```

This enables `errors.Is()` and `errors.As()` for error handling.

### Configuration Precedence

Configuration follows this precedence (highest to lowest):
1. CLI flags
2. Environment variables
3. Policy-level settings
4. Profile configuration
5. Defaults

---

*Last updated: 2026-01-27*
*Intended audience: Engineers joining the Sentinel project*
