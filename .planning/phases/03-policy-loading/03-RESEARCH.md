# Phase 3: Policy Loading - Research

**Researched:** 2026-01-13
**Domain:** AWS SSM Parameter Store integration with Go (aws-sdk-go-v2)
**Confidence:** HIGH

<research_summary>
## Summary

Researched the aws-sdk-go-v2 SSM client for fetching policy documents from AWS Systems Manager Parameter Store. The project already uses aws-sdk-go-v2 (v1.41.0) for STS/SSO operations, so SSM integration follows established patterns.

Key finding: The existing codebase pattern of `service.NewFromConfig(cfg)` applies directly. SSM client creation mirrors the STS pattern in `vault/vault.go`. No special credential handling needed — sentinel can use the same credential provider chain that aws-vault uses.

**Primary recommendation:** Use `ssm.NewFromConfig(cfg)` with `GetParameter` API. Implement simple TTL-based caching with `sync.Mutex` + map (no external dependency needed). Handle `ParameterNotFound` error gracefully for missing policy scenarios.
</research_summary>

<standard_stack>
## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| github.com/aws/aws-sdk-go-v2/service/ssm | latest | SSM Parameter Store client | Official AWS SDK, already using v2 for STS |
| github.com/aws/aws-sdk-go-v2/config | v1.32.6 | Configuration loading | Already in project for credential chain |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| github.com/aws/smithy-go | v1.24.0 | Error type handling | Already indirect dependency, for API errors |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| GetParameter | GetParametersByPath | ByPath fetches multiple params under a path hierarchy — overkill for single policy |
| Simple TTL cache | jellydator/ttlcache | External dep for simple use case; stdlib solution sufficient |
| Standard tier | Advanced tier | Advanced costs money, 8KB limit; Standard tier 4KB free, policy fits easily |

**Installation:**
```bash
go get github.com/aws/aws-sdk-go-v2/service/ssm
```
</standard_stack>

<architecture_patterns>
## Architecture Patterns

### Recommended Project Structure
```
policy/
├── types.go           # Policy structs (existing)
├── parse.go           # YAML/JSON parsing (existing)
├── validate.go        # Validation (existing)
├── loader.go          # SSM loading (new)
├── loader_test.go     # Loader tests (new)
└── cache.go           # TTL cache (new)
```

### Pattern 1: SSM Client Creation (Follow aws-vault pattern)
**What:** Create SSM client using same pattern as STS client in vault/vault.go
**When to use:** Always — consistency with existing codebase
**Example:**
```go
// Source: Matches existing pattern in vault/vault.go:58
import (
    "context"
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/ssm"
)

func NewSSMClient(cfg aws.Config) *ssm.Client {
    return ssm.NewFromConfig(cfg)
}
```

### Pattern 2: GetParameter with Decryption
**What:** Fetch single parameter, auto-decrypt SecureString
**When to use:** Fetching policy document from SSM
**Example:**
```go
// Source: AWS docs, verified against pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/ssm
func (l *Loader) GetPolicy(ctx context.Context, parameterName string) (string, error) {
    output, err := l.client.GetParameter(ctx, &ssm.GetParameterInput{
        Name:           aws.String(parameterName),
        WithDecryption: aws.Bool(true), // Handles SecureString, ignored for String
    })
    if err != nil {
        return "", err
    }
    return *output.Parameter.Value, nil
}
```

### Pattern 3: Error Handling with Type Assertion
**What:** Check for specific SSM error types using errors.As
**When to use:** Distinguishing "not found" from other errors
**Example:**
```go
// Source: AWS SDK v2 error handling docs
import (
    "errors"
    "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func (l *Loader) GetPolicy(ctx context.Context, name string) (*policy.Policy, error) {
    output, err := l.client.GetParameter(ctx, &ssm.GetParameterInput{
        Name:           aws.String(name),
        WithDecryption: aws.Bool(true),
    })
    if err != nil {
        var notFound *types.ParameterNotFound
        if errors.As(err, &notFound) {
            return nil, fmt.Errorf("policy not found at %s: %w", name, ErrPolicyNotFound)
        }
        return nil, fmt.Errorf("failed to fetch policy: %w", err)
    }
    // Parse output.Parameter.Value...
}
```

### Pattern 4: Simple TTL Cache with sync.Mutex
**What:** In-memory cache with time-based expiration
**When to use:** Avoid repeated SSM calls within short time window
**Example:**
```go
// Source: Common Go pattern, no external dependency
type CachedLoader struct {
    loader   *Loader
    mu       sync.Mutex
    policy   *Policy
    expiry   time.Time
    ttl      time.Duration
}

func (c *CachedLoader) GetPolicy(ctx context.Context, name string) (*Policy, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.policy != nil && time.Now().Before(c.expiry) {
        return c.policy, nil
    }

    p, err := c.loader.GetPolicy(ctx, name)
    if err != nil {
        return nil, err
    }

    c.policy = p
    c.expiry = time.Now().Add(c.ttl)
    return p, nil
}
```

### Anti-Patterns to Avoid
- **Creating new client per request:** Cache the SSM client, create once
- **Ignoring WithDecryption:** Always set true, it's ignored for non-SecureString
- **Using GetParameters for single param:** GetParameter is more efficient
- **External cache library for single value:** Overkill, simple mutex+map sufficient
- **Polling with goroutine:** CLI tool, not daemon; fetch on demand
</architecture_patterns>

<dont_hand_roll>
## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Credential resolution | Custom env var parsing | aws-vault credential provider | Already handles SSO, keyring, session caching |
| Retry logic | Custom retry loops | SDK built-in retry | aws-sdk-go-v2 handles retries with backoff |
| SecureString decryption | KMS client calls | WithDecryption: true | SSM handles KMS automatically |
| Config loading | Manual file parsing | config.LoadDefaultConfig | Handles all credential chain sources |
| Error classification | String matching | errors.As with types | SDK provides typed errors |

**Key insight:** The aws-sdk-go-v2 already handles the hard parts (retries, credential chains, encryption). Just use the high-level APIs.
</dont_hand_roll>

<common_pitfalls>
## Common Pitfalls

### Pitfall 1: Rate Limiting/Throttling
**What goes wrong:** ThrottlingException when calling GetParameter frequently
**Why it happens:** SSM has rate limits (now 10,000 TPS for GetParameter, was 3,000 before July 2023)
**How to avoid:** Implement caching with reasonable TTL (30s-5m); sentinel is CLI, not high-frequency
**Warning signs:** "Rate exceeded" errors in logs

### Pitfall 2: Parameter Size Limits
**What goes wrong:** Policy truncated or fails to save
**Why it happens:** Standard tier limit is 4KB, advanced tier is 8KB
**How to avoid:** Keep policies concise; 4KB is plenty for rule-based policies; validate size on write
**Warning signs:** Policies missing rules, silent truncation

### Pitfall 3: Region Mismatch
**What goes wrong:** ParameterNotFound when parameter exists
**Why it happens:** SSM is regional; parameter in us-west-2 won't be found from us-east-1
**How to avoid:** Document expected region; consider config option for policy region
**Warning signs:** Works in one region, fails in another

### Pitfall 4: Missing IAM Permissions
**What goes wrong:** Access denied errors
**Why it happens:** User/role needs ssm:GetParameter permission (and kms:Decrypt for SecureString)
**How to avoid:** Document required IAM policy; provide clear error message
**Warning signs:** "Access denied" or "not authorized" errors

### Pitfall 5: Credential Chain Confusion
**What goes wrong:** SSM call uses different credentials than intended
**Why it happens:** config.LoadDefaultConfig uses default chain, not aws-vault credentials
**How to avoid:** Pass explicit credentials to SSM client OR document that policy fetch uses ambient creds
**Warning signs:** Policy fetch works/fails independently of aws-vault profile
</common_pitfalls>

<code_examples>
## Code Examples

Verified patterns from official sources:

### Complete Loader Implementation
```go
// Source: Adapted from aws-sdk-go-v2 docs and aws-vault patterns
package policy

import (
    "context"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/ssm"
    "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

var ErrPolicyNotFound = errors.New("policy not found")

type Loader struct {
    client *ssm.Client
}

func NewLoader(cfg aws.Config) *Loader {
    return &Loader{
        client: ssm.NewFromConfig(cfg),
    }
}

func (l *Loader) Load(ctx context.Context, parameterName string) (*Policy, error) {
    output, err := l.client.GetParameter(ctx, &ssm.GetParameterInput{
        Name:           aws.String(parameterName),
        WithDecryption: aws.Bool(true),
    })
    if err != nil {
        var notFound *types.ParameterNotFound
        if errors.As(err, &notFound) {
            return nil, fmt.Errorf("%s: %w", parameterName, ErrPolicyNotFound)
        }
        return nil, fmt.Errorf("ssm GetParameter failed: %w", err)
    }

    return Parse([]byte(*output.Parameter.Value))
}
```

### Cached Loader
```go
// Source: Common Go caching pattern
type CachedLoader struct {
    loader *Loader
    mu     sync.RWMutex
    cache  map[string]*cacheEntry
    ttl    time.Duration
}

type cacheEntry struct {
    policy *Policy
    expiry time.Time
}

func NewCachedLoader(loader *Loader, ttl time.Duration) *CachedLoader {
    return &CachedLoader{
        loader: loader,
        cache:  make(map[string]*cacheEntry),
        ttl:    ttl,
    }
}

func (c *CachedLoader) Load(ctx context.Context, name string) (*Policy, error) {
    // Try read lock first
    c.mu.RLock()
    if entry, ok := c.cache[name]; ok && time.Now().Before(entry.expiry) {
        c.mu.RUnlock()
        return entry.policy, nil
    }
    c.mu.RUnlock()

    // Cache miss or expired, fetch with write lock
    c.mu.Lock()
    defer c.mu.Unlock()

    // Double-check after acquiring write lock
    if entry, ok := c.cache[name]; ok && time.Now().Before(entry.expiry) {
        return entry.policy, nil
    }

    policy, err := c.loader.Load(ctx, name)
    if err != nil {
        return nil, err
    }

    c.cache[name] = &cacheEntry{
        policy: policy,
        expiry: time.Now().Add(c.ttl),
    }
    return policy, nil
}
```

### Integration with aws-vault Credentials
```go
// Source: Follows vault/vault.go pattern
package policy

import (
    "context"
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
)

// LoaderFromDefaultConfig creates a Loader using default AWS credential chain.
// This uses ambient credentials (env vars, ~/.aws/credentials, IAM role).
func LoaderFromDefaultConfig(ctx context.Context, region string) (*Loader, error) {
    cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
    if err != nil {
        return nil, err
    }
    return NewLoader(cfg), nil
}

// LoaderFromCredentials creates a Loader with explicit credentials.
// Use this to create SSM client with aws-vault provided credentials.
func LoaderFromCredentials(creds aws.CredentialsProvider, region string) *Loader {
    cfg := aws.Config{
        Region:      region,
        Credentials: creds,
    }
    return NewLoader(cfg)
}
```
</code_examples>

<sota_updates>
## State of the Art (2024-2026)

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| aws-sdk-go v1 | aws-sdk-go-v2 | v1 EOL July 2025 | Must use v2, project already does |
| 3,000 TPS limit | 10,000 TPS limit | July 2023 | Less concern about rate limits |
| Manual retry | Built-in retry | aws-sdk-go-v2 | Don't implement custom retry |

**New tools/patterns to consider:**
- **SSM Parameter labels:** Can version policies with labels like `/sentinel/policy:production`
- **Parameter policies:** Can set expiration/notification on parameters (advanced tier only)

**Deprecated/outdated:**
- **aws-sdk-go v1:** End of support July 31, 2025; project uses v2
- **Manual credential handling:** Use config.LoadDefaultConfig or explicit provider
</sota_updates>

<open_questions>
## Open Questions

Things that need design decisions during planning:

1. **Which credentials fetch the policy?**
   - What we know: Can use default credential chain OR explicit aws-vault credentials
   - What's unclear: Should policy fetch use ambient creds or profile-specific creds?
   - Recommendation: Use ambient credentials (simpler); document IAM requirements

2. **Parameter path convention?**
   - What we know: SSM supports hierarchical paths like `/sentinel/policies/default`
   - What's unclear: Single global policy or per-profile policies?
   - Recommendation: Start with single path (e.g., `/sentinel/policy`), configurable via flag

3. **Cache invalidation trigger?**
   - What we know: TTL-based expiration is simple and sufficient
   - What's unclear: What TTL is appropriate for CLI tool?
   - Recommendation: Default 60 seconds, configurable; short-lived CLI invocations may not benefit from cache

4. **SecureString vs String parameter type?**
   - What we know: WithDecryption handles both; SecureString encrypts at rest
   - What's unclear: Are policies sensitive enough to warrant SecureString?
   - Recommendation: Support both; let org decide; String is simpler, SecureString more secure
</open_questions>

<sources>
## Sources

### Primary (HIGH confidence)
- [aws-sdk-go-v2/service/ssm - pkg.go.dev](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/ssm) - SSM client API
- [GetParameter API - AWS Docs](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html) - Request/response format, errors
- [Configure the SDK - AWS Docs](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html) - Credential chain, LoadDefaultConfig
- [Parameter hierarchies - AWS Docs](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-hierarchies.html) - Path conventions

### Secondary (MEDIUM confidence)
- [SSM rate limits - AWS re:Post](https://repost.aws/knowledge-center/ssm-parameter-store-rate-exceeded) - Throttling solutions
- [Parameter tiers - AWS Docs](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-advanced-parameters.html) - 4KB vs 8KB limits
- Existing codebase `vault/vault.go` - Verified client creation patterns

### Tertiary (LOW confidence - needs validation)
- None - all findings verified against official sources
</sources>

<metadata>
## Metadata

**Research scope:**
- Core technology: aws-sdk-go-v2 SSM client
- Ecosystem: Existing aws-vault patterns, Go stdlib caching
- Patterns: Client creation, error handling, caching
- Pitfalls: Rate limits, size limits, credentials, region

**Confidence breakdown:**
- Standard stack: HIGH - aws-sdk-go-v2 already in project
- Architecture: HIGH - follows existing vault patterns
- Pitfalls: HIGH - documented in AWS docs and issues
- Code examples: HIGH - adapted from official docs and existing codebase

**Research date:** 2026-01-13
**Valid until:** 2026-02-13 (30 days - SDK stable)
</metadata>

---

*Phase: 03-policy-loading*
*Research completed: 2026-01-13*
*Ready for planning: yes*
