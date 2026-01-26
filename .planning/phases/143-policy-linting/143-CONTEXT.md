# Phase 143: Policy Linting - Context

**Gathered:** 2026-01-26
**Status:** Ready for planning

<vision>
## How This Should Work

Linting is integrated into the existing `sentinel policy validate` command — not a separate command. When users validate a policy, they get schema validation AND lint checks in one pass.

Output is minimal and compiler-like. Just the essential info: issue type and location. No verbose explanations or hand-holding — users reading lint output know what they're doing.

</vision>

<essential>
## What Must Be Nailed

- **All three lint checks equally important** — allow-before-deny conflicts, unreachable rules, and time window overlaps are all critical catches
- **Integrated experience** — linting happens automatically as part of `policy validate`, not a separate workflow
- **Minimal output** — terse, compiler-style errors with locations, no fluff

</essential>

<specifics>
## Specific Ideas

- Integrate into existing `sentinel policy validate` command
- Compiler-style output: issue type + location, nothing more
- Non-zero exit code when issues found (for CI/CD)

</specifics>

<notes>
## Additional Context

No additional notes

</notes>

---

*Phase: 143-policy-linting*
*Context gathered: 2026-01-26*
