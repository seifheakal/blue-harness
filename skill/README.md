# skill/ — the Claude skill that drives the harness

A Claude Code skill that runs `harness/` against a target build, reads the audit
score, and recommends the next highest-value hardening for the operator's target.
This closes the product loop (CLAUDE.md "done and worth it" #4): **audit → score →
recommend → (apply) → re-audit.**

- `SKILL.md` — the skill definition (frontmatter + how Claude drives the loop,
  including the non-negotiable honesty rules: audit-first, tier + named bypass on
  every recommendation, server-side-truth, never "unbreakable").
- `carapace.py` — the deterministic driver the skill calls. The policy lives here
  (in one place, testable) so the skill's behavior is reproducible, not improvised.

```
python3 skill/carapace.py audit     <binary>               # full exposure report
python3 skill/carapace.py recommend <binary> [--all] [--json]
python3 skill/carapace.py apply     <binary> [--mode S|M|D] # post-build hardening only
```

`recommend` returns the next highest-value hardening with its **strength tier** and
a **named bypass**, labeled by kind:

- **post-build** — applicable to the shipped binary now (the dev↔release identity
  transform). `apply` runs it and writes a **private mapping file** to keep out of
  the artifact.
- **build-time** — requires a rebuild (core-dump / anti-ptrace guards). `apply`
  honestly **refuses** to fake these onto a built binary and points at the
  integration step.
- **roadmap** — valuable but not yet implemented here (e.g. live-string
  encryption), stated plainly.
- **design** — server-side relocation of secrets, the only *Strong* tier.

Verified by `harness/verify/test_slice_c.sh` (9/9): the loop runs, every
recommendation carries a tier + bypass and never overclaims, `apply` fires the
post-build hardening (app still runs), the recommendation then advances and the
score drops, and a build-time hardening is honestly refused.

**Install as a Claude Code skill:** copy or symlink this directory to
`.claude/skills/carapace/` (so `SKILL.md` is discovered). Status: **landed
(Slice C).**
