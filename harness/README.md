# harness/ — the Carapace hardening & audit harness

The tool an operator runs against **their own** native/mobile build. Three parts
(audit-first, per CLAUDE.md):

- **audit/** — measure a build's RE-resistance posture and score it. Reads the
  same signals the attacker's agent (e.g. `rea`) reads. Never changes the build.
- **harden/** — apply selected countermeasures (anti-debug, core-dump suppression,
  symbol/string transform, integrity, …). Each maps to a named attacker weapon.
- **verify/** — prove each hardening actually fires and that the audit detects its
  presence/absence. No countermeasure is "done" without a test here.

Status: empty — **Implementation Slice A** lands here first (see `docs/STATE.md`).
Every countermeasure carries a strength tier + named bypass (CLAUDE.md §3/§8).
