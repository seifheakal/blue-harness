# harness/ — the Carapace hardening & audit harness

The tool an operator runs against **their own** native/mobile build. Three parts
(audit-first, per CLAUDE.md):

- **audit/** — measure a build's RE-resistance posture and score it. Reads the
  same signals the attacker's agent (e.g. `rea`) reads. Never changes the build.
- **harden/** — apply selected countermeasures (anti-debug, core-dump suppression,
  symbol/string transform, integrity, …). Each maps to a named attacker weapon.
- **verify/** — prove each hardening actually fires and that the audit detects its
  presence/absence. No countermeasure is "done" without a test here.

Status: **Implementation Slice A landed** (see `docs/STATE.md`). Every
countermeasure carries a strength tier + named bypass (CLAUDE.md §3/§8).

```
harness/
  audit/   elf_exposure_audit.py   — read-only ELF exposure scanner (scored, tiered)
  harden/  carapace_guards.{c,h}   — core-dump suppression + anti-ptrace guards
  sample/  sample_app.c + Makefile — one source, two builds (baseline / hardened)
  verify/  test_slice_a.sh         — proves the audit flips and both guards fire
```

Prove the whole slice end-to-end:

```
bash harness/verify/test_slice_a.sh     # exit 0 = Slice A verified
```

Each subdirectory has its own README (signals read, tiers, bypasses, how to run).
Slice A denies two **named `rea` weapons**: Cluster E (`inspect_recorded_crash`)
and Cluster G/H (Frida-attach + GDB). Honest tiers: Speed-bump / Meaningful —
never "unbreakable."
