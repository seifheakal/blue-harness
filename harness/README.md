# harness/ — the Carapace hardening & audit harness

The tool an operator runs against **their own** native/mobile build. Three parts
(audit-first, per CLAUDE.md):

- **audit/** — measure a build's RE-resistance posture and score it. Reads the
  same signals the attacker's agent (e.g. `rea`) reads. Never changes the build.
- **harden/** — apply selected countermeasures (anti-debug, core-dump suppression,
  symbol/string transform, integrity, …). Each maps to a named attacker weapon.
- **verify/** — prove each hardening actually fires and that the audit detects its
  presence/absence. No countermeasure is "done" without a test here.

Status: **Implementation Slices A + B landed** (see `docs/STATE.md`). Every
countermeasure carries a strength tier + named bypass (CLAUDE.md §3/§8).

```
harness/
  audit/   elf_exposure_audit.py          — read-only ELF exposure scanner
                                            (scored/tiered + informativeness)
  harden/  carapace_guards.{c,h}          — core-dump + anti-ptrace guards (Slice A)
           carapace_identity_transform.py — dev<->release S/M/D transform (Slice B)
           decoy_dictionary.txt           — plausible decoy names for Mode D
           carapace_integrity.{c,h}       — code-integrity + attestation (Slice D)
           carapace_antifrida.{c,h}       — anti-Frida detector (Slice D)
           attest_server.py               — reference server-nonce verifier (Slice D)
  sample/  sample_app.c, sample_attest.c  — samples (+ Makefile): baseline/hardened/dev/attest
  verify/  test_slice_a.sh                — audit flips + both guards fire (15/15)
           test_slice_b.sh                — identity transform measured + round-trips (18/18)
           test_slice_c.sh                — the drive-the-harness skill loop (9/9)
           test_slice_d.sh                — integrity/attestation + anti-Frida (16/16)
```

The driver + skill that tie this together live in `../skill/` (Slice C): run the
audit, read the posture, recommend/apply the next highest-value hardening.

Prove the slices end-to-end:

```
bash harness/verify/test_slice_a.sh     # exit 0 = Slice A verified
bash harness/verify/test_slice_b.sh     # exit 0 = Slice B verified
bash harness/verify/test_slice_c.sh     # exit 0 = Slice C verified
bash harness/verify/test_slice_d.sh     # exit 0 = Slice D verified
```

Each subdirectory has its own README (signals read, tiers, bypasses, how to run).
Named `rea` weapons denied/degraded so far: Cluster E (`inspect_recorded_crash`),
Cluster G (Frida attach/inject/patch) + Cluster H (GDB), and Cluster B/C + the AI
layer (names/strings the agent reasons from). Honest tiers: Speed-bump /
Meaningful, with integrity→Strong only when server-nonce-tied — never
"unbreakable."
