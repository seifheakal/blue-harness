# harness/verify — Slice A proof

No countermeasure is "done" until a test demonstrates it (CLAUDE.md §4).

```
bash test_slice_a.sh        # Slice A: core-dump + anti-ptrace guards
bash test_slice_b.sh        # Slice B: dev<->release identity transform
```
Exit 0 = all hard assertions passed.

`test_slice_a.sh` builds the sample + the attach probe, then proves the three
claims from `docs/STATE.md` on real binaries (mechanism-level, not vibes):

**(A) The AUDIT flips present↔absent** — baseline reports both guards ABSENT,
hardened reports both PRESENT, and the exposure score drops (84 → 60 here).

**(B) The core-dump guard FIRES** — hardened `dumpstate` shows
`dumpable=0 rlimit_core=0` (environment-independent mechanism proof), and a real
SIGSEGV produces a `core` file for baseline but **none** for hardened (end-to-end;
auto-skipped with a reason if `core_pattern` isn't observable in cwd). The
hardened sample still runs (`ran OK`).

**(C) The anti-ptrace guard FIRES** — `PTRACE_ATTACH` to a live baseline process
succeeds (`ATTACHED`); to the hardened process it is refused with **EPERM**
(errno=1 "already traced" — asserted specifically, so an early-exit ESRCH can't
pass for the wrong reason). Running hardened under `gdb` trips the TRACEME
detection branch (exit 42). The hardened sample still runs.

`ptrace_attach_probe.c` — deterministic stand-in for "a debugger / Frida tries to
attach" (both use ptrace on Linux): exit 0 `ATTACHED` / exit 1 `REFUSED errno=<n>`.

### Slice B — `test_slice_b.sh` (18/18)

Proves the dev↔release identity transform on a real sample ELF:

**(A) The AUDIT measures it** — dev symbols read as English (ratio≈1.0); Mode S
strips them (total=0); Mode M renames to opaque tokens (ratio≈0); Mode D keeps
them plausible (ratio≈1.0) — and D reads more natural than M, the honest
distinguishing property (D avoids the "opaque ⇒ obfuscated" tell).

**(B) The private MAPPING round-trips** — every release symbol resolves back to
its dev original (full set, via the `resolve` CLI); the internal string decoy
resolves too; and **no dev name leaks** into any shipped artifact (`nm` + `strings`
checked on all three).

**(C) The app still runs** — byte-identical output in every mode; libc imports are
preserved (scope = internal symbols only, so dynamic linking stays intact).

**Honest scope:** both harnesses prove the countermeasures *fire* and the audit
*detects/measures* them. Neither claims unbypassability — see each countermeasure's
named bypass in `../harden/README.md`.
