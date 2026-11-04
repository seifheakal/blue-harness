# harness/verify — Slice A proof

No countermeasure is "done" until a test demonstrates it (CLAUDE.md §4).

```
bash test_slice_a.sh        # Slice A: core-dump + anti-ptrace guards
bash test_slice_b.sh        # Slice B: dev<->release identity transform
bash test_slice_c.sh        # Slice C: the drive-the-harness skill loop
bash test_slice_d.sh        # Slice D: integrity/attestation + anti-Frida
bash test_slice_e.sh        # Slice E: the report one-shot (front door)
bash test_slice_f.sh        # Slice F: build-time string encryption
bash test_slice_g.sh        # Slice G: PE/Windows exposure audit

bash run_all.sh             # run every slice, print ONE posture summary (= make verify)
```
Exit 0 = all hard assertions passed. `run_all.sh` (what `make verify` calls from
the repo root) runs all seven slices and prints a single consolidated table (99/99).

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

### Slice C — `test_slice_c.sh` (9/9)

Proves the drive-the-harness skill (`../../skill/`): `carapace audit` reports a
posture; `carapace recommend` yields the next highest-value hardening with a
strength tier **and** a named bypass on every item and never overclaims;
`carapace apply` fires the post-build hardening (app still runs), the
recommendation then advances (identity-transform → coredump-guard) and the score
drops; and a build-time hardening is **honestly refused** rather than faked onto
an already-built binary.

### Slice D — `test_slice_d.sh` (16/16)

Proves the runtime integrity/attestation + anti-Frida guards **without installing
Frida** (the test reproduces the exact OS footprint Frida leaves and patches the
on-disk code):

- the audit detects both guards present↔absent;
- **integrity/attestation fires** — the C client MAC matches the stdlib server
  (SHA-256/HMAC correct) so a pristine build is ACCEPTED; patching the hot
  function's license-check constant on disk changes the checksum and the server
  **REJECTS** it; a replayed response is **REJECTED** (fresh nonce); and the
  patched app still runs locally — the server is the gate;
- **anti-Frida fires** — a clean process is clean (no false positive); a process
  carrying a `frida-agent` mapping + a `gum-js-loop` thread + a `:27042` listener
  is detected on all three signals.

### Slice E — `test_slice_e.sh` (7/7)

Covers the front-door `report` one-shot (`skill/carapace.py report`): it exits 0,
renders the full audit **and** the ordered hardening plan in one call, every plan
item carries a strength tier + a named bypass, the server-side-relocation Strong
tier is surfaced, and it never overclaims ("unbreakable" appears only as a
negation). Slice E adds no countermeasure — this just keeps the new skill code
tested.

### Slice F — `test_slice_f.sh` (10/10)

Proves build-time string encryption on two builds from one manifest (plaintext vs
encrypted): every protected plaintext is present in the plain build's bytes and
**entirely gone** from the encrypted build; both decode to identical, correct
output at runtime; and the audit flips `string_encryption_present` and shows the
string informativeness drop.

### Slice G — `test_slice_g.sh` (24/24)

Proves the **PE/Windows exposure audit** (`../audit/pe_exposure_audit.py`) on
minimal PE32+ fixtures generated in-process by `../sample/pe_fixture.py` (no
mingw/pefile needed): it parses format/machine and the import table (KERNEL32:
CreateFileW, VirtualProtect, …); the DllCharacteristics flip soft→hard
(ASLR/DEP/CFG/HighEntropyVA); it recovers a PDB path, reports Authenticode
presence **as read-only / not verified**, flags a packer (UPX0 + high entropy),
drops the exposure score soft(77)→hard(15), and rejects a non-PE gracefully.

**Honest scope:** these harnesses prove the countermeasures *fire*, the audit
*detects/measures* them, and the skill *recommends honestly*. None claims
unbypassability — see each countermeasure's named bypass in `../harden/README.md`.
