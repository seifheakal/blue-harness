# Mach-O harden path — attacker steps → countermeasures (Slices N/O/Q)

> Blue-team only (CLAUDE.md §3). We harden a Mach-O **the operator owns**. Every lever
> names a strength tier and a bypass; nothing here is "unbreakable." We run on Linux and
> cannot execute a Mach-O, so each transform is proven **structurally / byte-level** and
> runtime-identical is **platform-gated to a macOS host** (same discipline as the PE
> path, Slice P, and the Slice K VM).

## The attacker (AI-assisted RE on a Mach-O)
A commodity AI-RE agent (e.g. rea driving Ghidra/radare2/Frida) mines a shipped Mach-O
for free: the **symbol table** (internal names), **`__TEXT,__cstring`** plaintext, the
**load-command / segment map** and section inventory (`otool -l`-style), linked dylibs,
and — if present — a crash dump or a live process. It reads an on-disk **code signature**
but does not verify it. The AI layer especially leans on readable names + a small,
clean inventory it can fit in a context window.

## Steps and countermeasures

| Attacker step | Carapace countermeasure | Slice | Tier | Named bypass |
|---|---|---|---|---|
| Read the posture for free (symtab size, string density, entropy, PIE/`__RESTRICT`/signature/`__TEXT` encryption) | **Audit** `macho_exposure_audit.py` (read-only, scored, tiered) — *measure first* | N | n/a (read-only) | — |
| Mine internal (LOCAL/static) symbol names | **Local-symbol strip** (`strip -x` equivalent, byte-level; externals dyld needs preserved) | O | Speed-bump→Meaningful | exported names remain; logic recoverable from behaviour/xrefs |
| Ingest the whole file / enumerate every segment to build a map | **Decoy non-mapped segment + trailer** (`carapace_macho_exhaust.py`): bulk decoy bytes in the non-mapped trailer **and** a real `LC_SEGMENT_64 __CARAPACE_EXH` with `vmsize=0` (dyld ignores it → maps nothing), spliced into header pad in place | Q | Trivial→Speed-bump | a loader-faithful tool reads only mapped segments and drops `vmsize==0` LCs + the trailer (a one-line filter) — this is **cost**, not prevention |
| Trust mined "secrets" as real findings; (later) attribute a leaked crack | **Honeytokens / canaries** (`carapace_macho_honeytokens.py`): plausible fake secrets in the non-mapped trailer + a **private** per-build ledger (`check` attributes a leak) | Q | Speed-bump (poison) / Meaningful FOR DETECTION (attribution) | xref-validate drops unreferenced tokens; the default marker is a tell — rename for production |
| Read `__cstring` plaintext live strings | Encrypt + decode-on-demand (ELF `carapace_string_encrypt.py` today; Mach-O codegen is future work) | — | Speed-bump→Meaningful | embedded key → recover at rest / lift from memory |
| Keep any client-side secret at all | **Relocate secrets & trust server-side** (the only Strong tier) | — | Strong | none for the relocated secret; client still needs anti-tamper on the request path |

## Why the decoy is a real *segment* (and why it needs header pad)
`LC_SEGMENT_64` (cmd `0x19`) is Mach-O's native "map this file range" extension point.
dyld **ignores a segment whose `vmsize == 0`**, so such a segment reserves no address
space and maps nothing — provably non-mapped from the load-command bytes, and inert to
the loader. Load commands must sit contiguously below the first segment's file data, so
splicing one in place needs ≥ its `cmdsize` (72 B for a section-less `segment_64`) of
zero **header pad**. ld64's default pad is only 32 B; a real target wants
`-Wl,-headerpad_max_install_names`. When the pad is too small we **do not corrupt the
file**: we fall back to a trailer-only decoy and report it with the relink remedy.
See `research/findings/2026-11-13-macho-harden-levers.md` for the cited format facts.

## Proof without a macOS host (what `test_slice_q.sh` asserts)
1. **Surgical splice** — every changed in-file byte lies in the header pad we consumed
   or the two mach-header count fields (`ncmds`, `sizeofcmds`); the consumed pad bytes
   were zero in the input (we overwrote padding, nothing else moved).
2. **Maps nothing** — the added `__CARAPACE_EXH` segment has `vmsize == 0`
   (`initprot == maxprot == 0`).
3. **Non-mapped trailer** — decoy/honey bytes sit at the original EOF, past `mapped_end`
   (the end of every segment/section/table), so no segment maps them; append-only prefix.
4. **Honeytokens** — unique + plausible (AKIA shape) + whole-file-strings-visible;
   `check` attributes a leak (rc 7) and does not false-fire; unique per build.
5. **Honest** — tier + bypass on every lever, the macOS-host caveat printed, fat/32-bit/
   nothing-to-do inputs refused cleanly, code-signature warnings, no "unbreakable".
