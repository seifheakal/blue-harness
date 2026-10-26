# STATE — living handoff (read this right after CLAUDE.md)

> **Purpose:** the single "where we are / what's next" file. Every chat reads it
> at the start and **updates it at the end** before handing off. This is how we
> pass work between chats without dumping context. Keep it short and current.

- Last updated: 2026-10-26
- Phase: **Research ✅ → Analysis ✅ → Implementation (Slice A ✅) → Testing ✅ for A → Slice B ⬅ next**
- Worked specimen: **`rea`** (morluto/rea, npm `rea-agents`) — the P0 reference.

## Done so far
- Project scaffolded; scope locked to **native binaries + mobile** (CLAUDE.md §2).
- P0 thesis set: **AI-assisted / commodity RE** as a 3-layer stack (model →
  tooling → distribution). Catalog: `docs/re-techniques/_index.md`.
- Research on `rea`: `research/findings/2026-10-25-rea-agents.md` (profile) and
  `research/findings/2026-10-25-rea-weapons-inventory.md` (full weapon inventory,
  cited).
- Analysis: `docs/re-techniques/rea.md` — weapon-by-weapon countermeasure matrix,
  honest tiers + bypasses, the dev↔release identity transform (operator's decoy
  idea), and the recommended implementation slices.
- **Implementation — Slice A ✅ (audit → harden → verify, all green).** In
  `harness/` (built on Linux x86-64, `make`+`python3`, no external deps):
  - **Audit:** `harness/audit/elf_exposure_audit.py` — read-only ELF exposure
    scanner (self-contained ELF parser). Reads the same signals `rea` reads
    (symbols/DWARF, string density, section entropy, PIE/NX/RELRO/canary/CET,
    Go/Rust/PyInstaller/UPX metadata, **core-dump & anti-ptrace guard present?**);
    emits a scored, tiered posture report + next highest-value hardening (`--json`
    for machines). Honest: labels itself heuristic, never "unbreakable."
  - **Harden:** `harness/harden/carapace_guards.{c,h}` — core-dump suppression
    (`setrlimit(RLIMIT_CORE,0)`+`prctl(PR_SET_DUMPABLE,0)`; denies rea **Cluster
    E**, tier *Speed-bump*) and anti-ptrace (TracerPid read **then**
    `PTRACE_TRACEME` slot-claim; denies **Cluster G/H**, tier *Meaningful*). Each
    carries its named bypass in-file.
  - **Sample:** `harness/sample/sample_app.c`+`Makefile` — one source, two builds
    (`sample_baseline` vs `sample_hardened` via `-DCARAPACE_HARDENED`) so the
    audit flip is attributable to the guards alone.
  - **Verify:** `harness/verify/test_slice_a.sh` (+ `ptrace_attach_probe.c`) —
    **15/15 hard assertions pass**: audit flips absent↔present (score 84→60);
    core-dump guard fires (`dumpable=0 rlimit_core=0`; real core for baseline, none
    for hardened); anti-ptrace fires (baseline `ATTACHED`, hardened refused with
    **EPERM**; gdb trips the TRACEME detection branch); hardened still runs.
  - Caught & fixed a real logic bug mid-slice: TracerPid must be read *before*
    TRACEME (TRACEME makes the parent the tracer → self-false-positive otherwise).

## Next step (decided)
**Implementation — Slice B** (the operator's decoy idea, AI-specific): the
dev↔release **identity transform** — targets the AI comprehension layer directly.
1. **Audit:** an "identifier/string informativeness" score (dictionary-word ratio
   of symbols, plaintext-string density, debug-info present) — how much free intel
   the binary hands an agent. Extends the Slice-A scanner.
2. **Harden:** build-time transform with modes **S** (strip/opaque), **M**
   (reversible secret map), **D** (decoy: plausible-but-wrong names/strings) on a
   sample native binary, emitting a **private mapping file** kept out of the ship.
3. **Verify:** dev-vs-release identity diff, mapping round-trips on a sample crash,
   and the app still runs correctly.
Honesty: tier **Speed-bump→Meaningful** (Meaningful vs lazy/one-shot agents),
never "unbreakable"; scope decoys to internal symbols only. See the dedicated
section in `docs/re-techniques/rea.md`.

## Parked / needs operator action
- A **sandboxed, operator-owned `rea` install** (throwaway VM) is the only way to
  resolve the deep open questions (authoritative `tools/list`, whether `rea`
  screens Frida scripts, GDB/MI reality, stripped-binary decompile). Not required
  for Slice A/B. Do not install offensive tooling in the dev container.
- P0 entries still `list (verify in research)`: `disasm-mcp`+`agentic-re` are in
  analysis (via `rea.md`); the rest await their own research passes.

## Handoff protocol (how chats pass work)
1. New chat: clone the repo, read `CLAUDE.md` then this file.
2. Do the "Next step." Keep the talking-chat thin; write detail to files
   (`research/findings/` or `docs/`), using `docs/workflow/handoff-template.md`.
3. Before ending: update **this file** (Done / Next step / Parked) AND append a
   dated bullet to `cv/contribution-of-blue-team.md` (Contribution Log), then
   commit and push.
