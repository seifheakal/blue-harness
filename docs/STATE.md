# STATE — living handoff (read this right after CLAUDE.md)

> **Purpose:** the single "where we are / what's next" file. Every chat reads it
> at the start and **updates it at the end** before handing off. This is how we
> pass work between chats without dumping context. Keep it short and current.

- Last updated: 2026-10-26
- Phase: **Research ✅ → Analysis ✅ → Implementation ⬅ next → Testing**
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

## Next step (decided)
**Implementation — Slice A** (audit-first, binary pass/fail to lock the loop):
1. **Audit:** an ELF exposure scanner in `harness/` that reads the same signals
   `rea` reads (symbols/debug-info present, plaintext-string density, section
   entropy, hardening flags RELRO/NX/PIE/canary/CFG, Go/Rust/PyInstaller metadata,
   and "is an anti-debug / core-dump guard present?") and prints a scored, tiered
   posture report + the next highest-value hardening.
2. **Harden:** a **core-dump suppression** guard (`setrlimit(RLIMIT_CORE,0)`,
   `prctl(PR_SET_DUMPABLE,0)`) and an **anti-ptrace** guard (`PTRACE_TRACEME` +
   `/proc/self/status` TracerPid poll) for a sample Linux ELF. Each denies a
   *named* `rea` weapon (Cluster E crash-reader; Cluster G/H Frida+GDB).
3. **Verify:** tests proving (a) the audit flips present↔absent, and (b) the
   guards actually fire (no core produced; `ptrace(PTRACE_ATTACH)` refused) and
   the sample still runs.
Honesty: tier these **Speed-bump / Meaningful**, never "unbreakable" (CLAUDE.md §3).

**Then Slice B** (the operator's decoy idea, AI-specific): the dev↔release identity
transform — audit "identifier/string informativeness" + strip/decoy on a sample
binary with a private mapping file + verify round-trip. See `docs/re-techniques/rea.md`.

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
3. Before ending: update **this file** (Done / Next step / Parked), commit, push.
