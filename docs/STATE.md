# STATE — living handoff (read this right after CLAUDE.md)

> **Purpose:** the single "where we are / what's next" file. Every chat reads it
> at the start and **updates it at the end** before handing off. This is how we
> pass work between chats without dumping context. Keep it short and current.

- Last updated: 2026-11-05
- Phase: **Research ✅ → Analysis ✅ → Implementation (Slices A–I ✅) → Testing ✅ (122/122 via `make verify`, enforced in CI) → Slice J (poison/hallucinate depth) ⬅ next**
- Competitive scan done (2026-11-05): `research/findings/2026-11-05-competitive-landscape.md`
  — peers now defend against AI-RE (BLA ~2.3k★ the serious one). Operator decision:
  **absorb their good ideas into Carapace** ("engulf"), keeping our native-depth +
  mechanism-proof edge. Absorb ideas, not their MIT code (clean-room).
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
- **Implementation — Slice B ✅ (dev↔release identity transform; the AI-layer
  decoy play).** In `harness/` (Linux x86-64, `python3`+binutils, no external
  deps):
  - **Audit:** extended `harness/audit/elf_exposure_audit.py` with an
    **identifier/string informativeness** block — ratio of the binary's own
    symbols that read as English words vs opaque, plus an informative-string
    count. Reported separately; does **not** alter the Slice-A exposure score.
    Factored a shared `own_symbols()` so audit and transform agree on scope.
  - **Harden:** `harness/harden/carapace_identity_transform.py` — operates on the
    compiled ELF via `objcopy`/`strip` with modes **S** (strip symtab+DWARF),
    **M** (opaque `cp_NNNNNN` + reversible map), **D** (plausible decoy names from
    `decoy_dictionary.txt` + reversible map); plus an opt-in **same-length**
    `.rodata` string-decoy pass. Emits a **private `mapping.json`** (new→old) kept
    out of the ship; `resolve` recovers dev names for crash triage. Scope =
    internal FUNC/OBJECT only; libc imports untouched. Denies rea Cluster B/C +
    the AI layer. Tier **Speed-bump→Meaningful**, bypass named in-file.
  - **Sample:** added an internal, never-printed `INTERNAL_BUILD_TAG` (folded into
    a volatile sink) as a sound string-decoy target; `sample_dev` build target.
  - **Verify:** `harness/verify/test_slice_b.sh` — **18/18 pass**: audit measures
    the transform (S total=0; M ratio≈0 opaque; D ratio≈1.0 plausible, and D reads
    more natural than M); mapping round-trips for every symbol + the string decoy;
    **no dev name leaks** into any artifact (nm+strings); byte-identical output in
    every mode; libc imports preserved.
  - Honest gap stated, not skipped: encrypting *live* strings needs a runtime
    decode loader (separate hardening); this slice decoys only declared-internal
    strings, behavior-guarded by the verify.

- **Implementation — Slice C ✅ (the drive-the-harness skill).** In `skill/`:
  - `skill/carapace.py` — deterministic driver over `harness/`: `audit` (full
    exposure report), `recommend [--all] [--json]` (next highest-value hardening
    with a strength tier + a **named bypass** on every item, ordered plan ending
    in the server-relocation Strong-tier truth), and `apply` (runs the post-build
    identity transform; **honestly refuses** to fake a build-time guard onto an
    already-built binary, pointing at the rebuild step instead).
  - `skill/SKILL.md` — the Claude skill: frontmatter + the audit→recommend→apply
    loop and the non-negotiable honesty rules (audit-first, tier+bypass verbatim,
    server-side truth, never "unbreakable"). Install by symlinking `skill/` to
    `.claude/skills/carapace/`.
  - **Verify:** `harness/verify/test_slice_c.sh` — **9/9 pass**: the loop runs,
    every recommendation carries a tier + bypass and never overclaims, `apply`
    fires the post-build hardening (app still runs), the recommendation advances
    (identity-transform → coredump-guard) and the score drops (84→39), and a
    build-time hardening is refused with guidance (rc=3).

- **Implementation — Slice D ✅ (runtime integrity/attestation + anti-Frida; rea
  Cluster G).** In `harness/` (libc-only C — self-contained SHA-256/HMAC, no
  OpenSSL; stdlib-only Python server):
  - **Harden:** `harness/harden/carapace_integrity.{c,h}` — SHA-256 of a hot
    function's loaded bytes + `HMAC(key, nonce || checksum)` attestation;
    `carapace_antifrida.{c,h}` — maps/thread-name/port-27042 (connect-probe) Frida
    scan; `harness/harden/attest_server.py` — reference server-nonce verifier.
    Tiers: anti-Frida *Meaningful*; integrity *Meaningful→Strong* (server-nonce
    binding), bypasses named in-file.
  - **Audit:** detects `integrity_guard_present` (our symbols or a SHA-256 constant
    tell) and `antifrida_guard_present` (our symbol or the Frida signature
    strings); reported in the guards section (not folded into the main score).
  - **Sample:** `harness/sample/sample_attest.c` — a hot "license check" fn with a
    patchable magic constant + modes (checksum/attest/antifrida/antifrida-plant).
  - **Verify:** `harness/verify/test_slice_d.sh` — **16/16**, no Frida installed
    (footprint reproduced; code patched on disk): audit flip; pristine ACCEPT (C
    MAC == stdlib `hmac`); patched hot-fn → server REJECT; replay → REJECT; patched
    app still runs; anti-Frida clean→clean and planted→maps+threads+port27042.
  - **Skill:** wired `antifrida-detector` + `integrity-attestation` into
    `skill/carapace.py`'s recommendation policy (present guards aren't re-recommended).

- **Implementation — Slice E ✅ (public front door + one-command demo).**
  - Repo-root `Makefile`: `make demo` (measure → prove in ~30s), `make verify`,
    `make report BIN=…`, `make audit BIN=…`, `make clean`.
  - `harness/verify/run_all.sh`: runs every slice and prints ONE consolidated
    posture summary (**65/65** across A–E), honest footer (proves they *fire*,
    not that they're unbreakable; each has a named bypass).
  - `skill/carapace.py report <bin>`: full audit + ordered hardening plan in one
    call. Reworded the honest footer to lead with the negation.
  - Refreshed `README.md` (quickstart, "what's built" tiers+bypasses table,
    honest "what it is / isn't", updated status) — no more "early scaffolding".
  - **Verify:** `harness/verify/test_slice_e.sh` (**7/7**) covers the `report`
    one-shot (audit+plan, tier+bypass on every item, no overclaiming).

- **Implementation — Slice F ✅ (build-time string encryption + runtime decode
  loader).** Closed the one gap the skill labelled *roadmap*:
  - **Harden:** `harness/harden/carapace_string_encrypt.py` (codegen: manifest →
    encrypted C byte tables, position-dependent xorshift32 keystream, enc|plain
    modes) + `harness/harden/carapace_strings.{c,h}` (runtime decode-on-demand
    loader, byte-identical keystream). Manifest `harness/sample/secret_strings.json`
    is the dev source of truth; the shipped binary carries only ciphertext.
  - **Audit:** `string_encryption_present` (enc-mode marker symbol — a name, not a
    plaintext tell) in the guards section.
  - **Sample:** `harness/sample/sample_strings.c` — one source, two builds
    (plaintext vs encrypted) from the one manifest, referencing CSTR_* ids only.
  - **Verify:** `harness/verify/test_slice_f.sh` (**10/10**) — every plaintext is
    in the plain build's bytes and **entirely gone** from the encrypted build;
    both decode to identical correct output at runtime; audit flips + string
    informativeness drops (7→3, density 0.60→0.10).
  - **Skill:** string-encryption rule promoted from `roadmap` to `build-time` with
    the real command; not recommended when already present.
  - Tier **Speed-bump→Meaningful**; named bypass (embedded key → recover at rest,
    or lift from memory at runtime) stated in-tool. Not a secret store.

- **Implementation — Slice G ✅ (PE / Windows exposure audit).** Audit-first, no
  new countermeasure:
  - **Audit:** `harness/audit/pe_exposure_audit.py` — self-contained PE32/PE32+
    parser (no `pefile`). Reads DllCharacteristics (ASLR/DEP/CFG/HighEntropyVA/SEH),
    imports (RVA→offset mapped) + exports, section entropy, string density,
    COFF-symbols + debug/PDB path, Authenticode presence (**read-only — does NOT
    verify**, the honest note it prints), and .NET/packer tells; scored + tiered
    like the ELF scanner. `make audit-pe BIN=…`.
  - **Fixture:** `harness/sample/pe_fixture.py` — minimal valid PE32+ generator
    (soft/hard/packed profiles) so verify needs no mingw.
  - **Verify:** `harness/verify/test_slice_g.sh` (**24/24**) — format/machine +
    import table parsed; DllCharacteristics flip soft→hard; PDB path recovered;
    Authenticode read-only; packer (UPX0 + high entropy); score soft(77)→hard(15);
    non-PE rejected gracefully. `make verify` now **99/99 across 7 slices**.

- **Implementation — Slice H ✅ (CI that enforces `make verify` on every
  push/PR).** No new countermeasure — it locks in the "prove it" guarantee:
  - **Workflow:** `.github/workflows/verify.yml` — Ubuntu runner, runs
    `make verify` on every `push` (all branches) and every `pull_request`.
    `concurrency` cancels superseded runs on the same ref; `permissions:
    contents: read` (least privilege). Installs **gdb** so Slice A's under-tracer
    detection branch runs (not skips), and sets `kernel.yama.ptrace_scope=0` so
    Slice A's anti-ptrace *control* (a sibling probe attaching to the unhardened
    baseline) works as designed. Neither weakens the test — the guards proven are
    in the binary, not the host policy. The real-core end-to-end check in Slice A
    self-skips on CI (apport `core_pattern`) and relies on its mechanism proof, as
    designed.
  - **Badge:** `README.md` carries the Actions status badge in the header and the
    Status section now says the gate is CI-enforced.
  - **Verify:** `harness/verify/test_slice_h.sh` (**9/9**) — a static *config lint*
    (does not launch Actions): asserts the workflow exists, triggers on push +
    pull_request, actually runs `make verify`, keeps both Slice-A accommodations
    (gdb + ptrace_scope), pins the checkout action, runs on Ubuntu, and that the
    README advertises the badge. So a future edit that silently drops the gate or
    an accommodation is caught by `make verify` itself. Negative-tested: the lint
    fails when the `make verify` step is removed.
  - `make verify` now **108/108 across 8 slices**.

- **Implementation — Slice I ✅ (analysis-surface Exhaust; 14/14; now 122/122
  across 9 slices).** Absorbed the peers' "Exhaust" axis into our native lane,
  mechanism-proven (not a size diff):
  - **Harden:** `harness/harden/carapace_exhaust.py` — post-build `objcopy` pass,
    two non-breaking levers: decoy **non-alloc** sections (`.carapace_exh_*`,
    SHF_ALLOC clear → never mapped at runtime) + synthetic **LOCAL FUNC** symbols
    (`carapace_exh_fn_*`, `.symtab` only → exports/`.dynsym` untouched).
    Deterministic (seeded) for reproducible builds.
  - **Audit:** `exhaustion_present` + measured `exhaust_decoy_bytes` /
    `exhaust_synth_symbols` / `nonalloc_byte_ratio` (guards section, not the main
    score).
  - **Skill:** added the `exhaustion` recommendation (post-build; tier + named
    bypass; not re-recommended when present).
  - **Verify:** `harness/verify/test_slice_i.sh` (**14/14**) — audit flips +
    measures; runtime output **byte-identical**, app still runs, **`.dynsym`
    byte-identical** (dynamic linking intact); decoy sections proven **non-alloc**;
    300 synthetic FUNC in `.symtab`, **zero** leaked into `.dynsym`; deterministic.
  - Tier **Trivial→Speed-bump** (Speed-bump vs the naive ingest-everything agent —
    the commodity path; Trivial vs anyone who filters). Named bypass: filter to
    SHF_ALLOC sections + code-referenced symbols. COST, not prevention.

## Next step (decided)
**Slice J — Poison/Hallucinate depth.** Extend the decoy transform (Slice B) with
honey-metadata + decoy control-flow/notes; fold Quarkslab's "agents fabricate
plausible-but-wrong output" insight (a correct-*looking* answer ≠ real analysis).
In scope, no VM. Audit→harden→verify as usual; honest tier + named bypass.

## Roadmap — absorbed from the competitive scan (ordered)
- **Slice I — Exhaust** — ✅ done (above).
- **Slice J — Poison/Hallucinate depth** — ⬅ next. Extend the decoy transform (Slice B)
  with honey-metadata + decoy control-flow notes; fold Quarkslab's "agents
  fabricate plausible-but-wrong output" insight. In scope, no VM.
- **Slice K — Empirical validation + CrackMe** — ⚠ **operator-gated**: needs a
  throwaway, operator-owned `rea` VM to measure decoy/exhaustion effect for real
  (no offensive tooling in the dev container). Ship a Carapace CrackMe (digest-
  sealed) built from our sample + slices. Produces *measured* numbers or none —
  no vendor-style "internal estimate" multipliers.
- **Slice L — one-command `carapace harden .` + MCP/skill install parity** (UX
  parity with `npx bla-agents harden .`). In scope.
- **PE/Mach-O reach** — wire PE into the skill's `audit`/`report` dispatch by
  magic byte (small, was the old Slice I); extend strip/transform to PE + Mach-O
  audit (third format) as those land.
- **REJECTED as a defense:** instruction-file barriers / terminal shims (antirea
  style) — relies on a cooperative model; violates CLAUDE.md §2. Never scored.

## Needs operator decision
- **Scope expansion:** "have all things" vs Electron/JS/Wasm/.NET bundles is a
  **CLAUDE.md §2 change**. Recommendation: keep native/mobile as the mechanism-
  proven core (our edge); add a web/bundle track only as an explicit, separately-
  tiered second track, never silently and never at the cost of "prove it".
  Confirm before any web/bundle work starts.

**Then / parked:** empirical AI-layer validation (decoy effectiveness,
coverage-poisoning) still needs the sandboxed, operator-owned `rea` VM — do not
install offensive tooling in the dev container.

## Parked / needs operator action
- A **sandboxed, operator-owned `rea` install** (throwaway VM) is the only way to
  resolve the deep open questions (authoritative `tools/list`, whether `rea`
  screens Frida scripts, GDB/MI reality, stripped-binary decompile). Not required
  for the implemented slices or the skill; it gates *empirical* validation of the
  AI-layer claims (decoy effectiveness, coverage-poisoning). Do not install
  offensive tooling in the dev container.
- P0 entries still `list (verify in research)`: `disasm-mcp`+`agentic-re` are in
  analysis (via `rea.md`); the rest await their own research passes.

## Handoff protocol (how chats pass work)
1. New chat: clone the repo, read `CLAUDE.md` then this file.
2. Do the "Next step." Keep the talking-chat thin; write detail to files
   (`research/findings/` or `docs/`), using `docs/workflow/handoff-template.md`.
3. Before ending: update **this file** (Done / Next step / Parked) AND append a
   dated bullet to `cv/contribution-of-blue-team.md` (Contribution Log), then
   commit and push.
