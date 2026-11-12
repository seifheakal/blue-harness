# STATE — living handoff (read this right after CLAUDE.md)

> **Purpose:** the single "where we are / what's next" file. Every chat reads it
> at the start and **updates it at the end** before handing off. This is how we
> pass work between chats without dumping context. Keep it short and current.

- Last updated: 2026-11-12
- Phase: **Research ✅ → Analysis ✅ → Implementation (Slices A–P ✅) → Testing ✅ (265/265 via `make verify`, enforced in CI) → all three native formats audited; ELF/PE/Mach-O all have a post-build harden path; open items are operator decisions (below)**
- Competitive scan done (2026-11-05): `research/findings/2026-11-05-competitive-landscape.md`
  — peers now defend against AI-RE (BLA ~2.3k★ the serious one). Operator decision:
  **absorb their good ideas into Carapace** ("engulf"), keeping our native-depth +
  mechanism-proof edge. Absorb ideas, not their MIT code (clean-room).
- Worked specimen: **`rea`** (morluto/rea, npm `rea-agents`) — the P0 reference.
- **2026-11-12 — PR #1 merged to `main`** (merge `3b0205d`, branch deleted). The
  whole Slice H–O arc + the measured run landed on main. README was reworked
  (reader-facing: no internal slice jargon, a clear done/not-done/next section, a
  real comparison table, and a red top call-to-arms) and now opens with the
  hardware/model disclaimer. New `docs/HOW-WE-TESTED.md` documents both testing
  layers (mechanism proofs + the N=1 empirical run) and **publicly solicits
  bigger-model runs** so the one datapoint gets sharper over time.

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

- **Implementation — Slice J ✅ (honeytokens / canaries; Poison + attribution;
  15/15; now 137/137 across 10 slices).** The Poison/Hallucinate play, our way:
  - **Harden:** `harness/harden/carapace_honeytokens.py` — `plant` drops N
    plausible, format-valid FAKE secrets (AWS-style keys, bearer tokens, internal
    URLs, DB creds) into a non-alloc section (default `.carapace_honey`; never
    mapped → byte-identical runtime, provably unreferenced decoys) yet
    strings-visible, and writes a **private ledger** (unique token values per
    build). `check` matches a leaked token back to its exact build (canary).
    Deterministic (seeded).
  - **Audit:** `honeytokens_present` + `honeytoken_count` (guards section).
  - **Skill:** `honeytokens` recommendation (post-build; tier + named bypass +
    keep-ledger-private note).
  - **Verify:** `harness/verify/test_slice_j.sh` (**15/15**) — audit flips+counts;
    tokens unique + plausible (AKIA shape) + strings-visible; runtime
    byte-identical, app runs, `.dynsym` untouched, honey section proven non-alloc;
    attribution hits a leak (rc=7) + no false positive + unique per build;
    deterministic.
  - Tier **Speed-bump** (poison / time-waste) / **Meaningful FOR DETECTION**
    (attribution). Named bypass: xref-validate drops unreferenced tokens; the
    default section name is a tell (rename for production). Detects/attributes a
    crack — does not prevent it.

- **Implementation — Slice L ✅ (one-command `harden` + skill `install`; UX parity;
  17/17; now 154/154 across 11 slices).** Closed the ergonomics gap vs the peers'
  `npx … harden .`, honestly:
  - **Skill:** `skill/carapace.py harden <bin>` chains every applicable POST-BUILD
    pass in a safe order (identity decoy → exhaust → honeytokens), writes
    `<bin>.hardened` + the PRIVATE map/ledger, then prints the build-time guards it
    did **not** apply (with the rebuild step) and the server-side Strong tier — it
    never fakes a build-time guard. `carapace install [--user|--dir]` symlinks the
    skill into `.claude/skills/carapace` (idempotent; refuses to clobber a real dir).
  - **Front door:** `make harden BIN=…` and `make install-skill`.
  - **Verify:** `harness/verify/test_slice_l.sh` (**17/17**) — harden applies all 3
    post-build passes (map + exhaustion + honeytokens present), runtime
    byte-identical, defers the 5 build-time guards honestly, surfaces the Strong
    tier, tier+bypass on every applied item, no overclaim; install creates a working
    link, is idempotent, and refuses to clobber a real dir (rc=2).
  - `.gitignore`: harden/apply outputs under `harness/sample/` ignored (never ship
    the private keys). SKILL.md refreshed (removed the stale "roadmap" line — string
    encryption shipped in Slice F).

- **Implementation — Slice K ✅ (empirical harness + CrackMe + scorer; plumbing
  20/20; now 174/174 across 12 slices).** The *harness* is built and verified; the
  *effectiveness run itself* is **operator-gated** (needs a sandboxed, operator-
  owned `rea` VM — no offensive tooling in the dev container):
  - **CrackMe:** `harness/crackme/` — one source, two builds (`crackme_baseline`
    flag plaintext / `crackme_hardened` flag string-encrypted + build-time guards +
    post-build `carapace harden`). Flag plaintext never committed (env/`secret.local
    .txt`/labelled default); `seal.py` publishes only `SEAL.json` (the digest).
  - **Scorer:** `harness/measure/rea_measure.py` — honest by construction: a crack
    counts only if it hashes to the seal; tokens/wall are agent-reported and absent
    values read **not measured** (no estimate multipliers); honeytokens the agent
    surfaced are scored as poison + attribution; caveats printed. `run-template.json`
    is what the operator fills on the VM.
  - **Runbook:** `docs/workflow/slice-k-empirical-runbook.md` (sandboxed VM, build →
    run agent per variant → record → score → interpret; ethics/scope up top).
  - **Verify:** `harness/verify/test_slice_k.sh` (**20/20**) proves the PLUMBING
    (build/seal/verify round-trip, flag gone from hardened static view, honeytokens
    + exhaustion present, scorer verifies crack vs seal, attributes a honeytoken,
    multiplier from real inputs, "not measured" on absent data, readiness state) —
    explicitly **not** the effectiveness claim, which only the VM run yields.

- **Implementation — Slice M ✅ (format dispatch; PE reach; 13/13; now 187/187
  across 13 slices).** The Slice-G PE scanner was only reachable via
  `make audit-pe`; now the skill detects the format by magic byte and routes the
  one front door:
  - **Skill:** `_detect_format` (ELF `\x7fELF` / PE `MZ` / Mach-O magics) drives
    `carapace audit`/`report`/`recommend` to the right scanner; PE renders the PE
    audit + the format-independent server-side Strong truth. `apply`/`harden`
    **refuse** a non-ELF with guidance (rc 3) rather than mangling it — the ELF
    transforms are not pretended onto a PE. Unknown blobs error cleanly (rc 2, no
    traceback).
  - **Verify:** `harness/verify/test_slice_m.sh` (**13/13**) — audit routes ELF→ELF
    and PE→PE; PE report carries the audit + server-side truth and no ELF-only
    hardening; apply/harden refuse a PE and leave it byte-identical; ELF path
    unregressed; unsupported blob handled cleanly. Mach-O magic is already detected
    (wired lazily) — the scanner itself lands in Slice N.

- **Implementation — Slice N ✅ (Mach-O exposure audit — the third format; 21/21;
  now 208/208 across 14 slices).** Completes the native-format audit trio:
  - **Audit:** `harness/audit/macho_exposure_audit.py` — self-contained Mach-O
    parser (thin 32/64-bit, both byte orders, + fat/universal). Reads symbol-table
    size, `__TEXT,__cstring` density, section entropy, linked dylibs, PIE /
    stack-exec / `__RESTRICT` flags, a code signature (**read-only — presence only,
    not verified**), and `__TEXT` encryption (`LC_ENCRYPTION_INFO` cryptid). Scored
    + tiered parallel to the ELF/PE scanners. `make audit-macho BIN=…`.
  - **Fixture:** `harness/sample/macho_fixture.py` — toolchain-free generator
    (soft/hard/encrypted + a fat wrapper) so verify needs no Apple toolchain.
  - **Skill:** the Slice-M magic-byte dispatch now has a live Mach-O target
    (`audit`/`report`/`recommend` route it; `apply`/`harden` refuse it honestly).
  - **Verify:** `harness/verify/test_slice_n.sh` (**21/21**) — header/arch/filetype,
    symtab + `__cstring` + dylibs parsed; soft→hard flip (stripped + PIE +
    `__RESTRICT` + signed; score 64→18, tier changes); `__TEXT` encryption craters
    the score to 0; fat parsed; code-signature read-only note; skill routes Mach-O;
    non-Mach-O rejected cleanly.

- **Implementation — Slice O ✅ (Mach-O local-symbol strip — first Mach-O harden;
  15/15; now 223/223 across 15 slices).** The Mach-O analog of the ELF identity
  strip, platform-honest:
  - **Harden:** `harness/harden/carapace_macho_strip.py` — byte-level `strip -x`
    (no Apple/LLVM toolchain): removes LOCAL/static symbols via `LC_SYMTAB` +
    `LC_DYSYMTAB`, preserves external/undefined (dyld needs them), keeps all load
    commands/segments/sections and **file offsets stable** (in-place, size
    unchanged). Refuses fat / empty-symtab / no-`LC_DYSYMTAB` with guidance; warns
    if code-signed (strip → codesign order). Deterministic.
  - **Fixture:** `macho_fixture.py` now emits `LC_DYSYMTAB` + a local/external
    split so the strip is meaningful and testable.
  - **Skill:** `carapace apply <macho>` now dispatches to the strip (ELF `apply`
    unchanged; `harden` full-chain stays ELF-only). `make harden-macho BIN=…`.
  - **Verify:** `harness/verify/test_slice_o.sh` (**15/15**) — locals gone +
    externals preserved; symbol_count 6→2; size stable; segments/sections/dylibs
    byte-identical; still parses; deterministic; runtime caveat printed; fat /
    no-symbol inputs refused; skill drives it.
  - **Honest limit:** we can't execute a Mach-O on Linux, so this is a
    **structural** proof; **runtime-identical is platform-gated to a macOS host**
    (stated in the tool + verify, like the Slice K VM). Tier Speed-bump→Meaningful;
    bypass: exported names remain, behavior recoverable.

- **Implementation — Slice P ✅ (Windows PE harden path — first PE harden; 42/42;
  now 265/265 across 16 slices).** PE was audit-only (Slice G); now it has a
  post-build harden path with three provable, non-breaking levers, all proven
  STRUCTURALLY / byte-level on Linux with NO Windows host (same discipline as the
  Slice O Mach-O strip):
  - **Harden:** `harness/harden/carapace_pe_strip.py` — COFF symbol table + debug
    directory / CodeView PDB-path strip, **in-place, size stable**, proven surgical
    (only symbol/debug metadata bytes change; imports/exports/entry/sections/
    `SizeOfImage` byte-identical). `harness/harden/carapace_pe_exhaust.py` — decoy
    **non-mapped OVERLAY** regions (append-only; past every section's raw end, so
    the loader never maps them). `harness/harden/carapace_pe_honeytokens.py` —
    plausible fake secrets into the overlay + a **private ledger** (poison +
    attribution; token generators shared with the ELF Slice J).
  - **Audit:** `pe_exposure_audit.py` gains `decoy_overlay_present` +
    `honeytokens_present` (guards line; not scored) and its PDB recommendation now
    points at `carapace_pe_strip.py`.
  - **Fixture:** `pe_fixture.py` gains an `exposed` profile + `--coff-symbols`/
    `--signed` overrides so the strip has a COFF symbol table AND a PDB to remove
    (soft/hard/packed defaults untouched).
  - **Skill:** `carapace apply <pe>` → the strip; `carapace harden <pe>` → the full
    chain (strip → decoy overlay → honeytokens), writing a separate output + the
    private ledger, then honestly listing the build-time levers NOT applied (relink
    `/DYNAMICBASE /NXCOMPAT /GUARD:CF`, string encryption, runtime+server
    Authenticode) and the server-side Strong truth. Never fakes a build-time guard.
    `make harden-pe BIN=…`. Slice M updated (PE now dispatches, not refuses);
    ELF/Mach-O paths unchanged.
  - **Verify:** `harness/verify/test_slice_p.sh` (**42/42**) — audit flips
    present↔absent for all three levers; dev names + `.pdb` gone, imports preserved,
    strip surgical (every changed byte inside a metadata region), size stable;
    decoys provably non-mapped (append-only + past `mapped_end`); honeytokens unique
    + AKIA-plausible + strings-visible + attributable (rc 7) + unique per build;
    skill drives apply/harden; honest refusals (nothing-to-strip rc 2, non-PE rc 2)
    + Authenticode warnings + no overclaim.
  - **Honest limit:** we can't execute a PE on Linux, so this is a **structural**
    proof; **runtime-identical is platform-gated to a Windows host** (same class of
    gating as the Mach-O macOS host + the Slice K VM). Tiers: strip
    Speed-bump→Meaningful; exhaust Trivial→Speed-bump; honeytokens Speed-bump /
    Meaningful for DETECTION — each with a named bypass.

## Status: absorption plan complete
Every in-scope idea from the competitive scan is now folded in and
mechanism-proven: **I** (exhaust), **J** (poison/honeytokens), **K** (empirical
harness + CrackMe), **L** (one-command `harden` + install). The only things left
are **operator decisions / operator-gated actions**, not pending build work.

## Open items — operator decisions / gated (no in-flight build work)
1. **Run Slice K for real — ✅ DONE (2026-11-11).** Ran on an isolated,
   operator-owned VM: baseline **CRACKED** (hash-verified, 1,256 tok / 1.6s) vs
   hardened **not cracked** (16,785 tok / 195s; **13.4× tokens, 121.9× wall**) by
   a local `qwen2.5-coder:7b` shell-agent. Defenses seen firing: string-encryption
   (static grep empty), anti-debug (`strace`/`ltrace` refused), exhaustion (gdb/r2
   timed out). Honest limits: single VM, one 7B, N=1; honeytokens did **not** fire
   (agent blocked upstream); the agent was a **custom shell loop, not `rea`-via-
   Codex** — commodity local models emit tool calls as unparsed JSON text (Codex +
   Ollama both drop them), a P0-relevant friction finding. Detail + caveats:
   `research/findings/2026-11-11-slice-k-empirical-run.md`.
2. **Scope expansion** (the one real fork): native/mobile vs. adding Electron/JS/
   Wasm/.NET = a **CLAUDE.md §2 change**. Recommendation unchanged: keep the
   mechanism-proven native core; add a web/bundle track only as an explicit,
   separately-tiered second track, never silently. Confirm before any such work.
3. **PE/Mach-O reach** — ✅ DONE. PE dispatch (Slice M) + Mach-O audit (Slice N) +
   Mach-O local-symbol **harden** (Slice O) + **PE harden path** (Slice P: COFF/
   debug strip, decoy non-mapped overlay, honeytokens). All three native formats
   are audited and auto-detected, and **ELF, PE and Mach-O all have a post-build
   harden path**. Possible future increments (in-scope, no VM): more Mach-O harden
   (decoy/exhaust/honeytokens as added segments — trickier than ELF, needs care
   without a macOS host to verify), and mobile-container reach (APK `.so` / iOS).
   None pressing; raise with the operator before starting. **PE and Mach-O runtime
   verification is platform-gated to a Windows / macOS host respectively** (same
   class of gating as open item 1's VM — the harness proves the transforms
   structurally, byte-level, with no such host).

## Roadmap — absorbed from the competitive scan (ordered)
- **Slice I — Exhaust** — ✅ done.
- **Slice J — Poison/Hallucinate depth (honeytokens/canaries)** — ✅ done.
- **Slice K — Empirical harness + CrackMe + scorer** — ✅ harness done (plumbing
  20/20) **and run for real (2026-11-11)**: baseline cracked vs hardened not
  (13.4× tokens, 121.9× wall) — see open item 1 and
  `research/findings/2026-11-11-slice-k-empirical-run.md`.
- **Slice L — one-command `carapace harden` + skill `install`** — ✅ done (UX
  parity with `npx … harden .`, without faking build-time guards).
- **PE/Mach-O reach** — ✅ done: PE dispatch (Slice M) + Mach-O audit (Slice N) +
  Mach-O harden (Slice O) + **PE harden (Slice P)**; the skill auto-detects
  ELF/PE/Mach-O and all three have a post-build harden path. Remaining future
  increments: more Mach-O harden (added segments) + mobile-container reach.
- **REJECTED as a defense:** instruction-file barriers / terminal shims (antirea
  style) — relies on a cooperative model; violates CLAUDE.md §2. Never scored.

## Parked / needs operator action
- The Slice K run (2026-11-11) used a **custom shell-agent**, not `rea` itself,
  because commodity local models could not drive the `rea` MCP via Codex (tool
  calls emitted as unparsed JSON text). So the deep `rea`-internals questions
  (authoritative `tools/list`, Frida-script screening, GDB/MI reality, stripped
  decompile) remain open, as does a re-run with a reliably tool-calling model
  (e.g. Codex-native `gpt-oss`) and/or `rea` itself to exercise Slice J + the
  decompiler path. Nothing is blocked on it. **As of 2026-11-12 this re-run is
  publicly solicited** in the README (red top box) and `docs/HOW-WE-TESTED.md` —
  anyone with the hardware can run it against a bigger model and PR the scored
  result; a stronger, reliably tool-calling attacker is the only way to exercise
  the honeytoken poison/attribution path, which the 7B run never reached.
- P0 entries still `list (verify in research)`: `disasm-mcp`+`agentic-re` are in
  analysis (via `rea.md`); the rest await their own research passes.

## Handoff protocol (how chats pass work)
1. New chat: clone the repo, read `CLAUDE.md` then this file.
2. Do the "Next step." Keep the talking-chat thin; write detail to files
   (`research/findings/` or `docs/`), using `docs/workflow/handoff-template.md`.
3. Before ending: update **this file** (Done / Next step / Parked) AND append a
   dated bullet to `cv/contribution-of-blue-team.md` (Contribution Log), then
   commit and push.
