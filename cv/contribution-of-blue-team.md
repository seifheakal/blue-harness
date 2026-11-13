# Contribution — Blue Team Project (Carapace)

> Living CV / portfolio record for this project. **Append a dated entry to the
> Contribution Log after every meaningful bit of progress.** Keep claims honest
> and matched to what actually exists (see the repo); never overstate.

---

## Headline (CV-ready)
**Carapace — Defensive Anti-Reverse-Engineering Hardening & Audit Harness**
*Protecting shipped native and mobile apps against the new wave of AI-assisted,
one-command reverse engineering.*

- **Role:** Creator & lead — security engineering, threat research, design, implementation.
- **Type:** Independent blue-team / application-security project.
- **Repo:** https://github.com/seifheakal/blue_team (private)
- **Status:** Active — research & analysis complete on the first threat specimen;
  harness implementation underway.

## Summary (2–3 sentences for a CV / LinkedIn)
Designing and building a defensive toolkit that measures and raises a native or
mobile application's resistance to reverse engineering, with a specific focus on
the emerging threat of **AI-driven, low-skill RE** (agent + MCP tooling and
uncensored local models). The project pairs a cited threat catalog with a
build-time **audit → harden → verify** harness, and holds itself to honest
security claims — every countermeasure ships with a realistic strength tier and a
known bypass.

## Why it matters (the thesis — current and interview-worthy)
Reverse engineering used to require real skill and classic tools (Ghidra, IDA,
Frida). The material shift is the **collapse of the skill floor**: anyone can now
install an AI agent skill or MCP server, point it at a binary or app, and get
readable code or a working hook from a single prompt — and route around model
refusals using uncensored local models. This project treats *that* democratized
threat as Priority 0 and builds defenses for it.

## Key contributions so far
- **Framed the modern RE threat model.** Identified AI-assisted / commodity RE as
  the priority threat and modeled it as a three-layer stack — *model* (uncensored
  local LLMs) → *tooling* (disassembler MCP servers, autonomous RE agents) →
  *distribution* (crack-as-a-service, agent skill routers). Encoded the hard
  assumption that the attacker's model is fully cooperative and unrestricted.
- **Built a structured, cited threat catalog** of AI-RE tooling scoped to native
  (ELF/PE/Mach-O) and mobile (Android/iOS) targets.
- **Performed read-only threat-intelligence analysis of a real P0 specimen**
  (`rea` / `rea-agents`), enumerating ~75–80 capabilities and mapping each to the
  target dependency it relies on and its observable footprint — all from public
  sources, cited and dated.
- **Produced a weapon-by-weapon countermeasure matrix** with honest strength tiers
  (*Trivial → Speed-bump → Meaningful → Strong*) and a named bypass for every
  defense; established that only server-side relocation is truly *Strong*.
- **Designed an AI-layer-specific defense** — a dev↔release decoy identity
  transform (misleading-but-plausible symbols/strings with a private mapping file)
  that targets how LLM agents actually reason, while keeping the dev tree clean.
- **Established an engineering methodology** — a research→analysis→implementation→
  testing pipeline, a multi-model agent orchestration pattern, and a file-based
  cross-session handoff system that keeps working context small.

## Skills & competencies demonstrated
- Reverse-engineering defense & anti-tamper (anti-debug, integrity/attestation,
  obfuscation, symbol/string hardening) across ELF/PE/Mach-O and Android/iOS.
- Threat intelligence and adversary-tooling analysis from primary sources.
- **LLM / AI-agent security** — MCP-based tooling, autonomous RE agents, the
  uncensored-local-model threat.
- Secure build engineering and the audit-before-harden discipline.
- Honest security communication — strength tiers and explicit bypasses, no overclaiming.
- Technical writing, structured documentation, and multi-agent workflow design.

## Tech & tools
Git/GitHub · ELF/binary hardening concepts · anti-debug/ptrace, core-dump control ·
R8/`mapping.txt` & iOS dSYM symbol-mapping patterns · threat tools studied for
defense (Ghidra, IDA, Frida, JADX, Binwalk) · Claude Code multi-agent orchestration.

## Ready-to-paste CV bullets (trim to taste; keep honest to current state)
- Designed a defensive anti-reverse-engineering harness for native and mobile apps,
  targeting the emerging threat of AI-driven, one-command reverse engineering.
- Modeled AI-assisted RE as a three-layer threat (model/tooling/distribution) and
  built a cited catalog of real-world agent-based RE tooling.
- Analyzed a live AI-RE tool's ~80 capabilities and produced a weapon-by-weapon
  countermeasure matrix with honest strength tiers and documented bypasses.
- Devised an AI-specific hardening (decoy symbol/string transform) that degrades
  LLM-agent comprehension while preserving a clean development codebase.

---

## Contribution Log (append after every bit — newest at top)

### 2026-11-14
- **Produced Slice T — a decision-ready scope-expansion proposal (research +
  analysis only; no code, no scope change).** Resolved the project's one standing
  governance fork — whether to add a second "web/bundle" track (Electron/ASAR, V8
  bytecode, minified/obfuscated JavaScript, WebAssembly, managed .NET/CIL) alongside
  the native + mobile core — into a cited, operator-ready recommendation, following
  the project's research→analysis→proposal pipeline and its CLAUDE.md §3 rule to
  confirm before any scope-expansion work:
  - **Ran a parallel, cited landscape study of all four formats** (Lead →
    four Scout sub-agents → Evaluator sign-off), each dated and honest about
    unverified sources: `research/findings/2026-11-14-{electron,js-deobf,wasm,
    dotnet-il}-re-landscape.md`. Centered every format on the Priority-0
    AI-assisted-RE threat (a non-expert points an LLM-driven MCP/skill at the
    target) and confirmed off-the-shelf tooling already exists for each
    (`humanify`, dnSpy-MCP/ILSpy-MCP wrappers, `re-electron`, `webcrack`).
  - **Established an honest exposure ranking — managed-IL ≳ JS ≳ Electron ≫ Wasm ≫
    native** — and the load-bearing finding that *no client-side countermeasure for
    these managed/high-level formats honestly exceeds the Speed-bump tier*, there is
    *no mechanism-proof "it fired" story* (unlike the native guards), and the only
    Strong lever is the server-side relocation the project already recommends. Every
    per-format tier carries a named bypass; every AI-layer tier is flagged unmeasured.
  - **Surfaced the NativeAOT/IL2CPP insight:** the best honest "harden my .NET/Unity
    app" answer is to compile to a *native* binary, which folds into the EXISTING
    native track — no scope change needed — and that .NET MAUI/Android is a
    mobile-track question, not a web/bundle one.
  - **Delivered the proposal** (`docs/proposals/scope-expansion-web-bundle-track.md`)
    with the case for/against, an effort estimate, a concrete recommendation (default
    no harden track; conditional audit-first track only for a format the operator's
    target ships; adopt the no-scope-change NativeAOT routing now), a *quoted*
    CLAUDE.md §2 wording change to apply only if approved (deliberately not applied),
    and an explicit "Operator decision requested" section. Added four reference-only
    catalog entries (marked NOT worked) without expanding scope.

### 2026-11-13
- **Shipped Implementation Slice Q (Mach-O harden DEPTH — parity with ELF/PE,
  39/39 green; 304/304 across 17 slices).** Mach-O had only the Slice O local-symbol
  strip; added the two remaining post-build levers as **Mach-O-native constructs**,
  proven **structurally / byte-level on Linux with no macOS host** (same discipline as
  Slice O and the PE path):
  - **Decoy non-mapped segment + trailer** (`carapace_macho_exhaust.py` on a shared
    `carapace_macho_segment.py`) — appends bulk decoy bytes to the file **trailer**
    (past `mapped_end`, so no segment maps them) and splices a real `LC_SEGMENT_64`
    named `__CARAPACE_EXH` with **`vmsize=0`** into the header pad **in place** (dyld
    ignores a `vmsize==0` segment → it maps nothing; XNU `loader.h` + dyld). When there
    is < 72 B of header pad it falls back to a trailer-only decoy and names the
    `-headerpad_max_install_names` remedy — never corrupts, never silently skips.
  - **Honeytokens / canaries** (`carapace_macho_honeytokens.py`) — plants plausible
    fake secrets into the non-mapped trailer + a **private per-build ledger**; a leaked
    token is attributed back to its exact build (`check`, rc 7). Token generators shared
    with the ELF (Slice J) and PE (Slice P) passes.
  - **Audit** (`macho_exposure_audit.py`) gained `decoy_segment_present` /
    `carapace_segment_count` / `honeytokens_present` (guards line, not scored) and a
    `recommend()` that chains strip → decoy segment → honeytokens. The skill's
    `carapace harden <macho>` now runs the full chain (apply stays = strip); `make
    harden-macho` routes it; the fixture gained `--headerpad` / `--signed` with defaults
    that keep the Slice N/O fixtures byte-identical.
  - **Verified** (`test_slice_q.sh`, 39/39): the added segment proven to map nothing
    (`vmsize==0`, prot NONE); the splice proven **surgical** (every changed in-file byte
    is a mach-header count or the consumed zero pad); the decoy/honey trailer proven
    past `mapped_end` (non-mapped); honeytokens unique + AKIA-plausible + strings-visible
    + attributable + unique per build; honest refusals (fat / 32-bit / non-Mach-O) +
    code-signature warnings + the header-pad fallback + no overclaim. **Runtime-identical
    and real-dyld acceptance of the decoy segment are platform-gated to a macOS host.**
    Cited format facts: `research/findings/2026-11-13-macho-harden-levers.md`;
    attacker→countermeasure map: `docs/re-techniques/macho-harden.md`.
- **Shipped Implementation Slice R (mobile-container reach — APK/AAB/IPA; 26/26 on
  CI, +21 cross-platform here).** Closed the one in-scope format family Carapace
  could not previously reach into: the native payloads *inside* a mobile package.
  The harness now unpacks a container (all three are ZIP), enumerates the **native**
  payloads, and applies the **existing** per-format hardeners to them — no new
  countermeasure, pure reach:
  - **Audit-first** (`harness/audit/mobile_container_audit.py`) — classifies the
    container (APK / AAB / IPA) by marker members, enumerates native payloads by
    path **and magic byte** (Android `lib/<abi>/*.so` → ELF; iOS app binary +
    `Frameworks/*.framework/*` + `*.dylib` → Mach-O), and **delegates** each to the
    existing ELF / Mach-O auditor for a per-payload scored posture. DEX/managed code
    is enumerated-and-skipped (a separate track, out of scope per CLAUDE.md §2).
  - **Harden** (`harness/harden/carapace_mobile.py`) — dispatches each payload
    through the **stable Slice-M format entry point** (`carapace harden`, falling
    back to `apply`), so it uses whatever each format hardener offers today and
    **automatically picks up new levers** (e.g. Slice Q's Mach-O decoy/honeytokens)
    once merged — **no lever is hard-coded**. Repacks the container; collects the
    PRIVATE de-obfuscation map + honeytoken ledger **outside** the package.
  - **Honest signing limitation, stated and never faked** — repacking invalidates
    the APK/IPA signature; the tool + the verify say the **operator re-signs**
    (apksigner / codesign + provisioning) and that on-device integrity ultimately
    rests on the **platform verifying the signature**, which a client harness cannot
    provide or fake (server-side-truth, CLAUDE.md §3).
  - **Tiers/bypass:** the container layer adds **no** strength of its own — every
    tier (and bypass) is **inherited** from the delegated ELF/Mach-O slice; the
    container-level bypass is that the ZIP wrapper is not a barrier (re-unpack the
    repack). No overclaim: we harden the native payloads, not the DEX/managed code.
  - **Proof** (`harness/verify/test_slice_r.sh`) — synthetic ZIP fixtures (a
    toolchain-free ELF `.so` generator + the Mach-O fixture): enumeration delegates
    correctly (score parity with the standalone auditors), the skill routes
    containers, a non-mobile ZIP is refused cleanly, and harden **dispatches +
    repacks** (IPA/Mach-O cross-platform; APK/ELF gated on ELF binutils, like the
    bare-ELF slices) with the signing limitation + tier + bypass asserted and **no
    false signing claim**. `make audit-mobile` / `harden-mobile` / `harden-apk` /
    `harden-ipa`. Research + analysis:
    `research/findings/2026-11-13-mobile-container-reach.md`,
    `docs/re-techniques/mobile-containers.md`.
- **Shipped Implementation Slice S (Slice-K empirical re-run harness — one command +
  the tool-call fix; +23 CI checks, proven with a deterministic MOCK attacker).**
  Turned the parked, manual AI-RE measurement into a packaged, scored, operator-
  runnable procedure, and fixed the P0-relevant friction that blocked the 2026-11-11
  run:
  - **Fixed the tool-call friction.** Commodity local models emit tool calls as
    plain JSON text that Codex/Ollama drop (the 2026-11-11 blocker). Built a robust
    shim (`attacker_agent.py:extract_tool_calls`) that prefers a model's native
    `tool_calls` and otherwise parses JSON-as-text with a string-aware brace matcher,
    accepting only declared tool names and never parsing tool *output*
    (prompt-injection-safe). Researched + cited the current state of local-model
    tool calling (`research/findings/2026-11-13-local-model-tool-calling.md`).
  - **One command.** `make slice-k-run MODEL=… TARGET=…` (+ `slice_k_run.py`) builds
    the sealed CrackMe pair, drives an attacker agent against baseline AND hardened,
    and emits the honest before/after via the existing scorer. Pluggable backends:
    Ollama (the operator's local model — downloads nothing) and a deterministic Mock.
  - **Exercised Slice J.** Wired the loop + scorer so a stronger attacker trips the
    honeytoken poison/attribution path (the 7B run never reached it); the scorer
    records the attribution and still scores the surfaced decoy *not cracked*.
  - **Proved it green in CI with no model and no VM.** `harness/verify/test_slice_s.sh`
    (23/23) runs the shim unit tests + the full mock pipeline end-to-end; the output
    is loudly stamped **NOT A MEASUREMENT** and no cost number is ever fabricated.
  - **Honest tier + bypass.** This packages the measurement and fixes the tooling; it
    is **not** itself a defense and produces no effectiveness number — real numbers
    need the operator's isolated VM + chosen model + hardware. Bypass: a reliably
    tool-calling model or grammar-constrained decoding makes the shim unnecessary.
  - (Sibling branches off the same base: Slice Q (Mach-O harden, PR #5) and Slice R
    (mobile reach, PR #6); each states only its own increment.)

### 2026-11-12
- **Shipped Implementation Slice P (Windows PE harden path — the first PE harden,
  42/42 green; 265/265 across 16 slices).** PE was audit-only (Slice G); gave it a
  post-build **harden** path with three provable, non-breaking levers, each proven
  **structurally / byte-level on Linux with no Windows host** (the same honesty
  discipline as the Slice O Mach-O strip):
  - **COFF-symbol + debug/PDB strip** (`carapace_pe_strip.py`) — clears the COFF
    symbol table and the debug directory / CodeView PDB-path record in place, size
    stable; proved **surgical** (every changed byte lies inside a symbol/debug
    metadata region — the import/export tables, entry point, section headers and
    `SizeOfImage` are byte-identical, and the dev-identity names + the `.pdb` build
    path are gone). The PE analog of the ELF/Mach-O identity strip.
  - **Decoy non-mapped overlay** (`carapace_pe_exhaust.py`) — appends decoy regions
    to the PE **overlay** (the bytes past every section's raw data, described by no
    section header, so the loader never maps them), inflating what a whole-file
    static/AI sweep must ingest while the mapped image is untouched. Proved
    **append-only** (original file is a byte-identical prefix) and **provably
    non-mapped** (decoys start past `mapped_end`). Documented *why the overlay* (a
    non-mapped PE *section* would need a loader-specific trick we can't verify
    headless, or an offset-shifting header grow that breaks the byte-stable claim).
  - **Honeytokens + attribution** (`carapace_pe_honeytokens.py`) — plants unique,
    plausible fake secrets (shared generators with the ELF pass) into the overlay +
    a **private ledger**; whole-file-`strings` visible but provably inert, and a
    leaked token is attributed back to its exact build (`check`).
  - **Routed through the skill honestly:** `carapace apply <pe>` runs the strip and
    `carapace harden <pe>` chains all three (writing a separate output, leaving the
    input byte-identical), then plainly lists the build-time levers it did **not**
    apply (relink `/DYNAMICBASE /NXCOMPAT /GUARD:CF`, string encryption, runtime+
    server Authenticode check) and the server-side Strong truth — never faking a
    build-time guard onto a built PE. Updated Slice M (PE now dispatches, not
    refuses); ELF and Mach-O paths unchanged.
  - **Kept the honesty line precise:** tier + named bypass on every lever, never
    "unbreakable", and *runtime-identical is platform-gated to a Windows host* (the
    same class of gating as the Mach-O macOS host and the Slice K VM). Proof:
    `harness/verify/test_slice_p.sh`.

### 2026-11-11
- **Ran Slice K for real — the first *measured* RE-resistance before/after (isolated
  operator VM).** Stood up a network-isolated, operator-owned VM and pointed a local
  uncensored-class model (`qwen2.5-coder:7b`, served on the host GPU and reached over
  an SSH reverse tunnel) at the CrackMe's baseline vs Carapace-hardened builds, then
  scored the recorded runs with the honest scorer:
  - **Baseline cracked, hardened resisted.** The same agent recovered the real flag
    from the baseline in 1.6 s / 1,256 tokens (**hash-verified** against the seal),
    but against the hardened build spent **13.4× the tokens and ~122× the wall-clock
    and still failed** — its confident final answer did not hash to the seal.
  - **Watched three Carapace defenses fire in sequence** on the hardened build:
    string-encryption (every static `strings`/`objdump`/`nm`/`readelf`/`xxd` grep
    for the flag came back empty), anti-debug guards (`strace` → *"tracer detected —
    refusing to run"*; `ltrace` → breakpoint-tamper `SIGSEGV`), and analysis-surface
    exhaustion (gdb/radare2 timed out on the 26×-larger binary) — after which the
    model hallucinated a wrong flag.
  - **Kept it honest, including where it falls short:** single VM, one 7B model,
    N=1; the honeytoken/poison layer (Slice J) **did not fire** (the agent was
    blocked upstream, not fooled by a decoy); and the agent was a **custom shell-tool
    loop, not the `rea` MCP** — because commodity local models emit tool calls as
    plain JSON text that neither Codex nor Ollama parses into executable calls
    (reproduced by calling Ollama directly). That tool-call-parsing gap is itself a
    P0-relevant finding: the AI-RE "skill-floor collapse" has real friction at the
    lowest tier. Full writeup + caveats:
    `research/findings/2026-11-11-slice-k-empirical-run.md`.

### 2026-11-05
- **Shipped Implementation Slice O (Mach-O local-symbol strip — the first Mach-O
  harden, 15/15 green; 223/223 across 15 slices).** Built a dependency-free
  `strip -x` equivalent that removes a Mach-O's LOCAL/static symbols via
  `LC_SYMTAB` + `LC_DYSYMTAB` while preserving the external/undefined symbols the
  dynamic linker needs — keeping every load command, segment, section and file
  offset byte-identical (surgical, in-place, deterministic), and refusing unsafe
  inputs (fat, empty/undeclared symbol tables). Drew the honesty line precisely:
  because a Mach-O can't be executed on the Linux build host, the verify proves the
  transform is *surgical* (locals gone, externals kept, nothing else moved) and the
  tool states plainly that *runtime-identical* confirmation is platform-gated to a
  macOS host — no overclaiming. Wired it into `carapace apply` and `make
  harden-macho`.
- **Shipped Implementation Slice N (Mach-O exposure audit — the third native
  format, 21/21 green; 208/208 across 14 slices).** Wrote a dependency-free Mach-O
  parser (thin 32/64-bit, both byte orders, and fat/universal) that reads what an
  AI-RE agent reads — symbol-table size, `__TEXT,__cstring` string density, section
  entropy, linked dylibs, PIE / stack-exec / `__RESTRICT` flags, a code signature
  (kept honest: presence only, **not** verified), and `__TEXT` encryption — and
  scores a posture tier parallel to the ELF and PE scanners. Made it testable with
  **zero Apple toolchain** via a byte-level fixture generator (soft/hard/encrypted
  + a fat wrapper) driving a 21-check verify (soft→hard flip, encryption cratering
  the static-view score, fat parsing, skill dispatch). With Slice M's magic-byte
  routing, Carapace now audits **all three native formats (ELF/PE/Mach-O)** from one
  `carapace audit <bin>`.
- **Shipped Implementation Slice M (format dispatch, 13/13 green; 187/187 across
  13 slices).** Unified the audit front door across formats: the skill now detects
  ELF / PE / Mach-O by magic byte and routes `audit`/`report`/`recommend` to the
  right scanner, so the Windows-PE audit (built in Slice G) is reachable through
  the same `carapace audit <bin>` an operator already uses for ELF. Kept it honest
  — the ELF-only post-build transforms (`apply`/`harden`) **refuse** a non-ELF with
  guidance and leave it untouched rather than pretending, and an unrecognized file
  errors cleanly. The server-side Strong truth is surfaced regardless of format.
- **Shipped Implementation Slice K (empirical harness + CrackMe + honest scorer,
  plumbing 20/20 green; 174/174 across 12 slices).** Built the apparatus to put
  *measured* numbers on the hardening — the empirical claim the competitive space
  makes with "internal estimate" multipliers — but honest by construction:
  - A digest-sealed **CrackMe** (one source, baseline vs Carapace-hardened) whose
    flag plaintext is never committed; only its SHA-256 is published, so a claimed
    crack is verifiable without shipping the answer.
  - An **honest scorer** that turns an operator's recorded agent runs into a
    before/after: a "crack" counts only if it hashes to the seal (the agent's
    self-report isn't trusted), token/wall figures are agent-reported with absent
    values shown as *not measured* (never estimated), and a honeytoken the agent
    reported as a secret is scored as poison + attribution.
  - A **runbook** for running a real AI-RE agent against the pair on a sandboxed,
    operator-owned VM — with the ethics/scope guardrail that offensive tooling is
    never installed in the dev/CI container.
  - Scoped the honesty precisely: the verify proves the *plumbing* (20/20); the
    effectiveness claim is explicitly gated on the operator VM run, not asserted.
- **Shipped Implementation Slice L (one-command `harden` + skill install, 17/17
  green; 154/154 across 11 slices).** Matched the competitive space's one-command
  ergonomics without sacrificing honesty:
  - Added `carapace harden <binary>` — a single command that chains every
    applicable post-build pass (identity decoy → analysis-surface exhaustion →
    honeytokens), emits the hardened binary plus its private map/ledger, and then
    **plainly lists the build-time guards it did not apply** (with the rebuild
    step) and the server-side Strong tier. It refuses to fake a build-time guard
    onto an already-built binary — the exact honesty line a convenience command is
    tempted to cross.
  - Added `carapace install` (+ `make harden` / `make install-skill`) for
    one-command skill loading; idempotent and guarded against clobbering a real
    directory.
  - Verified the whole flow (post-build passes applied, runtime byte-identical,
    build-time deferred, Strong surfaced, tier+bypass on every item, no overclaim),
    and refreshed the skill docs (retiring a stale "not yet implemented" note now
    that string encryption ships).
- **Shipped Implementation Slice J (honeytokens / canaries, 15/15 green; 137/137
  across 10 slices).** The "Poison / Hallucinate" axis of the competitive space,
  built as a real blue-team canary primitive:
  - Plants plausible, format-valid **fake secrets** (AWS-style keys, bearer
    tokens, internal URLs, DB creds) that a naive AI-RE agent mines and reports as
    real findings — poisoning its output and baiting the confident-but-wrong
    conclusions agents are known to produce.
  - Made each token **unique per build** and logged to a **private ledger**, so it
    doubles as an **attribution tripwire**: a `check` tool matches a leaked token
    back to the exact build that leaked (demonstrated end-to-end — leak detected,
    build attributed, no false positives, unique across builds).
  - Proved non-breakage at mechanism level (runtime byte-identical, exports
    untouched, the decoy section provably non-allocated so the tokens are inert),
    kept the output deterministic, and wired audit detection + a skill
    recommendation.
  - Honest tiering: **Speed-bump** as poison, **Meaningful for detection** as a
    canary — explicitly *detection/attribution, not prevention* — with the exact
    bypass named (xref-validation drops unreferenced tokens; rename the tell-tale
    section for production).
- **Shipped Implementation Slice I (analysis-surface exhaustion, 14/14 green;
  122/122 across 9 slices).** Absorbed the competitive space's "Exhaust" axis into
  Carapace's native lane — and did it in our mechanism-proven style, not a peer's
  size-diff "verify":
  - Built a post-build pass (`carapace_exhaust.py`, binutils only) with two
    provably non-breaking levers — **decoy non-allocated sections** (never mapped
    at runtime) and **synthetic LOCAL FUNC symbols** (`.symtab`-only) — that
    balloon the inventory and context budget a naive "ingest everything" AI-RE
    agent must pay, while the program is byte-identical.
  - Proved non-breakage at mechanism level: runtime output byte-identical, exports
    (`.dynsym`) untouched, decoy sections verified SHF_ALLOC-clear, zero synthetic
    symbols leaking into the dynamic table, and deterministic (reproducible) output.
  - Extended the audit to detect + *measure* it (decoy bytes, synthetic-symbol
    count, non-alloc byte ratio) and wired an honest recommendation into the skill.
  - Kept it honest: tier **Trivial→Speed-bump** with the exact bypass named (filter
    to allocated sections + code-referenced symbols) — cost against the commodity
    automated path, not prevention.
- **Ran a competitive-landscape scan of the emerging anti-AI-RE defender space and
  turned it into an absorption plan.** Found three public defenders (notably **BLA**,
  ~2.3k★, MIT) now shipping against AI-RE agents like `rea`/REA — independent
  validation of the project's thesis. Wrote a cited finding
  (`research/findings/2026-11-05-competitive-landscape.md`) with a
  technique-by-technique **absorption matrix**: identified Carapace's durable edge
  (native-depth, *mechanism-proven firing* vs. the peers' self-admitted drift-check
  "verify," and a named bypass + honest tier on every defense), folded their best
  ideas (analysis-surface **exhaustion**, decoy/poison depth, an empirical REA
  benchmark + CrackMe, one-command UX) into the Carapace roadmap, and **rejected on
  principle** the instruction-file/terminal-shim "barriers" that rely on a
  cooperative model (the exact non-defense the project forbids). Flagged the one
  real fork — expanding past native/mobile into web/bundle formats — as an explicit
  operator scope decision rather than silent scope creep.

### 2026-11-04
- **Shipped Implementation Slice H (CI that enforces `make verify`, 9/9 green;
  108/108 across all slices).** Turned the "prove it" claim from a local run into
  an enforced gate:
  - Added a **GitHub Actions workflow** (`.github/workflows/verify.yml`) that runs
    the full `make verify` suite on every push and pull request, so a regression in
    any of the eight slices fails the check and turns the README status badge red.
  - Handled the two CI-environment subtleties honestly rather than weakening the
    tests: installed **gdb** so Slice A's under-tracer detection branch actually
    runs, and relaxed **Yama `ptrace_scope`** so the anti-ptrace *control* (a
    sibling attaching to the unhardened baseline) runs as designed — the guards
    being proven live in the binary, not the host policy. Scoped the workflow to
    least privilege (`contents: read`) with superseded-run cancellation.
  - Kept the gate self-checking: a **config-lint verify slice**
    (`test_slice_h.sh`) asserts the workflow still runs `make verify` and still
    carries both accommodations and the badge, and is negative-tested to fail when
    the gate is removed — so the CI wiring can't silently rot.
- **Shipped Implementation Slice G (PE/Windows exposure audit, 24/24 green; 99/99
  across all slices).** Broadened the harness beyond Linux ELF to the #1 commodity-
  cracking target:
  - Wrote a **self-contained PE32/PE32+ parser** (no `pefile`) that reads the
    signals an AI-RE agent reads — DllCharacteristics (ASLR/DEP/CFG/high-entropy
    ASLR), the import/export tables (with correct RVA→file-offset mapping), section
    entropy, string density, debug/PDB paths, Authenticode presence, and .NET/
    packer tells — and scores a tiered posture parallel to the ELF scanner.
  - Kept the signature claim honest: an Authenticode signature on disk is reported
    as **read-only / not verified** — its defensive value is only in a runtime,
    server-checked signature.
  - Made it testable with **zero toolchain**: a minimal PE32+ fixture generator
    (soft/hard/packed) drives a 24-check verify proving the DllCharacteristics flip,
    import parsing, PDB recovery, packer tell, score drop (77→15), and graceful
    non-PE rejection.
- **Shipped Implementation Slice F (build-time string encryption + runtime decode
  loader, 10/10 green; 75/75 across all slices).** Closed the last countermeasure
  the harness openly labelled "roadmap":
  - Built a **build-time codegen pass** that encrypts marked strings into C byte
    tables with a position-dependent **xorshift32 keystream** (not a trivial
    single-byte XOR), plus a tiny **runtime decode-on-demand loader** whose
    keystream is byte-identical to the encoder — so live, used strings are
    **entirely absent from a static `strings`/`list_strings` view** yet correct
    in-process. The dev tree keeps the plaintext manifest; the binary ships only
    ciphertext.
  - Extended the audit to detect it and demonstrated the measured drop (string
    informativeness 7→3, density 0.60→0.10), wired it into the skill's
    recommendation policy (now a real build-time step, not a placeholder).
  - Kept it honest: tiered Speed-bump→Meaningful with the embedded-key bypass
    named (recover at rest, or lift from memory at runtime), and stated plainly
    that it is not a secret store — that still belongs server-side.

### 2026-10-29
- **Shipped Implementation Slice E (public front door + one-command demo, 7/7
  green; 65/65 across all slices).** Made the "measure it, harden it, prove it"
  story legible end-to-end:
  - Added a repo-root `Makefile` (`make demo` / `verify` / `report` / `audit`)
    and a consolidated `run_all.sh` that runs every verify slice and prints a
    single honest posture summary — a newcomer sees the whole thing work in ~30s.
  - Gave the skill a `report` one-shot (full audit + ordered hardening plan, each
    item tiered and bypass-named) and tightened the no-overclaim footer.
  - Rewrote the README into a real front door (quickstart, a "what's built" table
    of five countermeasures with strength tiers and named bypasses, and an honest
    "what it is / isn't"), retiring the stale "early scaffolding" status.
  - Caught and fixed an over-strict honesty test (it rejected the legitimate
    negation "nothing here is unbreakable") rather than weakening the honesty check.

### 2026-10-28
- **Shipped Implementation Slice D (runtime integrity/attestation + anti-Frida,
  16/16 green)** — the push toward the only *Strong* client-side tier, against
  Frida (the adversary agent's one in-process modification path):
  - Implemented a **code-integrity self-checksum + server-nonce attestation**
    protocol — the client returns `HMAC(key, nonce || SHA-256(hot-function))` and
    a reference server holds the known-good checksum and issues a fresh nonce per
    challenge. Wrote a **self-contained SHA-256 + HMAC-SHA256 in C** (no OpenSSL),
    cross-checked byte-for-byte against Python's `hmac`/`hashlib`.
  - Demonstrated the defense end-to-end **without installing any offensive
    tooling**: patching a license-check constant in the on-disk binary changes the
    checksum and the server rejects the attestation; a replayed response is
    rejected by the nonce binding; the patched app still runs locally — proving the
    *server* is the gate.
  - Built an **anti-Frida detector** (injected-agent mapping, Frida worker thread
    names, default-port listener via a portable connect probe) with deliberate
    false-positive avoidance, tested by reproducing Frida's exact OS footprint.
  - Extended the audit to detect both guards, wired them into the skill's
    recommendation policy, and tiered honestly: anti-Frida *Meaningful*, integrity
    *Meaningful→Strong* only when server-nonce-tied — with the client-key-extraction
    limitation stated, not hidden.

### 2026-10-26
- **Shipped Implementation Slice C (the drive-the-harness skill, 9/9 green)** —
  closed the product loop (audit → score → recommend → apply → re-audit):
  - Built a **deterministic driver** (`skill/carapace.py`) over the harness with
    `audit` / `recommend` / `apply`, and the **Claude skill** (`SKILL.md`) that
    calls it — putting the recommendation policy in one testable place rather than
    improvised prose.
  - The recommender emits the **next highest-value hardening** with an honest
    strength tier **and a named bypass on every item**, orders the full plan, and
    always surfaces the server-side-relocation *Strong* tier — and `apply`
    **refuses to fake a build-time guard** onto an already-built binary, pointing
    at the rebuild instead (honest about what can and can't be patched post-hoc).
  - Verified the loop end-to-end: recommendations never overclaim ("unbreakable"
    guarded against in tests), the post-build hardening fires with the app still
    running, and the recommendation advances as posture improves (score 84→39).
- **Shipped Implementation Slice B (dev↔release identity transform, 18/18 green)**
  — the project's novel, AI-specific countermeasure, targeting how LLM agents
  actually reason (from names and strings):
  - Extended the audit scanner with an **identifier/string informativeness** score
    (English-word ratio of the binary's own symbols + informative-string count) —
    a measure of the free intel a binary hands an AI agent.
  - Built a **build-time identity transform** over the compiled ELF (binutils-
    based) with three modes — **strip**, reversible **map**, and **decoy**
    (plausible-but-wrong names) — plus an opt-in same-length internal-string decoy,
    emitting a **private mapping file** so crash reports stay decodable while the
    shipped artifact misleads.
  - Verified end-to-end: the audit measures the transform, the mapping round-trips
    with **no dev identity leaking** into the artifact, the decoy build stays
    *plausible* (avoiding the "opaque ⇒ obfuscated" tell), and the app runs with
    **byte-identical output** — scope held to internal symbols so dynamic linking
    stays intact.
  - Kept it honest: tiered Speed-bump→Meaningful with a named behavioral bypass,
    and explicitly scoped out live-string encryption (needs a runtime loader)
    rather than overclaiming.
- **Shipped Implementation Slice A (audit → harden → verify, all green)** — the
  first working end-to-end defense in `harness/`, proving the full pipeline on two
  named `rea` weapons:
  - Built a dependency-free **ELF exposure audit scanner** (pure-Python ELF parser)
    that reads the same static signals an AI-assisted RE agent reads and emits a
    scored, tiered posture report + the next highest-value hardening.
  - Implemented two **self-defense guards** for a sample Linux ELF — core-dump
    suppression (denies `rea` Cluster E crash-reader) and anti-ptrace
    (`PTRACE_TRACEME` slot-claim + `TracerPid`; denies Cluster G Frida-attach /
    Cluster H GDB) — each with an honest tier (Speed-bump / Meaningful) and a
    named bypass in-file.
  - Wrote a **verification harness (15/15 assertions)** proving the audit flips
    present↔absent on the guards alone and that both guards actually fire (real
    core suppressed; `PTRACE_ATTACH` refused with EPERM) while the app still runs.
  - Demonstrated the audit-before-harden discipline and honest-claims rule on real
    binaries, and caught/fixed a genuine ordering bug (read `TracerPid` before
    `TRACEME`, else the guard self-false-positives).
- Set up the CV/portfolio record (this file) and wired its upkeep into the
  cross-chat handoff protocol.
- Added the living `docs/STATE.md` handoff file and purpose READMEs for `harness/`
  and `skill/`; documented the file-based cross-session workflow.
- Extended the P0 catalog with `skill-packs` (incl. the 43.4k★ `reverse-skill`
  agent router) under the distribution layer.
- Designed the dev↔release decoy identity transform countermeasure (operator idea),
  including honest tiering and safety caveats.

### 2026-10-25
- Scaffolded the project: constitution (`CLAUDE.md`), threat model, catalog,
  orchestration playbook, agent roles; created the private GitHub repo.
- Locked scope to native binaries + mobile; set the P0 thesis (AI-assisted RE) and
  the three-layer model; added the uncensored-local-model axis and the "assume a
  cooperative, unrestricted model" assumption.
- Researched the first P0 specimen `rea`: produced a cited weapons inventory
  (~75–80 capabilities, dependencies, OS matrix, runtime/Frida paths).
- Wrote the `rea` weapon-by-weapon countermeasure analysis with tiers and bypasses.
