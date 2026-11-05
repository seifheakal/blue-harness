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

### 2026-11-05
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
