# Electron desktop RE landscape (ASAR, V8 bytecode, fuses, AI-assisted front) — research
- Date: 2026-11-14
- Author role: Scout
- Phase: research
- Status: draft (needs Evaluator)

## TL;DR
- **Exposure is structural and high.** An Electron app's UI and most logic ship as JavaScript inside `app.asar`, which is a plain archive that extracts in one command. Bytenode (V8 bytecode) and minification raise the cost only slightly, and an agent does not need a disassembler to read JS. Treat Electron as the most AI-exposed target class in our catalog, and treat it as a **scope-expansion proposal**, not a native-track feature (CLAUDE.md §2 currently excludes Electron).
- **Best available client-side levers are integrity-first, not obfuscation-first.** ASAR integrity plus the `onlyLoadAppFromAsar` and `embeddedAsarIntegrityValidation` fuses is the Electron-native control (Speed-bump on user-writable installs). Its documented gap (V8 heap snapshots not covered; CVE-2025-55305, fixed in patched Electron releases) shows the control is only as good as its coverage and patch level.
- **Obfuscation/bytecode are Speed-bumps at best against the substrate, and their AI-layer effect is unmeasured.** The one controlled 2026 AI-layer data point (arXiv 2604.04289) shows identifier poisoning survives LLM deobfuscation in baseline, but a "rewrite from scratch" framing removes most of it. No 2026 controlled study measures an LLM against flattening + string arrays together.
- **The honest #1 is still server-side.** Anything you cannot afford to leak (license-validation keys, premium logic, secrets) belongs in the main process's remote call, not in `app.asar`.

## Detail

### 1. Attacker workflow needs (design-level, not a how-to)
Defender-relevant description of what an attacker needs from a shipped Electron app:
- **Container access.** `app.asar` is an archive with a JSON header. Electron's own ASAR-integrity doc says the header carries hashes that the runtime checks *only if* the integrity fuse is on (source: electronjs.org ASAR integrity, accessed 2026-11-14). Without integrity, the archive is readable and rewritable in place.
- **Source readability.** JS (minified or not) is high-level source to an LLM. Obfuscation changes the surface, not the class of artifact.
- **Bytecode artifacts.** Bytenode compiles JS to `.jsc` V8 bytecode. Its README states: "V8 bytecode is not encryption," and "Bytenode should not be your only line of defense" (github.com/bytenode/bytenode, accessed 2026-11-14). It also requires the exact Node/V8 version and hashes to match at load time.
- **Snapshot artifacts.** Chromium-based apps load V8 heap snapshots at startup. Trail of Bits (2025-09-03) showed these were not integrity-checked by Electron or Chromium, so they are a tamper location even when ASAR integrity is on (blog.trailofbits.com, accessed 2026-11-14).
- **Runtime surfaces.** Main-process inspector (`--inspect`, `SIGUSR1`), `ELECTRON_RUN_AS_NODE`, and remote debugging ports. These are controlled by fuses (Electron fuses doc, accessed 2026-11-14).

### 2. Electron fuses (current state per Electron docs)
Source: electronjs.org/docs/latest/tutorial/fuses (accessed 2026-11-14; page shows no last-updated date).
- Nine fuses. Defaults relevant to us: `runAsNode` = **enabled**; `nodeCliInspect` = **enabled**; `nodeOptions` = **enabled**; `embeddedAsarIntegrityValidation` = **disabled**; `onlyLoadAppFromAsar` = **disabled**; `loadBrowserProcessSpecificV8Snapshot` = **disabled**.
- Fuses are stored as bytes in the Electron binary after a sentinel; a static reader can report their state without launching the app. This is a documented defensive audit path (PenTestIT, 2026-10-20, accessed 2026-11-14, one Windows 11 test host, one tool version: "not a claim about all apps"). Our harness could implement the same read as an audit check.
- Caveat: `runAsNode` is required by some shipping apps (the same PenTestIT source says VS Code/Cursor CLI launchers depend on it), so disabling it is an app-specific decision.

### 3. ASAR integrity (Electron docs, accessed 2026-11-14)
- Hash of archive header + per-block hashes; expected value stored in `Info.plist` (macOS, SHA256) or an `ElectronAsar` resource (Windows).
- Supported from Electron 16 (macOS) and 30 (Windows). Requires `embeddedAsarIntegrityValidation` fuse; recommends `onlyLoadAppFromAsar`.
- Documented limit: without `onlyLoadAppFromAsar`, the app-code search path can bypass the check. Mismatch = forced termination.
- The Electron doc does **not** claim this is a security boundary against a local attacker (no statement either way).

### 4. Known bypass classes (published, dated)
- **CVE-2025-55305 (ASAR-integrity coverage gap, heap snapshots).** Trail of Bits 2025-09-03; Electron fixed; affects apps with both integrity fuses on. Severity: NVD/GitHub CVSS 6.1 Medium (vuldb / Fluid Attacks / cvelogic mirrors, accessed 2026-11-14). Note: press called it "critical"; the CVSS data does not support that. Patched in 1Password 8.11.8-40 (per Trail of Bits). Affected-version ranges differ across mirrors; check GHSA-vmqv-hx8q-j7mg for the authoritative range (not fetched).
- **Bytenode decompilation.** Positive Technologies published "How we bypassed bytenode and decompiled Node.js bytecode in Ghidra" (swarm.ptsecurity.com). **Could not fetch: TLS certificate error on two attempts (2026-11-14). Publication date and details are UNVERIFIED.** Treat as: a published public bypass exists; date unknown.
- **Bytenode version gate.** Bytenode README: on Electron ≥ 42 (V8 ≥ 14.8), bytecode compiled via `ELECTRON_RUN_AS_NODE` crashes the main process with `SIGTRAP`; use `compileElectronMainCode()`; renderer uses `compileElectronRendererCode()` on Electron 43.5.1+ (github.com/bytenode/bytenode, accessed 2026-11-14). This is a compatibility fact, not a protection fact; it is a maintenance hazard for us.

### 5. Automation: how exposed is Electron to LLM agents? (honest)
- **Agent routers that explicitly handle Electron/JS, found this session:**
  - `re-electron` skill (dslsdzc). Listed Aug 17 2026 on skills.rest (accessed 2026-11-14). Capabilities: asar unpacking (via `@electron/asar` or direct header parse), CDP debugging of main/renderers, `.jsc` analysis with version-lock limits. Install: `npx skills add https://github.com/dslsdzc/rev-skills --skill re-electron-dslsdzc`. License not stated. This is a skill, not a benchmarked tool.
  - **REA** (`morluto/rea`), an MCP/CLI tool for Claude Code/Codex/Cursor, which supports Electron ASAR and extracted-directory static analysis (jacar.es and hackernoon mentions; dates not fetched). Already in our weapons inventory (2026-10-25).
  - **BLA** (`qybaihe/bla`). **Confirmed defensive, not offensive**: a "Blue Defense" MCP/CLI. Its README (accessed 2026-11-14) lists Electron ASAR/fuses as a shield target, with fuse hardening `RunAsNode=0`, `Inspect=0`; ASAR 16 MiB header-limit exhaustion; IPC de-literalization; a `runtime-shield` that detects CDP/inspector/Frida/WebDriver. Caveats in the README: its token and USD figures are "internal estimates"; the empirical table is first-party on the author's machine; bytecode is **not** given an Electron-specific defense. Version now shown as npm `bla-agents` v3.3.1 and 5.6k stars. **This conflicts with the 2026-11-05 competitive note (2.3k stars, v1.4.0)**. Likely the project grew in nine days, but I did not verify the release history. Flag it.
  - Note: the earlier search snippet implied BLA and REA are paired. They are not; no source links them.
- **Human vs agent cost.** Electron's JS surface is the most agent-friendly class in our catalog: an agent needs no disassembly. The cost savings are mostly in unpacking and grep-through; obfuscation adds cost only to the human-scale parsing step.
- **AI-layer research (2026):**
  - arXiv 2604.04289 (2026-04-05; single author; Claude Opus 4.6 primary, Haiku 4.5 spot-check; 192 runs; two code samples). Poisoned identifiers survived deobfuscation in all baseline runs. Reframing as a fresh implementation cut propagation to 0-20% (physics) and 0% (pathfinding). Explicit verification prompts had no effect. Sample size is small, and it does not test CFF or string arrays.
  - NDSS 2026 "From Obfuscated to Obvious" (ndss-symposium.org, accessed 2026-11-14, from search only, not fetched): reports that some approaches struggle with control-flow manipulation and string-array deobfuscation. Use as "reported" until the PDF is read.
  - CASCADE (Google, arXiv 2507.17691, 2025-07-23, rev. 2026-02-25): a hybrid LLM+engine deobfuscator, deployed internally. **The fetched abstract does not contain the Obfuscator.IO accuracy claim** that a search snippet attributed to it. Do not cite that claim as fact.
  - Vendor blog (javascriptobfuscator.com) claims flattened control flow removes LLM cues. Vendor material, no controlled measurement. Not evidence.
- **Net:** the AI-layer effect of CFF/string-array is **unmeasured** for current frontier and open-weight models. Our K-slice methodology (measure baseline vs hardened on a VM) would be the honest way to find out.

### 6. Candidate countermeasures (tiers, bypasses, front)
Tier scale: Trivial / Speed-bump / Meaningful / Strong (CLAUDE.md §8). "Front" = **S** = break-the-substrate (defeats classic/agent tool); **A** = break-the-AI-layer (degrades LLM comprehension/automation).

| # | Countermeasure | Tier (proposed) | Named bypass (or known gap) | Front |
|---|---|---|---|---|
| 1 | ASAR integrity + `embeddedAsarIntegrityValidation` + `onlyLoadAppFromAsar` fuses | Speed-bump (user-writable installs) | Patch the integrity check in the Electron binary, or the snapshot coverage gap (CVE-2025-55305) | S |
| 2 | Fuse hardening: `runAsNode`=off, `nodeCliInspect`=off, `nodeOptions`=off (per app) | Speed-bump | Flip fuse bytes in the binary (fuses are static bytes; this is the audit read in reverse); some apps need `runAsNode` | S |
| 3 | Snapshot integrity (`loadBrowserProcessSpecificV8Snapshot` off or snapshot checked) | Speed-bump (pending Electron fix coverage) | Tamper with snapshot if unsigned; depends on patch level | S |
| 4 | Bytenode / `.jsc` compilation | Speed-bump | Public Ghidra-based bypass (PT Swarm, date unverified); version gate (Electron ≥42) | S |
| 5 | Minification + bundling | Trivial | Any pretty-printer / agent reads it | S (+ A marginal) |
| 6 | JS obfuscation: string array + control-flow flattening | Speed-bump | Deobfuscation tools/LLMs (CASCADE; JSIMPLIFIER NDSS 2026); AI-layer effect unmeasured | S + A (unproven) |
| 7 | Identifier poisoning / decoy identifiers | Speed-bump (AI-layer) | Reframe the task as "rewrite" (arXiv 2604.04289: 0-20% survival) | A |
| 8 | Runtime detection of CDP / inspector / Frida (BLA `runtime-shield`) | Speed-bump | Hook/patch the detector; design claim, not measured | S |
| 9 | ASAR header exhaustion / decoy depth (BLA) | Speed-bump for AI; Trivial for classic tools | Self-reported; parser limits vary; not independently measured | A |
| 10 | **Server-side logic / secrets** | **Strong for the moved data; none for the client contract** | Attacker replays or patches the client call to the server; server must validate. This is the honest #1. | Neither (moves the asset) |

Note on #10: Electron docs say nothing about this (electronjs.org security page, accessed 2026-11-14, does not address local tampering or secret storage in the client). The recommendation comes from our CLAUDE.md §3, not from Electron.

### 7. Observations for the proposal
- **Electron is a native-adjacent target** in the sense that a native-binary defense (fuse bytes, binary-level checks) applies; the JS payload is the part that needs a separate track.
- **Our harness fit.** An audit check for fuse state (read sentinel bytes) and ASAR integrity presence are feasible and read-only. Hardening (fuse flips, bytenode, obfuscation) is a build-step change that the existing `harness/` could host.
- **Maintenance cost.** Bytenode's version gate and Electron's patch cadence mean the harness needs version pinning and a test per Electron major version.

## Decisions needed from operator
- Whether to expand scope to Electron (CLAUDE.md §2 change), given Electron is currently "out of scope — reference only." Recommendation in this note: keep it a separate, labeled track with its own catalog entry; do not fold it into native.
- Whether the audit-first MVP should be "read Electron fuse and ASAR-integrity state" (read-only, low risk) before any hardening.

## Open questions
- PT Swarm bytenode article: date and technical scope (TLS error; re-fetch later).
- CVE-2025-55305 authoritative affected-version range (GHSA-vmqv-hx8q-j7mg not fetched).
- BLA release history: the README says 5.6k stars / npm `bla-agents` v3.3.1, vs 2.3k / v1.4.0 in the 2026-11-05 note. Verify which is current.
- Electron minimum version for fuse-reading support: not stated in the fuses doc.
- Controlled measurement of CFF + string-array against current LLMs: none found (2026). This is the K-style experiment we would need to run.
- NDSS 2026 JSIMPLIFIER PDF was not fetched (search snippet only).

## Sources
- Electron Fuses doc — https://www.electronjs.org/docs/latest/tutorial/fuses — accessed 2026-11-14 (no date shown)
- Electron ASAR Integrity doc — https://www.electronjs.org/docs/latest/tutorial/asar-integrity — accessed 2026-11-14 (no date shown)
- Electron Security doc — https://www.electronjs.org/docs/latest/tutorial/security — accessed 2026-11-14 (no date shown; cites v45.3.2 tag)
- Trail of Bits, "Subverting code integrity checks to locally backdoor Signal, 1Password, Slack, and more" — https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/ — 2025-09-03 — accessed 2026-11-14
- CVE-2025-55305 mirrors (vuldb, Fluid Attacks, cvelogic, Red Hat, Wiz) — e.g. https://www.cvelogic.com/cve/CVE-2025-55305 — accessed 2026-11-14 (severity CVSS 6.1 per NVD/GitHub as reported)
- PT Security dbugs PT-2025-35936 — https://dbugs.ptsecurity.com/vulnerability/PT-2025-35936 — listed in search, not fetched
- bytenode README — https://github.com/bytenode/bytenode — accessed 2026-11-14 (page shows "245 Commits", no release date)
- PT Security Swarm, "How we bypassed bytenode and decompiled Node.js bytecode in Ghidra" — https://swarm.ptsecurity.com/how-we-bypassed-bytenode-and-decompiled-node-js-bytecode-in-ghidra/ — **fetch failed (TLS) 2026-11-14; date unverified**
- PenTestIT, "Auditing Electron fuses with REA" — https://pentestit.com/auditing-electron-fuses-with-rea/ — 2026-10-20 — accessed 2026-11-14
- re-electron skill (skills.rest) — https://skills.rest/skill/re-electron-dslsdzc — "Updated Aug 17, 2026" — accessed 2026-11-14
- BLA (qybaihe/bla) README — https://github.com/qybaihe/bla — accessed 2026-11-14 (no release date on page)
- arXiv 2604.04289, "Poisoned Identifiers Survive LLM Deobfuscation: A Case Study on Claude Opus 4.6" — https://arxiv.org/abs/2604.04289 — 2026-04-05 — accessed 2026-11-14
- arXiv 2507.17691, CASCADE (Google) — https://arxiv.org/abs/2507.17691 — 2025-07-23 (rev. 2026-02-25) — accessed 2026-11-14
- NDSS 2026, "From Obfuscated to Obvious: A Comprehensive JavaScript Deobfuscation" — https://www.ndss-symposium.org/wp-content/uploads/2026-f2198-paper.pdf — search snippet only, not fetched
- javascriptobfuscator.com "Can AI Deobfuscate JavaScript?" — https://javascriptobfuscator.com/blog/can-ai-reverse-engineer-obfuscated-javascript.aspx — vendor, undated, not evidence
- Prior notes: `research/findings/2026-11-05-competitive-landscape.md`, `research/findings/2026-10-25-rea-weapons-inventory.md`

## Review log
- Scout 2026-11-14: draft. Known gaps listed under Open questions. Two fetch failures (PT Swarm) and one claim-correction (CASCADE) are flagged inline; no unverified claim is used as a load-bearing fact.
