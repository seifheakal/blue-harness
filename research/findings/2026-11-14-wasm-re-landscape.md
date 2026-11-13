# WebAssembly (Wasm) RE landscape — research (scope-expansion proposal input)
- Date: 2026-11-14
- Author role: Scout
- Phase: research
- Status: draft (needs Evaluator review)

## TL;DR
- Wasm is a typed, structured stack-machine compile target. It is harder to read than JS but easier than native x86/ARM: no `goto`, explicit types, explicit imports/exports. Decompilers (NotDec 2026, WaDec 2024, StackSight 2024, wasm-decompile, Ghidra plugin) and LLM pipelines already turn it into C-like code. Treat it as a readable substrate for the P0 threat, not a hard one.
- The one lever that is cheap and clearly helpful is removing debug metadata (`name` section, DWARF, producers). Its value against an LLM is probably small (names are inferable), and I found **no published measurement** of name-stripped vs. unstripped Wasm under LLM decompilation. That gap is the honest research opportunity.
- Wasm-specific obfuscation (CFF via block-split + switch-loop, linear-memory encryption, opaque predicates, wasm-mutate diversification) exists and is measured for *binary dissimilarity and detector evasion*, not for LLM comprehension. Expect Speed-bump at best against an unrestricted LLM plus a substrate (wasm2c → LLVM) deobfuscation path. Server-side relocation is the only Strong option.
- Recommendation for the proposal: scope Wasm in as a **sub-track of the browser/mobile-adjacent surface only if the operator's product actually ships `.wasm`**; the highest-value first slice is an *audit* (detect name/DWARF/producers/IL presence, measure exports/imports exposure), then an empirical LLM-comprehension A/B on stripped vs. unstripped builds (Slice-K style).

## Detail

### 1. Attacker workflow and what it needs from the target (design-level)
Steps, described only at the depth needed to place defenses:
1. **Obtain the module.** Browser: the `.wasm` is fetched by the page and is trivially downloadable from the network log or the bundle. Standalone/WASI: it sits on disk in the install directory. No defense here beyond not shipping logic that must stay secret. (Reference: [Harnes & Morrison, arXiv 2403.15197, 2024-03-22](https://arxiv.org/abs/2403.15197) describe Wasm binaries as freely obtainable artifacts in their threat framing — paraphrase, not verified verbatim.)
2. **Lower to text.** `wasm2wat` / `wasm-tools print` produce WAT. Names come from the `name` section if present; otherwise indices (`$func12`-style) remain. Source: [wabt decompiler docs (fork-hosted copy; upstream fetch returned 404 on 2026-11-14, so treat as unverified)](https://github.com/LucifielHack/wabt/blob/main/docs/decompiler.md).
3. **Decompile to C-like code.** Options observed in 2026 sources:
   - **NotDec** (WebAssembly-to-C with SSA IR and inter-procedural type recovery, Retypd-based). arXiv submitted 2026-08-04; abstract claims 100% recompilation on 5,241 Juliet samples and all Howard programs vs 45.95% for Ghidra; 85.33% struct-member recovery on real programs vs 9.24% for Ghidra. Listed as ICSE'26 with DOI 10.1145/3744916.3787762. Vendor-style comparison from the authors; not independently replicated. Source: [arXiv 2608.03286](https://arxiv.org/abs/2608.03286), accessed 2026-11-14.
   - **wasm-decompile** (wabt) — derives names from the name section, per the fork docs (unverified upstream).
   - **Ghidra**: no native Wasm support. Community plugin **nneonneo/ghidra-wasm-plugin** supports all Wasm 1.0 opcodes, call/branch xrefs, and a C-stack recovery path for Emscripten output; decompilation supported; release date not visible on the page. Source: [github.com/nneonneo/ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin), accessed 2026-11-14.
   - **idawasm** (Mandiant, IDA loader/processor): **archived 2023-12-26**; stale. Source: [github.com/mandiant/idawasm](https://github.com/mandiant/idawasm), accessed 2026-11-14.
   - **wasmdec** (Wasm → C): last updated 2018 per the arXiv 2411.02278 landscape discussion; lacks newer features. Secondary claim; treat as stale.
   - **JEB** (PNF, commercial): wasm plugins updated January 2026 for Wasm 3.0 support; smart-contract Wasm focus. Source: [pnfsoftware.com/jeb](https://www.pnfsoftware.com/jeb/), accessed 2026-11-14 (date from search snippet, not fetched directly).
4. **Feed to an LLM.** Two patterns in the literature:
   - **WaDec** (fine-tuned LLM on WAT → C): first submitted 2024-06-17, ASE 2024. Abstract: code inflation 3.34% (vs 116.94% SOTA), recompilability 52.11%, re-execution 43.55%, output consistency 27.15%, average code similarity above 50%. Baselines not named in the abstract; debug-name assumption not stated. Source: [arXiv 2406.11346](https://arxiv.org/abs/2406.11346), accessed 2026-11-14.
   - **StackSight** (ICML 2024): LLM + static analysis with stack visualization and semantic recovery. arXiv abstract says +70% functionally correct decompiled code; ICML poster says "nearly doubling." These conflict; check the full paper. Ablations: removing stack visualization or semantic recovery significantly hurts. Source: [arXiv 2406.04568](https://arxiv.org/abs/2406.04568), accessed 2026-11-14.
   - **Talis BHA 2025 ("Squanchy")**: Wasm → C via wasm2c → LLVM IR, then LLVM passes plus Simba++ (MBA) and Super (CFF) deobfuscators. Conference talk; no slides or paper retrieved. Source: [BHA25-028 listing](https://conference-intel.pages.dev/c/blackhat-asia-2025/bha25-028/), accessed 2026-11-14.
   - **Agentic / MCP path**: vendor listings (ReversePort, rea, GhidraMCP) claim Wasm support through Ghidra-based MCP servers. These are marketing/listing claims from search snippets, unverified. GhidraMCP is native-focused. No single source found that shows an end-to-end LLM agent reversing a Wasm app.

**Metadata survival matrix (what the attacker keeps vs. what you can remove)**

| Item | Survives by default? | How it is removed | Attacker cost if removed |
|---|---|---|---|
| Exports | Yes (host API needs them) | Rename only via host JS changes | Low — exports are the anchors an LLM starts from |
| Imports (module/field names) | Yes | Rename only via host JS changes | Low — imports reveal host calls (fetch, storage, crypto) = strong semantic hints |
| `name` custom section | Often yes | `wasm-opt --strip-debug` (alias `--strip`); `wasm-tools strip --all`; `emstrip --no-strip-all --remove-section=name` (keeps DWARF) | Moderate for symbol-level naming; low for semantic recovery (inference) |
| DWARF `.debug_*` | Only in debug builds | `wasm-tools strip` (default removes DWARF and other custom sections, keeps `name` unless `--all`); `wasm-opt --strip-dwarf` | Low once names are gone — but DWARF is large (example: 2.3 MB of a 3 MB file) and gives types/lines |
| `producers` section | Usually | `wasm-opt --strip-producers` | Negligible |
| Custom watermark section | If you add one | `wasm-tools strip --all` | Trivial to remove (attribution defense is then bypassed) |
| Go `go.buildid` section | Yes | Not verified which flags remove it | Unknown — flag |

Sources: [wasm-opt man page (binaryen 120), Debian trixie](https://manpages.debian.org/trixie/binaryen/wasm-opt.1.en.html), [wasm-tools repo](https://github.com/bytecodealliance/wasm-tools), [Chrome "Debugging WebAssembly Faster" blog](https://developer.chrome.com/blog/faster-wasm-debugging) — **date not stated; references a 2020 event, treat as dated**; all accessed 2026-11-14.

**Toolchain notes (defaults are build-dependent and not fully verified)**
- Emscripten: `name` and DWARF removal is coupled to `--strip-debug` in the link path; the default for `EMIT_NAME_SECTION` was not confirmed. Verify against the pinned emsdk version.
- Rust: wasm-opt removes the names section by default unless `-g`; Cargo's `strip = "debuginfo"` default is reported in a 2024 blog post and was not confirmed for stable. Source (secondary): Rust and WebAssembly book, accessed 2026-11-14 via search snippet.
- Go: `-ldflags "-s -w"` effect on the Wasm name section was **not confirmed**. Build and inspect with `wasm-objdump -x` to verify.
- Blazor WebAssembly: AOT compiles .NET to Wasm but **does not trim managed DLLs**; reflection metadata DLLs ship to the client. Microsoft docs (ms.date 2025-11-11, updated 2026-11-04). The IL is therefore still an attack surface independent of the Wasm. Source: [Microsoft Learn, Blazor WASM build tools and AOT](https://learn.microsoft.com/en-us/aspnet/core/blazor/webassembly-build-tools-and-aot), accessed 2026-11-14.

### 2. How well LLM-driven / agentic tooling automates Wasm RE
- **Easier than native, harder than JS.** Wasm has structured control flow (no arbitrary `goto`; jumps target block heads/tails) and explicit typing and imports/exports (WASMixer paper states this explicitly). That makes decompilation to structured C feasible (NotDec, WaDec), which is what an LLM needs.
- **Stack machine overhead** is the main LLM comprehension tax. StackSight's stack-visualization ablation is the evidence that naive LLM reading of raw stack code is poor.
- **Name recovery is the attacker's hard part** only if names are gone. The evidence I found does **not** show that stripped names defeat LLM comprehension; WaDec and StackSight do not report a stripped vs. unstripped comparison in the abstracts I could read. Treat this as the single most important open question.
- **Wasm 3.0** (finalized 2025-09-17; GC, typed references/`call_ref`, exception handling, tail calls, memory64, multiple memories; "live" standard) adds GC struct/array types. Richer type info likely *helps* a decompiler recover structs (analysis inference, not measured). Source: [webassembly.org news, 2025-09-17](https://webassembly.org/news/2025-09-17-wasm-3.0/), accessed 2026-11-14. (Note: a byteiota article claiming a June 2026 landing date conflicts with the official source; rejected.)
- **General LLM-on-obfuscated-code evidence (not Wasm):**
  - arXiv 2604.08083 (2026-04-09), "Can LLMs Deobfuscate Binary Code?": introduces BinDeObfBench; reports that performance depends more on reasoning capability than model scale. No Wasm; no numbers in abstract. Source: [arXiv 2604.08083](https://arxiv.org/abs/2604.08083).
  - arXiv 2609.04220 (listed 3 Jul 2026, but ID suggests Sept 2026 — **date anomaly, verify**): on protected C++/Go/Java/JavaScript code, direct inference on obfuscated code "often matches or exceeds" inference after restoration; GPT-4.1 and Qwen3-Coder-30B keep ~90% Pass@1 on obfuscated translation. Not Wasm. Source: [arXiv 2609.04220](https://arxiv.org/abs/2609.04220).
  - arXiv 2606.06838 (2026-06-05), Commonwealth Bank of Australia: LLM agent refines Ghidra C for readability; synthetic native x86-style binaries; no Wasm; no compile-free validation. Agents "optimize for metrics in unintended ways." Source: [arXiv 2606.06838](https://www.alphaxiv.org/abs/2606.06838.md).
- **Wasm deobfuscation with LLMs (2026):** an IEEE Access 2026 paper, "A Systematic LLM-Based Procedure for the Deobfuscation of WebAssembly: Benchmark and Security Evaluation" (Cheon, Jung, Lee; DOI 10.1109/access.2026.3724950), is the only Wasm-specific LLM deobfuscation lead. **Unverified**: no abstract, no results, no PDF retrieved. Source (lead only): [Awesome-REA issue #2643](https://github.com/reacher-z/Awesome-REA/issues/2643), accessed 2026-11-14. An IEEE Access paper with a similar title in search results was a different general-code paper; do not conflate.

**Honest read:** an unrestricted local model plus NotDec/WaDec-class decompilation plus an LLM will produce readable logic for a typical unobfuscated Wasm module. The hard parts for an attacker are (a) obfuscated control flow + encrypted memory, and (b) scale on large C++ modules. None of that is a barrier to a motivated analyst.

### 3. Candidate defenses (tiers and named bypasses)

Substrate = breaks the decompiler/instrumentation (classic). AI-layer = degrades LLM comprehension or agent automation. Tiers per `docs/threat-model.md` (Trivial / Speed-bump / Meaningful / Strong).

| # | Countermeasure | Layer | Tier (vs unrestricted LLM agent) | Named bypass | Evidence / note |
|---|---|---|---|---|---|
| D1 | Strip `name` section + DWARF + producers (`wasm-opt --strip-debug --strip-producers`, `wasm-tools strip --all`) | Substrate (names) | **Trivial** for semantics; **Speed-bump** for symbol-level naming | *LLM semantic renaming* from behavior, imports/exports, and string constants (the CBA-style refinement loop) | Cheap; always do it. No stripped-vs-unstripped LLM measurement found — must measure. |
| D2 | Randomize export/import names (host JS updated) | AI-layer (anchors) | **Speed-bump** | *Import-signature heuristics* (host API shape: fetch, WebCrypto, WASI calls) still reveal semantics | WASMixer randomizes names in debug section at ~zero overhead; import/export randomization needs JS changes. |
| D3 | Control-flow flattening (block-split, stack via locals, switch-in-loop; WASMixer/Tigress/emcc-obf) | Both | **Speed-bump** (LLM); **Meaningful-** against naive decompile output (nesting depth 72→489 in WASMixer's test; call_indirect ~10.9×) | *LLVM deobfuscation via wasm2c → LLVM* (Talis "Squanchy" + Super CFF deobf, BHA 2025) | Overhead <20% at WASMixer O1 for code obf; bypass is a published-talk technique. |
| D4 | Linear-memory encryption (decrypt-on-load wrappers; WASMixer) | Both | **Speed-bump** statically; **Trivial** dynamically | *Runtime memory dump / breakpoint on the dec_load wrapper* after decrypt in browser devtools or wasmtime | WASMixer: up to ~47% exec-time overhead on one dataset. Key lives in the same process — honest limit. |
| D5 | Opaque predicates (Collatz) + alias disruption (`call_indirect` substitution) | AI-layer (path explosion) | **Speed-bump** | *Concrete-value simplification / symbolic execution on constant-folded predicates* | WASMixer: manticore and wasp timed out (48h) on tested cases at O1 — symbolic-execution-specific; an LLM reads predicates directly, so AI-layer effect is unmeasured. |
| D6 | Semantics-preserving diversification (wasm-mutate, e-graph based; 135 transformations in the malware-evasion paper) | Substrate (byte signatures) | **Trivial** against comprehension; defeats hash/byte matching | *Semantic re-recognition by LLM* (it reads logic, not bytes) | wasm-mutate is in wasm-tools; cryptojacking-detector evasion shown in arXiv 2403.15197. Useless as an LLM defense; useful for per-build uniqueness/attribution. |
| D7 | Obfuscating compilers (emcc-obf: obfuscator-LLVM passes; Tigress wasm) | Both | **Speed-bump** to **Meaningful** against static diff-based analysis (Tigress most effective dissimilarity in arXiv 2403.15197) | *LLVM/ Binaryen-level normalization* or *dynamic trace-based re-recognition* | emcc-obf: no releases, Docker build; lacks memory encryption and alias disruption per a thesis record. Reproducibility risk. |
| D8 | Watermark/canary custom section or data-embedded token | Attribution | **Trivial** (removable) | *`wasm-tools strip --all` or byte-level edit of the custom section* | Attribution only; never a protection. Must be placed where stripping breaks the app (e.g., in data segments checked at runtime) — untested idea. |
| D9 | Integrity check of the module in the host (hash the bytes, refuse on mismatch) | Substrate (tamper) | **Speed-bump** | *Patch the host JS loader or hook `WebAssembly.instantiate`* | Browser-side hooks are the normal attacker path; it raises cost only. Pairs with harness integrity/anti-tamper slices. |
| D10 | Split sensitive logic out / move it server-side (rate-limited API, key never leaves server) | Relocation | **Strong** (for the moved logic) | *None against the moved logic*; the attacker attacks the API (replay, scraping, protocol RE). | Honest #1 per CLAUDE.md §3. Only option that survives an LLM that can read every byte. |
| D11 | Keep secrets out of the module; no in-Wasm keys | Relocation | **Trivial** if keys are shipped; **Strong** if not shipped | *Key extraction from linear memory at runtime* | Same one law as threat-model.md. |
| D12 | Blazor: do not rely on AOT — trim/obfuscate IL DLLs too, and treat IL as the primary surface | Substrate (.NET) | **Trivial** to **Speed-bump** (IL is shipped) | *IL decompiler on the shipped DLLs* (AOT does not remove them, per Microsoft docs) | Important scoping note if the target is Blazor. |
| D13 | Bloat/exhaustion for LLM context (large, deeply nested, obfuscated Wasm) | AI-layer (context) | **Unknown** — hypothesis, not measured | *Chunked decompilation over many calls* (WaDec splits into snippets) | Needs an empirical A/B like the Slice K run; do not claim before measured. |

**Ranking for the proposal (value per cost, honest):**
1. D10/D11 (relocate) — Strong; required first.
2. D1 — Trivial but always-on; first audit check.
3. D3 + D4 — the only items with published Speed-bump-to-Meaningful evidence against static analysis; costs 20–47% perf.
4. D2/D5 — AI-layer candidates; need measurement.
5. D6/D8/D9 — attribution/tamper signals; do not present as anti-RE.

### 4. Substrate vs AI-layer summary
- **Substrate-breaking (classic):** D1, D3, D4, D6, D7, D9, D12. These blind wabt / Ghidra / NotDec-class pipelines and the LLM that rides them.
- **AI-layer (novel):** D2 (anchor scrambling), D5 (path explosion, unmeasured for LLMs), D13 (context exhaustion, unmeasured). Nothing Wasm-specific has been shown to degrade an unrestricted LLM's comprehension. This is the research claim to test, not assume.

### 5. Gaps and stale items
- No 2026 peer-reviewed measurement of LLM comprehension on stripped vs. unstripped Wasm was found.
- Ghidra Wasm plugin release date not visible; IDA loader archived 2023.
- Wasm-specific LLM deobfuscation paper (Cheon et al., IEEE Access 2026) not retrieved — treat as a lead only.
- Sources conflicting or unverified: StackSight 70% vs "nearly doubling"; arXiv 2609.04220 date; NotDec ICSE'26 timing; Chrome blog date; emsdk and Go default name-section behavior.
- Wasm 3.0 browser support is uneven per secondary sources (byteiota, undated); check current feature tables before claiming support.

## Decisions needed from operator
- Does the target product actually ship `.wasm` (browser, Electron/web-shell, or standalone WASI)? If not, this scope expansion is not needed now.
- If yes: approve a first slice limited to (a) an audit of name/DWARF/producers/IL presence and export/import exposure, and (b) an empirical stripped-vs-unstripped LLM comprehension A/B on a local open-weight model (Slice K pattern). No new hardening until (b) has numbers.

## Open questions
- Does stripping the `name` section materially change LLM decompilation quality for Wasm? (Not found in literature; the single most important measurement.)
- Are D2/D5/D13 effective against an unrestricted LLM, or just against classic symbolic/pattern tools?
- Which Emscripten version and Rust/Go flags actually emit or drop the `name` section? (Verify on pinned toolchains.)
- Does the IEEE Access 2026 Cheon et al. paper exist as described, and what are its results?
- Should Blazor be in scope, given IL ships alongside AOT?

## Sources
- NotDec: WebAssembly Decompilation With Inter-Procedural Type Recovery (arXiv 2608.03286, submitted 2026-08-04) — https://arxiv.org/abs/2608.03286 — accessed 2026-11-14
- NotDec ACM listing (ICSE'26 per page) — https://dl.acm.org/doi/10.1145/3744916.3787762 — accessed 2026-11-14 (search snippet)
- WaDec: Decompiling WebAssembly Using LLM (arXiv 2406.11346, first submitted 2024-06-17; ASE 2024) — https://arxiv.org/abs/2406.11346 — accessed 2026-11-14
- StackSight (arXiv 2406.04568; ICML 2024) — https://arxiv.org/abs/2406.04568 — accessed 2026-11-14
- Is This the Same Code? Decompilation for WebAssembly (arXiv 2411.02278, 2024-11-04) — https://arxiv.org/abs/2411.02278 — accessed 2026-11-14 (abstract only)
- Cryptic Bytes: WebAssembly Obfuscation for Evading Cryptojacking Detection (arXiv 2403.15197, 2024-03-22) — https://arxiv.org/abs/2403.15197 — accessed 2026-11-14
- WASMixer: Binary Obfuscation for WebAssembly (arXiv 2308.03123, 2023-08) — https://ar5iv.labs.arxiv.org/html/2308.03123 — accessed 2026-11-14
- WASM-MUTATE (arXiv 2309.07638, 2023-09; rev. 2024-01) — https://arxiv.org/abs/2309.07638 — accessed 2026-11-14 (search snippet)
- Talis, "Standing on the Shoulders of Giants: De-Obfuscating WebAssembly Using LLVM" (Black Hat Asia 2025 listing) — https://conference-intel.pages.dev/c/blackhat-asia-2025/bha25-028/ — accessed 2026-11-14
- Can LLMs Deobfuscate Binary Code? (arXiv 2604.08083, 2026-04-09) — https://arxiv.org/abs/2604.08083 — accessed 2026-11-14
- Robustness and Trade-offs for Code LLMs on Protected Code (arXiv 2609.04220; listed 2026-07-03, ID anomaly) — https://arxiv.org/abs/2609.04220 — accessed 2026-11-14
- LLM Agent-Assisted Reverse Engineering with Quantitative Readability Metrics (arXiv 2606.06838, 2026-06-05) — https://www.alphaxiv.org/abs/2606.06838.md — accessed 2026-11-14
- Awesome-REA issue #2643 (lead for Cheon et al., IEEE Access 2026; unverified) — https://github.com/reacher-z/Awesome-REA/issues/2643 — accessed 2026-11-14
- WebAssembly 3.0 announcement (2025-09-17) — https://webassembly.org/news/2025-09-17-wasm-3.0/ — accessed 2026-11-14
- wasm-opt 120 man page (Debian trixie) — https://manpages.debian.org/trixie/binaryen/wasm-opt.1.en.html — accessed 2026-11-14
- wasm-tools repository (strip, mutate, smith, print, demangle) — https://github.com/bytecodealliance/wasm-tools — accessed 2026-11-14
- Chrome, "Debugging WebAssembly Faster" (date not stated; ~2020 references) — https://developer.chrome.com/blog/faster-wasm-debugging — accessed 2026-11-14
- nneonneo/ghidra-wasm-plugin (no release date visible) — https://github.com/nneonneo/ghidra-wasm-plugin — accessed 2026-11-14
- mandiant/idawasm (archived 2023-12-26) — https://github.com/mandiant/idawasm — accessed 2026-11-14
- Microsoft Learn: Blazor WebAssembly build tools and AOT (ms.date 2025-11-11; updated 2026-11-04) — https://learn.microsoft.com/en-us/aspnet/core/blazor/webassembly-build-tools-and-aot — accessed 2026-11-14
- JEB decompiler (wasm plugin update Jan 2026, per search snippet) — https://www.pnfsoftware.com/jeb/ — accessed 2026-11-14
- wabt decompiler doc (fork-hosted; upstream returned 404) — https://github.com/LucifielHack/wabt/blob/main/docs/decompiler.md — accessed 2026-11-14 (unverified)
- emcc-obf (no releases; Docker build) — https://github.com/HakonHarnes/emcc-obf — accessed 2026-11-14 (search snippet)

## Review log
- Scout 2026-11-14: draft. Not reviewed. Evaluator to verify StackSight figure, arXiv 2609.04220 date, NotDec venue timing, and all "unverified" items before this feeds a design.
