# JS deobfuscation / minified-JS RE landscape (scope-expansion proposal input) — research
- Date: 2026-11-14
- Author role: Scout
- Phase: research
- Status: draft (needs Evaluator)

## TL;DR
- Minified or obfuscated JavaScript is the most exposed client-side target we have studied. The artifact is already in the language an LLM reads best, and the transformations are text-to-text. An LLM can rename identifiers back to meaningful names with a single prompt. The skill floor is close to zero: one CLI command (humanify) or one agent request.
- Measured evidence on modern LLMs is mixed, not uniformly strong. A 2025 benchmark (JsDeObsBench) found LLM execution correctness around 61% on benign obfuscated code and far lower on malware. Deterministic tools (webcrack, synchrony) still reverse javascript-obfuscator's output. Google's CASCADE pairs an LLM with compiler IR for string recovery. Do not read the numbers as "LLMs cannot do it", and do not read them as "obfuscation works".
- Only Trivial to Speed-bump protections exist for logic that stays on the client. The one Strong lever is moving secret logic to the server. Source-map withholding is hygiene, not a barrier.
- Recommendation for the proposal: treat JS/web as a P0-exposed track where the honest product is "measure exposure, remove secrets, withhold source maps, then obfuscate as a cost speed-bump." Do not sell client-side JS obfuscation as protection.

## Detail

### 1. Attacker workflow and what it needs from the target
Steps only, at the level needed to design defenses.

1. **Acquire the artifact.** Client JS is shipped to the attacker's machine by definition. Check first for leaked sourcemaps and unminified source, which are the cheapest wins for an attacker.
   - Source-map leakage. Webpack's own docs list `hidden-source-map` as a production option that omits the reference comment but still emits full source content. Third-party guides say the `.map` file must also be removed from the served artifact, because hiding the reference is not enough. `nosources-source-map` and `devtool: false` are the documented alternatives. Source: [webpack devtool docs](https://webpack.js.org/configuration/devtool/index.html) and [v4 devtool table](https://v4.webpack.js.org/configuration/devtool/), accessed 2026-11-14. The "remove the map" advice comes from third-party guides (e.g. [Sentry guide](https://www.mintlify.com/getsentry/sentry-javascript/guides/best-practices/sourcemaps)), not from an official webpack page.
   - Real-world precedent (secondary sources only, conflicting details). In late March 2026 a Claude Code npm package reportedly shipped a `.map` whose `sourcesContent` embedded full TypeScript source. Sources disagree on size, file count, and whether the cause was the bundler. Treat as reported, not verified. Examples: [SocRadar write-up](https://socradar.io/blog/claude-code-leak-what-to-know/) and [DevStarsJ analysis, dated 2026-04-01](https://devstarsj.github.io/ai/2026/04/01/claude-code-source-leak-npm-sourcemap-bun-bug-analysis/). Accessed 2026-11-14.
2. **Un-bundle.** Webpack and browserify bundles are split back into modules. webcrack does this and rewrites `__webpack_require__(id)` into relative `require` paths. Source: [webcrack README](https://github.com/j4k0xb/webcrack), accessed 2026-11-14.
3. **Undo mechanical obfuscation (deterministic).** javascript-obfuscator output (string arrays, rotation, control-flow flattening) is handled by deterministic tools. webcrack targets obfuscator.io output and lists string array rotation/shuffling. Source: [webcrack README](https://github.com/j4k0xb/webcrack), accessed 2026-11-14. synchrony is "primarily javascript-obfuscator/obfuscator.io" and notes that artifacts from old javascript-obfuscator versions may not deobfuscate. Source: [synchrony README](https://github.com/uwu/synchrony), accessed 2026-11-14. restringer is a string-recovery and cleanup tool with specialized processors for javascript-obfuscator patterns. Source: [restringer README (npm/cdn)](https://cdn.jsdelivr.net/npm/restringer@2.2.0/README.md), accessed 2026-11-14.
4. **Restore names and meaning (LLM).** This is the step that changes the skill floor.
   - humanify (npm `humanifyjs`, repo `jehna/humanify`, MIT). The LLM only proposes new identifier names. The rewrite is done at AST level via oxc, so structure is preserved. Backends include OpenAI, Gemini, Anthropic, Ollama (local), OpenRouter, and Requesty. It makes one LLM call per identifier. Source: [humanify README](https://github.com/jehna/humanify), accessed 2026-11-14. Version 3 (single static Rust binary) is announced on the page, but the page gives no version number or release date. Treat the date as unverified.
   - An arXiv preprint (JSimplifier, 2512.14070, submitted 2025-12-16, NDSS 2026) includes "LLM-enhanced identifier renaming" as one stage of a pipeline. Its abstract reports 100% processing across 20 obfuscation techniques and an 88.2% complexity reduction. The abstract does not describe the LLM step or give semantic-consistency or hallucination rates. Source: [arXiv 2512.14070](https://arxiv.org/abs/2512.14070), accessed 2026-11-14. Numbers are self-reported, unreplicated.
   - CASCADE (Google, arXiv 2507.17691, July 2025; ICSE-SEIP 2026, talk 15 Apr 2026). Gemini plus JavaScript IR (JSIR) for obfuscator.io string obfuscation. Reports 99.56% success for detecting prelude functions on a synthetic 12K-file set. Deployed internally. Prompts and JSIR are open-sourced at github.com/google/jsir. Source: [arXiv 2507.17691](https://arxiv.org/pdf/2507.17691), [ICSE-2026 page](https://conf.researchr.org/details/icse-2026/icse-2026-software-engineering-in-practice/21/CASCADE-LLM-powered-JavaScript-Deobfuscator-at-Google), accessed 2026-11-14.
5. **Verify and iterate.** Run the code, diff behaviour, and re-prompt. Hostile automation can chunk per-function and retry.

### 2. How well LLM and agentic tooling automates this
- **Benchmark (June 2025, CCS 2025).** JsDeObsBench (Chen, Jin, Lin, Ohio State; arXiv 2506.20170, submitted 2025-06-25). Uses javascript-obfuscator on CodeNet programs, 36,260 unique obfuscated programs. Models: CodeLlama, Llama-3.1, Codestral, Mixtral, DeepSeek-Coder, and GPT-4o. Main findings (from the arXiv HTML and a secondary summary): LLMs did best on simplification and readability (higher CodeBLEU), but had syntax and execution-reliability problems versus baseline tools. Failure modes were context truncation and refusals on malware (GPT-4o). A secondary summary reports execution correctness near 61% on benign code, falling to about 15% on malware. These figures are not checked against the paper. Sources: [arXiv 2506.20170 HTML](https://arxiv.org/html/2506.20170v1), [leaderboard](https://jsdeobf.github.io) (no numbers on the page), accessed 2026-11-14.
  - Note: the benchmark used the models available as of mid-2025. Expect 2026 frontier and local models to do better. Re-run before quoting.
- **OBsmith (arXiv 2510.10066, Oct 2025).** Tests seven models against bogus control flow, instruction substitution, control-flow flattening, and combinations. Reports a three-tier ordering: bogus control flow lowest resistance, flattening moderate, instruction substitution and combined highest. Also reports 11 correctness bugs found in JS obfuscators. Source: [arXiv listing via deeppaper mirror](https://arxiv.deeppaper.ai/papers/2510.10066v1), accessed 2026-11-14. Secondary summary, not checked against the paper.
- **Promon App Threat Report 2026 Q1 (2026-03-26).** Tests 10 models on Obfuscator-LLVM over native C binaries, not JS. Relevant as a native baseline for comparison. Best models reconstructed working x86 code 20–36% of the time on three-pass obfuscation. Clean-code baseline for the same models was up to 86%. Vendor report with a short-program, zero-shot setup. Source: [Promon report](https://promon.io/security-news/app-threat-report-2026-q1-the-state-of-code-obfuscation-against-ai), accessed 2026-11-14. Do not use as JS evidence.
- **Skill-floor observation (our assessment, not a measured claim).** Public agent-skill routers already list "deobfuscate JavaScript" as a capability. Examples found: [skills.sh "deobfuscate javascript"](https://www.skills.sh/jimliu/decode-codex/deobfuscate-javascript) and [skills.sh "reverse engineer js"](https://www.skills.sh/vladmdgolam/agent-skills/reverse-engineer-js). Both were surfaced by search; neither was reviewed in depth. Treat their presence as evidence the routing exists, not as a measure of efficacy.
- **Honest comparison to native.** Our assessment: JS is much more exposed than native. Reasons: (a) the shipped text is the source language; (b) the transform is text-to-text, which LLMs handle natively; (c) renaming and string recovery are local and cheap; (d) the open-weight models run locally with no gate. Native binaries still need decompilation and lose type and name information, which is why the Promon numbers are lower.

### 3. Candidate defenses (for code the operator owns)
Tier scale: Trivial / Speed-bump / Meaningful / Strong. Each one names a bypass. Substrate = the deterministic tooling (webcrack, synchrony, restringer, AST passes). AI layer = LLM renaming, summarisation, and reasoning.

| Countermeasure | What it does | Tier (honest) | Named bypass | Layer |
|---|---|---|---|---|
| Withhold source maps (no `.map` served or shipped, no `sourcesContent`) | Removes the cheapest leak | Trivial as protection of logic. Meaningful only against the map-leak vector | Logic is still in the shipped JS; humanify and webcrack operate without maps | Substrate (hygiene) |
| Minification (terser / esbuild / SWC mangle) | Removes names and whitespace | Trivial | humanify renames identifiers back from context, one LLM call per identifier | AI layer |
| Property and identifier mangling (aggressive, consistent) | Harder to map to API names | Speed-bump | LLM infers from call shapes, string literals, and library signatures; unbundled webpack keeps module names | AI layer |
| javascript-obfuscator default-ish profile (string array + rotate) | Hides literals behind an indexed, rotated array | Speed-bump | webcrack handles obfuscator.io string-array rotation; synchrony, restringer, CASCADE cover the same class | Substrate (deterministic), plus AI (CASCADE) |
| Control-flow flattening (`controlFlowFlattening`) | Breaks linear control flow | Speed-bump. Costs up to 1.5× runtime per README | OBsmith rates flattening as "moderate" resistance; deterministic unflatteners are a known class; LLMs reconstruct linear flow from the state machine | Both |
| Dead-code injection (`deadCodeInjection`) | Inflates size and noise, increases context cost | Speed-bump. Size can grow up to 200% per README | Chunking per function and filtering dead branches; deterministic dead-code elimination | Both (context-exhaustion idea is untested for JS) |
| `selfDefending` / `debugProtection` | Breaks if beautified; freezes DevTools | Trivial | Remove the check after deobfuscation, or run in a non-browser runtime or headless harness. Our assessment: a headless agent does not need DevTools at all | Substrate |
| Server-side secret logic (move the logic and keys off the client) | Attacker never receives the secret | **Strong** for the moved logic. Honest #1 recommendation | Attacker can still call the server; design the API as the security boundary (rate limits, auth, input checks) | Neither. Architectural |
| VM-based obfuscation (vendor Pro tier at obfuscator.io, token-gated) | Interprets logic in a bespoke bytecode VM | Unknown. Not measured by us | Not tested in any source we found. Do not claim a tier until we test | Unknown |

Notes on the table:
- The javascript-obfuscator README itself says output "is still JavaScript", and marks the free package as "fully vulnerable (no LLM-specific defenses)". Source: [javascript-obfuscator README](https://github.com/javascript-obfuscator/javascript-obfuscator), accessed 2026-11-14.
- The README also warns about 15–80% runtime slowdown and significantly larger files, and advises against obfuscating vendor scripts and polyfills. Source: same.
- `disableConsoleOutput` and `renameGlobals` are listed but not evaluated here.
- Integrity or attestation of JS, and watermarking of AI-generated cracks, are open design questions. We did not find a shipped, measured JS-specific control in this pass.

### 4. Where this leaves the Priority-0 threat front
- **Break the substrate:** deterministic obfuscation is reversible by existing public tools, so cost is a few minutes per target. The classic countermeasures do not defeat this class.
- **Break the AI layer:** the strongest available cheap lever is still structural (flattening, dead code, string encryption) and it is only a speed-bump, because a capable LLM can work per function. The "AI will refuse" assumption is not a defense (JsDeObsBench already saw refusals on malware for one model, which is not a control we can rely on).
- **Strongest honest lever:** move the logic that matters to the server. Everything else is a cost multiplier, and should be presented as one.

## Decisions needed from operator
- Scope: confirm whether JS/web (and React Native / Electron-style shells, which we have not researched) moves from "reference-only" to an active track. The current CLAUDE.md §2 puts web/JS/Electron out of scope.
- Positioning: confirm that the JS track is framed as "measure exposure, remove secrets, withhold maps, obfuscate as speed-bump", not as "protection".

## Open questions
- Release dates for humanify (v3), webcrack, javascript-obfuscator, and synchrony were not confirmed. The fetched pages showed no dated releases. Check GitHub releases or npm before quoting versions.
- JsDeObsBench per-transformation numbers and the 61% / 15% figures come from secondary summaries. Verify against the arXiv HTML table before use.
- JSimplifier's LLM-renaming numbers were not found in the abstract. The earlier 83% / 12% figures from a search snippet are unverified and are not used here.
- Wakaru: the only mention found was in a benchmark gist, with no documentation. Not characterized.
- Whether a headless or harnessed agent is blocked by `debugProtection`-style checks was not tested.
- Does the 2026 Claude Code source-map incident have an official Anthropic statement? Not found. Treat the details as unconfirmed.
- Needs empirical measurement: a Carapace-style A/B on a javascript-obfuscator build with a local model, similar to the Slice K run, before any tier is stated as measured.

## Sources
- humanify README (jehna/humanify) — https://github.com/jehna/humanify — accessed 2026-11-14 (no release date on page)
- webcrack README (j4k0xb/webcrack) — https://github.com/j4k0xb/webcrack — accessed 2026-11-14 (no release date on page)
- synchrony README (uwu/synchrony) — https://github.com/uwu/synchrony — accessed 2026-11-14 (no release date on page)
- restringer README (npm/cdn 2.2.0) — https://cdn.jsdelivr.net/npm/restringer@2.2.0/README.md — accessed 2026-11-14
- javascript-obfuscator README (master) — https://github.com/javascript-obfuscator/javascript-obfuscator — accessed 2026-11-14 (page says master may differ from stable)
- JSimplifier, arXiv 2512.14070 (submitted 2025-12-16; NDSS 2026) — https://arxiv.org/abs/2512.14070 — accessed 2026-11-14
- CASCADE, arXiv 2507.17691 (2025-07) and ICSE-SEIP 2026 page — https://arxiv.org/pdf/2507.17691 ; https://conf.researchr.org/details/icse-2026/icse-2026-software-engineering-in-practice/21/CASCADE-LLM-powered-JavaScript-Deobfuscator-at-Google — accessed 2026-11-14
- JsDeObsBench, arXiv 2506.20170 (2025-06-25; CCS 2025) — https://arxiv.org/html/2506.20170v1 — accessed 2026-11-14 (secondary-summary figures flagged)
- JsDeObsBench leaderboard — https://jsdeobf.github.io — accessed 2026-11-14 (no numbers on page)
- OBsmith, arXiv 2510.10066 (2025-10) — https://arxiv.deeppaper.ai/papers/2510.10066v1 — accessed 2026-11-14 (secondary mirror)
- Promon App Threat Report 2026 Q1 (2026-03-26), native OLLVM — https://promon.io/security-news/app-threat-report-2026-q1-the-state-of-code-obfuscation-against-ai — accessed 2026-11-14
- webpack devtool docs — https://webpack.js.org/configuration/devtool/index.html — accessed 2026-11-14
- webpack devtool v4 table — https://v4.webpack.js.org/configuration/devtool/ — accessed 2026-11-14
- Sentry JS source-map guide (third-party mirror) — https://www.mintlify.com/getsentry/sentry-javascript/guides/best-practices/sourcemaps — accessed 2026-11-14
- Claude Code source-map incident (secondary, conflicting) — https://socradar.io/blog/claude-code-leak-what-to-know/ ; https://devstarsj.github.io/ai/2026/04/01/claude-code-source-leak-npm-sourcemap-bun-bug-analysis/ — accessed 2026-11-14
- skills.sh routers — https://www.skills.sh/jimliu/decode-codex/deobfuscate-javascript ; https://www.skills.sh/vladmdgolam/agent-skills/reverse-engineer-js — accessed 2026-11-14

## Review log
- Scout 2026-11-14: draft. Figures from secondary sources are marked. No code or CLAUDE.md edits made.
