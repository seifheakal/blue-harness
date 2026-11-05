# Competitive landscape — anti-AI-RE defenders — research + absorption plan
- Date: 2026-11-05
- Author role: Primary (inline)
- Phase: research → feeds analysis/implementation
- Status: draft (needs Evaluator sign-off)

## TL;DR
- The thesis is validated by the market: **others now ship defenses against AI-RE
  agents like `rea`/REA.** Three public repos found (2026-11-05). All MIT.
- **BLA** (`qybaihe/bla`, ~2.3k★, v1.4.0, active) is the serious one and the
  closest to our P0 thesis — *"Poison → Exhaust → Hallucinate … against AI
  reverse-engineering agents like REA."* It is **broad** (JS/Electron/Wasm/
  SQLite/GGUF/BEAM/Flutter/…) and has **empirical REA runs**, a **benchmark**, and
  a **CrackMe**.
- **antirea** (`MockirDev/antirea`, ~36★) and **AREA**
  (`davepartner/anti-reverse-engineer-anything`, ~3★) are small/new; antirea leans
  on **instruction-file barriers** (a non-defense by our rules — see below).
- **BLA is not a superset of Carapace.** It is broad-and-shallow and is strongest
  exactly where our CLAUDE.md §2 scope is *out of scope* (Electron/web/JS/Wasm/
  .NET bundles). On **native binaries** — our lane — BLA's own README says
  Ghidra/Frida/LLDB/Rizin/JADX were **"not run … does not claim those paths are
  defeated yet,"** and its `verify:rea` is a **"constant-drift check only, not
  proof of protection."** Our verify proves *mechanism firing*; our tiering names
  a bypass per countermeasure. Those are our differentiators.
- **Operator decision (2026-11-05): absorb every good idea from them into Carapace**
  ("engulf them"), planned as our own slices, keeping our native/mobile depth and
  mechanism-proof discipline. Absorb *techniques/ideas* only — **not their MIT
  code** (clean-room; no code lift).

## Detail

### The three defenders (all self-described; external, unverified — I ran none)

**BLA — `qybaihe/bla` — ~2.3k★ / 309 forks / MIT / v1.4.0 / active (pushed 2026-11-05).**
- Model: **Poison** (format-valid canary creds, honey metadata, decoy control
  flow) → **Exhaust** (push artifacts past REA's *documented* resource budgets:
  header sizes, nesting depth, interface inventories, PCAP-JSON size) →
  **Hallucinate** (truncated inventories, redaction failures, ambiguous dead ends).
- Runtime guard: Electron fuse hardening; CDP/Frida/inspector detection → returns
  synthetic telemetry.
- Install UX: **`npx bla-agents setup`** registers an **MCP server + agent skill**
  (Claude Code/Cursor/Codex/VS Code); **`npx bla-agents harden .`** = one pass
  (audit→protect→verify→defend).
- Honesty signals: status labels **verified / designed-for / skipped / benchmark-
  only / LIMITED**; token/cost multipliers (≈612× tok / ≈292× cost on a 14-target
  benchmark) are **"internal estimates"**; `verify:rea` is a **drift check, not
  proof**; Ghidra/Frida/LLDB/Rizin/JADX **"not run."**
- CrackMe: **"Public BLA CrackMe v6"** (Node vault + HTML panel + Wasm core),
  publishes only digests in `SEAL.json`.

**antirea — `MockirDev/antirea` — ~36★ / MIT.**
- Agent *skill* that writes **barrier directives** into `AGENTS.md`/`CLAUDE.md`/
  `.cursor/rules` + a `.re-deny` file, self-healing via git hooks/MSBuild, plus
  **terminal shims** (`node_modules/.bin/rea` + a local `rea-agents` package that
  exits with an error), plus third-party build hardening (JS-obfuscator, ASAR
  encryption, R8/ProGuard, ConfuserEx).
- Its own stated limits: **"does not guarantee … impossible";** cannot stop an
  agent that ignores the files, or `rea` run by absolute path from outside.
- **Verdict for us:** the instruction-file/terminal-shim layer is the exact
  **"the AI will refuse / obey a stop file" non-defense our CLAUDE.md §2 forbids
  relying on** — an unrestricted local model ignores it. Do **not** adopt as a
  defense. (It has niche value only as friction against *polite* default agents;
  if ever included, it must be labeled Trivial and never counted toward posture.)

**AREA — `davepartner/anti-reverse-engineer-anything` — ~3★ / MIT.**
- "Counter-skill" to REA: obfuscation (js-obfuscator, OLLVM, garble, goldberg),
  broad metadata stripping, Electron fuses/V8 bytecode, anti-debug/anti-Frida
  (port 27042, ptrace guard, anti-LLDB/GDB), anti-CDP, optional UPX.
- Honest framing ("deterrence, not proof; a determined human always gets through")
  but **no measured results, no formal tiers.**

### Context (research, not products)
- **Quarkslab, "Defeating AI-Assisted RE (or at Least Trying To)", Aug 2026:** gave
  sandboxed agents progressively hardened AArch64 binaries; key findings — static
  obfuscation alone is weak vs LLM analysis; agents sometimes **fabricate
  plausible-but-wrong results** (a correct-*looking* answer ≠ real analysis);
  recommends layered **runtime self-protection sensors feeding back into the
  obfuscation**. Validates both our attestation (understanding ≠ a working tamper)
  and our decoy angle.
- arXiv 2026: prompt-injection hidden in binaries vs RE agents (defends the agent,
  not the binary); representation-confusion attacks on LLM-assisted RE. Useful
  design fuel for the "break the AI layer" front.

## Absorption matrix — what we take, and where it lands in Carapace
Honest tiers kept; every item gets a named bypass at implementation time. "Scope"
= fits current CLAUDE.md §2 (native + mobile) yes/no.

| Their idea (source) | Carapace already has? | Plan | Slice | Scope |
|---|---|---|---|---|
| **Exhaust** — inflate analysis surface past agent budgets (BLA) | No | **Build now:** non-alloc decoy sections + synthetic `.symtab` FUNC symbols (binutils; proven non-breaking) that balloon an agent's inventory/context while runtime stays byte-identical | **I** | ✅ native ELF |
| **Poison / Hallucinate** — decoys + ambiguous dead ends (BLA) | Partial — decoy identity transform (Slice B) + string encryption (F) | Extend decoy depth: honey-metadata + decoy control-flow notes; fold "fabrication" insight from Quarkslab | **J** | ✅ |
| **Empirical REA validation** — real runs, before/after, benchmark (BLA) | No (parked) | Stand up sandboxed **operator-owned `rea` VM**; measure decoy/exhaustion effect; honest numbers, no vendor-style estimates | **K** | ⚠ operator-gated (no offensive tooling in dev container) |
| **CrackMe challenge** — public, digest-sealed (BLA) | No | Ship a Carapace CrackMe built from our sample + slices; publish only digests | **K** | ✅ |
| **One-command + MCP/skill install UX** (BLA/antirea) | Partial — `skill/` + `make` | Add a `carapace harden .` one-shot + document MCP/skill install parity | **L** | ✅ |
| **anti-Frida / anti-debug / port 27042 / ptrace** (AREA) | **Yes** — Slices A + D (and *proven firing*) | None (already ahead, mechanism-tested) | — | ✅ |
| **Metadata stripping across formats** (AREA/antirea) | Yes for ELF (Slice B); PE audit (G) | Extend strip/transform to PE + Mach-O as those slices land | G+/M | ✅ |
| **Instruction-file barriers / terminal shims** (antirea) | No | **Reject as a defense** (relies on a cooperative model; violates §2). Optional Trivial-labeled friction only, never scored | — | n/a |
| **Breadth: Electron / JS / Wasm / .NET bundles** (BLA/AREA) | No (explicitly out of §2 scope) | **Operator decision required** — engulfing these = a CLAUDE.md §2 scope change. Recommend: keep native/mobile as the proven core; add web/bundle as a *separate, clearly-labeled* track only if the operator wants it | — | ❌ needs §2 change |

## Decisions needed from operator
- **Scope expansion (the one real fork):** "have all things" vs. Electron/JS/Wasm/
  .NET is a CLAUDE.md §2 change. Recommendation: **keep native/mobile as the
  mechanism-proven core (our edge), and only add a web/bundle track as an explicit,
  separately-tiered second track** — not silently, and not at the cost of our
  "prove it" guarantee. Confirm before any web/bundle work starts.
- **Empirical track (Slice K):** needs a throwaway, operator-owned VM with `rea`
  installed. Will **not** install offensive tooling in this dev container.

## Open questions
- BLA's "≈612× tokens" is an internal estimate off REA's documented limits, not a
  measured agent run — our Slice K should produce *measured* numbers or none.
- Whether `rea` filters/deduplicates non-alloc sections and synthetic symbols
  (would change the Exhaust tier) — resolves only on the Slice K VM.

## Sources
- BLA — https://github.com/qybaihe/bla — accessed 2026-11-05
- antirea — https://github.com/MockirDev/antirea — accessed 2026-11-05
- AREA — https://github.com/davepartner/anti-reverse-engineer-anything — accessed 2026-11-05
- Quarkslab, "Defeating AI-Assisted Reverse Engineering (or at Least Trying To)" — https://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html — accessed 2026-11-05
- arXiv 2605.30677 (prompt-injection vs RE agents); arXiv 2607.12507 (representation-confusion) — accessed 2026-11-05

## Review log
- Primary 2026-11-05: drafted from web + GitHub scan; competitor claims are
  self-described and unverified. Needs Evaluator sign-off before any claim here is
  quoted as fact in README/CV.
