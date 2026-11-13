# Proposal — a second "web/bundle" track (Electron / JS / Wasm / .NET-IL)?

- Date: 2026-11-14
- Author role: Lead (Primary-delegated), synthesising four Scout research notes
- Phase: research → analysis → **proposal** (decision-ready)
- Status: **awaiting operator sign-off** — this is a PROPOSAL ONLY. No `CLAUDE.md`
  §2 edit has been made and no harden/audit code for these formats has been
  built. Slice T (this work) produced research + analysis + this document only.
- Decision this resolves: `docs/STATE.md` open item 2 — "the one real fork."

> **Governance note (CLAUDE.md §3).** Expanding past native + mobile is a `CLAUDE.md`
> §2 scope change and must be confirmed before any such work. This document exists
> so the operator can make that call on cited evidence. The suggested §2 wording in
> §9 is a **quoted snippet to apply only if approved** — it is deliberately *not*
> applied.

---

## 1. TL;DR — the decision in one page

- **The question.** Should Carapace add a second, separately-tiered **web/bundle**
  track — Electron (ASAR / V8 bytecode), minified/obfuscated **JavaScript**,
  **WebAssembly**, and **managed .NET / CIL (IL)** — alongside the native +
  mobile core?
- **What the research says.** All four formats are **more exposed to AI-assisted
  RE than native binaries**, in roughly this order: **managed-IL ≳ JS ≳ Electron ≫
  Wasm ≫ native**. They ship the program in (or very close to) a high-level,
  self-describing form, so an LLM barely has to reverse anything — it reads
  decompiler/deobfuscator output. This is the Priority-0 "skill-floor collapse" at
  its purest: off-the-shelf MCP servers and one-command CLIs already exist for
  every one of these formats today (`humanify`, dnSpy-MCP, ILSpy-MCP wrappers,
  `re-electron` skill, `webcrack`). See §4 and the four cited notes.
- **The honesty problem.** Precisely *because* these are managed/high-level
  formats, there is **no honest client-side countermeasure above Speed-bump**, and
  **no mechanism-proof story** like native has. Our native edge is that we can
  *prove a guard fires* (anti-ptrace returns EPERM; a core dump is suppressed; a
  patched function fails server attestation). A JS/IL/Wasm "defense" is reversible
  by a public tool (`webcrack`, `de4dot`, `wasm2c`→LLVM) in minutes, so there is
  nothing to prove firing — only a cost multiplier to *measure*. The one **Strong**
  lever is the same for all four and is already our stated #1: **move the secret /
  trust decision server-side** (`CLAUDE.md` §3).
- **Two things change the picture.** (1) **NativeAOT / IL2CPP**: the realistic
  "harden my .NET/Unity app" answer is to compile to a **native** PE/ELF/Mach-O,
  which folds into Carapace's **existing native track** — *no scope change needed*.
  (2) **Mobile overlap**: .NET MAUI / Xamarin-on-Android is managed IL inside an
  APK, which Track B (Android APK/AAB) already claims by construction — a
  **mobile-track** decision, not a web/bundle §2 decision.
- **Recommendation (concrete, §8).** **Default: do NOT add a managed/web *harden*
  track.** It cannot honestly beat Speed-bump, has no prove-it story, and drags us
  onto the incumbent's (BLA's) breadth turf while diluting the native-depth +
  mechanism-proof edge that is the project's whole differentiator. **Conditional
  yes:** *if and only if* the operator's own target actually ships one of these
  formats, add a **narrow, audit-first, explicitly-sub-tiered "web/bundle exposure
  audit"** — read-only exposure scoring that ends in the server-side truth, with
  **no lever presented as protection above a labeled Speed-bump** and **nothing
  counted toward the mechanism-proven posture guarantee**. **Adopt now, with no §2
  change:** recognise NativeAOT/IL2CPP native output and route it to the existing
  native audit; treat MAUI/Android as a mobile-track question.

---

## 2. Context — what triggered this, and what is already decided

The 2026-11-05 competitive scan (`research/findings/2026-11-05-competitive-landscape.md`)
found that the serious incumbent defender, **BLA** (`qybaihe/bla`), is *broad*
(Electron / JS / Wasm / SQLite / GGUF / Flutter / …) and is strongest **exactly
where our `CLAUDE.md` §2 is out of scope**. That scan logged the one real fork as
an operator decision and recommended, provisionally: *keep the mechanism-proven
native core; add a web/bundle track only as an explicit, separately-tiered second
track, never silently.* `docs/STATE.md` open item 2 carries that forward as
pending. This proposal turns that provisional lean into a cited,
decision-ready recommendation.

Nothing here changes the native/mobile work (Slices A–S), which is complete and
mechanism-proven (265/265 on main at this branch's base; more on sibling branches
Q/R/S). This is purely about whether to *add* a second track.

## 3. The test every candidate must pass (P0 north star)

Carapace exists to defend against the **Priority-0** threat: *a non-expert points
an LLM-driven agent / MCP / skill at a target and gets readable code, a patch, or a
working hook from one sentence* — running an **unrestricted local model**, so
"the AI will refuse" is **never** a defense (`CLAUDE.md` §2). Every lever below is
judged on that threat, tiered **Trivial / Speed-bump / Meaningful / Strong**, with
a **named bypass**, and split across our two P0 fronts:

- **Substrate front** — defeat the tool the AI rides on (decompiler / deobfuscator
  / unpacker). Blinding the substrate blinds the LLM on top.
- **AI-layer front** — degrade the LLM's own comprehension / agentic automation
  (semantic confusion, context exhaustion, poisoning, anti-automation).

A recurring, honest finding across all four formats: **the AI-layer front is
almost entirely unmeasured** for these high-level formats against current
frontier/open-weight models. No tier above "hypothesis" may be claimed for it
without a Slice-K-style A/B. We will not repeat the incumbent's "internal estimate"
multipliers.

## 4. Per-format analysis (tiers + named bypasses)

Full detail, citations and dates live in the four research notes
(`research/findings/2026-11-14-{electron,js-deobf,wasm,dotnet-il}-re-landscape.md`).
Condensed here so the decision can be made without opening them. **All tiers below
are analysis judgments from cited sources; none is Carapace-measured yet.**

### 4.1 Managed .NET / CIL (IL) — *most exposed*
ECMA-335 IL is self-describing: full type/method/field names, generics and control
flow. ILSpy (v11.2, actively maintained), dnSpyEx (v6.5.0; live edit-and-continue
IL patching) and dotPeek return **near-source C#**. Off-the-shelf **MCP servers**
already wrap these for an LLM (ZeraTS **dnSpy-MCP** even emits a 0–10 "protection
risk score + bypass recommendations"; several ILSpy-MCP wrappers). The P0 scenario
in its purest form — the decompiler does the reversing; the LLM just reads it.

| Lever | Front | Tier | Named bypass |
|---|---|---|---|
| Ship plain IL / strip only PDB | — | **Trivial** | Decompiler reads it regardless; AOT emits `.pdb`/`.dbg` by default — must not ship |
| Renaming | substrate | **Trivial** | Decompiler + LLM infer roles from structure/API/strings; `de4dot` covers known protectors |
| String encryption / proxy-call indirection | substrate | **Speed-bump** | `de4dot` strategies; cyber.wtf shows IL-parsing recovery of hidden keys |
| Control-flow obf (ConfuserEx-class) | substrate | **Speed-bump** (unmeasured vs LLM) | Deobfuscators exist; LLM reading costs tokens/turns, not a block |
| Encrypted-payload packer / anti-tamper / anti-debug | runtime | **Speed-bump** | Dump plain module from memory after runtime load (dnSpy "Open Module from Memory", DotDumper); patch the one check |
| **NativeAOT (ship native PE/ELF/Mach-O, not IL)** | **native** | **Meaningful** (vs IL; *not* Strong) | Native disasm; runtime memory dump; library-signature match (WARP recovered >85% of runtime funcs in one sample); Univ. Twente project (Feb–Dec 2026) targets AOT type recovery |
| **Server-side relocation** | relocate | **Strong** (only real one) | Attacker replays/patches the client call; the server must validate |

Honest verdict: **client-side managed-IL secrecy is close to hopeless.** The
standard automated deobfuscator, **`de4dot`, is archived (2020)** and its coverage
of *current* protector versions is unknown — so even "obfuscate it" rests on stale
tooling. The one real step up is NativeAOT, which is **already our native track**.

### 4.2 Minified / obfuscated JavaScript — *next most exposed*
The shipped artifact is already the language an LLM reads best, and every transform
is text-to-text.

| Lever | Front | Tier | Named bypass |
|---|---|---|---|
| Withhold source maps (`.map` + `sourcesContent`) | hygiene | **Trivial** as logic-protection (**Meaningful** only vs the map-leak vector) | Logic is still in the shipped JS; `humanify`/`webcrack` work without maps |
| Minification | — | **Trivial** | `humanify` renames identifiers back — one LLM call per identifier (local Ollama backend supported) |
| `javascript-obfuscator` string-array + rotation | substrate (+AI via CASCADE) | **Speed-bump** | `webcrack` / `synchrony` / `restringer` reverse obfuscator.io output deterministically |
| Control-flow flattening / dead-code injection | both | **Speed-bump** (15–80% runtime cost, size up to +200%) | OBsmith rates flattening "moderate"; deterministic unflatteners; LLM reconstructs per-function |
| `selfDefending` / `debugProtection` | substrate | **Trivial** | A headless agent doesn't open DevTools; remove the check after deobfuscation |
| **Server-side secret logic** | relocate | **Strong** (honest #1) | Attacker calls the server; the API must be the boundary (authn, rate limit, validation) |

The `javascript-obfuscator` README itself states output "is still JavaScript" and
marks the free package "fully vulnerable (no LLM-specific defenses)." Measured
evidence is mixed, not one-sided (JsDeObsBench ~61% execution-correctness on benign
obfuscated code for mid-2025 models; secondary-sourced — re-verify). **Do not sell
client-side JS obfuscation as protection.**

### 4.3 Electron (ASAR + V8 bytecode + fuses) — *JS-exposed, plus a container*
Essentially the JS case wrapped in `app.asar` (a one-command-extract archive) with
some **native-adjacent** levers an existing binary reader can check.

| Lever | Front | Tier | Named bypass |
|---|---|---|---|
| ASAR integrity + `embeddedAsarIntegrityValidation` + `onlyLoadAppFromAsar` fuses | substrate | **Speed-bump** (user-writable installs) | Patch the integrity check in the Electron binary; snapshot coverage gap (CVE-2025-55305, since fixed) |
| Fuse hardening (`runAsNode`/`nodeCliInspect`/`nodeOptions` off, per app) | substrate | **Speed-bump** | Flip the static fuse bytes (the audit read in reverse); some apps *need* `runAsNode` |
| Bytenode (`.jsc` V8 bytecode) | substrate | **Speed-bump** | Public Ghidra-based bytenode→JS bypass (PT Swarm; date unverified — TLS fetch failed); bytenode's own README: "not encryption" |
| JS obfuscation / identifier poisoning | both (AI unproven) | **Speed-bump** | As §4.2; arXiv 2604.04289: poisoned identifiers survive baseline deobf but a "rewrite from scratch" prompt removes most |
| **Server-side logic / secrets** | relocate | **Strong** | Same as §4.2 |

Electron's own docs do **not** claim ASAR integrity is a security boundary against
a local attacker. A read-only **fuse-state + ASAR-integrity audit** is feasible and
low-risk — the most defensible first step if a track is ever built.

### 4.4 WebAssembly — *least exposed of the four, still a readable substrate*
A typed, structured stack machine: no arbitrary `goto`, explicit types,
imports/exports. Harder than JS/IL, easier than native x86/ARM. Decompilers
(NotDec 2026, WaDec, StackSight) + LLM pipelines produce C-like code today.

| Lever | Front | Tier | Named bypass |
|---|---|---|---|
| Strip `name` section + DWARF + producers (`wasm-opt --strip-debug`, `wasm-tools strip --all`) | substrate | **Trivial** (semantics) / **Speed-bump** (symbol naming) | LLM semantic renaming from behaviour, imports/exports, string constants — **name-strip-vs-LLM effect is unmeasured** |
| Randomise export/import names (needs host-JS change) | AI-layer | **Speed-bump** | Import-signature heuristics (fetch, WebCrypto, WASI) still reveal semantics |
| Control-flow flattening (WASMixer / Tigress) | both | **Speed-bump** (LLM) / Meaningful- vs naive decompile | LLVM deobf via `wasm2c`→LLVM (Black Hat Asia 2025 "Squanchy") |
| Linear-memory encryption (decrypt-on-load) | both | **Speed-bump** static / **Trivial** dynamic | Runtime memory dump / breakpoint on the decrypt wrapper; key lives in-process |
| **Server-side relocation / no in-Wasm keys** | relocate | **Strong** | Key extraction from linear memory at runtime if shipped |

Scoping trap: **Blazor WebAssembly** AOT-compiles to Wasm but **still ships the
managed IL DLLs** (Microsoft docs) — so the real attack surface there is §4.1, not
the Wasm.

## 5. Cross-cutting findings (these drive the recommendation)

1. **Exposure ranking: managed-IL ≳ JS ≳ Electron ≫ Wasm ≫ native.** Every
   candidate is strictly *more* exposed to the P0 threat than the native formats we
   already defend — the LLM does less work, not more. (Honest caveat: the .NET, JS
   and Electron notes each independently call *their own* format "the most exposed";
   the `≳`/`≫` and "roughly this order" reflect that the top three are close and not
   a hard ordinal ranking. Wasm being least exposed of the four, and all four being
   above native, is the firm part.)
2. **No mechanism-proof story.** Native hardening earns its honesty tier by
   *proving the guard fires* (EPERM, suppressed core, failed attestation). A
   web/bundle lever's entire value is a *reversible cost multiplier*; there is no
   "it fired" to prove, only a number to *measure*. This is a structural mismatch
   with the project's "audit → harden → **verify it fires**" identity.
3. **The Strong tier is identical to what we already say.** For all four formats
   the only Strong lever is server-side relocation — `CLAUDE.md` §3's "one law,"
   which the harness already surfaces for native. A web/bundle track would mostly
   re-deliver advice we already give.
4. **NativeAOT / IL2CPP folds .NET (and Unity) into the EXISTING native track.**
   The best honest "harden my .NET app" answer requires **no scope change**:
   compile to native, then use the native audit/harden path we built (Slices
   G/M/N/O/P + sibling Q). NativeAOT is Meaningful *relative to IL*, not Strong.
5. **Part of the surface is already in scope via mobile.** .NET MAUI / Xamarin on
   Android is managed IL inside an APK; Track B already claims APK/AAB. (Slice R's
   mobile-container reach handles the *native* payloads inside the container; the
   *managed* payload would be new mobile-track work — a Track-B decision, not a
   web/bundle §2 decision.)
6. **The AI-layer front is unmeasured here.** No published, controlled study shows
   any of these formats' obfuscation degrading an unrestricted LLM's comprehension.
   Claiming a tier for it would be exactly the overclaiming we criticised in the
   incumbent.

## 6. The case for / against

**For a web/bundle track**
- The P0 threat bites *hardest* here (lowest skill floor; the most ready-made AI
  tooling). Defending the most-attacked surface has obvious appeal.
- Breadth is where attention is: the incumbent **BLA** is broad and visible
  (2.3k★ / `bla-agents` v1.4.0 per the 2026-11-05 note; its README now reportedly
  shows ~5.6k★ / v3.3.1 — **growth unverified, flag before quoting**). A buyer
  comparing tools may expect these formats covered.
- Real developers do ship Electron/JS/Wasm/.NET and would value an honest *exposure
  audit* even if hardening is weak.

**Against (or for strictly bounding it)**
- **Honesty ceiling.** Nothing client-side here honestly beats Speed-bump; the
  Strong lever is advice we already give. A harden track risks implying protection
  that does not exist — the one thing `CLAUDE.md` §3 forbids.
- **No prove-it story.** It breaks the project's defining discipline (verify the
  guard *fires*). We would be shipping size-diff / drift-check "verification" — the
  exact weakness we called out in BLA's `verify:rea`.
- **Wrong battlefield.** It moves us onto the incumbent's breadth turf and away
  from our durable edge (native depth + mechanism proof). "Broad and shallow" is
  already taken and is shallow *by the format's nature*, not by effort.
- **Maintenance tax.** Electron fuses + bytenode version gates, `javascript-obfuscator`/
  deobfuscator cat-and-mouse, protector churn (Dotfuscator ships ~quarterly),
  Wasm 3.0 — each is a per-release upkeep burden with stale reference tooling
  (`de4dot` archived 2020).
- **Redundancy.** The highest-value .NET/Unity move (NativeAOT/IL2CPP → native) and
  the MAUI/Android surface are reachable **without** a §2 web/bundle change.

## 7. Effort / complexity estimate (if approved)

Rough, for comparison only; audit-first framing.

| Scope | What it is | Effort | Honesty ceiling |
|---|---|---|---|
| **A. Audit-only, 1 format** (e.g. Electron fuse + ASAR-integrity read; or managed-IL metadata/PDB exposure) | Read-only exposure scorer parallel to the ELF/PE/Mach-O auditors; ends in server-side truth | ~1 slice/format (self-contained parsers; the pattern is proven) | Honest — audit ≠ protection |
| **B. Audit for all four** | Four read-only scorers + skill dispatch by magic/extension | ~3–4 slices | Honest |
| **C. Audit + labeled Speed-bump harden** (strip maps / `name`-section / PDB; wire existing obfuscators) | Adds build-step wiring + an A/B measurement gate per lever before any tier is asserted | ~1–2 extra slices/format + VM-measured A/Bs | Risky — must stay "Speed-bump, measured, bypass-named" and never counted toward posture |
| **D. NativeAOT/IL2CPP native routing** | Recognise AOT output, route to existing native audit | ~0.5 slice | Honest; **no §2 change** |

The cheap, honest, highest-value items are **D** (no scope change) and a minimal
**A** gated on a real target. **C** is where overclaiming risk concentrates.

## 8. Recommendation

**Three parts, in priority order:**

1. **Adopt now — no §2 change required.** Teach the harness to recognise
   **NativeAOT / IL2CPP native output** (PE/ELF/Mach-O) and route it to the
   existing native audit (check: PDB/`.dbg` shipped? reflection disabled?
   stack-trace support off? `global-metadata.dat` present/encrypted?). This
   captures the single best honest "harden my .NET/Unity app" answer inside current
   scope. Also record that **.NET MAUI / Xamarin-on-Android** managed IL is a
   **mobile-track (Track B)** question, to be decided there, not here.

2. **Default: do NOT add a managed/web *harden* track.** It cannot honestly exceed
   Speed-bump client-side, has no mechanism-proof story, re-delivers the
   server-side advice we already give, and competes on breadth where our edge is
   depth. Leave Electron/JS/Wasm/managed-IL as **reference-only** catalog entries
   (now written — see §10).

3. **Conditional yes — only if the operator's own target ships one of these
   formats:** add a **narrow, audit-first, explicitly sub-tiered "web/bundle
   exposure audit"** for that format, under these non-negotiable guardrails:
   - **Read-only exposure scoring first** (fuse/ASAR state; source-map/`.map`
     leakage; Wasm `name`/DWARF/producers; managed-IL metadata/PDB), always ending
     in the **server-side-truth** recommendation.
   - **No lever presented as protection above a labeled Speed-bump**, and **every
     tier gated behind a Slice-K-style measured A/B** before it is asserted —
     no "internal estimate" multipliers.
   - **Nothing in this track counts toward the mechanism-proven posture guarantee.**
     It is a clearly-separate, lower-tier second track, scored and badged apart from
     the native/mobile core, exactly as the 2026-11-05 note required.

This keeps the project honest, protects the native-depth + prove-it differentiator,
and still gives a developer with a real Electron/JS/Wasm/.NET target a truthful
exposure read plus the one lever that actually works.

## 9. Suggested `CLAUDE.md` §2 wording change — **apply ONLY if approved**

> **Do not apply this now.** It is the change to make *if* the operator approves
> part 3 of §8 (a conditional web/bundle audit track). If the operator approves only
> parts 1–2, **no §2 edit is needed** — NativeAOT routing is already in scope and
> the formats stay reference-only.

Current text (`CLAUDE.md` §2, "Out of current scope"):

```
Out of current scope (revisit only if the operator changes target): Electron /
web / JS / WebAssembly / pure-.NET app shells. They are left in the catalog at
low priority for reference, not worked.
```

Proposed replacement (adds an explicit, lower-tier second track; keeps the core
unchanged):

```
Second track — web/bundle (audit-first, separately tiered, OPT-IN per target):
Electron (ASAR / V8 bytecode / fuses), minified-or-obfuscated JavaScript,
WebAssembly, and managed .NET / CIL (IL). These are managed/high-level formats and
are MORE exposed to AI-assisted RE than native binaries; against the Priority-0
(LLM-driven) threat no client-side countermeasure for them honestly exceeds the
Speed-bump tier, and the only Strong lever is server-side relocation (§3). This
track is therefore AUDIT-FIRST (score
exposure, name the server-side truth), ships no lever presented as protection above
a labeled, measured Speed-bump, and is SCORED AND BADGED SEPARATELY from the
native/mobile core — it never counts toward the mechanism-proven posture guarantee.
It is worked only for a format the operator's actual target ships. NativeAOT /
IL2CPP native output is NOT in this track — it compiles to a native PE/ELF/Mach-O
and is handled by the native track. .NET MAUI / Xamarin on Android is managed IL
inside an APK and is a mobile-track (Track B) decision.
```

(If approved, the `docs/re-techniques/_index.md` "Out of current scope" section and
the four reference entries in §10 are promoted from "reference only — NOT worked"
to the new track's status, and `docs/STATE.md` open item 2 is closed.)

## 10. Reference catalog entries (written this slice — reference only)

Per `CLAUDE.md` §2, reference entries are allowed for out-of-scope formats. Four
concise entries were added and are **explicitly marked "reference only — NOT
worked; pending the operator decision in this proposal"**:
`docs/re-techniques/{electron-asar,js-deobf,wasm-decompile,dotnet-decompile}.md`,
linked from the catalog index. They do not change scope.

## 11. Operator decision requested

Please choose (they are not mutually exclusive — 1 is recommended regardless):

- **[1] Adopt the no-scope-change wins** (NativeAOT/IL2CPP native routing; log
  MAUI/Android as a Track-B question). **Recommended. No §2 edit.**
- **[2] Hold the line** — keep Electron/JS/Wasm/managed-IL reference-only; add no
  web/bundle track. **Recommended default.** (Compatible with [1].)
- **[3] Approve a conditional, audit-first web/bundle track** under the §8-part-3
  guardrails, for a named target format — and apply the §9 wording. *Which
  format(s), and is there a real target that ships it?*
- **[4] Approve a broader harden track** (option C in §7). **Not recommended** —
  this is where overclaiming risk and maintenance cost concentrate, and where we
  lose the prove-it edge.

Until a decision is recorded, `docs/STATE.md` open item 2 stays **pending**, no §2
edit is made, and no harden/audit code for these formats is built.

## Sources

- `research/findings/2026-11-14-electron-re-landscape.md` — Electron (cited, dated)
- `research/findings/2026-11-14-js-deobf-re-landscape.md` — minified/obfuscated JS
- `research/findings/2026-11-14-wasm-re-landscape.md` — WebAssembly
- `research/findings/2026-11-14-dotnet-il-re-landscape.md` — managed .NET / IL
- `research/findings/2026-11-05-competitive-landscape.md` — BLA/antirea/AREA scan + the original fork
- `CLAUDE.md` §2 (scope), §3 (ethics / server-side truth), §8 (honesty tiers)
- `docs/STATE.md` open item 2

## Review log

- Lead 2026-11-14: synthesised from four same-day Scout notes; all tiers are
  analysis judgments (none Carapace-measured); unverified items (BLA stats, PT
  Swarm bytenode date, `de4dot` currency, every AI-layer tier) flagged inline.
  Pending Evaluator sign-off.
- Evaluator 2026-11-14: **signed-off (with optional nits)** — tiers faithfully
  transcribed from the four cited notes and each bypass-named; the only Strong lever
  is server-side relocation and the Speed-bump ceiling is stated plainly; all
  flagged-unverified items (BLA stats, PT Swarm date, `de4dot` currency, every
  AI-layer tier) are hedged; confirmed no `CLAUDE.md` §2 edit was applied
  (git-clean), all four catalog entries marked reference-only, and the recommendation
  is argued against the P0 threat. Two optional precision nits (reconcile the three
  "most exposed" source claims; scope the "exceeds Speed-bump" ceiling to the P0 LLM
  threat in the §9 snippet) — **both applied 2026-11-14**; neither blocked sign-off.
