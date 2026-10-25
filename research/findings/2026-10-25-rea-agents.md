# rea / rea-agents — defensive threat profile — research
- Date: 2026-10-25
- Author role: Primary (inline; see note)
- Phase: research → feeds analysis
- Status: draft (needs Evaluator sign-off; some facts need deeper verification)

## TL;DR
- **What:** `rea` (npm `rea-agents`, GitHub `NabilRFG12/Reverse-Engineer-anything`,
  upstream `morluto/rea`) is an **MCP server that turns any coding agent into an
  autonomous reverse-engineering operator** — "reverse engineer anything with
  agents, from app behavior down to native binaries." MIT, active (1,520 commits,
  326 forks; star count shown inconsistently — 969 vs a claimed 20k).
- **Why it's P0:** it is `disasm-mcp` + `agentic-re` in one package, and it is
  **model-agnostic** — works with Claude Code, Codex, Cursor, Gemini CLI, Grok, or
  "any agent that supports local MCP servers." That means the attacker supplies
  the model, so our `uncensored-local-models` layer is real and intended, not
  theoretical. The skill floor is: install an MCP + type a sentence.
- **Defensive handle:** it does not reverse by magic — it **orchestrates the
  classic engines** (Ghidra/IDA/Hopper, JADX, pwntools/GDB, Binwalk/Unblob,
  mitmdump) and feeds their output to an LLM. So (1) every classic countermeasure
  that degrades those engines also blinds the agent, and (2) the LLM layer adds a
  *new* soft spot: comprehension can be attacked cheaply.

## Detail

### Classification (maps to our catalog)
- Layers: **tooling** (`disasm-mcp` + `agentic-re`) + **model** (brings its own,
  via MCP) + partial **distribution** (ships a `skills.sh` skill package → easy
  spread to non-experts).
- Our tracks hit: **A** (native ELF/PE/Mach-O, firmware), **B** (Android APK).
  It also targets out-of-scope surfaces (JS/Electron/ASAR, .NET, websites, EVM) —
  breadth worth noting, not our focus.

### What it automates (stated capabilities)
Natural-language goal → the agent plans and chains external engines:
| Target surface | Engine it drives | Our track |
|---|---|---|
| Native binaries (pseudocode/asm/symbols/xrefs) | Hopper / Ghidra / IDA | A |
| Offline ELF diagnostics; recorded Linux crashes | pwntools, optional GDB/pwndbg | A |
| Android APKs | headless JADX + JDK | B |
| Firmware images | Binwalk / Unblob | A (embedded) |
| Process / runtime behavior | native PTY capture | A+B |
| Network | HAR / mitmdump captures | (secondary) |
| JS/Electron/ASAR, .NET | static file reads (no execution) | out of scope |
Output is framed as "evidence and limitations" — i.e. built to be auditable,
which makes it *more* effective and trustworthy to a non-expert.

### Requirements → defensive leverage points
The core deliverable. For each capability, what it NEEDS — and therefore what
denying it costs the attacker:

| Capability | What it needs from the target | Defensive leverage (catalog entry) | Tier vs this tool |
|---|---|---|---|
| Native static decompile | the binary + a decompiler producing clean pseudocode | obfuscation, control-flow flattening, string encryption, symbol strip, packing (`ghidra`/`ida`) | Meaningful (degrades LLM input) |
| Runtime / process capture | ability to **execute** target under a PTY with user perms | anti-debug/anti-ptrace, anti-instrumentation, VM/sandbox/PTY detection, integrity self-check refusing to run (`frida`/`debuggers`) | Meaningful |
| Android analysis | dex decompilable by JADX | R8/DexGuard-class obfuscation, logic migration into native `.so`, anti-repackaging/signature check (`jadx-apktool`/`android-root-hook`) | Meaningful |
| Firmware | unpackable (unencrypted/unsigned) image | signed + encrypted firmware (out-of-band) | Strong |
| Network | observable traffic | cert pinning, mTLS, traffic obfuscation (`ssl-pinning-bypass`) | Meaningful |
| Static JS/.NET | just the files (no execution) | obfuscation only — RASP can't touch static reads | Speed-bump (and out of scope) |

### The AI-specific soft spot (our novelty front)
Because decompiler/JADX output is fed to an LLM, we can attack **comprehension**,
not just the bytes — transforms that keep the program functionally identical but:
- inflate decompiled pseudocode volume to **exhaust the agent's context window**
  (aggressive CFG flattening, function splitting/merging, opaque predicates);
- inject **valid-but-misleading semantic noise** (confusing-but-legal structure,
  junk data flows) that lowers LLM summary accuracy;
- make the *runtime* path detectable so the agent's "evidence" is poisoned or the
  target refuses to run under capture.
Plus **attestation** (server-side checks: understanding ≠ a working tamper) and
**watermarking** (attribute any leaked/cracked build). These are what make the
project novel vs. a 20-year-old obfuscator.

### Observable footprint (what the harness/RASP can detect)
- Runtime path spawns a **PTY and executes the target** → ptrace/debugger
  presence, instrumentation signatures, headless/automation env, timing anomalies.
- Host side runs known engines (ghidra/jadx/pwndbg/binwalk processes) + a Node 22+
  MCP server — relevant for endpoint defenders, less so for in-binary RASP.

### Honesty — where it wins regardless
- Pure static native/JS/.NET inspection **needs no execution**, so anti-debug/RASP
  never fires; only obfuscation/packing + **server-side relocation** help there.
- A motivated operator still gets *some* pseudocode. Our job is **cost**, not
  prevention. Secrets that can't leak must live server-side (threat-model §"one law").

## Decisions needed from operator
- Confirm `rea` becomes the worked reference instance for the `disasm-mcp` +
  `agentic-re` catalog entries (I'll link it there).
- Approve scaling the research phase to the rest of the P0 list via Scouts, or
  keep going one subject at a time inline.

## Open questions
- Real popularity (969★ vs claimed 20k) — affects how we prioritize it.
- Does the runtime-capture path use Frida/ptrace specifically, or only PTY + the
  target's own I/O? Changes which anti-instrumentation checks actually fire.
- `skill-src` / `skills.sh` packaging — how turnkey is it for a true non-expert?
  (distribution-layer severity)
- Does it do automated **patching/binary rewriting**, or only analysis? (stated
  focus is analysis + evidence; patching not confirmed from the landing page.)

## Sources
- GitHub — github.com/NabilRFG12/Reverse-Engineer-anything (landing page, README) — accessed 2026-10-25
- Referenced but not yet read: upstream `morluto/rea`, npm `rea-agents` — pending

## Review log
- Primary 2026-10-25: draft from landing-page facts only. Deeper source reads
  (upstream repo, npm, actual MCP tool list) deferred to a Scout pass. Needs
  Evaluator sign-off before it graduates into docs/re-techniques/.

---
_Note on process: written inline by the Primary rather than delegated, because it
is a single focused subject and the core facts came from one fetch. Scaling to the
full P0 list is the point where Lead + Scouts earn their keep (CLAUDE.md §6)._
