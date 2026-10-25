# RE Techniques Catalog — Index

The core knowledge base. One file per technique/tool. Each entry decomposes the
attacker workflow into **steps**, and maps a **countermeasure** to each step —
because we defend by raising the cost of individual steps, not by magic.

## Per-entry template
Every `docs/re-techniques/<slug>.md` uses this structure:

```
# <Tool / Technique name>
- Category: static | dynamic | packaging | mobile | network | ai-assisted
- What it does: 1–3 sentences.
- What it needs from the target: (symbols? unencrypted strings? debuggable? asar?)

## Attacker workflow (steps)
1. ...
2. ...

## Defensive leverage (step → countermeasure)
| Attacker step | Countermeasure | Strength tier | Known bypass |
|---------------|----------------|---------------|--------------|

## Harness hooks
- Audit check(s) this maps to:
- Hardening(s) this maps to:

## Sources
- <cited, dated>
```

## ⚠️ Priority 0 — AI-assisted / commodity RE (the headline threat)

The skill-floor collapse: a non-expert drives these from **one sentence** and an
LLM does the reversing. This is the project's core focus (see `CLAUDE.md` §2).
Almost all of them **sit on top of** a classic engine (the Substrate table
below) — so defeating the substrate blinds the AI, *and* we research AI-specific
hardening on top.

> Assembled from knowledge as of the model's cutoff — **not yet web-verified**.
> Status `list (verify in research)` = named here so research can confirm,
> date, and detail it. The RE-AI space moves monthly; treat every name as a
> lead, not a citation, until a Scout note backs it.

| Slug | AI-assisted threat | Typically drives (substrate) | Track | Status |
|------|--------------------|------------------------------|-------|--------|
| `disasm-mcp` | MCP servers exposing a disassembler to an LLM agent (GhidraMCP, IDA-Pro-MCP, r2mcp, Binary Ninja MCP). The archetypal "install a skill, one sentence, you're in." | Ghidra / IDA / radare2 / Binja | A (+native .so in B) | **analysis** → worked ref: [`rea.md`](rea.md) |
| `agentic-re` | End-to-end autonomous RE agents that chain a disasm-MCP + LLM into a goal loop ("find & understand the trial check"). The fully-automated endpoint of P0. | all of the above | A+B | **analysis** → worked ref: [`rea.md`](rea.md) |
| `decompiler-gpt-plugins` | In-tool LLM assistants: Gepetto (IDA), aiDAPal, GhidraGPT/GptHidra/ReVa, r2ai — one-click explain/rename/summarize of decompiled functions. | IDA / Ghidra / radare2 | A | list (verify in research) |
| `llm-decompile-models` | Models that turn stripped binaries/assembly into readable C from a prompt (LLM4Decompile-class, DeGPT for readability). Skip the human analyst entirely. | — (model) | A | list (verify in research) |
| `ai-frida-gen` | AI agents that generate Frida hooks/instrumentation from a prompt ("hook the license check"). Turns "write a hook" into one sentence. | Frida | A+B | list (verify in research) |
| `mobile-ai-re` | LLM plugins/agents over JADX / APK analysis and iOS equivalents — "explain this app, find the check." | JADX / APKTool / iOS tooling | B | list (verify in research) |
| `ai-deobfuscators` | LLM-driven deobfuscation & symbol/name recovery (humanify-class, AI string/control-flow recovery). Undoes the cheap obfuscation layer. | — (model) | A+B | list (verify in research) |
| `uncensored-local-models` | **The model layer.** Open-weight / abliterated / "uncensored" models run locally (GLM-4.x/5.x-class, Qwen-class, DeepSeek-class, Llama-abliterated, dolphin/hermes-uncensored) via Ollama / LM Studio / llama.cpp / vLLM — chosen specifically to strip the vendor **refusal gate, rate limits, and logging** out of the RE loop. Powers every row above when a hosted model would decline. | is the brain behind every P0 row | A+B | list (verify in research) |
| `ai-crack-as-a-service` | AI-backed crack / keygen / patch "services": Discord & Telegram bots, web SaaS, shared agent skills that hand a finished crack to someone who never opens a tool. The **distribution layer** that makes cracks "public." | `agentic-re` + uncensored models | A+B | list (verify in research) |
| `ai-cheat-gen` | AI that generates game cheats / trainers / memory patches from a prompt (games specifically). | `memory-scan` / Frida + model | A+B | list (verify in research) |

### The three layers (how to read the table)
P0 is not one tool — it's a **stack**, and we can attack any layer:
1. **Model layer** — what reasons (`uncensored-local-models`). *Defensive
   consequence: assume a fully cooperative, unrestricted model. "The AI will
   refuse" is NOT a defense.*
2. **Tooling layer** — what acts on the binary (`disasm-mcp`, `agentic-re`,
   `ai-frida-gen`, `decompiler-gpt-plugins`, `llm-decompile-models`,
   `mobile-ai-re`, `ai-deobfuscators`).
3. **Distribution layer** — how a finished crack reaches non-experts
   (`ai-crack-as-a-service`).

**Next phase:** research + analysis on these P0 entries, highest-impact first.
Leads: `disasm-mcp` and `agentic-re` (tooling), `uncensored-local-models`
(because it invalidates the lazy "model refuses" assumption). Each gets its own
`docs/re-techniques/<slug>.md`.

## Substrate — classic engines the P0 tools drive (secondary)

Old, skill-heavy, already-handled-by-the-industry. We track them because the P0
tools orchestrate them and because defeating them blinds the AI on top.

| Slug | Tool / Technique | Track | Category | Priority | Status |
|------|------------------|-------|----------|----------|--------|
| `frida` | Frida (+ objection) runtime hooking | A+B | dynamic | P1 | todo |
| `ghidra` | Ghidra decompiler | A | static | P1 | todo |
| `debuggers` | GDB / LLDB / x64dbg / WinDbg | A | dynamic | P2 | todo |
| `ida` | IDA Pro / Hex-Rays | A | static | P2 | todo |
| `jadx-apktool` | JADX / APKTool (Android dex) | B | mobile | P1 | todo |
| `android-root-hook` | Magisk / Zygisk / Xposed / LSPosed | B | mobile | P2 | todo |
| `ios-decrypt` | class-dump / app decrypt / Hopper (iOS) | B | mobile | P2 | todo |
| `memory-scan` | Cheat Engine / GameGuardian / mem edit | A+B | dynamic | P2 | todo |
| `ssl-pinning-bypass` | SSL-pinning bypass (Frida/objection) | B | network | P3 | todo |
| `radare2` | radare2 / rizin / Cutter | A | static | P3 | todo |
| `packers` | UPX / PyInstaller unpacking | A | packaging | P3 | todo |

**Track A** = native binaries (ELF/PE/Mach-O). **Track B** = mobile (Android/iOS).
The substrate is P1/P2 only because the P0 AI tools ride on it — not a headline in itself.

## Out of current scope (reference only — do not work unless target changes)
`electron-asar`, `js-deobf`, `wasm-decompile`, `dotnet-decompile`. Kept for
completeness; the operator's target is native + mobile (see `CLAUDE.md` §2).

> Research phase fills these in, highest priority first. Entries are written by
> Scout (research) + Builder (drafting) and signed off by Evaluator.
