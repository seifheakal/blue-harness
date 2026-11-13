# Research Index

Structured research notes live in `research/findings/`. This index is the map.
Keep it current: one row per note.

| File | Topic | Phase | Status | Date |
|------|-------|-------|--------|------|
| `findings/2026-10-25-rea-agents.md` | rea / rea-agents — agent-driven RE MCP (P0 `disasm-mcp`+`agentic-re`) | research | draft (needs Evaluator) | 2026-10-25 |
| `findings/2026-10-25-rea-weapons-inventory.md` | rea — per-capability weapons inventory (tools, surfaces, engines, target requirements, runtime-capture path, turnkey severity, popularity, deps/OS; Frida present, PTY path not ptrace) | research | draft (needs Evaluator) | 2026-10-25 |
| `findings/2026-11-05-competitive-landscape.md` | anti-AI-RE defenders scan (BLA/antirea/AREA) + absorption matrix — what we fold into Carapace and the one scope-change decision | research | draft (needs Evaluator) | 2026-11-05 |
| `findings/2026-11-11-slice-k-empirical-run.md` | Slice K run for real — measured baseline-vs-hardened on an isolated VM (local `qwen2.5-coder:7b` shell-agent): baseline cracked, hardened not (13.4× tok, 121.9× wall); string-enc/anti-debug/exhaust fired; honeytokens did not; local-model tool-call-parsing gap (rea-via-Codex blocked) | testing | done (measured, N=1) | 2026-11-11 |
| `findings/2026-11-13-macho-harden-levers.md` | Mach-O harden levers (Slice Q) — decoy non-mapped segment (`LC_SEGMENT_64` `vmsize=0` → dyld ignores) + trailer + honeytokens; header-pad constraint (ld64 32B default, `-headerpad_max_install_names`); byte-level proof with no macOS host | analysis | done | 2026-11-13 |
| `findings/2026-11-13-local-model-tool-calling.md` | Local-model tool calling (Slice S): Ollama `message.tool_calls` vs tool JSON in `content` (qwen2.5-coder, Hermes 3, Qwen 3.5 reports); Qwen and gpt-oss native formats; recommendation = native-first + validated text shim + grammar-constrained where supported | research | reviewed | 2026-11-13 |
| `findings/2026-11-14-electron-re-landscape.md` | Electron desktop RE landscape (ASAR, V8 bytecode/bytenode, fuses, ASAR integrity, CVE-2025-55305, AI-layer deobfuscation evidence) — scope-expansion proposal input; tiered countermeasures with named bypasses | research | draft (needs Evaluator); PT Swarm bytenode article unfetched (TLS error) | 2026-11-14 |
| `findings/2026-11-14-dotnet-il-re-landscape.md` | .NET / CIL managed-IL RE landscape for a scope-expansion proposal — ILSpy/dnSpyEx/de4dot (archived 2020)/AI MCP wrappers; tiered countermeasures (C0–C13) with named bypasses; NativeAOT folds into native track (Meaningful, not Strong); scope decisions (MAUI/Android) | research | draft (needs Evaluator) | 2026-11-14 |
| `findings/2026-11-14-wasm-re-landscape.md` | WebAssembly RE landscape (browser + WASI; NotDec/WaDec/StackSight decompilers, Ghidra plugin, wasm-opt/wasm-tools metadata survival, D1–D13 defense tiers with named bypasses) — scope-expansion input | research | draft (needs Evaluator; name-strip LLM effect unmeasured) | 2026-11-14 |
| `findings/2026-11-14-js-deobf-re-landscape.md` | Minified/obfuscated-JS RE landscape (source-map leakage, webcrack/synchrony/restringer deterministic deobf, humanify LLM renaming, JsDeObsBench/OBsmith/CASCADE evidence, javascript-obfuscator tiers with named bypasses) — scope-expansion input | research | draft (needs Evaluator; several version/figure dates secondary-sourced) | 2026-11-14 |

## Conventions
- One note per topic, named `findings/YYYY-MM-DD-<slug>.md`.
- Use `docs/workflow/handoff-template.md`.
- Cite and date every external fact — the RE landscape moves monthly.
- Analysis that becomes stable reference graduates into `docs/` (e.g. a
  `re-techniques/<slug>.md` entry); the research note stays as the dated record.
