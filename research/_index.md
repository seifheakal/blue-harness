# Research Index

Structured research notes live in `research/findings/`. This index is the map.
Keep it current: one row per note.

| File | Topic | Phase | Status | Date |
|------|-------|-------|--------|------|
| `findings/2026-10-25-rea-agents.md` | rea / rea-agents — agent-driven RE MCP (P0 `disasm-mcp`+`agentic-re`) | research | draft (needs Evaluator) | 2026-10-25 |
| `findings/2026-10-25-rea-weapons-inventory.md` | rea — per-capability weapons inventory (tools, surfaces, engines, target requirements, runtime-capture path, turnkey severity, popularity, deps/OS; Frida present, PTY path not ptrace) | research | draft (needs Evaluator) | 2026-10-25 |
| `findings/2026-11-05-competitive-landscape.md` | anti-AI-RE defenders scan (BLA/antirea/AREA) + absorption matrix — what we fold into Carapace and the one scope-change decision | research | draft (needs Evaluator) | 2026-11-05 |
| `findings/2026-11-11-slice-k-empirical-run.md` | Slice K run for real — measured baseline-vs-hardened on an isolated VM (local `qwen2.5-coder:7b` shell-agent): baseline cracked, hardened not (13.4× tok, 121.9× wall); string-enc/anti-debug/exhaust fired; honeytokens did not; local-model tool-call-parsing gap (rea-via-Codex blocked) | testing | done (measured, N=1) | 2026-11-11 |

## Conventions
- One note per topic, named `findings/YYYY-MM-DD-<slug>.md`.
- Use `docs/workflow/handoff-template.md`.
- Cite and date every external fact — the RE landscape moves monthly.
- Analysis that becomes stable reference graduates into `docs/` (e.g. a
  `re-techniques/<slug>.md` entry); the research note stays as the dated record.
