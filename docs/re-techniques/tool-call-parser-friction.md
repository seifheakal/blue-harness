# Tool-call parser friction (accidental anti-automation)
- Category: ai-assisted
- What it does: Local LLM attacker stacks sometimes fail to turn a model's tool call into an executable call (tool JSON emitted as plain text; malformed tool-call markup rejected by the server). The agent loop stalls or dies. **We did not build this and do not control it.**
- What it needs from the target: nothing. It is a property of the attacker's serving stack, not of the binary.

## Attacker workflow (steps)
1. Operator installs an agent/skill and points it at a local model (Ollama etc.).
2. Model emits a tool call (native `tool_calls`, or JSON/XML in text).
3. Server/client parses it into an executable call.
4. Tool output returns to the model; loop repeats.

Friction lives at step 3.

## Defensive leverage (step → countermeasure)
| Attacker step | Countermeasure | Strength tier | Known bypass |
|---------------|----------------|---------------|--------------|
| 3. parse tool call | None built. Incidental server behaviour, observed twice (below) | **Trivial** (incidental, version-specific) | Switch server or version; use native `tool_calls`; retry; run a client-side parser (the Slice S text shim does this) |

Sightings:
- **2026-11-11** — commodity local models (Hermes 3, Qwen) emitted tool calls as
  plain JSON text that Ollama's parser and Codex did not convert into calls, which
  blocked the `rea`-via-Codex path. See
  `research/findings/2026-11-11-slice-k-empirical-run.md` and
  `research/findings/2026-11-13-local-model-tool-calling.md`. Routed around by a
  custom loop and later the Slice S text shim.
- **2026-11-22** — in the killed 200-step sweep, `qwen3-coder-next:q8_0` at step 177
  emitted malformed tool-call markup and Ollama's `/api/chat` returned HTTP 500 with
  body `{"error":"XML syntax error on line 4: element <function> closed by </parameter>"}`.
  This is a parser failure **inside Ollama**, upstream of the Slice S text shim, so
  the shim cannot intervene. Observed on one Ollama version on one machine; not
  tested on other versions or servers.

Honest reading: two independent sightings, both accidental, neither a defense. We
must not credit it to the hardening, and must not rely on it.

## Harness hooks
- Audit check(s) this maps to: none (not a property of the build).
- Hardening(s) this maps to: none. Measurement rule instead: such failures are
  recorded as `stopped=backend_error` with data preserved (commit `532336b`), never
  counted as a defense effect or a clean "resisted."
- Relevance: the P0 "one-sentence crack" skill floor has real friction at the lowest
  tier today. Do not plan around it; it is a tooling-maturity gap, not a barrier.

## Sources
- `research/findings/2026-11-11-slice-k-empirical-run.md` — 2026-11-11
- `research/findings/2026-11-13-local-model-tool-calling.md` — 2026-11-13
- 2026-11-22 200-step sweep (qualitative, `~/blue-harness-runs/2026-11-22-steps200-PARTIAL-killed/`, not a dataset); summarized in `research/findings/2026-11-22-slice-k-two-model-measurement.md`
