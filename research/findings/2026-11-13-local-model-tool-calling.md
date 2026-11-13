# Local-model tool calling (text-vs-structured) — research
- Date: 2026-11-13
- Author role: Scout
- Phase: research
- Status: reviewed (Evaluator sign-off 2026-11-13)

## TL;DR
- Ollama returns tool calls in a structured `message.tool_calls` field only when its parser recognizes the model's tool-call format. Several 2026 reports show tool calls landing as raw text in `content` (including qwen2.5-coder), so the failure is real and recurring, not a one-off. Source: Ollama docs (accessed 2026-11-13); Hermes Agent issue #5867 (opened 2026-04-07).
- The robust fix is layered: native `tool_calls` where the runtime parses it, a validated text-extraction shim as fallback, and grammar-constrained decoding where the runtime supports it. Our shim should only accept calls whose tool name is in the declared tool list.
- gpt-oss (2025, Harmony format) has first-class function calling in its model card. Its 20b variant is about 14 GB on Ollama, which may not fit in an 8 GB GPU; verify hardware before choosing it.

## Detail

### 1. Ollama tool-calling surface (2025–2026)
- `/api/chat` takes a `tools` list (`type: "function"`, `name`, `description`, JSON Schema `parameters`). A tool-calling reply carries `message.tool_calls`, each with `function.name` and `function.arguments`. Tool results return as `role: "tool"` messages. Source: https://docs.ollama.com/capabilities/tool-calling (accessed 2026-11-13; page shows no date; examples use qwen3).
- Ollama's streaming-with-tools post (2025-05-28) says the parser reads each model's template to recognize tool-call prefixes and falls back to JSON parsing when a model emits a call without a prefix. It lists Qwen 3, Qwen2.5 and Qwen2.5-coder, Llama 3.1, and Llama 4 as tool-calling models. It also says a context window of 32k or higher "improves tool-calling performance" (anecdotal). Source: https://registry.ollama.ai/blog/streaming-tool (published 2025-05-28; accessed 2026-11-13).
- Ollama library page for `qwen2.5-coder` lists capability tag `tools`; sizes 0.5b–32b. Page reads "Updated 1 year ago" at time of fetch, so treat as possibly stale. Source: https://ollama.com/library/qwen2.5-coder (accessed 2026-11-13).
- Support is per model and per parser, not per "tools" tag. An October 2026 analysis (secondary, via search snippet) says Ollama uses the parser named in the model config, and falls back to a generic parser keyed on the template's tool-call tag if none is named. Source: https://pub.towardsai.net/local-llm-tool-calling-depends-on-your-runtimes-parser-b636843b6c97 (page returned HTTP 403 to our fetch; claim unverified beyond snippet).

### 2. Known failure: tool calls emitted as text in `content`
- **qwen2.5-coder:** Hermes Agent issue #5867 (opened 2026-04-07): qwen2.5-coder:14b, later confirmed on qwen2.5-coder:7b-instruct-q3_K_L. Tool call came back as a JSON string in `content`, with no `tool_calls` and `finish_reason: "stop"`. Root cause on the client side: it only checks for `tool_calls`. Still open; a May 2026 comment says switching provider from `ollama` to `custom` restores execution. Source: https://github.com/NousResearch/hermes-agent/issues/5867 (accessed 2026-11-13).
- **Qwen 3.5 family:** Ollama issue #14493 (opened 2026-02-27, still open as of Sept 2026 in thread): tool calls printed as raw `<tool_call><function=…>` text in `content`, traced to Hermes-style renderer/parser mismatch with the model's Qwen3-Coder XML format. Source: https://github.com/ollama/ollama/issues/14493 (accessed 2026-11-13). Fix status across versions is disputed in the thread.
- **Hermes 3 (NemoClaw issue, search snippet only):** tool calls came back as template-shaped text that Ollama did not extract. Source: https://github.com/NVIDIA/NemoClaw/issues/2731 (not fetched; treat as unverified).
- **Our own observation (2026-11-11 run):** same behaviour via direct `/api/chat` for hermes3:8b and qwen2.5-coder:7b. Source: `research/findings/2026-11-11-slice-k-empirical-run.md`.
- Ollama's own guidance (the "Why local models print tool call JSON" article, published 2026-11-09): check whether `message.tool_calls` is present; confirm `/api/chat` and `tools`; remove `format: "json"` or a schema (it can conflict with tool-call structure); check the chat template for imported models; and "don't execute JSON found in plain text unless you validate it and apply the same authorization checks." Source: https://www.vincentschmalbach.com/why-local-models-in-ollama-print-tool-call-json-instead-of-calling-the-tool/ (secondary blog; accessed 2026-11-13).

### 3. Qwen family native calling
- Qwen's official function-calling guide (example dated 2024-09-30; Qwen3-focused) recommends Hermes-style tool use: "We recommend using Hermes-style tool use for Qwen3 to maximize function calling performance." It says malformed calls can still occur and output must be validated. Recommended server: vLLM (≥ v0.8.5) with `--enable-auto-tool-choice --tool-call-parser hermes`. Source: https://qwen.readthedocs.io/en/latest/framework/function_call.html (accessed 2026-11-13). Note: the page does not cover Ollama parser flags.
- llama.cpp's function-calling doc lists native handlers for Qwen 2.5 and Qwen 2.5 Coder, Hermes 2/3, Llama 3.1/3.2/3.3, and GPT-OSS (Harmony). It requires `--jinja` and a tool-aware template; otherwise it falls back to a "Generic" handler that "may consume more tokens and be less efficient." Source: https://github.com/ggml-org/llama.cpp/blob/master/docs/function-calling.md (accessed 2026-11-13; page footer © 2026).
- Qwen2.5 Jinja templates tell the model to wrap a JSON `{name, arguments}` in `<tool_call></tool_call>` tags (secondary, via llama.cpp docs and search snippets). Source: https://huggingface.co/OpenTransformer/llama.cpp-prismml/blob/main/docs/function-calling.md (mirror; unverified against upstream).

### 4. gpt-oss and Harmony
- gpt-oss model card (arXiv:2508.10925, submitted 2025-08-08; card dated 2025-08-05): Harmony channels are "analysis for CoT tokens, commentary for function tool calling and final for answers shown to users." Models trained for browsing, Python, and developer-defined function tools. Source: https://arxiv.org/html/2508.10925v1 (accessed 2026-11-13).
- Reported tool-use evals in the card: τ-Bench Retail for gpt-oss-120b at high reasoning 67.8; gpt-oss-20b at high reasoning 54.8 (vendor-reported, not independently replicated here). Same source.
- Ollama gpt-oss launch post (2025-08-05): "Use the models' native capabilities for function calling, web browsing… python tool calls, and structured outputs." Harmony itself is not mentioned on that page. Source: https://registry.ollama.ai/blog/gpt-oss (accessed 2026-11-13).
- Ollama library: gpt-oss tags `tools, thinking`; `gpt-oss:20b` is 14 GB; `:120b` is 65 GB; updated "1 month ago" at fetch. Source: https://ollama.com/library/gpt-oss (accessed 2026-11-13).
- Harmony must be used as-is: the openai/harmony project notes gpt-oss "will not work correctly without the harmony format" (search snippet; GitHub repo not fetched). Source: https://github.com/openai/harmony (not fetched directly; cited from search results 2026-11-13).

### 5. Is this a widely known failure mode?
- Yes. Multiple independent projects report the same symptom in 2026 (Hermes Agent, Strix, LiteLLM, NemoClaw, Ollama issue #14493; sources in §2). Practitioner posts describe the same pattern. The root cause is usually one of: (a) client reads only `content`; (b) no `tools` sent; (c) template/parser mismatch; (d) model simply does not emit the native marker.
- Parsing approaches in the wild (search results only; not vetted): brace-balanced extraction followed by repair (e.g. `json_repair`), strict parse → balanced-span extraction → repair → return error to model; `<tool_call>`-tag-specific parsers with fallback to line-based parsing. Examples (not fetched): https://docs.rs/crate/kowalski-core/1.2.0/source/src/utils/json.rs and https://huggingface.co/joshuaeric/vllm-tool-calling-guide/blob/main/examples/robust_json_extraction.py.
- Grammar-constrained decoding: llama.cpp converts JSON Schema to GBNF; masking removes tokens that cannot extend a valid parse, so invalid JSON is never sampled. Caveats: a single practitioner test showed prompt-only ~80–85% valid JSON vs 100% with GBNF on Llama 3.2 3B (anecdotal; not replicated); a llama.cpp issue reports large tool sets rejected at grammar-build time. Sources: https://dev.to/software_mvp-factory/structured-output-and-tool-calling-with-on-device-llms-on-android-3e9j and https://dev.to/janpauldahlke/how-i-use-gbnf-grammars-to-make-small-local-models-stop-hallucinating-json-46g (accessed 2026-11-13; both undated in snippet).
- Known conflict: Ollama's JSON `format` (structured output) can block the `<tool_call>` prefix on some models (Towards AI article, search snippet; claim unverified).

### 6. Recommendation (for shim + docs)
The most reproducible path on commodity hardware is layered, not single-method. Step 1: probe each model with one trivial tool through `/api/chat` and check for `message.tool_calls`; use native calls only when the probe passes, and record the model/parser/Ollama version. Step 2: where native parsing fails, use a text-extraction shim as fallback: strict JSON first, then balanced-brace extraction of `<tool_call>` blocks or bare `{name, arguments}` objects, then schema validation against the declared tools, rejecting any name not in that list, and treating extracted calls with the same authorization as native ones (this blocks prompt-injected tool-call text in tool output). Step 3: where the runtime supports it (llama.cpp `--jinja` with a native Qwen/Hermes/gpt-oss handler, or vLLM with the hermes parser), prefer grammar/parser-constrained output over post-hoc repair, because it removes the failure class instead of cleaning it up. Do not rely on Ollama's `format` JSON mode alongside tools without a probe.

## Decisions needed from operator
- Which runtime is the default for the re-run: Ollama (native-first + shim fallback) or llama.cpp `--jinja` (native handler, grammar-capable)? Recommendation: Ollama + shim for portability, with llama.cpp as the verified path.
- Whether to take gpt-oss on the 8 GB RTX 3070 (`gpt-oss:20b` is 14 GB on Ollama; will need CPU offload and slower runs). Hardware spec not cited here; verify.

## Open questions
- Ollama version-to-behaviour mapping for qwen2.5-coder is not established by an official changelog; the Hermes and Ollama threads disagree on whether fixes landed. We need our own probe log (model tag, Ollama version, template hash).
- Whether our 2026-11-11 Ollama tool-call failure was a client request issue (missing or altered `tools`) or a parser issue is not resolved by the sources. The probe in Step 1 should answer it.
- The Ollama library page for qwen2.5-coder shows "Updated 1 year ago"; the tool-support tag may not reflect current parser behavior.
- Towards AI and NemoClaw claims were read from snippets only (blocked or not fetched). Treat as leads, not facts.
- No independent benchmark found for tool-call reliability of qwen2.5-coder:7b vs hermes3:8b vs gpt-oss on Ollama in 2026. Gap for the measurement track.

## Sources
- Ollama — Tool calling — https://docs.ollama.com/capabilities/tool-calling — accessed 2026-11-13 (undated page)
- Ollama blog — Streaming responses with tool calling — https://registry.ollama.ai/blog/streaming-tool — published 2025-05-28, accessed 2026-11-13
- Ollama library — qwen2.5-coder — https://ollama.com/library/qwen2.5-coder — accessed 2026-11-13 (page says "Updated 1 year ago")
- Ollama library — gpt-oss — https://ollama.com/library/gpt-oss — accessed 2026-11-13 (page says "Updated 1 month ago")
- Ollama blog — gpt-oss — https://registry.ollama.ai/blog/gpt-oss — published 2025-08-05, accessed 2026-11-13
- Ollama issue #14493 (Qwen 3.5 tool calls in content) — https://github.com/ollama/ollama/issues/14493 — opened 2026-02-27, accessed 2026-11-13
- Hermes Agent issue #5867 (qwen2.5-coder tool call in content) — https://github.com/NousResearch/hermes-agent/issues/5867 — opened 2026-04-07, accessed 2026-11-13
- NVIDIA NemoClaw issue #2731 (Hermes-3 text tool calls, snippet only) — https://github.com/NVIDIA/NemoClaw/issues/2731 — accessed 2026-11-13 (not fetched)
- "Why local models in Ollama print tool-call JSON" — https://www.vincentschmalbach.com/why-local-models-in-ollama-print-tool-call-json-instead-of-calling-the-tool/ — published 2026-11-09 (per page), accessed 2026-11-13
- Towards AI — Local LLM tool calling depends on your runtime's parser — https://pub.towardsai.net/local-llm-tool-calling-depends-on-your-runtimes-parser-b636843b6c97 — date unknown, 403 on fetch; snippet only
- Qwen — Function Calling guide — https://qwen.readthedocs.io/en/latest/framework/function_call.html — example dated 2024-09-30, accessed 2026-11-13
- llama.cpp — docs/function-calling.md — https://github.com/ggml-org/llama.cpp/blob/master/docs/function-calling.md — accessed 2026-11-13 (footer © 2026)
- gpt-oss model card (arXiv:2508.10925) — https://arxiv.org/html/2508.10925v1 — submitted 2025-08-08, accessed 2026-11-13
- openai/harmony — https://github.com/openai/harmony — not fetched; cited from search results, accessed 2026-11-13
- Qwen2.5-Coder-7B-Instruct model card — https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct — accessed 2026-11-13 (no tool-use section; no date)
- Grammar-constrained tool calls (practitioner, anecdotal) — https://dev.to/janpauldahlke/how-i-use-gbnf-grammars-to-make-small-local-models-stop-hallucinating-json-46g — accessed 2026-11-13 (undated snippet)

## Review log
- Scout 2026-11-13: draft written from fetched sources; several claims are secondary or snippet-only and are flagged inline.
- Evaluator 2026-11-13: SIGN-OFF WITH NITS (see Evaluator sign-off below). Research note is well-cited and flags its own uncertainty; the Slice-S implementation it underpins is honest, in-scope, and genuinely tested.

## Evaluator sign-off
- Date: 2026-11-13 — Role: Evaluator (Opus) — Verdict: **SIGN-OFF WITH NITS**
- Scope reviewed: Slice S — `harness/measure/attacker_agent.py`, `slice_k_run.py`,
  the `rea_measure.py` diff, `harness/verify/test_slice_s.sh`, this note, and the
  doc edits (STATE/HOW-WE-TESTED/runbook/README/measure-README/CV/Makefile).

**1. Honesty / no fabrication — PASS.** No path emits a non-agent-reported cost
number. `MockBackend.chat` always returns `usage=None` (attacker_agent.py:299,305,
312,316) and `run_agent` gates `wall_clock_s` to `None` unless `grade=="live"`
(attacker_agent.py:391), so a mock yields tokens=None/wall=None and the scorer
prints "not measured (need both token counts)" (rea_measure.py:144) — verified by
running the scorer directly. `_ratio` returns None whenever either side is None
(rea_measure.py:73-76): no estimation. Mock output is unmissably labelled — banner
in render (rea_measure.py:110-111) AND in the runner (slice_k_run.py:142-146). The
operator-VM gating is stated in the tool output (`_GATING`, slice_k_run.py:40-44,89,
146), the verify (test_slice_s.sh:166,185), and the docs. No "unbreakable"-class
language anywhere in harness/measure.

**2. Scope (§3) — PASS.** Nothing downloads/serves/bundles a model; `OllamaBackend`
only POSTs via urllib to an operator-supplied `endpoint` (attacker_agent.py:243,
253-256), default localhost. In CI only `MockBackend` runs, and its scripted brain
only ever issues `strings -n 6 <own-crackme>` (attacker_agent.py:296) — no offensive
toolkit against third-party software. The shim parses only the ASSISTANT turn
(`run_agent` calls `extract_tool_calls(reply)` at attacker_agent.py:368; tool output
is appended as `role:"tool"` and never re-parsed), and rejects tool names not in the
`_SHELL_ALIASES` allowlist (attacker_agent.py:152-156) — both proven by the
"unknown tool name dropped" and "honeytoken-shaped text is not a call" cases.

**3. Tier + bypass (§8) — PASS.** Framed honestly as "packaging + tooling, NOT a
defense" (STATE.md:408-413; attacker_agent.py:1-27 header; CV entry). Named bypass
stated: "a reliably tool-calling model or grammar-constrained decoding makes the
shim unnecessary" (STATE.md:412-413). It is a "Speed-bump remover for the attacker's
tooling", not a new countermeasure — correct, no tier inflation.

**4. Test coverage — PASS (genuine, not vacuous).** I re-ran the shim cases (incl.
the exact 2026-11-11 JSON-as-text blocker) plus adversarial additions (multi-call,
list-args, function-wrapper, rm-shaped) — all pass. The MockBackend is genuinely
end-to-end: a scripted brain over REAL `strings` output on REAL binaries, deciding
flag-vs-honeytoken from what it actually reads — not a hardcoded result. The decoy-
not-seal assertion (test_slice_s.sh:147-152) could pass vacuously with
recovered_secret=None, BUT it is guarded by the preceding attribution assertion
(`honeytoken attributions : [1-9]`, test_slice_s.sh:143) which forces a real
honeytoken to have been surfaced — so the pair is sound. Proves both that the
defense fires (baseline CRACKED vs seal, hardened not) and that the audit/scorer
detects presence (Slice J honeytoken surfaced AND attributed).

**5. Regression — PASS.** I ran rea_measure.py against synthetic artifacts: all five
strings test_slice_k.sh greps are preserved verbatim — "baseline CRACKED | hardened
not cracked", "honeytokens surfaced       : 1", "token cost multiplier      : 10.0x",
"not measured", "NO RUN ARTIFACTS YET". Hand-filled artifacts (no `measurement_grade`)
yield grade=None → no MOCK banner, so Slice K is unaffected. The new
"honeytoken attributions" line does not collide with any existing grep.

**6. Research note — PASS.** Cited with access/publish dates throughout; uncertainty
is flagged inline ("snippet only", "unverified", "anecdotal", 403-on-fetch, "not
fetched") and in an explicit Open-questions section. §6 recommendation (native-first
→ validated text shim restricted to declared tools → grammar-constrained where
supported) matches the implementation.

**NITS (non-blocking):**
- Status line (this note, line 4) and `research/_index.md` still read "draft (needs
  Evaluator)"; with this sign-off they should flip to reviewed/validated.
- `_normalise_call` also accepts a name-less `{"command": ...}` object as a shell
  call (attacker_agent.py:153), slightly looser than the note's strict declared-name
  allowlist. Harmless here (assistant-turn-only parsing, single declared tool), but
  worth a comment noting the intentional relaxation.
