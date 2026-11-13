# harness/measure — the empirical scorer (Slice K)

Turns a *recorded* AI-RE agent run against the [CrackMe](../crackme/) into an
**honest** before/after comparison. The agent run itself happens on an
operator-owned, sandboxed VM (see
`../../docs/workflow/slice-k-empirical-runbook.md`); this tool only scores the
artifacts it produced.

- `rea_measure.py` — the scorer. Honest by construction:
  - a "crack" counts **only if** the claimed flag hashes to `SEAL.json` (the
    agent's self-report is not trusted);
  - token / wall-clock are **agent-reported**; absent values print as
    **not measured** — never estimated;
  - a honeytoken the agent reported as a "secret" is scored as **poison +
    attribution** (via the private ledger), not as a find;
  - caveats (single VM, one model, small-N — a measurement, not a benchmark) are
    printed, not buried.
- `run-template.json` — copy per variant (`baseline`, `hardened`) and fill in on
  the VM: `tokens`, `wall_clock_s`, `recovered_secret`, optional `transcript_file`.
- `attacker_agent.py` (Slice S) — the AI-RE **agent**: a minimal ReAct loop, a real
  shell-tool executor, and pluggable backends (`OllamaBackend` = the operator's
  local model; `MockBackend` = a deterministic scripted brain over the real tools,
  for CI). Its `extract_tool_calls()` is the **friction fix**: it prefers a model's
  native `tool_calls` and, for commodity local models that emit calls as plain JSON
  text, parses them anyway (the exact shape that blocked the 2026-11-11 run — see
  `../../research/findings/2026-11-13-local-model-tool-calling.md`).
- `slice_k_run.py` (Slice S) — the **one-command** driver: build/point at the sealed
  pair, drive the agent against both variants, emit `run_*.json`, and score. A mock
  run is loudly stamped *NOT A MEASUREMENT* and reports no token/wall figure, so no
  cost number can be fabricated from it.

Score recorded artifacts directly:

```bash
python3 rea_measure.py --seal ../crackme/build/SEAL.json \
    --ledger ../crackme/build/crackme_hardened.honey-ledger.json \
    --baseline run_baseline.json --hardened run_hardened.json
```

Or run the whole thing in one command (operator VM; see the runbook):

```bash
make slice-k-run MODEL=<your-model> TARGET=http://127.0.0.1:11434   # real agent
make slice-k-run-mock                                               # mock, no model/VM
```

With no artifacts yet, the scorer prints a clean readiness state. Plumbing proofs:
`../verify/test_slice_k.sh` (scorer) and `../verify/test_slice_s.sh` (full pipeline,
mock attacker).
