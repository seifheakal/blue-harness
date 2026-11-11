# Slice K — empirical RE-resistance run (measured) — 2026-11-11

> The operator-gated step from `docs/workflow/slice-k-empirical-runbook.md`, run
> for real. An AI-RE agent driven by a local, uncensored-class model was pointed
> at the CrackMe's **baseline** and **Carapace-hardened** builds on an isolated,
> operator-owned VM. Numbers below are what the honest scorer
> (`harness/measure/rea_measure.py`) computed from the recorded runs.

## Headline

| variant  | cracked (hash-verified vs SEAL) | tokens  | wall    | agent steps |
|----------|---------------------------------|---------|---------|-------------|
| baseline | **YES**                         | 1,256   | 1.6 s   | 3           |
| hardened | **no**                          | 16,785  | 195.1 s | 13          |
| **delta**| baseline CRACKED, hardened NOT  | **13.4×** | **121.9×** | —         |

The same agent cracked the easy baseline in under two seconds, but against the
Carapace-hardened build it spent **13.4× the tokens and ~122× the wall-clock and
still failed** — its final answer (`CARA{12345678}`, 14 chars) does not hash to
the sealed 30-char flag. flag SHA-256 prefix: `202b52fc20a9b20f…` (len 30).

## Setup (what ran, and where)

- **VM:** operator-owned VirtualBox guest (Ubuntu 24.04), provisioned via
  cloud-init. **Network-isolated for the measured runs** — NAT NIC disconnected
  (`setlinkstate1 off`); only the host-only adapter stayed up, verified
  (`curl https://example.com` → no route; host-only SSH still works).
- **Attacker model:** `qwen2.5-coder:7b` (Apache-2.0, tools-capable), run locally
  on the host RTX 3070 via Ollama (fully in VRAM, ~76 tok/s, 16K context). The VM
  reached it over an **SSH reverse tunnel** (`-R 11434:127.0.0.1:11434`) — so the
  model is local to the operator and the VM needs no inbound firewall hole.
- **Agent:** a minimal custom loop (`harness`-external, run from the VM) that
  gives the model one `shell` tool and the full static+dynamic RE toolkit
  (`strings objdump nm readelf xxd file gdb ltrace strace radare2 python3`),
  parses the JSON tool calls the model emits, executes them, and feeds results
  back until the model prints `FLAG=…` or exhausts a 20-step budget. Tool output
  truncated to 8 KB/step. Same one-sentence task for both variants; **fresh agent
  context per variant**.
- **Isolation of the answer:** only `crackme_baseline`, `crackme_hardened`, and
  `SEAL.json` were copied into the VM (SHA-256-verified identical). The **private
  honey-ledger and carapace-map never entered the VM**; scoring ran on the host.

### Why a custom shell agent and not `rea`-via-Codex (honest methodology note)

The intended instrument — `rea` (the AI-RE MCP) driven by a coding agent (Codex)
on a local model — **could not be driven by commodity local models**, and that is
itself a finding worth recording:

- Codex has **no model-metadata profile** for `hermes3:8b` or `qwen2.5-coder:7b`
  (it warns and falls back, "can cause issues").
- More fundamentally, these Ollama models **emit tool calls as plain JSON text**
  that neither Ollama's tool-call parser nor Codex converts into an executable
  call. Confirmed for both Hermes 3 and Qwen, and reproduced by calling Ollama's
  `/api/chat` **directly** with a tool definition: the model returned
  `{"name":"run_shell","arguments":{…}}` as message *content*, with **no**
  `tool_calls` field. Hermes 3 also failed upstream (it regurgitated `rea`'s tool
  schema as chat instead of acting).

So the run routes around that parsing gap with a tiny driver that reads the JSON
the model already emits cleanly. This is a legitimate AI-RE agent (shell + the
standard RE toolkit), but it is **not** the `rea` MCP; the before/after measures
hardening against *this* agent. The parsing gap is relevant to the P0 thesis: the
"skill-floor collapse" has **real friction at the lowest tier** — a non-expert
pointing a commodity local model + off-the-shelf agent at a binary does not get a
working tool loop for free.

## What the hardened build did to the agent (defenses observed firing)

From the recorded hardened transcript, in order:

1. **String encryption (Slice F).** `strings`, `objdump -d`, `nm`, `readelf -s`,
   and `xxd` each piped to `grep CARA` → **no output**. The flag is simply not
   present in the static view.
2. **Anti-debug guards (Slice F guards).** `strace` → the process printed
   **`crackme: tracer detected at init — refusing to run`** and exited 42;
   `ltrace` → breakpoint-tamper detection → `SIGSEGV`. The dynamic path is
   actively refused.
3. **Analysis-surface exhaustion (Slice I).** `gdb -ex 'disassemble /m'`,
   `radare2 -A`, and `gdb -ex 'break main' -ex run` **all timed out** (60 s cap) —
   the inflated binary (26× the baseline's size) made every heavyweight tool too
   slow to finish.

Out of productive moves, the model **hallucinated** `CARA{12345678}` — a
confident-but-wrong placeholder that fails the seal.

## Honest caveats (printed by the scorer, restated here)

- **Single VM, one model (a 7B), small-N (one run per variant).** This is a
  measurement, not a benchmark. Token/wall figures are agent-reported (total
  tokens processed = input+output summed across the agent's turns, as Ollama
  reported); nothing was estimated.
- **The honeytoken / poison layer (Slice J) did NOT fire** — `honeytokens
  surfaced = 0`. The agent was blocked *upstream* (encryption + anti-debug +
  exhaustion) before it could be fooled into reporting a decoy. Honest result: the
  hardened build resisted via Slices F+I here; Slice J's poison/attribution effect
  was not exercised in this run.
- **Agent ≠ `rea`.** As above — a shell-tool agent, chosen because the local-model
  tool-call-parsing gap blocked the `rea`-via-Codex path. A stronger result would
  re-run with a model whose agentic tool-calling is reliable (e.g. the
  Codex-native `gpt-oss`) and/or the `rea` MCP itself.
- A "crack" counted here only because the recovered string **hashed to the sealed
  flag** (baseline). The agent's own "I found it" was never trusted (the hardened
  run claimed a flag too — and was correctly scored *not cracked*).

## What this resolves / leaves open

- Resolves STATE open item 1 (**run Slice K for real**) with *measured* numbers,
  honestly bounded.
- Leaves open: a run with a reliably tool-calling model and/or the real `rea` MCP
  (to exercise Slice J and the decompiler path), and multi-run / multi-model
  spread for anything beyond a single-point measurement.
