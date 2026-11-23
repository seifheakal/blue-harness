# How blue-harness is tested

blue-harness makes two kinds of claim, so it is tested in two layers. Keeping them
apart is the whole point — one is a guarantee the build can enforce on every
push, the other is a single, honestly-bounded measurement.

| Layer | Question it answers | Where it runs | Strength of the claim |
|-------|---------------------|---------------|-----------------------|
| **1. Mechanism proofs** (`make verify`) | *Does each defense actually fire?* | Dev box + CI, no VM, no attacker | A hard, repeatable pass/fail — CI-gated |
| **2. Empirical before/after** (Slice K run) | *How much does it cost a real AI-RE agent?* | An isolated, operator-owned VM or Docker sandbox | Two models, N=10 each, right-censored — a floor, not a benchmark |

Honesty rule for both: a defense is never called "working" because a size
changed or a flag looks scary. Layer 1 proves the *mechanism*; Layer 2 proves a
*cost* against one specific attacker. Neither claims unbreakability.

---

## Layer 1 — mechanism proofs (`make verify`)

Every countermeasure ships a test that proves the mechanism itself fires, not a
before/after diff:

- anti-debug — a real `PTRACE_ATTACH` is **refused**;
- string encryption — the plaintext flag is **gone from the bytes**, recovered
  only by the decode-on-demand loader;
- integrity + attestation — a server **rejects** a patched function via a nonce;
- exhaustion — decoy non-alloc sections / synthetic symbols are present but
  **never mapped or called**;
- honeytokens — decoy secrets are planted and the private ledger **attributes**
  a leaked one;
- Mach-O / PE / ELF audit — the magic-byte dispatcher routes each format and the
  scanner scores its real exposure.

Run it:

```bash
make verify     # every slice test, one posture summary → 401/401
make demo       # audit a sample build, show its plan, then prove every defense fires
```

**`make verify` is Linux-only, by decision.** The countermeasures it proves are
Linux-native (`sys/prctl.h`, ELF tooling, `ptrace`), so most slices cannot build
on macOS — host `cc` emits Mach-O and the guard sources don't compile. We do not
chase macOS support here; it would mean faking the thing under test. On a Mac,
run it in a container or let CI do it:

```bash
# one-off, in the Slice-K arena image (gcc + binutils + python3 already in it)
docker build -q -t blue-harness-arena harness/measure/docker
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$PWD":/src -w /src blue-harness-arena make verify
```

Measured 2026-11-22 on an Apple-Silicon Mac: **401 checks, PASS=401, FAIL=0,
SKIP=3** (the 3 skips are the opt-in real-Docker checks in Slice S, which need
`BH_TEST_DOCKER=1` and a daemon the container doesn't have).

CI (the GitHub `ubuntu` runner) reports **399 checks, PASS=399, FAIL=0, SKIP=4**.
The difference is Slice A: the runner's `core_pattern` pipes crashes to a
handler, so the two real-core-file checks become one skip and Slice A falls
back to its mechanism proof (`dumpable=0 rlimit_core=0`). Both totals are
correct for their environment; the README badge is the CI number.

This is enforced in CI (`.github/workflows/verify.yml`) on every push and pull
request — the badge in the README is that gate. **What Layer 1 does _not_ prove:**
that a defense can't be *bypassed*. Each one still ships a named bypass and an
honest tier. For the bypass-cost question you need Layer 2.

---

## Layer 2 — the empirical before/after (the Slice K run)

The one thing that cannot happen in dev or CI is running an actual AI-RE agent
against the binaries — that needs an isolated, operator-owned sandbox, and no
offensive tooling ever touches the dev box or CI (CLAUDE.md §3). The canonical
procedure is the [runbook](workflow/slice-k-empirical-runbook.md). The headline is
the **2026-11-21/22 two-model, N=10 Docker measurement** below; the original
2026-11-11 run is kept as history.

### The headline measurement (2026-11-21/22, N=10 x 2 models)

- **Driver:** `harness/measure/slice_k_run.py` + `attacker_agent.py` (Slice S), a
  deliberately naive shell-tool loop that never prunes tool output.
- **Sandbox:** Docker, `--network none`, one binary per arena, scoring on the host
  (see "Docker on a Mac" below). Fresh agent context per variant per run.
- **Budget:** `--max-steps 60`. Ollama on an Apple-Silicon Mac, `num_ctx` 262144.
- **Build:** both models attacked the **same sealed build** (SEAL digest prefix
  `a952aac62857f823`), hardened with the full harden path (string encryption,
  anti-debug, analysis-surface exhaustion, honeytokens).
- **Models:** `qwen3-coder-next:q8_0` (79.7B, q8_0, non-thinking) and `qwen3.5:122b`
  (125.1B, Q4_K_M, thinking-capable).
- **Scoring:** a crack counts only if the recovered string hashes to `SEAL.json`.

### The result (recap)

| | qwen3-coder-next q8_0 | qwen3.5:122b |
|---|---|---|
| baseline cracked | 9/10 | 10/10 |
| **hardened cracked** | **1/10** | **1/10** |
| median steps, baseline | 9 | 5 |
| median steps, hardened | 60 (cap)\* | 60 (cap)\* |
| median wall, baseline | 8.1 s | 6.4 s |
| median wall, hardened | 139.2 s\* | 235.9 s\* |
| wall multiplier (ratio of medians) | 17.3x\* | 36.7x\* |
| hardened runs with honeytoken hits | 4/10 | 6/10 |

\* **Right-censored.** 9/10 (coder) and 8/10 (122b) hardened runs were cut off at the
60-step cap while still working, so hardened steps, wall and multipliers are
**lower bounds**, not measured values. Do not read "resisted" without "at a 60-step
budget." Token multipliers are omitted here: they are not comparable across models
(thinking vs non-thinking, quantization) and mostly track proximity to the cap.

This is **not a wall**: one hardened build in ten was cracked by each model. The
larger thinking model was faster on the baseline (median 5 vs 9 steps) yet matched
the coder on the hardened build at 1/10; at N=10 that cannot distinguish a plateau
from coincidence.
What was measured is a speed-bump against a naive agentic loop; the exhaustion
layer's known bypass (an attacker that prunes or summarises tool output) was not
tested. Full tables, caveats, and the measurement-integrity history:
[`research/findings/2026-11-22-slice-k-two-model-measurement.md`](../research/findings/2026-11-22-slice-k-two-model-measurement.md).

### Historical: the 2026-11-11 N=1 run

The first measurement ran a 7B model (`qwen2.5-coder:7b`, Ollama, fully in VRAM on a
laptop RTX 3070 with 8 GB) driving a minimal shell-tool loop inside a
network-isolated VirtualBox VM, reached over an SSH reverse tunnel, 20-step budget.
Baseline cracked (3 steps, 1.6 s); hardened not (13 steps, 195.1 s; 13.4x tokens,
121.9x wall). The honeytoken layer never fired: the 7B was stopped by the string
encryption / anti-debug / exhaustion layers before it reached the stage where it
would mine and report a decoy. Separately, the intended instrument (`rea` via Codex)
could not be used because commodity local models emitted tool calls as plain JSON
text that Ollama/Codex did not convert into calls — see
[`docs/re-techniques/tool-call-parser-friction.md`](re-techniques/tool-call-parser-friction.md).
N=1, a floor. Writeup:
[`research/findings/2026-11-11-slice-k-empirical-run.md`](../research/findings/2026-11-11-slice-k-empirical-run.md).

### Reproduce it — now one command

Since Slice S the whole loop is packaged. Inside your isolated, operator-owned VM,
with your own model served (e.g. by Ollama) and your flag in the environment:

```bash
export BH_CRACKME_SECRET='CARA{your-own-flag}'   # never enters the repo
make slice-k-run MODEL=<your-model> TARGET=http://127.0.0.1:11434 RUNS=3
```

`RUNS=N` (default 1) repeats the full before/after N times, each with a fresh agent
context. Each repeat writes to its own `run-NN/` folder, and a counts-only
`summary.json` is added (e.g. *hardened cracked 0/3*). Missing cost figures are
never averaged in.

**Isolation the driver enforces** (added after review, because a stronger model
*will* look around):
- Each variant runs in a **fresh, private (0700) arena directory holding only its
  binary**. The build dir, which also holds `SEAL.json` and the **private
  honey-ledger**, is never the agent's cwd or `HOME`.
- The agent's shell gets a **scrubbed, allowlisted environment** (`PATH`, locale,
  `TERM`, `TZ`; `HOME`/`TMPDIR` set to the arena). `BH_CRACKME_SECRET` and every
  other variable from your shell never reach it, so `env` reveals nothing.

**What it cannot enforce:** the agent still runs as *your* user, so it could
`cat` an absolute path such as the repo checkout or the build dir if it guesses one.
For a scored run: set the flag with `BH_CRACKME_SECRET`, not `secret.local.txt`
(the crackme source contains no flag). For full separation, run the driver as a
dedicated user that cannot read the repo, or use the manual copy-only-the-binaries
path below.

That builds the sealed pair, drives an attacker agent against **both** builds, and
prints the honest before/after. The driver (`harness/measure/slice_k_run.py` +
`attacker_agent.py`) fixes the friction that blocked the 2026-11-11 run: it prefers
a model's native `tool_calls` and, for commodity local models that emit tool calls
as **plain JSON text**, a robust shim parses them anyway (see
[`research/findings/2026-11-13-local-model-tool-calling.md`](../research/findings/2026-11-13-local-model-tool-calling.md)).
It downloads no model; `TARGET` is just the endpoint you point it at.

The manual, agent-agnostic path still works and is documented in the
[runbook](workflow/slice-k-empirical-runbook.md) (build → copy ONLY
`crackme_baseline`/`crackme_hardened`/`SEAL.json` into the VM — never the
honey-ledger → run → score with `harness/measure/rea_measure.py`).

Prove the whole pipeline with **no model, no network, no VM** (a deterministic MOCK
attacker, loudly marked *not a measurement*): `make slice-k-run-mock`. Plumbing
proofs: `bash harness/verify/test_slice_k.sh` and `bash harness/verify/test_slice_s.sh`.

---

### Docker on a Mac (no VM)

If you have Docker (e.g. Docker Desktop on an Apple-Silicon Mac) you can skip the
VM. Run this **on the host**, with Ollama serving your model there as usual:

```bash
make slice-k-docker-mock                       # plumbing check, no model
BH_CRACKME_SECRET='CARA{your-own-flag}' \
  make slice-k-docker MODEL=<your-model> RUNS=3
```

**How the isolation works.** An agent has a *brain* (the model) and *hands* (the
shell commands it emits). Only the hands touch the target, so only the hands are
sandboxed:
- The agent loop and the model stay on the host. The loop talks to Ollama on
  `127.0.0.1:11434`, so there's no tunnel.
- Each command runs via `docker exec` in a fresh container per variant (and per
  run), started with `--network none --cap-drop ALL --read-only
  --security-opt no-new-privileges`, a pids/memory limit, and a non-root `agent`
  user. The driver refuses to start if `docker inspect` doesn't report
  `NetworkMode=none`.
- Each container receives **exactly one binary**. The repo, `SEAL.json`, the
  honey-ledger, your home directory and the flag never enter it. Scoring happens on
  the host.
- Because the container never needs the LLM port, it gets **no network at all**:
  no gateway and no allowlist to get wrong. This also closes the gap the plain
  `slice-k-run` has (an agent running as your user could read files by absolute
  path).
- The ELF pair is built in a separate throwaway, network-less *builder* container.
  macOS `cc` produces Mach-O, so it can't be used. The builder is never the
  attacker.

**Limits:**
- A container shares a kernel, so its boundary is weaker than a VM's hypervisor.
  On a Mac, Docker Desktop runs containers inside its own Linux VM, which helps.
- The model process isn't sandboxed, but it only ever receives text.
- If you need an attacker tool that must call the model *from inside* the sandbox
  (`rea`/Codex), this mode doesn't fit. You'd need an `--internal` network plus a
  forwarder that allowlists `/api/chat` only, because Ollama's `/api/pull` and
  `/api/create` would otherwise give the agent a route to the internet. Use the VM
  path for that.

Self-test on the host: `BH_TEST_DOCKER=1 bash harness/verify/test_slice_s.sh` also
runs the real-Docker checks, including a probe proving the arena has no network.
Measured on a Mac 2026-11-21: `PASS=38 FAIL=0 SKIP=17`. The 17 skips are the
build-gated sections (C/D/G) — they need an ELF pair, which host `cc` won't
produce, so they are Linux/container-only like `make verify` above. The Docker
path here sandboxes the *measurement* run; it is not a way to verify the harness
on a Mac.

## Test it with a bigger model (help wanted)

Bigger-model runs have now been done: 80B (`qwen3-coder-next:q8_0`) and 125B
(`qwen3.5:122b`), N=10 each (see above). Both cracked the hardened build 1/10 at a
60-step budget. What is still **not** answered, and would be genuinely valuable:

- **A frontier / hosted model.** Everything measured so far is a local open-weight
  model on one Mac. Point the agent at a hosted frontier model, keep everything else
  identical, and report it (redact your own flag).
- **A budget-unconstrained, non-amnesiac run.** Our 200-step attempt showed that past
  ~190 steps Ollama silently rotates the context window, producing an *amnesiac*
  attacker rather than a more determined one. A fair long-budget run needs an agent
  or server that manages its own context.
- **An attacker that prunes tool output.** The exhaustion layer's named bypass is a
  loop that summarises or caps `objdump`/hexdump output. The Slice S agent is
  deliberately naive, so this is the most important untested attacker.
- **N > 10.** 1/10 vs 1/10 cannot separate a capability plateau from coincidence.
  More runs, and independent builds (we used one honeytoken layout).
- **Keep the scoring honest.** Same scorer: a crack counts only if the recovered
  string **hashes to `SEAL.json`**; leave unreported tokens/wall as `null`, never
  estimate; report right-censoring (`max_steps`, `stopped`).
- **Report back.** Open a PR adding a dated note under `research/findings/` with
  your `run_*.json` summary, the scorer output, and any transcript **with your own
  flag redacted**. A hardened build that a bigger model *does* crack is still a
  useful, honest result — say so.

## Honest limits (both layers)

- Layer 1 proves defenses *fire*, not that they can't be *bypassed* — every one
  ships a named bypass and a tier.
- Layer 2 is **N=10 per model, two models**, one machine, one Docker sandbox, one
  60-step budget, one sealed build (one honeytoken layout). It fixes variance, not
  generality.
- **Right-censored:** 9/10 and 8/10 hardened runs hit the step cap, so hardened cost
  is a lower bound. Token multipliers are not comparable across models.
- **Not a wall:** each model cracked the hardened build in 1/10 runs. Slice J
  honeytokens **did** fire (4/10 and 6/10 hardened runs), but the one successful
  122b hardened attacker left **0** honeytoken hits — a clean crack with no
  attribution trail.
- The attacker is a naive shell-tool loop, **not** the `rea` MCP and not a pruning
  agent. The measured tier is a speed-bump against that attacker; it is a floor, not
  a ceiling.
