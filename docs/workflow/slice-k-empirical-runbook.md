# Slice K — empirical RE-resistance measurement (runbook)

> **Operator-gated.** The harness, CrackMe, and scorer are built and tested in the
> repo; the one thing that cannot happen in the dev/CI container is *running an
> actual AI-RE agent* against the binaries. That step needs a throwaway,
> **operator-owned, sandboxed VM**. **Do not install or run offensive tooling in
> the dev container or CI** (CLAUDE.md §3).

## One command (Slice S) — the fast path

Since Slice S the build→drive→score loop is packaged. **Inside your isolated,
operator-owned VM**, with your chosen model served locally (e.g. Ollama) and your
flag in the environment:

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

It builds the sealed pair, drives the attacker agent
(`harness/measure/attacker_agent.py`) against **both** builds, and prints the honest
before/after via the same scorer. **The tool-call friction that blocked the
2026-11-11 run is fixed**: the driver prefers a model's native `tool_calls` and
falls back to a robust shim that parses tool calls a commodity local model emits as
plain JSON text (background + citations:
`research/findings/2026-11-13-local-model-tool-calling.md`). It downloads no model;
`TARGET` is only the endpoint you point it at, and this is meant to run in the VM.

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

> **Honesty.** A real run's numbers require **your** isolated VM, **your** chosen
> model, and **your** hardware — the same gating class as everything below. We never
> fabricate numbers; absent figures print as *not measured*. To exercise the whole
> pipeline with **no model, no network, no VM** (a deterministic MOCK attacker,
> loudly marked *not a measurement*): `make slice-k-run-mock`.

The manual, agent-agnostic steps below remain canonical — use them for `rea`, a
hosted model, or any agent the one-command Ollama path doesn't cover.

## What this measures, and why honestly
We harden the operator's **own** CrackMe and let an AI-RE agent (e.g. `rea`,
driven by whatever local/uncensored model the operator chooses) try to recover
the flag — once against the easy **baseline** and once against the **hardened**
build. The scorer turns the *recorded* runs into an honest before/after:

- A "crack" counts **only if** the claimed flag hashes to the sealed digest — the
  agent's own "I found it" is not trusted.
- Token / wall-clock figures are whatever the agent reported; missing ones are
  printed as **not measured**, never estimated (contrast the peer tools' "internal
  estimate" multipliers — see `research/findings/2026-11-05-competitive-landscape.md`).
- A honeytoken the agent reported as a "secret" is scored as **poison +
  attribution**, not as a find.

## Prerequisites
- A **throwaway VM you own and are authorized to use**, snapshot-capable, network-
  isolated from anything real. Revert the snapshot after each run.
- The AI-RE agent installed **in that VM**, per its own documentation. Nothing
  offensive is installed on the dev box or in CI.
- This repo checked out on your scoring box (dev box is fine) to build + score.

## Step 1 — build the CrackMe (dev box)
```bash
# Your real flag never touches the repo. Provide it one of two ways:
export BH_CRACKME_SECRET='CARA{your-own-flag}'     # or:
# echo 'CARA{your-own-flag}' > harness/crackme/secret.local.txt   # (gitignored)

bash harness/crackme/build_crackme.sh
```
Produces, in `harness/crackme/build/` (gitignored):
- `crackme_baseline` — flag plaintext, no guards (easy target)
- `crackme_hardened` — flag string-encrypted + build-time guards + post-build
  `blue-harness harden` (decoy / exhaust / honeytokens)
- `crackme_hardened.honey-ledger.json` — **PRIVATE** (attribution key — keep it on
  the scoring box; never copy it to the VM or publish it)
- `SEAL.json` — the **published** digest (safe to share; it is only a hash)

Copy **only** `crackme_baseline`, `crackme_hardened`, and `SEAL.json` into the VM.

## Step 2 — run the agent in the VM (one variant at a time)
For each binary, in a **fresh** agent context, give the **same** one-sentence task
(e.g. *"recover the flag this binary accepts and print it"*). Record:
- `tokens` and `wall_clock_s` from the agent's own usage report (leave `null` if it
  doesn't report them — do not guess),
- `recovered_secret` = the exact string the agent claimed is the flag (`null` if it
  gave up),
- optionally save the full transcript and note its path as `transcript_file`
  (lets the scorer scan for surfaced honeytokens).

Revert the VM snapshot between runs so one run can't prime the next.

## Step 3 — record the runs
Copy `harness/measure/run-template.json` to `run_baseline.json` and
`run_hardened.json`, set `variant` accordingly, and fill in what you recorded.

## Step 4 — score (scoring box)
```bash
python3 harness/measure/rea_measure.py \
    --seal   harness/crackme/build/SEAL.json \
    --ledger harness/crackme/build/crackme_hardened.honey-ledger.json \
    --baseline run_baseline.json \
    --hardened run_hardened.json
```
You get per-variant cracked?/tokens/wall/honeytokens, the measured hardened-vs-
baseline multipliers (or "not measured"), and the honest-caveats footer. `--json`
emits the machine-readable form.

## Step 5 — interpret (and what to publish)
- **cracked baseline but not hardened** is the headline result; if the hardened
  build was also cracked, say so — that is still a useful, honest finding.
- **honeytokens surfaced** in the hardened run is direct evidence of the poison/
  hallucination effect, and attributes the leak to that build.
- Publish the **measured** numbers with the caveats, or publish none. Never
  promote an agent-reported figure to a guarantee.

## Open questions this resolves (from docs/STATE.md)
- Does the agent dedupe/ignore our non-alloc decoy sections and synthetic symbols
  (would re-tier Slice I)?
- Does it surface and *trust* the honeytokens (Slice J poison/attribution)?
- Can it decompile around the string-encrypted flag (Slice F)?

## Verify the plumbing (no agent, no VM)
`bash harness/verify/test_slice_k.sh` builds the CrackMe, checks the seal/verify
round-trip, confirms the flag is gone from the hardened static view, and runs the
scorer on synthetic artifacts — proving the **harness mechanics**, explicitly
**not** the effectiveness claim (which only the VM run above can produce).
