# How Carapace is tested

Carapace makes two kinds of claim, so it is tested in two layers. Keeping them
apart is the whole point — one is a guarantee the build can enforce on every
push, the other is a single, honestly-bounded measurement.

| Layer | Question it answers | Where it runs | Strength of the claim |
|-------|---------------------|---------------|-----------------------|
| **1. Mechanism proofs** (`make verify`) | *Does each defense actually fire?* | Dev box + CI, no VM, no attacker | A hard, repeatable pass/fail — CI-gated |
| **2. Empirical before/after** (Slice K run) | *How much does it cost a real AI-RE agent?* | An isolated, operator-owned VM | One measurement, N=1 — a floor, not a benchmark |

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
make verify     # every slice test, one posture summary → 223/223
make demo       # audit a sample build, show its plan, then prove every defense fires
```

This is enforced in CI (`.github/workflows/verify.yml`) on every push and pull
request — the badge in the README is that gate. **What Layer 1 does _not_ prove:**
that a defense can't be *bypassed*. Each one still ships a named bypass and an
honest tier. For the bypass-cost question you need Layer 2.

---

## Layer 2 — the empirical before/after (the Slice K run)

The one thing that cannot happen in dev or CI is running an actual AI-RE agent
against the binaries — that needs a throwaway, operator-owned, network-isolated
VM, and no offensive tooling ever touches the dev box or CI (CLAUDE.md §3). The
canonical procedure is the [runbook](workflow/slice-k-empirical-runbook.md); what
follows is exactly how the **2026-11-11 run** was carried out, so it can be
reproduced and — better — pushed harder.

### The setup we used

- **Hardware:** a single laptop — **NVIDIA RTX 3070 Laptop GPU (8 GB VRAM) + 16 GB
  system RAM**. This is the constraint that set everything else: 8 GB of VRAM caps
  how big the local attacker model can be.
- **Attacker model:** **`qwen2.5-coder:7b`** (Apache-2.0, tools-capable), served
  by **Ollama** on the host GPU, **fully in VRAM** (~4.7 GB at 4-bit, ~76 tok/s),
  16K context (`OLLAMA_CONTEXT_LENGTH=16384`, flash-attention on, `q8_0` KV cache).
  A small, quantised 7B is roughly the largest that fits — **not** a frontier model.
- **VM:** a VirtualBox Ubuntu 24.04 guest with the standard RE toolkit
  (`strings objdump nm readelf xxd file gdb ltrace strace radare2 python3`).
  **Network-isolated for the scored runs** — the NAT NIC disconnected, only the
  host-only adapter up, verified no route out (`curl https://example.com` fails).
- **Linking the VM to the host model:** an **SSH reverse tunnel**
  (`ssh -R 11434:127.0.0.1:11434 …`), so the isolated VM reaches the host's Ollama
  without opening any inbound hole and the model stays bound to host localhost.
- **The agent:** a **minimal custom shell-tool loop** run from the VM. It gives the
  model one `shell` tool plus the RE toolkit above, parses the tool calls the model
  emits, executes them (60 s/step cap, output truncated to 8 KB), and loops until
  the model prints `FLAG=…` or hits a 20-step budget. **Fresh agent context per
  variant**, same one-sentence task for both.
  - *Why a custom loop and not the `rea` MCP via Codex:* commodity local models
    (both Hermes 3 and Qwen) **emit tool calls as plain JSON text** that neither
    Ollama's parser nor Codex converts into an executable call — confirmed by
    calling Ollama's `/api/chat` directly. That parsing gap blocked the
    `rea`-via-Codex path, so the run routed around it with a tiny driver that reads
    the JSON the model already emits. The gap is itself a P0-relevant finding: the
    "one-sentence crack" skill floor has real friction at the lowest tier.
- **Isolating the answer:** only `crackme_baseline`, `crackme_hardened`, and
  `SEAL.json` were copied into the VM. The **private honey-ledger and carapace-map
  never entered the VM**; scoring ran on the host.

### The result (recap)

| variant  | cracked (hash-verified) | tokens | wall | steps |
|----------|-------------------------|--------|------|-------|
| baseline | **YES** | 1,256 | 1.6 s | 3 |
| hardened | **no** | 16,785 | 195.1 s | 13 |
| delta    | baseline CRACKED, hardened NOT | **13.4×** | **121.9×** | — |

String encryption, anti-debug guards, and analysis-surface exhaustion were all
observed firing. **The honeytoken layer (Slice J) never fired** — the agent was
blocked upstream before it could reach, and be fooled by, a decoy. Full writeup
with the defenses-firing transcript and every caveat:
[`research/findings/2026-11-11-slice-k-empirical-run.md`](../research/findings/2026-11-11-slice-k-empirical-run.md).

### Reproduce it

Follow the [runbook](workflow/slice-k-empirical-runbook.md) for the canonical,
agent-agnostic steps. In short:

```bash
# 1. Build the matched pair on your scoring box (your flag never enters the repo)
export CARAPACE_CRACKME_SECRET='CARA{your-own-flag}'
bash harness/crackme/build_crackme.sh          # → harness/crackme/build/

# 2. Copy ONLY these into your isolated VM (never the honey-ledger):
#    crackme_baseline, crackme_hardened, SEAL.json

# 3. In the VM, point your agent at each binary in a FRESH context with the SAME
#    one-sentence task; record tokens, wall_clock_s, recovered_secret, transcript.

# 4. Score on the host — a crack counts only if it hashes to the seal:
python3 harness/measure/rea_measure.py \
    --seal   harness/crackme/build/SEAL.json \
    --ledger harness/crackme/build/crackme_hardened.honey-ledger.json \
    --baseline run_baseline.json --hardened run_hardened.json
```

Plumbing proof (no agent, no VM): `bash harness/verify/test_slice_k.sh`.

---

## Test it with a bigger model (help wanted)

Our measurement is one data point from a constrained 7B on a laptop. The
interesting question is what a **stronger attacker** costs — and it would be
genuinely valuable if someone ran it. Concretely:

- **Swap in a bigger / better model.** More VRAM (a bigger card, multi-GPU, or a
  cloud GPU) lets you run a 32B–70B coder, or a hosted frontier model. Point the
  agent at it and keep everything else identical.
- **Prefer a reliably tool-calling model so you can use the real `rea` MCP.** A
  model whose agentic tool-calling actually parses (e.g. the Codex-native
  `gpt-oss`) closes the gap that forced our custom loop, and lets the agent reach
  the **decompiler path** and the **string/secret-reporting stage** — which is the
  only way to finally **exercise Slice J (honeytokens)**, the one layer our run
  never triggered.
- **Keep the scoring honest.** Use the same scorer: a crack counts only if the
  recovered string **hashes to `SEAL.json`**; leave unreported tokens/wall as
  `null` (they print *not measured*), never estimate.
- **Report back.** Open a PR adding a dated note under `research/findings/` with
  your `run_*.json`, the scorer output, and a transcript (redact your own flag).
  A hardened build that a bigger model *does* crack is still a useful, honest
  result — say so. That is exactly how this number should get sharper over time.

## Honest limits (both layers)

- Layer 1 proves defenses *fire*, not that they can't be *bypassed* — every one
  ships a named bypass and a tier.
- Layer 2 is **N=1**: one 7B model, one laptop, one VM, one run per variant.
  Agent-reported figures, not estimates. **Slice J went unexercised.** The agent
  was a shell-tool loop, **not** the `rea` MCP. It is a floor, not a ceiling.
