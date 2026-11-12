# Slice K — empirical RE-resistance measurement (runbook)

> **Operator-gated.** The harness, CrackMe, and scorer are built and tested in the
> repo; the one thing that cannot happen in the dev/CI container is *running an
> actual AI-RE agent* against the binaries. That step needs a throwaway,
> **operator-owned, sandboxed VM**. **Do not install or run offensive tooling in
> the dev container or CI** (CLAUDE.md §3).

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
export CARAPACE_CRACKME_SECRET='CARA{your-own-flag}'     # or:
# echo 'CARA{your-own-flag}' > harness/crackme/secret.local.txt   # (gitignored)

bash harness/crackme/build_crackme.sh
```
Produces, in `harness/crackme/build/` (gitignored):
- `crackme_baseline` — flag plaintext, no guards (easy target)
- `crackme_hardened` — flag string-encrypted + build-time guards + post-build
  `carapace harden` (decoy / exhaust / honeytokens)
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
