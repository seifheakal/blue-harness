# Slice K two-model measurement (N=10 x 2) — testing
- Date: 2026-11-22
- Author role: Lead
- Phase: testing
- Status: signed-off (Evaluator 2026-11-22, with nits applied)

## TL;DR
- Same sealed build, same Docker sandbox, same 60-step budget, two local attacker
  models, N=10 each. Baseline cracked 9/10 (qwen3-coder-next q8_0) and 10/10
  (qwen3.5:122b). **Hardened cracked 1/10 for both.** This is **not a wall**: one
  in ten got through, and the 122b crack left zero honeytoken attribution.
- **Right-censored.** 9/10 (coder) and 8/10 (122b) hardened runs were cut off at
  the 60-step cap while still working. For those runs hardened cost is a **lower
  bound** (>= 60 steps, >= the recorded wall); only the two cracks and one give-up
  are uncensored. Never read "resisted" without "at a 60-step budget."
- Wall-clock cost on the hardened build: median 139.2 s vs 8.1 s (coder, 17.3x) and
  235.9 s vs 6.4 s (122b, 36.7x) — ratios of medians, lower bounds, hardware- and
  model-confounded (caveats 1, 3).
- Slice J honeytokens fired in 4/10 (coder) and 6/10 (122b) hardened runs, so the
  layer that never fired on 2026-11-11 is now exercised.

## Setup
- Driver: `harness/measure/slice_k_run.py` + `attacker_agent.py` (Slice S). Agent is
  a deliberately naive shell-tool loop; it never prunes or summarises tool output.
- Sandbox: Docker, `--network none`, one binary per arena, fresh container per
  variant per run; scoring on the host. Fresh agent context per variant per run.
- Budget: `--max-steps 60`. Ollama on an Apple-Silicon Mac, `num_ctx` 262144.
- Build: **one sealed build for both datasets.** SEAL built 2026-11-21T21:43:33Z,
  digest prefix `a952aac62857f823`, len 22. Honeytoken `build_tag`
  `crackme-20261121T214333Z` appears in both datasets' hits, confirming the same
  binary, ledger, and decoy layout.
- Hardened build: full blue-harness harden path (string encryption, anti-debug,
  analysis-surface exhaustion, honeytokens/decoys).
- Scoring: cracked = `sha256(recovered_secret)` equals the SEAL sha256. Nothing else
  counts.
- Models:
  - **A (primary)** `qwen3-coder-next:q8_0` — 79.7B params, q8_0, non-thinking.
    `~/blue-harness-runs/2026-11-21-steps60/`. Driver predates commit `532336b`, so
    `peak_prompt_tokens` was **not recorded**.
  - **B** `qwen3.5:122b` — 125.1B params, Q4_K_M, thinking-capable (57% more
    parameters than A). `~/blue-harness-runs/2026-11-22-qwen122b-steps60/`.
    `peak_prompt_tokens` recorded.

## Headline tables

### Per-model aggregate
| metric | coder q8_0 (A) | qwen3.5:122b (B) |
|--------|----------------|------------------|
| baseline cracked | 9/10 | 10/10 |
| hardened cracked | **1/10** | **1/10** |
| baseline stop reasons | final_answer 9, no_tool_call 1 (run 3: model flake, not a defense effect; its baseline leg claimed nothing) | final_answer 10 |
| hardened stop reasons | step_cap 9, final_answer 1 (the crack) | step_cap 8, no_tool_call 1 (run 7, stopped at step 31, a give-up/flake), final_answer 1 (the crack) |
| right-censored hardened runs | **9/10** at the 60-step cap | **8/10** at the 60-step cap |
| median baseline steps | 9 | 5 |
| median hardened steps | 60 (cap; lower bound) | 60 (cap; lower bound) |
| median baseline wall | 8.1 s | 6.4 s |
| median hardened wall | 139.2 s (range 77.0-600.5) | 235.9 s (range 171.0-353.5) |
| wall multiplier, ratio of medians | 17.3x | 36.7x |
| wall multiplier, median of per-run ratios | 19.8x (all 10); 15.7x excluding flake run 3 (n=9) | 40.4x |
| median cumulative tokens, baseline | 14.5k | 4.9k |
| median cumulative tokens, hardened | 2.58M | 1.79M |
| median token multiplier (per-run) | 242.8x (all 10); 170.6x excluding flake run 3 (n=9) | 431.6x (**not comparable across models**; caveat 3) |
| hardened runs with >= 1 honeytoken hit | 4/10; per-run [0,3,10,0,0,10,0,10,0,0] | 6/10; per-run [6,2,10,2,0,3,0,2,0,0] |
| baseline honeytoken hits | 0 in all runs (baseline has none to surface) | same |
| hardened peak prompt tokens | **unmeasured** (predates `532336b`) | median 58,814.5; min 41,923; max 90,509 (16-35% of the 262,144 window) |

No 122b run approached the context ceiling, so there is no context-rotation/amnesia
confound in dataset B. Baseline peaks were 1,211-1,531.

### Dataset A — coder q8_0 (B = baseline, H = hardened; wall in s; ht = hardened honeytoken hits)
| run | B cracked | B steps | B stop | B wall | H cracked | H steps | H stop | H wall | ht | H peak ctx |
|-----|-----------|---------|--------|--------|-----------|---------|--------|--------|----|-----------|
| 01 | yes | 12 | final_answer | 9.8 | no | 60 | step_cap | 77.0 | 0 | unmeasured |
| 02 | yes | 6 | final_answer | 4.8 | no | 60 | step_cap | 134.4 | 3 | unmeasured |
| 03 | **NO** | 6 | no_tool_call | 4.3 | no | 60 | step_cap | 292.9 | 10 | unmeasured |
| 04 | yes | 15 | final_answer | 12.7 | no | 60 | step_cap | 123.9 | 0 | unmeasured |
| 05 | yes | 17 | final_answer | 22.6 | no | 60 | step_cap | 110.5 | 0 | unmeasured |
| 06 | yes | 6 | final_answer | 6.3 | **YES** | 55 | final_answer | 600.5 | 10 | unmeasured |
| 07 | yes | 13 | final_answer | 16.4 | no | 60 | step_cap | 149.7 | 0 | unmeasured |
| 08 | yes | 5 | final_answer | 3.8 | no | 60 | step_cap | 144.0 | 10 | unmeasured |
| 09 | yes | 8 | final_answer | 5.0 | no | 60 | step_cap | 120.2 | 0 | unmeasured |
| 10 | yes | 10 | final_answer | 10.0 | no | 60 | step_cap | 157.1 | 0 | unmeasured |

### Dataset B — qwen3.5:122b
| run | B cracked | B steps | B stop | B wall | H cracked | H steps | H stop | H wall | ht | H peak ctx |
|-----|-----------|---------|--------|--------|-----------|---------|--------|--------|----|-----------|
| 01 | yes | 6 | final_answer | 5.9 | no | 60 | step_cap | 300.8 | 6 | 90,509 |
| 02 | yes | 4 | final_answer | 5.8 | no | 60 | step_cap | 246.8 | 2 | 69,696 |
| 03 | yes | 5 | final_answer | 6.6 | no | 60 | step_cap | 294.7 | 10 | 74,736 |
| 04 | yes | 6 | final_answer | 8.6 | no | 60 | step_cap | 186.8 | 2 | 59,640 |
| 05 | yes | 4 | final_answer | 5.4 | no | 60 | step_cap | 261.4 | 0 | 55,788 |
| 06 | yes | 5 | final_answer | 7.6 | no | 60 | step_cap | 353.5 | 3 | 58,158 |
| 07 | yes | 5 | final_answer | 9.8 | no | 31 | no_tool_call | 177.7 | 0 | 58,690 |
| 08 | yes | 4 | final_answer | 5.9 | no | 60 | step_cap | 225.0 | 2 | 58,939 |
| 09 | yes | 4 | final_answer | 6.2 | no | 60 | step_cap | 217.2 | 0 | 52,626 |
| 10 | yes | 5 | final_answer | 7.3 | **YES** | 36 | final_answer | 171.0 | 0 | 41,923 |

### The two hardened cracks
- Coder run 06: 55 steps, 600.5 s, 10 honeytoken hits. It surfaced every decoy
  **and still recovered the real flag** — attribution trail exists, but the crack
  is a crack.
- 122b run 10: 36 steps, 171.0 s, **0 honeytoken hits**, peak 41,923. A clean crack
  with no attribution trail.

## The interesting result (stated carefully)
The 57%-larger thinking model was faster on the easy target (median 5 vs 9 steps;
10/10 vs 9/10, where the one coder miss was a `no_tool_call` flake rather than a
failed attempt), yet cracked the hardened build at the same 1/10. Read plainly: at
this budget the extra capability did not show up as a higher hardened crack rate.
**But** at N=10, 1/10 vs 1/10 cannot distinguish a plateau from coincidence: a
two-proportion test has essentially no power here, and we do not report a p-value.
Treat it as a lead for larger N, not a finding.

## Mandatory caveats
1. **Right-censoring.** 9/10 (A) and 8/10 (B) hardened runs were cut off at the
   60-step cap while still actively working. For those runs hardened cost is a lower
   bound (>= 60 steps, >= the recorded wall), not a measured value, and the medians
   and multipliers built on them are therefore also lower bounds. The three
   uncensored hardened runs are the two cracks (55 and 36 steps) and 122b run 7,
   which gave up (`no_tool_call`) at step 31. "Resisted" is meaningless without the
   budget.
2. **Not a wall.** 1/10 hardened cracks for both models. The failure rate is as
   important as the successes, and the 122b crack left zero honeytoken attribution.
3. **Token multipliers are not comparable across models** (thinking vs non-thinking;
   Q4_K_M vs q8_0). "Tokens" is cumulative prompt+completion re-sent each step, so
   it grows superlinearly with steps and largely measures proximity to the cap.
   Wall-clock is more defensible but still carries the quantization/thinking
   difference and hardware. Prefer steps and cracked-rate as the cross-model axes.
4. **Dataset A has no `peak_prompt_tokens`** (predates `532336b`): unmeasured. We do
   not infer it.
5. **Bypass (see next section).** What was measured is a speed-bump against a naive
   agentic loop at a 60-step budget; unmeasured against a pruning agent.
6. **N=10 per model; one machine, one sandbox, one budget, one sealed build.** This
   fixes variance, not generality. The coder baseline flake (run 3, no_tool_call)
   makes any multiplier derived from that run meaningless; both multiplier
   definitions are shown above, and 15.7x (n=9) is the one that excludes it.
7. **The model comparison is a plateau-or-coincidence question** at N=10 (see above).
8. **Same-build design.** It removes build-to-build variance in honeytoken
   placement, keys, and decoys from the model comparison, but it also means the
   result is for **one honeytoken layout**, not independent builds.

## Bypass and strength tier (CLAUDE.md §8)
- **Mechanism measured:** analysis-surface exhaustion (decoy sections/symbols that
  flood `objdump`/`strings`/hexdump output), plus string encryption, anti-debug,
  honeytokens.
- **Known bypass:** an attacker loop that prunes or summarises tool output, or caps
  `objdump`/hexdump dumps, defeats the exhaustion cost cheaply. The Slice S agent is
  deliberately naive and never prunes, so this run **does not measure** that attacker.
- **Other layers' named bypasses:** string encryption — run the binary / recover the
  decode loader; anti-debug — patch out or `LD_PRELOAD`-shim the ptrace/`TracerPid`
  check, or run under an emulator or tracer the guard does not detect; honeytokens —
  a decoy-aware model, or ledger-free verification by running the binary against a
  candidate.
- **Honest tier, for what was measured:** **Speed-bump** against a naive agentic loop
  at a 60-step budget. Unmeasured against a pruning agent. If the secret matters,
  it belongs on a server, not in the client.

## Measurement-integrity history
This is why the numbers are trustworthy.
- `f23b90f` — step budget and stop reason were not recorded; a cap-truncated run was
  indistinguishable from an agent giving up. Now `max_steps` and `stopped`
  (`final_answer|no_tool_call|step_cap`) are recorded and the report prints the
  censoring.
- `532336b` — an unhandled backend HTTPError destroyed an entire sweep. Now
  `BackendError`, `stopped=context_exhausted|backend_error` with data preserved, and
  `peak_prompt_tokens` recorded. Also clears stale `run-NN/` from an out-dir so two
  builds never mix.
- `65f9973` — `extract_final_answer` mis-scored a markdown answer: a qwen3.5:122b
  **baseline** crack in markdown-bold form captured the trailing `**` and was
  recorded as not cracked. That is a false negative that **flatters the defense**.
  `FLAG="x"` and `` FLAG=`x` `` forms previously matched nothing. Fixed; 7
  regression cases in `harness/verify/test_slice_s.sh`; `make verify` 393 -> 400 (Mac/container count; CI reports 398, see HOW-WE-TESTED.md).
- Mis-scoring audit (Lead, 2026-11-22, after `65f9973`): across all 40 run records
  (20 per dataset), **0** `recovered_secret` values were markdown-mangled (stripping
  emphasis/quotes/backticks never turned a non-crack into a crack); every hardened
  non-cracking run claimed **no flag at all**; per-run `report.json` cracked flags
  agree with the recomputed hash in all 40 cases.
- 2026-11-22 200-step sweep (`~/blue-harness-runs/2026-11-22-steps200-PARTIAL-killed/`;
  **not a dataset**: 2 complete + 1 partial run, killed after ~5 h). Two qualitative
  notes only:
  - Past ~190 steps Ollama silently rotates the context window (slot context shift,
    `n_discard=131069`, `truncated=1`). Run-02 hardened peaked at 262,131/262,144.
    A longer budget therefore yields an **amnesiac** attacker, not a more
    determined one, and 60 -> 200 is not clean budget scaling.
  - Run-01 hardened died at step 177 with an Ollama HTTP 500 (XML syntax error in
    the model's tool-call markup), recorded as `backend_error` with 177 steps
    preserved. See `docs/re-techniques/tool-call-parser-friction.md`.

## Flag hygiene
Baseline transcripts and `run_*.json` contain the plaintext flag. This note and its
companions deliberately reference the flag only by its SEAL digest prefix
`a952aac62857f823` (len 22). Keep the datasets out of the repo.

*SHAs in this section (`b2e2ace`, `f5c7716`, `e7518ed`) refer to the fork's
preserved reference branch `rselph/blue-harness@slice-k-run-isolation` (tag
`archive/slice-k-run-isolation`). The same markdown-scoring fix reached upstream as
`65f9973`.*

**Known breach (found by the Lead 2026-11-22; branch remediated, object still exposed
— see "Remediation applied" below):** the message of the commit originally pushed as
`b2e2ace` quotes the qwen3.5:122b baseline answer verbatim as the worked
example of the markdown bug, and the Lead confirmed by hashing that the quoted string
*is* the plaintext of the build these two datasets were measured against (its SHA-256
equals the SEAL digest above). The branch `slice-k-run-isolation` carrying that
commit has been pushed to `origin`. Consequences, honestly:
- The measurements themselves are unaffected, but not because of timing: dataset A
  completed before the commit existed, while dataset B ran 2026-11-22 01:40-02:21,
  *after* `b2e2ace` was committed (01:34). The integrity claim rests on the sandbox:
  every attacker command ran in a `--network none` container holding exactly one
  binary, with no git checkout, no `SEAL.json`, and no path to the commit message.
- The "sealed" property of this build's `SEAL.json` is void for any *future* or
  *third-party* run: the digest is now trivially reversible from git history, so this
  build must never be reused for a scored run, and its `SEAL.json` should not be
  published as "plaintext not published."

**Remediation applied (operator-authorized, 2026-11-22).** The commit message was
rewritten to describe the markdown bug with an illustrative `**FLAG=CARA{...}**`
instead of the live secret, and the branch was force-pushed. `b2e2ace` became
`f5c7716`; `origin/slice-k-run-isolation` was then `e7518ed`. All three trees are
byte-identical to the pre-rewrite chain and a `git diff --stat` across the rewrite is
empty, so no file content changed — only the message. The flag now appears in no
commit message and no committed content reachable from any branch.

**What the rewrite did NOT fix — verified, not assumed.** A force-push unlinks a
commit from branch history; it does not erase the object. The orphaned commit was
re-fetched from the GitHub API by SHA after the push and **still returns the message
containing the plaintext flag.** Only GitHub Support can force collection of an
unreachable object. Therefore:
- **This flag is burned.** It must never be reused for a sealed or scored build, and
  this build's `SEAL.json` must never be published as "plaintext not published." That
  conclusion is unchanged by the rewrite, which is why the rewrite is hygiene and not
  a fix.
- Residual exposure is nonetheless low: no `SEAL.json` was ever committed on any ref,
  and `sha256(flag)` appears nowhere in the tree, so nothing published corresponds to
  this secret. It unlocks only a retired local build.
- The safety branch `backup-pre-msg-rewrite` (local only, never pushed) was deleted
  2026-11-22 after confirming its trees are identical to the rewritten chain.

## Decisions needed from operator
- ~~**Flag-hygiene breach in commit `b2e2ace`.**~~ **Resolved 2026-11-22:** message
  rewritten and force-pushed (see "Remediation applied"). Two follow-ons remain: the
  orphaned object still exposes the flag via the GitHub API; the operator judged the
  secret low-risk (it unlocks only a retired local build) and chose **not** to file a
  GitHub Support purge. This sealed build is retired either way.
- Whether to spend compute on a budget-unconstrained, non-amnesiac run (needs an
  attacker that manages its own context; 60 -> 200 steps on this agent is confounded).
- Whether to fund a pruning-attacker variant (the named bypass) before any
  public claim above "Speed-bump."
- Whether to raise N above 10 per model to test plateau vs coincidence.

## Open questions
- Does the 1/10 plateau hold at N >= 30, or was it coincidence? Unanswered here.
- How much of the hardened cost survives an attacker that prunes tool output?
- Dataset A peak context is unmeasured; was the coder near the ceiling? Unknown.
- Does a different honeytoken layout (independent builds) change the 4/10 vs 6/10
  hit rates, and why did the one 122b crack avoid every decoy?
- Would a frontier/hosted model behave like either local model? Untested.

## Sources
- `~/blue-harness-runs/2026-11-21-steps60/` — dataset A, qwen3-coder-next:q8_0 — 2026-11-21 (not in repo; contains the flag)
- `~/blue-harness-runs/2026-11-22-qwen122b-steps60/` — dataset B, qwen3.5:122b — 2026-11-22 (not in repo; contains the flag)
- `~/blue-harness-runs/2026-11-22-steps200-PARTIAL-killed/` — qualitative only — 2026-11-22
- Commits: `f23b90f`, `532336b`, `65f9973`
- `research/findings/2026-11-11-slice-k-empirical-run.md` — the N=1 predecessor
- `research/findings/2026-11-13-local-model-tool-calling.md` — Slice S shim background

## Review log
- Lead 2026-11-22: figures recomputed from run JSONs (cracked = sha256 vs SEAL); draft written by Builder from the Lead's verified data. Awaiting Evaluator.
- Evaluator 2026-11-22: BLOCKED — every table figure checks out against the run JSONs (hash-only crack check: 9/1 and 10/1; per-run report.json agrees in 40/40; build_tag matches in both datasets; no stray 22-char flag in the tree; b2e2ace message confirmed to contain the SEAL plaintext). The block is for one false integrity claim and one §8 gap. Both are small fixes.
  - L193-194: "completed before the commit existed" is false for dataset B. b2e2ace was committed 2026-11-22 01:34:38 -0700, and dataset B's report.json files are dated 01:45-02:21 the same morning. Rest the claim on `--network none` plus the one-binary arena (the agent could not see git history), and say dataset B ran after the commit.
  - L144-146: anti-debug is listed as a measured mechanism but has no named bypass. Add one (e.g. patch out or LD_PRELOAD the ptrace/TracerPid check, or run under an emulator or tracer the guard doesn't detect).
  - L105-108 (and HOW-WE-TESTED.md "clearly stronger on the baseline"): "clearly stronger" and "a genuine signal" contradict the next sentence ("cannot distinguish a plateau from coincidence"). 10/10 vs 9/10 rests on one flake. Say "faster on the baseline (median 5 vs 9 steps)" and drop "genuine signal".
  - Nit L64: the median peak is 58,814.5. Write 58,815 or 58,814.5.
  - Nit L61: caveat 6 says both multiplier definitions are shown, but the coder token multiplier gives only 242.8x (all 10). Add 170.6x for the 9 runs without the flake.
  - Nit L14/L115: "lower bound" holds only for the censored runs. Note that the two cracks (55 and 36 steps) and 122b run 7 (no_tool_call at step 31) are uncensored.
  - Nit (outside these files): README.md L45-52 and L76-82 still give the N=1 / "honeytoken layer never fired" headline as current. Fix this before upstream. docs/STATE.md "Last updated: 2026-11-15" is stale.
  - Nit tool-call-parser-friction.md L30: "will likely vanish with an Ollama update" is an uncited prediction. Soften it or drop it.
- Evaluator 2026-11-22 (re-review): SIGNED-OFF WITH NITS — all three blocking items and every nit are fixed. 170.6x confirmed (median of summary.json per-run token_multiplier with run 3 excluded, n=9). The no-git/no-SEAL claim about the arena matches `_stage_arena` in slice_k_run.py. The README figures match this note. The tree rescan found no 22-char flag literal.
  - README.md "The measured result" table, row "hardened cost": "≥ 60 steps" reads as per-run, but the cracks took 55 and 36 steps and 122b run 7 stopped at 31. Make it "median 60 steps (cap)".
  - Precondition for upstream, not a doc fix: the `b2e2ace` flag leak is still unremediated on origin. The operator decision (rewrite the message, or retire and re-seal the build) must be made before publishing.
