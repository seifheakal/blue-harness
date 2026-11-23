<h1 align="center">🛡️ blue-harness</h1>
<p align="center"><em>Make your own app expensive to reverse — measure it, harden it, prove it.</em></p>
<p align="center"><strong>Anyone can now reverse-engineer a shipped app by typing one sentence to an AI agent; blue-harness makes that expensive, measures how expensive, and proves each defense actually fires.</strong></p>

<p align="center">
  A build-time <strong>anti-reverse-engineering hardening &amp; audit harness</strong>
  for <strong>native binaries and mobile apps</strong> you own.
</p>

<p align="center">
  <a href="https://github.com/seifheakal/blue-harness/actions/workflows/verify.yml"><img src="https://github.com/seifheakal/blue-harness/actions/workflows/verify.yml/badge.svg" alt="verify status"></a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue" alt="License: AGPL v3"></a>
  <a href="COMMERCIAL-LICENSE.md"><img src="https://img.shields.io/badge/commercial%20license-available-orange" alt="commercial license available"></a>
</p>

---

<p align="center">
  <img src="docs/assets/demo.gif" alt="blue-harness demo: a plain build audits at 84/100 (wide open); the guarded build is hardened in one command, re-audits at 40/100 (partially hardened), and still runs" width="860">
</p>
<p align="center"><sub>Recorded with <a href="docs/assets/demo.tape">docs/assets/demo.tape</a>. Real output, nothing staged.</sub></p>

## Quickstart

```bash
git clone https://github.com/seifheakal/blue-harness && cd blue-harness
make demo      # audit a sample build, show its hardening plan, then PROVE every defense fires
make verify    # run every check and print one posture summary
```

Point it at your **own** binary:

```bash
make report BIN=path/to/your/binary   # exposure audit + the ordered hardening plan
make harden BIN=path/to/your/binary   # apply every post-build hardening (honest about the rest)
```

No external dependencies: a C toolchain, `make`, and Python 3.

> [!CAUTION]
> ### 🔴 Help wanted — test blue-harness against a stronger attacker
> Our before/after below is **N=10 per model, two local open-weight models (80B and
> 125B)**, on one Mac, at a **60-step budget** — a **floor, not a ceiling**, and
> **not a wall**: each model cracked the hardened build in **1 of 10** runs. Still
> untested: a **frontier/hosted model**, an attacker loop that **prunes its tool
> output** (the named bypass of our exhaustion layer), and N > 10. If you have the
> hardware or the API budget, point one at the same two builds and **send the scored
> result back as a PR** — including the runs that did not go our way. It is now **one command** —
> `make slice-k-run MODEL=<your-model> RUNS=3` builds the sealed pair, drives the agent, and
> prints the honest before/after (and we fixed the tool-call friction that blocked
> commodity local models). No VM? On a Mac with Docker, `make slice-k-docker`
> runs the same thing in network-less containers. Five-minute guide:
> [**docs/HOW-WE-TESTED.md**](docs/HOW-WE-TESTED.md).

## What it is

Reverse engineering used to take real skill. Now anyone can point an AI agent at a
binary, type one sentence, and get back readable code or a working patch — and
commodity cracking of shipped software exploded with it.

blue-harness is a **defensive** toolkit aimed at that threat. It runs against **your own
build** and does three things, audit-first:

- **Audit** — scan a build and score how exposed it is (symbols, strings, entropy,
  hardening flags, which self-defense guards are present).
- **Harden** — apply tested countermeasures to raise the attacker's cost.
- **Prove** — verify each countermeasure actually *fires*, so your protection isn't
  theater.

## The measured result (N=10 per model, 60-step budget — see the red box)

| | qwen3-coder-next 80B (q8_0) | qwen3.5 125B (Q4_K_M, thinking) |
|---|---|---|
| unprotected cracked (hash-verified) | 9/10 (median 9 steps, 8.1 s) | 10/10 (median 5 steps, 6.4 s) |
| **hardened cracked** | **1/10** | **1/10** |
| hardened cost | median 60 steps (cap), median 139 s (≥ 17×)\* | median 60 steps (cap), median 236 s (≥ 37×)\* |
| honeytokens surfaced | 4/10 hardened runs | 6/10 hardened runs |

\* **Lower bounds.** 9/10 and 8/10 hardened runs were cut off at the 60-step cap while
still working; the agent did not give up, we stopped it. Both models attacked the same
sealed build in a network-less Docker sandbox; a crack counts only if the recovered
string hashes to the published digest.

Honestly: this is a **speed-bump against a naive agentic loop, not a wall** — one run
in ten got through for each model, and the 125B's crack surfaced **zero** honeytokens,
so it left no attribution trail. The exhaustion layer's known bypass (an attacker that
prunes or summarises tool output) was not tested. The larger model was faster on the
easy build yet no more successful on the hardened one; at N=10 that cannot be told
from coincidence. Method and every caveat: [docs/HOW-WE-TESTED.md](docs/HOW-WE-TESTED.md) ·
[full write-up](research/findings/2026-11-22-slice-k-two-model-measurement.md) ·
[the earlier N=1 run](research/findings/2026-11-11-slice-k-empirical-run.md).

## What it hardens

Nine countermeasures, each **proven to fire by a test** and each carrying an honest
strength tier and a **named bypass** — nothing here claims to be unbreakable.

| Countermeasure | Blunts | Tier | Named bypass |
|---|---|---|---|
| Anti-debug / anti-ptrace | live debugging & tracing (GDB, Frida attach) | Meaningful | Frida hooks the check; spawn-paused bypass loads first |
| String encryption (decode-on-demand) | reading secrets straight from the bytes | Speed-bump→Meaningful | embedded key → recover at rest; lift from memory |
| Dev→release identity transform (strip / rename / decoy) | names & symbols an agent reasons from | Speed-bump→Meaningful | behavioural cross-check ignores names |
| Anti-Frida detector | Frida injection (maps / threads / port) | Meaningful | stealth mode, renamed gadget, non-default port |
| Code-integrity + server attestation | patching a hot function | Meaningful→**Strong** (server-tied) | sustained live hook; client key is extractable |
| Core-dump suppression | crash-core memory reads | Speed-bump | re-enable cores on their host; read live memory |
| Analysis-surface exhaustion | the "ingest everything" agent's budget | Trivial→Speed-bump | filter to real sections + referenced symbols |
| Honeytokens / canaries | poisons string-mined "findings" + attributes a leak | Speed-bump / Meaningful (detection) | xref-validate drops decoys; rename the tell-tale section |
| Mach-O local-symbol strip | internal names in a macOS/iOS binary | Speed-bump→Meaningful | exported names remain; runtime-identical proven on macOS only |
| Mach-O decoy non-mapped segment (`vmsize=0` LC + trailer) | the "ingest everything" agent on a Mach-O | Trivial→Speed-bump | a loader-faithful tool drops `vmsize==0` LCs + the trailer |
| Mach-O honeytokens / canaries | poisons string-mined "findings" + attributes a leak | Speed-bump / Meaningful (detection) | xref-validate drops decoys; rename the tell-tale marker |

A [Claude skill](skill/) reads the posture and tells you the next highest-value
hardening — with its tier and bypass, every time.

## What's done, what isn't, what's next

**Working today**
- Read-only exposure audit + score for **all three native formats** — Linux ELF,
  Windows PE, macOS/iOS Mach-O — auto-detected by magic byte.
- The **countermeasures above** on Linux ELF (build-time + post-build), a
  Windows **PE** harden path (COFF/debug strip + decoy non-mapped overlay +
  honeytokens), and a **macOS/iOS Mach-O** harden path (local-symbol strip +
  decoy non-mapped segment + honeytokens). All three formats auto-detected, all
  three with a post-build harden path.
- One-command `harden`, the driving Claude skill, and a **CI gate that re-proves
  every defense fires on each push** (399 checks green in CI).
- An empirical harness (digest-sealed CrackMe + honest scorer), a **measured
  before/after (N=10 per model, two local models)**, and a **one-command re-run** (`make slice-k-run`) with a
  robust tool-call shim so a commodity local model can actually drive it.

**Not done yet**
- **Build-time hardening across PE & Mach-O** — both post-build paths ship (PE: COFF/
  debug strip + decoy overlay + honeytokens; Mach-O: local-symbol strip + decoy
  non-mapped segment + honeytokens); relink flags and string-encryption **codegen**
  still need a rebuild, and runtime checks need a Windows / Mac host to verify.
- **Mobile app reach** — Android native libraries via JNI, iOS app internals.
- **More measurement** — the before/after is N=10 per model from two local
  open-weight models at a 60-step budget (the red box at the top).

**Next, in order**
1. More measurement against **bigger / reliably tool-calling attackers** — the
   community ask at the top.
2. **String-encryption codegen for PE / Mach-O** (it ships for ELF today).
3. **Runtime verification on a Windows / Mac host** — lift the post-build harden
   proofs from structural to runtime-identical.
4. **Mobile** (Android / iOS) reach.

*Deliberately out of scope:* a web/bundle track (Electron / JS / Wasm / .NET). It
would only be added later as a separate, clearly-labelled track — never silently,
never at the cost of the "prove it" guarantee.

## How blue-harness compares

blue-harness isn't the only tool defending against AI-assisted RE — a good sign the
threat is real. The difference is **depth on native binaries and proof instead of
assertion**. (Peer descriptions below are from their own READMEs; we ran none of
them.)

| | **blue-harness** | BLA (~2.3k★) | antirea (~36★) | AREA (~3★) |
|---|---|---|---|---|
| **Focus** | native binaries + mobile (ELF / PE / Mach-O) | breadth: JS / Electron / Wasm / .NET bundles | agent instruction-file barriers | obfuscation toolbox |
| **Native-binary defenses** | **proven to fire by tests** | README: Ghidra / Frida / LLDB "not run" | — | "designed-for", no measured results |
| **Evidence of protection** | mechanism tests **+ a measured before/after** | internal estimates + a drift-check | self-limited ("no guarantee") | "deterrence, not proof" |
| **Honesty** | tier + **named bypass on every defense** | status labels; estimate multipliers | states its own limits | "a determined human gets through" |

blue-harness has already absorbed the peers' best native-applicable ideas (surface
exhaustion, honeytoken poisoning) as its own, mechanism-proven countermeasures. See
[the competitive scan](research/findings/2026-11-05-competitive-landscape.md).

## What it isn't

- ❌ **Not** a magic "uncrackable" wrapper. Anti-RE raises cost; a determined,
  skilled attacker on hardware they control still wins. The harness says so.
- ❌ **Not** a secrets vault. If a secret truly can't afford to leak, the first
  honest recommendation is to **move it server-side** — the only *Strong* tier.
- ❌ **Not** an offensive tool. Blue team only — it audits and hardens software the
  operator owns or is authorized to protect. See [docs/threat-model.md](docs/threat-model.md).

## Repo map

- [`harness/audit/`](harness/audit/) — the scored exposure scanners (read-only)
- [`harness/harden/`](harness/harden/) — the countermeasures (+ tiers & bypasses)
- [`harness/verify/`](harness/verify/) — the tests that prove each one fires
- [`skill/`](skill/) — the Claude skill that drives it all
- [`docs/HOW-WE-TESTED.md`](docs/HOW-WE-TESTED.md) — the two testing layers + how to re-run the measurement (bigger models welcome)
- [`docs/`](docs/) — threat model and the RE-technique catalog
- [`CLAUDE.md`](CLAUDE.md) — project constitution, scope & workflow

## Status

**Active.** All three native formats audited with magic-byte dispatch and each with
a post-build harden path; mechanism-proven countermeasures across ELF/PE/Mach-O; a
one-command `harden`; a CI gate with **399/399 checks green**
([`make verify`](.github/workflows/verify.yml) on every push and pull
request — the badge above is that gate); and a digest-sealed CrackMe with an honest
empirical scorer, now driven by a **one-command re-run** (`make slice-k-run`).
Roadmap in [docs/STATE.md](docs/STATE.md).

## License

blue-harness is open source under the [GNU AGPL-3.0](LICENSE) and is free for
everyone, including businesses, as long as you comply with the AGPL. To use it
in a closed-source product or a proprietary service without AGPL's copyleft
obligations, a paid commercial license is available; see
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md). Evaluation and testing are free
for everyone.
