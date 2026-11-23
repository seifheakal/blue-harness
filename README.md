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
> ### 🔴 Help wanted — test blue-harness against a bigger model
> Our before/after below is **one run (N=1)** by a small, 4-bit-quantised **7B**
> model on a laptop (RTX 3070, 8 GB VRAM / 16 GB RAM) — a **floor, not a ceiling**.
> If you have the hardware, point a **larger local or a frontier model** at the same
> two builds and **send the scored result back as a PR**. A stronger attacker is the
> only way to test the layers our small run never reached. It is now **one command** —
> `make slice-k-run MODEL=<your-model> RUNS=3` builds the sealed pair, drives the agent, and
> prints the honest before/after (and we fixed the tool-call friction that blocked
> commodity local models). Five-minute guide:
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

## The measured result (one run — see the red box)

| build | cracked (hash-verified) | tokens | wall | steps |
|-------|-------------------------|--------|------|-------|
| unprotected | **YES** | 1,256 | 1.6 s | 3 |
| hardened | **no** | 16,785 | 195 s | 13 |

The same agent cracked the unprotected build in under two seconds; against the
hardened build it burned **13× the tokens and ~120× the wall-clock and still
failed**. String encryption, anti-debug, and analysis-surface exhaustion were all
seen firing. Honestly: the **honeytoken layer never fired** — the agent was stopped
earlier, so that layer went untested (exactly what a bigger model would exercise).
Method and caveats: [docs/HOW-WE-TESTED.md](docs/HOW-WE-TESTED.md) ·
[full write-up](research/findings/2026-11-11-slice-k-empirical-run.md).

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
  every defense fires on each push** (379 checks green).
- An empirical harness (digest-sealed CrackMe + honest scorer), **one measured
  before/after run**, and a **one-command re-run** (`make slice-k-run`) with a
  robust tool-call shim so a commodity local model can actually drive it.

**Not done yet**
- **Build-time hardening across PE & Mach-O** — both post-build paths ship (PE: COFF/
  debug strip + decoy overlay + honeytokens; Mach-O: local-symbol strip + decoy
  non-mapped segment + honeytokens); relink flags and string-encryption **codegen**
  still need a rebuild, and runtime checks need a Windows / Mac host to verify.
- **Mobile app reach** — Android native libraries via JNI, iOS app internals.
- **More measurement** — the before/after is a single run from a small local model
  (the red box at the top).

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
one-command `harden`; a CI gate with **379/379 checks green**
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
