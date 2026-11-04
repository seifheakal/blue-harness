<h1 align="center">🛡️ Carapace</h1>
<p align="center"><em>Make your own app expensive to reverse — measure it, harden it, prove it.</em></p>

<p align="center">
  A build-time <strong>anti-reverse-engineering hardening &amp; audit harness</strong>
  for <strong>native binaries and mobile apps</strong> you own.
</p>

---

## Quickstart (see it in ~30 seconds)

```bash
git clone https://github.com/seifheakal/blue_team && cd blue_team
make demo      # audit a sample build, show its hardening plan, then PROVE every defense fires
make verify    # run every verify slice and print one posture summary
```

Point it at your **own** binary:

```bash
make report BIN=path/to/your/elf     # full exposure audit + the ordered hardening plan
```

No external dependencies: a C toolchain, `make`, and Python 3 (the audit is a
self-contained ELF parser; the integrity guard ships its own SHA-256/HMAC).

## What this is

Reverse engineering used to take real skill — Ghidra, IDA, Frida, years of
practice. Not anymore. Today anyone can install an AI skill or MCP server, point
an LLM agent at a binary or an app, type **one sentence**, and get back readable
code, a patch, or a working hook. The skill floor collapsed, and commodity
cracking of shipped software — games, creative suites, office apps — exploded
with it.

**Carapace** is a *defensive* toolkit aimed squarely at that new threat. It runs
against **your own build** and does three things, audit-first:

- **Audit** — scan a build and score how exposed it is (symbols/strings an agent
  reads for free, entropy, hardening flags, which self-defense guards are present).
- **Harden** — apply tested countermeasures and raise the attacker's cost.
- **Prove** — verify each countermeasure actually *fires*, so your "protection"
  isn't theater.

## What's built so far

Six implementation slices, each **audit → harden → verify**, every check green
(`make verify` → 75/75). Every countermeasure is rated on an honest tier and
ships with a **named bypass** — nothing here claims to be unbreakable.

| Countermeasure | Denies (the `rea` AI-RE agent) | Tier | Named bypass |
|---|---|---|---|
| **Core-dump suppression** | Cluster E — crash-core memory reads | Speed-bump | Attacker re-enables cores on their host; reads live memory via Frida/GDB |
| **Anti-ptrace / anti-debug** | Cluster G/H — Frida attach + GDB | Meaningful | Frida hooks the check; spawn-paused loads a bypass first |
| **Dev↔release identity transform** (strip / map / **decoy**) | Cluster B/C + the AI layer — names/strings the agent reasons from | Speed-bump→Meaningful | Behavioral cross-check (xrefs/value-flow) ignores names |
| **String encryption** (decode-on-demand loader) | Cluster B/C — `list_strings` on live strings | Speed-bump→Meaningful | Embedded key → recover at rest; lift decoded string from memory |
| **Anti-Frida detector** (maps / thread / port) | Cluster G — Frida inject | Meaningful | Stealth modes, renamed gadget, non-default port |
| **Code-integrity + server-nonce attestation** | Cluster G — patch a hot function | Meaningful→**Strong** (server-tied) | Sustained live hook; client key is extractable (trust rests on the server nonce) |

Driven by a scored [audit scanner](harness/audit/) and a [Claude skill](skill/)
(`carapace audit | recommend | apply | report`) that reads the posture and tells
you the next highest-value hardening — with its tier and bypass, every time.
Details and the attacker-weapon mapping: [`docs/re-techniques/rea.md`](docs/re-techniques/rea.md).

## What it is / what it isn't

- ✅ A way to **measure** your build's RE exposure and **prove** your hardening
  actually fires, with honest strength tiers.
- ✅ Focused on the **AI-assisted, one-command** RE threat (P0), not just the
  classic tools those agents drive.
- ❌ **Not** a magic "uncrackable" wrapper. Anti-RE raises cost; a determined,
  skilled attacker on hardware they control still wins. The harness says so.
- ❌ **Not** a secrets vault. If a secret truly can't afford to leak, Carapace's
  first recommendation is the honest one: **move it server-side** — the only
  *Strong* tier.
- ❌ **Not** an offensive tool. Blue team only — it audits/hardens software the
  operator owns or is authorized to protect. See [`docs/threat-model.md`](docs/threat-model.md).

## Scope

| Track | Targets | Top threats we defend against |
|-------|---------|-------------------------------|
| **A — Native binaries** | ELF / PE / Mach-O (C / C++ / Rust / Go) | Frida, Ghidra/IDA, GDB/LLDB/x64dbg, Cheat Engine |
| **B — Mobile** | Android (APK/AAB, Dalvik + JNI `.so`), iOS (Mach-O) | Frida/objection, JADX/APKTool, Magisk/Xposed, SSL-pinning bypass, iOS decrypt |

**Priority 0 across both tracks:** the AI-assisted tooling that drives those
engines from a single prompt — disassembler MCP servers, autonomous RE agents,
LLM decompilers, AI Frida-hook generators. That's the headline threat; the
classic tools are the substrate it rides on. The implemented slices currently
target **native ELF on Linux**; the catalog and design cover the rest. See
[`docs/re-techniques/_index.md`](docs/re-techniques/_index.md). Electron / web /
JS / WebAssembly / pure-.NET are out of current scope.

## Why it's honest

Anti-RE raises cost; it never makes software unbreakable. Every countermeasure
ships with a **strength tier** (*Trivial → Speed-bump → Meaningful → Strong*) and
a **known bypass**. The harness refuses to overclaim — `make verify` proves the
defenses *fire*, not that they can't be defeated.

## How it's built

Research-first pipeline — **Research → Deep Analysis → Implementation →
Testing** — with a multi-agent workflow documented in [`CLAUDE.md`](CLAUDE.md).
We study how real RE tools work, decompose each into steps, and map a defense to
each step.

## Repo map

- [`harness/audit/`](harness/audit/) — the scored ELF exposure scanner (read-only)
- [`harness/harden/`](harness/harden/) — the countermeasures (+ tiers & bypasses)
- [`harness/verify/`](harness/verify/) — the tests that prove each one fires (`run_all.sh`)
- [`skill/`](skill/) — the Claude skill that drives it all
- [`docs/`](docs/) — threat model, the RE catalog, and the worked countermeasure analysis
- [`CLAUDE.md`](CLAUDE.md) — project constitution, scope & workflow

## Status

**Active — six verified slices (audit + six countermeasures + the driving
skill), 75/75 checks green.** Roadmap in [`docs/STATE.md`](docs/STATE.md).

## License

TBD.
