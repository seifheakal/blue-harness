<h1 align="center">🛡️ Carapace</h1>
<p align="center"><em>Make your own app expensive to reverse — measure it, harden it, prove it.</em></p>

<p align="center">
  A build-time <strong>anti-reverse-engineering hardening &amp; audit harness</strong>
  for <strong>native binaries and mobile apps</strong> you own.
</p>

---

## What this is

Shipped applications get reverse-engineered every day: decompiled in Ghidra/IDA,
hooked live with Frida, unpacked, memory-scanned, repacked. **Carapace** is a
*defensive* toolkit that helps you fight back on **your own builds**:

- **Audit** — scan a build and get a scored report of how exposed it is to the
  common RE workflows (decompilation, dynamic instrumentation, memory
  inspection, repackaging).
- **Harden** — apply selected, tested countermeasures and raise the attacker's
  cost.
- **Prove** — verify each countermeasure actually fires, so your "protection"
  isn't theater.

It is **blue team only**: it protects software the operator owns or is
authorized to harden. It does not attack third-party software. See
[`docs/threat-model.md`](docs/threat-model.md).

## Scope

Two tracks:

| Track | Targets | Top threats we defend against |
|-------|---------|-------------------------------|
| **A — Native binaries** | ELF / PE / Mach-O (C / C++ / Rust / Go) | Frida, Ghidra/IDA, GDB/LLDB/x64dbg, Cheat Engine |
| **B — Mobile** | Android (APK/AAB, Dalvik + JNI `.so`), iOS (Mach-O) | Frida/objection, JADX/APKTool, Magisk/Xposed, SSL-pinning bypass, iOS decrypt |

Electron / web / JS / WebAssembly / pure-.NET are out of current scope.

## Why it's honest

Anti-RE raises cost; it never makes software unbreakable. Every countermeasure
ships with a **strength tier** (*Trivial → Speed-bump → Meaningful → Strong*) and
a **known bypass**. The harness refuses to overclaim. When a secret truly can't
afford to leak, Carapace's first recommendation is the honest one: *move it
server-side.*

## How it's built

Research-first pipeline — **Research → Deep Analysis → Implementation →
Testing** — with a multi-agent workflow documented in [`CLAUDE.md`](CLAUDE.md).
We study how real RE tools work, decompose each into steps, and map a defense to
each step.

## Status

🚧 Early research + scaffolding. Start here:
- [`CLAUDE.md`](CLAUDE.md) — project constitution, scope & workflow
- [`docs/re-techniques/_index.md`](docs/re-techniques/_index.md) — the RE catalog we defend against
- [`docs/threat-model.md`](docs/threat-model.md) — scope, assumptions, ethics

## License

TBD.
