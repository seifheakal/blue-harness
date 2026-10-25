# RE Techniques Catalog — Index

The core knowledge base. One file per technique/tool. Each entry decomposes the
attacker workflow into **steps**, and maps a **countermeasure** to each step —
because we defend by raising the cost of individual steps, not by magic.

## Per-entry template
Every `docs/re-techniques/<slug>.md` uses this structure:

```
# <Tool / Technique name>
- Category: static | dynamic | packaging | mobile | network | ai-assisted
- What it does: 1–3 sentences.
- What it needs from the target: (symbols? unencrypted strings? debuggable? asar?)

## Attacker workflow (steps)
1. ...
2. ...

## Defensive leverage (step → countermeasure)
| Attacker step | Countermeasure | Strength tier | Known bypass |
|---------------|----------------|---------------|--------------|

## Harness hooks
- Audit check(s) this maps to:
- Hardening(s) this maps to:

## Sources
- <cited, dated>
```

## Catalog status — in scope (native binaries + mobile)

| Slug | Tool / Technique | Track | Category | Priority | Status |
|------|------------------|-------|----------|----------|--------|
| `frida` | Frida (+ objection) runtime hooking | A+B | dynamic | ⭐ P1 | todo |
| `ghidra` | Ghidra decompiler | A | static | ⭐ P1 | todo |
| `debuggers` | GDB / LLDB / x64dbg / WinDbg | A | dynamic | P1 | todo |
| `ida` | IDA Pro / Hex-Rays | A | static | P1 | todo |
| `jadx-apktool` | JADX / APKTool (Android dex) | B | mobile | ⭐ P1 | todo |
| `android-root-hook` | Magisk / Zygisk / Xposed / LSPosed | B | mobile | P1 | todo |
| `ios-decrypt` | class-dump / app decrypt / Hopper (iOS) | B | mobile | P1 | todo |
| `memory-scan` | Cheat Engine / GameGuardian / mem edit | A+B | dynamic | P2 | todo |
| `ssl-pinning-bypass` | SSL-pinning bypass (Frida/objection) | B | network | P2 | todo |
| `radare2` | radare2 / rizin / Cutter | A | static | P2 | todo |
| `binja` | Binary Ninja | A | static | P3 | todo |
| `emulation` | QEMU / Unicorn / angr (symbolic) | A | dynamic | P3 | todo |
| `packers` | UPX / PyInstaller unpacking | A | packaging | P3 | todo |
| `ai-assisted-re` | LLM-assisted decompilation / deobfuscation | A+B | ai-assisted | P2 | todo |

**Track A** = native binaries (ELF/PE/Mach-O). **Track B** = mobile (Android/iOS).
**Priority** = relevance to the confirmed target. ⭐ = start here.

## Out of current scope (reference only — do not work unless target changes)
`electron-asar`, `js-deobf`, `wasm-decompile`, `dotnet-decompile`. Kept for
completeness; the operator's target is native + mobile (see `CLAUDE.md` §2).

> Research phase fills these in, highest priority first. Entries are written by
> Scout (research) + Builder (drafting) and signed off by Evaluator.
