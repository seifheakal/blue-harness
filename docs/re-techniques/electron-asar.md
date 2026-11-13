# Electron (ASAR / V8 bytecode / fuses)

> **Reference only — NOT worked.** Electron is out of current `CLAUDE.md` §2 scope.
> This entry is a catalog reference feeding the scope-expansion proposal
> (`docs/proposals/scope-expansion-web-bundle-track.md`). Full cited research:
> `research/findings/2026-11-14-electron-re-landscape.md` (accessed 2026-11-14).

- Category: static + packaging (web/bundle track candidate)
- What it does: an Electron app ships its UI and most logic as JavaScript inside
  `app.asar` (a plain archive with a JSON header). An attacker extracts it in one
  command and reads the JS directly — no disassembler needed. Bytenode (`.jsc` V8
  bytecode) and minification raise cost only slightly.
- What it needs from the target: the installed app directory (`app.asar`), and —
  for runtime attacks — a debuggable main/renderer process (fuses not hardened).

## Attacker workflow (steps)
1. Extract `app.asar` (`npx @electron/asar extract`, or parse the header directly).
2. Read bundled/minified JS; an LLM treats it as high-level source.
3. If `.jsc` bytecode: apply a public bytenode→JS decompilation path (e.g. a
   Ghidra-based bypass; bytenode's own README says "V8 bytecode is not encryption").
4. If debuggable: attach via `--inspect`/CDP, or abuse `ELECTRON_RUN_AS_NODE`.
5. Tamper: edit JS / `app.asar` in place (if ASAR integrity is off), or the V8 heap
   snapshot (historically not integrity-checked — CVE-2025-55305, since fixed).

AI automation: the most agent-friendly class in the catalog — off-the-shelf skills
(`re-electron`) and MCP tools unpack ASAR and triage JS from one sentence.

## Defensive leverage (step → countermeasure)
| Attacker step | Countermeasure | Strength tier | Known bypass |
|---|---|---|---|
| Edit app in place | ASAR integrity + `embeddedAsarIntegrityValidation` + `onlyLoadAppFromAsar` fuses | Speed-bump | Patch the integrity check in the Electron binary; snapshot coverage gaps |
| Debug/inject at runtime | Fuse hardening (`runAsNode`/`nodeCliInspect`/`nodeOptions` off, per app) | Speed-bump | Flip the static fuse bytes; some apps need `runAsNode` |
| Read `.jsc` | Bytenode compilation | Speed-bump | Public Ghidra-based bytenode bypass; version gate (Electron ≥42) |
| Read JS | Obfuscation / identifier poisoning | Speed-bump (AI-layer unproven) | Deterministic deobfuscators + LLM renaming (see `js-deobf`) |
| Read any client secret | **Server-side relocation** | **Strong** | Attacker replays/patches the client→server call; server must validate |

## Harness hooks
- Audit check(s) this maps to: **none yet** (proposed: read-only fuse-state +
  ASAR-integrity-presence scorer, if a web/bundle track is approved).
- Hardening(s) this maps to: **none** (reference only — pending scope decision).

## Sources
- `research/findings/2026-11-14-electron-re-landscape.md` (Electron Fuses/ASAR docs,
  Trail of Bits 2025-09-03, CVE-2025-55305 mirrors, bytenode README — all accessed
  2026-11-14; PT Swarm bytenode article date unverified, TLS fetch failed).
