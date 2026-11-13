# Managed .NET / CIL (IL) decompilation

> **Reference only — NOT worked.** Managed .NET / IL is out of current `CLAUDE.md`
> §2 scope. This entry feeds the scope-expansion proposal
> (`docs/proposals/scope-expansion-web-bundle-track.md`). Full cited research:
> `research/findings/2026-11-14-dotnet-il-re-landscape.md` (accessed 2026-11-14).

- Category: static + dynamic (web/bundle track candidate)
- What it does: recovers near-original C# from a managed assembly. ECMA-335 IL is
  self-describing — full type/method/field names, generics and control flow — so a
  decompiler returns readable source and an LLM barely has to reverse anything. The
  **most exposed** format in the catalog.
- What it needs from the target: the assembly (a PE with the CLI header + metadata).
  Nothing else; metadata is self-describing even without PDB symbols.

## Attacker workflow (steps)
1. Triage the CLI header / assembly metadata / P/Invokes (trivial, no symbols needed).
2. Decompile to C# (ILSpy, dnSpyEx, dotPeek) — high-quality output.
3. Deobfuscate known protectors (`de4dot` family — **archived 2020**, currency
   unknown) or repair manually.
4. Capture runtime-decrypted payloads: dump plain IL from memory once the runtime
   materialises it (dnSpy "Open Module from Memory"; DotDumper).
5. Live-patch via dnSpy edit-and-continue (e.g. flip a boolean license check); re-save.

AI automation: the purest P0 case. Off-the-shelf MCP servers wrap these engines for
an LLM — ZeraTS **dnSpy-MCP** even emits a 0–10 "protection risk score + bypass
recommendations"; several ILSpy-MCP wrappers exist. Client-side managed-IL secrecy
is close to hopeless.

## Defensive leverage (step → countermeasure)
| Attacker step | Countermeasure | Strength tier | Known bypass |
|---|---|---|---|
| Decompile | Renaming / strip PDB | Trivial | Decompiler + LLM infer roles; `de4dot` covers known protectors |
| Read literals | String encryption / proxy indirection | Speed-bump | `de4dot` strategies; IL-parsing key recovery (cyber.wtf) |
| Follow logic | Control-flow obfuscation (ConfuserEx-class) | Speed-bump (unmeasured vs LLM) | Deobfuscators; LLM reading costs tokens, not a block |
| Unpack | Encrypted payload / anti-tamper / anti-debug | Speed-bump | Dump plain module from memory after load; patch the one check |
| Decompile at all | **NativeAOT** (ship native PE/ELF/Mach-O, not IL) | **Meaningful** (vs IL; not Strong) → **handled by the native track** | Native disasm; runtime memory dump; library-signature match (>85% in one sample) |
| Read any secret | **Server-side relocation** | **Strong** (only real one) | Attacker replays/patches the client→server call |

## Harness hooks
- Audit check(s) this maps to: **none yet** (proposed: managed-IL metadata/PDB
  exposure scorer; and — *in current scope* — recognise NativeAOT/IL2CPP native
  output and route it to the existing ELF/PE/Mach-O native audit).
- Hardening(s) this maps to: **none** for managed IL (reference only). The native
  route (NativeAOT → native track) needs **no scope change**.
- Scope notes: .NET MAUI / Xamarin-on-Android is managed IL inside an APK — a
  **mobile-track (Track B)** question, not a web/bundle one.

## Sources
- `research/findings/2026-11-14-dotnet-il-re-landscape.md` (ILSpy/dnSpyEx/de4dot repos,
  dnSpy-MCP + ILSpy-MCP wrappers, cyber.wtf 2025, Microsoft Native AOT docs, Cyderes
  2026-03-17, Univ. Twente project, Il2CppDumper — all accessed 2026-11-14; no .NET-IL
  LLM-deobfuscation benchmark exists; several protector dates vendor/secondary-sourced).
