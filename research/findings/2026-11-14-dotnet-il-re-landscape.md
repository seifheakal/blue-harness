# .NET / CIL (managed IL) reverse-engineering landscape — research
- Date: 2026-11-14
- Author role: Scout
- Phase: research
- Status: draft (needs Evaluator)
- Purpose: evidence base for a SCOPE-EXPANSION PROPOSAL. Managed .NET is currently out of scope per CLAUDE.md §2 ("pure-.NET app shells" = low priority). No code or CLAUDE.md edits made.
- Access date for all external facts: 2026-11-14 (unless a different date is shown next to the source).

## TL;DR
- **Managed IL is the most exposed format we have studied.** ECMA-335 IL carries full type, method, field and (unless stripped) parameter/local names plus control flow. Decompilers (ILSpy, dnSpy/dnSpyEx, JetBrains dotPeek) return near-source C#. An LLM barely has to do reversing work; it reads decompiler output.
- **AI tooling for this already exists as open-source MCP servers** (ILSpy-based and dnSpy-engine-based, listed below). A non-expert can point one at a DLL today. This is the P0 scenario in its purest form.
- **Obfuscation is a speed bump, not a secret.** The standard automated answer, de4dot, is unmaintained since 2020, but still the reference deobfuscator for ~19 named protectors. Its coverage of *current* protector versions is unknown and must be treated as stale.
- **NativeAOT is the key finding.** Native AOT compiles IL to a native PE/ELF/Mach-O and strips most CIL and metadata. It folds .NET into Carapace's **existing native track** (ELF/PE/Mach-O) instead of needing a new one. It is a real cost increase against the IL-decompiler path, but it is not a secrecy mechanism: Mar 2026 research describes runtime-memory dumping and library-signature matching as the workflow, and a 2026 academic project (Univ. of Twente) is explicitly working to make NativeAOT RE tractable.
- **Honest verdict:** managed-IL client-side protection is best rated Trivial–Speed-bump. NativeAOT is best rated Meaningful relative to IL, not Strong. Neither is a substitute for keeping secrets server-side.

---

## Detail

### 1. Attacker workflow needs and what the target gives away (workflow level)

Needs from the target: the assembly itself (PE with CLI header and metadata). Nothing else. Stages, at design-level granularity:

1. **Triage.** Read the PE/CLI header, assembly name, target framework, embedded resources, P/Invoke declarations, attributes. Metadata is self-describing, so this is trivial without any symbols.
2. **Decompile.** Whole-assembly or per-type C# output plus IL disassembly. Output quality is high because IL preserves structure, types, and generics.
3. **Deobfuscate (if protected).** Automated de-protection for known protectors (de4dot family); manual or scripted repair for the rest. Typical targets: renaming, string encryption, proxy/delegate call indirection, control-flow obfuscation, packing (runtime `Assembly.Load` of an encrypted payload).
4. **Runtime capture.** For runtime-decrypted payloads (packers, encrypted method bodies), the attacker waits until the runtime has materialised plain IL in memory and dumps it. dnSpy/dnSpyEx can "Open Module from Memory"; memory-dump tooling (e.g. DotDumper, cited below) does the same at scale.
5. **Live instrumentation / patching.** dnSpy/dnSpyEx debugs managed code and supports edit-and-continue IL patching; the patched assembly is re-saved. Patching a boolean license check is the classic cost-of-entry case.
6. **Programmatic rewriting.** dnlib and AsmResolver (MIT, see §3) let a script rewrite IL at scale, which is also how a defender's build step works.

Structural point for the design: **renaming and string hiding remove names, not logic.** The decompiler still recovers control flow, call graphs and types. This is why the field's own writing says "obfuscation raises cost; it does not hide logic."

### 2. Tool landscape (status as of 2026-11-14)

| Tool | Role | Status (dated) | Source |
|---|---|---|---|
| ILSpy (icsharpcode) | Open-source decompiler, the engine for many AI wrappers | Latest release **v11.2, dated "27 Oct"** (year not shown on the page; releases 11.0 = 12 Aug, 11.1 = 23 Sep). Notes say "based on .NET 10". Actively maintained. | https://github.com/icsharpcode/ILSpy/releases (accessed 2026-11-14) |
| dnSpy / dnSpyEx | Debugger, decompiler, IL editor, live patching | dnSpyEx **v6.5.0** verified as latest stable (moved to .NET 8 and .NET Framework 4.8). A **v6.6.0-rc1** exists; its status as stable is **unconfirmed**. | https://github.com/dnSpyEx/dnSpy/releases ; https://newreleases.io/project/github/dnSpyEx/dnSpy/release/v6.6.0-rc1 (accessed 2026-11-14; release dates not shown) |
| de4dot (0xd4d) | Automated deobfuscator / unpacker for named protectors | **Archived by owner on 17 Oct 2020**, read-only. GPLv3. Lists 19 supported protectors (Agile.NET, Babel.NET, CodeFort, CodeVeil, CodeWall, CryptoObfuscator, DeepSea, Dotfuscator, .NET Reactor, Eazfuscator.NET, Goliath.NET, ILProtector, MaxtoCode, MPRESS, Rummage, Skater.NET, SmartAssembly, Spices.Net, Xenocode) **with no version numbers**. Author states no support for obfuscator updates released after the tool. | https://github.com/0xd4d/de4dot (accessed 2026-11-14) |
| de4dot-cex (ViRb3) | de4dot fork aimed at ConfuserEx | **Archived 8 Dec 2022** per a secondary aggregator; last push ~Mar 2020. Secondary-source date, verify before relying on it. | https://awesome.ecosyste.ms/projects/github.com%2FViRb3%2Fde4dot-cex (accessed 2026-11-14) |
| cyber.wtf .NET deobfuscation write-up | Technical explanation of why de4dot works and where it fails; notes de4dotEx as consolidated fork | Dated **7 Apr 2025** with a 2026 update note on the string-encryption fix. | https://cyber.wtf/2025/04/07/dotnet-deobfuscation/ (accessed 2026-11-14) |
| DotDumper | Runtime capture of managed assemblies (memory dump of loaded modules) | Referenced by cyber.wtf (2025). Status not verified. | same as above |
| dnSpy-MCP (ZeraTS, GitHub) | **MCP server exposing ILSpy/dnSpyEx engine to an LLM**: metadata, C# decompile, IL, string search, virtual breakpoints, and a **protection-analysis report with a 0–10 risk score and bypass recommendations** | No update date shown on the page (14 commits). Stated: "Never executes target assemblies." | https://github.com/ZeraTS/dnSpy-MCP (accessed 2026-11-14) |
| ILSpy MCP wrappers | Several: phantomical/ILSpyMCP (.NET 10 SDK), Kommisaar/dotnet-decompiler-mcp (ILSpy v9.0.0.7889), ilspy-mcp-server (PyPI, decompile_assembly tool), mcilspy (MIT), mcp-dotnet (ilspycmd wrapper) | Listing dates vary; maintenance **not verified** for any. | https://lobehub.com/mcp/phantomical-ilspymcp ; https://pypi.org/project/ilspy-mcp-server/ ; https://glama.ai/mcp/servers/w8tjhzfwr7 (accessed 2026-11-14) |
| AsmResolver | Programmatic PE/.NET read-write library (defender build steps and attacker rewriting use the same kind of library) | Version listings **disagree**: one feed shows 6.1.0 dated 6 Nov 2026, another shows 6.0.1 dated 25 Jul 2026. Verify the NuGet page directly. MIT. | https://www.nuget.org/packages/AsmResolver (accessed 2026-11-14) |
| ConfuserEx (mkaring/yck1509) | Open-source obfuscator (renaming, CFF, anti-tamper, anti-debug) | Mirror says "discontinued and unmaintained"; GitHub page is not archived but has no release. Lists .NET Framework 2.0–4.8 only. **Not usable for modern .NET** (Softanics vendor claim). Forks (ConfuserEx 2, neo-ConfuserEx, reborn) list support only to .NET Framework/Core 2.2 or 4.7.2. | https://github.com/mkaring/ConfuserEx (accessed 2026-11-14); https://www.softanics.com/net-obfuscation/tools/free-vs-paid (vendor) |
| ConfuserEx 2 analysis write-up | threat.zone technical walkthrough | **Could not fetch** (DNS failure on 2026-11-14). Search snippet says it recommends de4dot-cex for renaming and a separate unpacker for proxy-reference and control-flow cleanup. Treat as unverified. | https://blog.threat.zone/deobfuscation-technical-analysis-of-confuserex-2 (search snippet only) |

Commercial protectors (current versions, from vendor changelogs):
- **Dotfuscator** (PreEmptive): 7.5.0 (22 Dec 2025, .NET 10 support); 7.6.0 (30 Mar 2026); **7.7.0 (26 May 2026**, enhanced string encryption preview); 7.8.0 (undated blog; adds Blazor/Avalonia). Actively released. Also "Dotfuscator Community for VSC 1.0.0 (8 Jun 2026)". Source: https://support.preemptive.com/hc/en-us/articles/31784634997137 ; https://www.preemptive.com/blog/dotfuscator-7-8-0/ (accessed 2026-11-14).
- **.NET Reactor** (Eziriz): **7.5.0.0, 12 Nov 2025**, added .NET 10 protection and a VS 2026 add-in. Source: https://www.eziriz.com/history.htm (accessed 2026-11-14).
- **Babel Obfuscator**: most recent release notes found are **10.6.0.0 (27 Mar 2024)**; no .NET 10 evidence found. Stale-looking.
- **Eazfuscator.NET**: only 2025 prerelease NuGet packages found; no 2026 changelog found.
- **Softanics / ArmDot**: vendor comparison pages, copyright 2004–2026; vendor-biased. Used only for the claims flagged below.

### 3. How well LLM / agentic tooling automates managed-IL RE

- **The LLM barely has to work.** For unprotected or lightly protected IL, the decompiler does the reversing. The LLM's job collapses to: call decompile, read C#, summarise or patch. Examples above (ILSpy MCP wrappers, dnSpy-MCP) show this is off-the-shelf.
- **Protection-analysis is already automated.** dnSpy-MCP's own protection report flags anti-debug, obfuscation and anti-tamper patterns and suggests bypass steps. Expect commodity tools to triage protections for the attacker in seconds. Any countermeasure whose presence is a fixed, recognisable pattern (e.g. a known anti-debug P/Invoke set) is therefore a **trivial triage target**. Note the same MCP's own README says its anti-debug scanner only detects methods decorated with DllImport, a known gap.
- **Research gap (important).** I searched for LLM-based .NET/C# deobfuscation evaluations in 2025–2026. Results covered **native** binaries and **C** programs: arXiv 2505.19887 (LLM assembly deobfuscation, Mar 2025), arXiv 2604.08083 (BinDeObfBench, 2026, decompiled pseudocode), arXiv 2511.19130 (LLMs and KLEE artifacts, C programs), DSTA "ALFREDO" report (agentic LLM + Ghidra on Tigress-obfuscated C, 77.9% success). **No peer-reviewed or public benchmark specifically for .NET IL or C# decompiler output was found.** So any claim about how much obfuscation slows an LLM agent on .NET is currently a guess and must be measured (see Open questions).
- **Honest expectation:** with an unrestricted local model, an unprotected or renamed-only assembly is near-source in one step. Heavy obfuscation mainly makes output *uglier* and more expensive in tokens and turns; it does not stop the decompiler from producing a working understanding.
- **Client-side secrecy in managed .NET is close to hopeless** without moving the secret out of the process. The IL is the program, and the program must be readable by the runtime. Consistent with Carapace's "one law" (threat-model.md).

### 4. Countermeasure candidates and tiers

Tiers per `docs/threat-model.md`. Tier values are **this scout's judgment**, based on the cited sources; none are measured by Carapace yet. Each has a named bypass.

| # | Countermeasure | Layer | Tier | Named bypass / weakness | Evidence |
|---|---|---|---|---|---|
| C0 | Ship plain IL, default metadata | baseline | **Trivial** | ILSpy / dnSpy near-source output | ILSpy releases page; dnSpy releases |
| C1 | Strip PDB and debug info from the shipped set (do not ship .pdb) | substrate | **Trivial** | Not a protection: removes names/line info only, decompiler still works. Note Native AOT **emits .pdb by default on Windows** and .dbg on Linux; those must not ship. | Microsoft Learn Native AOT overview (updated 2026-11-03), https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/ |
| C2 | Renaming (identifier obfuscation) | substrate | **Trivial** | Decompiler and LLM infer roles from structure, API use and strings; de4dot renaming covers known protectors | cyber.wtf 2025; de4dot README |
| C3 | String encryption | substrate | **Speed-bump** | de4dot static/delegate/emulation strategies; custom decrypter found by pattern. cyber.wtf: keys hidden behind field values defeat de4dot's generic analysis, but IL-parsing workaround recovers them. | cyber.wtf 2025 |
| C4 | Proxy / delegate call indirection | substrate | **Speed-bump** | "replacing them is pretty much entirely handled by de4dot" (cyber.wtf 2025, on a known pattern) | cyber.wtf 2025 |
| C5 | Control-flow obfuscation (CFF, opaque predicates) | substrate | **Speed-bump** (untested vs LLM) | Deobfuscators exist; one write-up calls ConfuserEx CFF the hardest of those surveyed. Under LLM reading, expected to cost tokens/turns, not block. **Needs measurement.** | ConfuserEx-related write-ups (secondary); no independent benchmark found |
| C6 | Encrypted payload + runtime load (packer / encrypted method bodies) | substrate | **Speed-bump** | Runtime capture: plain module dumped from memory at load (dnSpy "Open Module from Memory", DotDumper). cyber.wtf 2025: "the runtime must eventually hand over the plain assembly." | cyber.wtf 2025 |
| C7 | Anti-tamper (encrypted/integrity-checked code) | substrate + runtime | **Speed-bump** | Dump-after-unpack as above; removing a single integrity check. Vendors claim layered detection; no independent test found. | Dotfuscator blog; cyber.wtf 2025 |
| C8 | Anti-debug / anti-dump | runtime | **Speed-bump** | Patching the check; a write-up claims a general method to bypass CLR anti-dump via internal data (secondary, unverified). dnSpy-MCP flags such checks automatically. The example "dnSpy strips anti-debug" from the brief was **not verified** in any source found. | dnSpy-MCP README; anti-dump write-up (wwh1004, secondary) |
| C9 | Native AOT (ILC) output (ship native PE/ELF/Mach-O, not IL) | **native substrate** | **Meaningful** (vs IL path; not Strong) | Native disassembly; runtime memory dump, because "the runtime-populated section" holds strings, vtable and type info; library-signature matching (WARP) of the runtime from a reference build reached **3,918 of 4,588 functions (>85%)** in one sample. Twente 2026 project explicitly aims to recover type hierarchies. | Cyderes Howler Cell, 17 Mar 2026, https://www.cyderes.com/howler-cell/reverse-engineering-net-aot-malware ; Twente project page, updated 17 Mar 2026, https://www.utwente.nl/en/eemcs/scs/research/running-projects/20260317-automated-analysis-and-reversing-of-net-malware/ ; migeel.sk, Sep 2023 (older, .NET 8 RC1-era) |
| C10 | NativeAOT + native protector / packer / VM on top | native track | **Meaningful** at best | Fold into existing native-track bypass analysis; not re-scored here. | BitMono docs recommend a native protector on top (see below) |
| C11 | Obfuscators compatible with AOT (choose IL-level, AOT-safe transforms only) | build step | **Speed-bump** (inherits C2–C4 limits) | BitMono docs: StringsEncryption + FullRenamer recommended; AntiDecompiler, BitMono-metadata, and runtime-trick transforms "pointless or harmful" under AOT. Community integration; **not Microsoft-supported**. | https://docs.bitmono.dev/en/latest/usage/native-aot.html (accessed 2026-11-14; redirected from bitmono.readthedocs.io; no date on page) |
| C12 | Server-side relocation of secrets/logic | — | **Strong** (the only real one) | None client-side if the server enforces it; the attacker can still replay requests. | CLAUDE.md §3; threat-model.md |
| C13 | ReadyToRun (AOT-precompiled but keeps IL) | — | **Trivial** (do not rely on) | IL remains, so ILSpy still reads it. | Softanics vendor claim (vendor-biased) |

**NativeAOT insight (key finding for the proposal):**
- NativeAOT removes IL and most metadata. Microsoft: "The Native AOT deployment model uses an ahead-of-time compiler to compile IL to native code at the time of publish" and "the app ... contains all the code needed to run in it, including a stripped-down version of the coreclr runtime." Source: https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/ (page updated 2026-11-03, accessed 2026-11-14).
- Microsoft's documentation describes NativeAOT as a performance and deployment feature. It does **not** claim security. Softanics says the same ("side effect, not a design goal"); this is consistent but is vendor-authored.
- The 2023 migeel.sk analysis says none of the .NET RE tools of the prior 20 years work on AOT output. That was true in 2023; the 2026 Cyderes and Twente sources show the tooling gap is closing, and that the industry is actively working on it.
- What survives (2023 analysis, .NET 8 era; treat as possibly stale): version strings and runtime commit hash, exception and accessor names, vtable structure, runtime helpers, unwind data, reflection type names unless reflection is disabled, stack-trace method names unless `StackTraceSupport=false`. Trimming and disabling reflection reduce these.
- Limitations that cost us: no `Assembly.LoadFile`, no `Reflection.Emit`, no C++/CLI, Windows: no built-in COM, trimming-compatibility required. Some .NET libraries are not AOT-annotated. Pick this only for apps that accept these constraints.
- Platform: Windows x64/x86/Arm64, Linux x64/Arm64/Arm, macOS x64/Arm64; iOS/tvOS/MacCatalyst experimental on .NET 8, supported Arm64 on .NET 9+; Android x64/Arm64/Arm, experimental, no Java interop (.NET 9+ table). Source: Microsoft Learn Native AOT page (2026-11-03).

**IL2CPP (Unity) — separate note:**
- IL2CPP converts C# to C++ but still ships `global-metadata.dat`, which carries type/method metadata. Il2CppDumper and Il2CppInspector-family tools recover names from it. Source: vendor pages only (JikGuard, Mar 2026 and Nov 2025 blog posts; treat as marketing). Il2CppDumper's documented workflow: if metadata is encrypted, it must be decrypted first; Zygisk-Il2CppDumper bypasses encryption on rooted Android. Source: https://github.com/perfare/il2cppdumper (accessed 2026-11-14).
- Metadata encryption is a Speed-bump at best with a known workaround. Not researched beyond this.

### 5. Scope notes (for the decision)

- CLAUDE.md §2 currently scopes out "pure-.NET app shells" and calls managed .NET low priority. **Managed IL assemblies are not covered by the native track.** Any managed-IL work is new scope.
- **Native AOT output is in scope** (native ELF/PE/Mach-O). It folds into existing Carapace native work (e.g. Slice P PE harden path, ELF/Mach-O levers). Recommending it does not require the scope change; only the managed-IL hardening does.
- **.NET MAUI and Xamarin on Android** are managed IL inside an APK. CLAUDE.md §2 includes Android APK/AAB (Dalvik/ART + JNI). **Managed .NET on Android falls in the mobile track by construction** and needs a separate decision. BitMono docs say: on MAUI Android the code stays managed IL and uses the normal (IL) flow; on iOS it is AOT-compiled and the app head cannot be obfuscated by BitMono. Source: https://docs.bitmono.dev/en/latest/usage/native-aot.html (accessed 2026-11-14).

### 6. Gaps and cautions

- **Stale tools:** de4dot (archived 2020, no updates, coverage list has no versions) and ConfuserEx (no modern .NET support). Any "de4dot defeats X" claim must be checked against the **current** version of X, which de4dot does not track.
- **Vendor-only evidence:** most of the protection effectiveness claims (Dotfuscator, ArmDot, Eazfuscator, JikGuard, Softanics) are vendor material. No independent benchmark of any .NET protector against current dnSpy/ILSpy plus LLM agents was found.
- **Unverified in this scout pass:** threat.zone ConfuserEx 2 analysis (fetch failed); the claim "dnSpy strips anti-debug" from the brief (not found in any source); ILSpy 11.2 year (page omits year); AsmResolver latest version (conflicting listings).

---

## Decisions needed from operator

1. **Scope decision.** Keep managed-IL assemblies out of scope (current CLAUDE.md §2), or add a managed-IL track for "pure .NET" shells? Recommendation from this scout: **do not add managed-IL protection as a track yet.** Its realistic tiers are Trivial–Speed-bump and the most likely cheap win is to push .NET customers to NativeAOT (native track) instead.
2. **MAUI / Xamarin Android.** Is managed .NET inside an Android APK in scope for the mobile track? If yes, the mobile track needs a .NET-specific subsection.
3. **NativeAOT as a recommendation.** Should the harness recognise NativeAOT output and route it to the native audit (PDB shipped? reflection disabled? stack-trace support off?), without any managed-IL work? This is cheap and in scope.

## Open questions

- **Measure before claiming.** Does a local unrestricted model (same class as the Slice K run, qwen2.5-coder:7b) recover the same logic from ILSpy output of (a) plain IL, (b) renamed + string-encrypted, (c) BitMono/Dotfuscator-protected, (d) NativeAOT-compiled? That is a Slice-K-style experiment and the only way to fill the LLM-tier gap in §3 and §4.
- **Does CFF or proxy obfuscation increase LLM token/turn cost enough to matter?** Unknown; no .NET-specific data found.
- **Does any AI-agent workflow already run de4dot-equivalent deobfuscation autonomously on current protectors?** Not found in this pass. Needs a targeted search.
- **Dotfuscator 7.8.0 release date** and whether Babel/Eazfuscator have .NET 10 support: not established.
- **Is the Twente NativeAOT project publishing results before end 2026?** Project runs Feb–Dec 2026; watch.
- **Does ReadyToRun survive any protector stack?** Only the vendor claim exists; not tested.

## Sources
- ILSpy releases (v11.2, 11.1, 11.0 dates) — https://github.com/icsharpcode/ILSpy/releases — accessed 2026-11-14
- dnSpyEx releases (v6.5.0 stable; v6.6.0-rc1) — https://github.com/dnSpyEx/dnSpy/releases ; https://newreleases.io/project/github/dnSpyEx/dnSpy/release/v6.6.0-rc1 — accessed 2026-11-14
- de4dot repository (archived 17 Oct 2020; 19 supported protectors, no versions; GPLv3) — https://github.com/0xd4d/de4dot — accessed 2026-11-14
- de4dot-cex (archived 8 Dec 2022, secondary aggregator) — https://awesome.ecosyste.ms/projects/github.com%2FViRb3%2Fde4dot-cex — accessed 2026-11-14
- cyber.wtf, ".NET Deobfuscation" (7 Apr 2025, 2026 update note) — https://cyber.wtf/2025/04/07/dotnet-deobfuscation/ — accessed 2026-11-14
- ZeraTS dnSpy-MCP README (no date shown) — https://github.com/ZeraTS/dnSpy-MCP — accessed 2026-11-14
- ILSpy MCP wrappers — https://lobehub.com/mcp/phantomical-ilspymcp ; https://pypi.org/project/ilspy-mcp-server/ ; https://glama.ai/mcp/servers/w8tjhzfwr7 — accessed 2026-11-14 (listing dates vary)
- ConfuserEx (mkaring; no release; .NET Framework 2.0–4.8) — https://github.com/mkaring/ConfuserEx — accessed 2026-11-14
- ConfuserEx forks/successors (support up to .NET FW 4.7.2 / Core 2.2) — https://awesome.ecosyste.ms/projects/github.com%2Fxenocoderce%2Fneo-confuserex — accessed 2026-11-14 (secondary)
- Dotfuscator 7.5.0 / 7.6.0 / 7.7.0 changelog (7.7.0 = 26 May 2026) — https://support.preemptive.com/hc/en-us/articles/31784634997137 — accessed 2026-11-14
- Dotfuscator 7.8.0 blog (undated) — https://www.preemptive.com/blog/dotfuscator-7-8-0/ — accessed 2026-11-14
- Dotfuscator Community for VSC 1.0.0 (8 Jun 2026) — https://support.preemptive.com/hc/en-us/articles/46658909461905-Changelog — accessed 2026-11-14
- .NET Reactor 7.5.0.0 (12 Nov 2025) — https://www.eziriz.com/history.htm — accessed 2026-11-14
- Babel Obfuscator 10.6.0.0 (27 Mar 2024, softpedia changelog) — https://www.softpedia.com/progChangelog/Babel-Obfuscator-Changelog-138865.html — accessed 2026-11-14
- Microsoft Learn, "Native AOT deployment overview" (ms.date 2026-11-03) — https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/ — accessed 2026-11-14
- Softanics, Native AOT vs obfuscation (vendor; ArmDot; undated, copyright 2004–2026) — https://www.softanics.com/net-obfuscation/vs-alternatives/native-aot — accessed 2026-11-14
- BitMono docs, Native AOT (undated; redirected to docs.bitmono.dev) — https://docs.bitmono.dev/en/latest/usage/native-aot.html — accessed 2026-11-14
- Cyderes Howler Cell, reverse engineering NativeAOT malware (17 Mar 2026) — https://www.cyderes.com/howler-cell/reverse-engineering-net-aot-malware — accessed 2026-11-14
- University of Twente, "Automated Analysis and Reversing of .NET Malware" (Feb–Dec 2026; page updated 17 Mar 2026) — https://www.utwente.nl/en/eemcs/scs/research/running-projects/20260317-automated-analysis-and-reversing-of-net-malware/ — accessed 2026-11-14
- migeel.sk, "Reverse engineering natively-compiled .NET apps" (15 Sep 2023; .NET 8 RC1-era) — https://migeel.sk/blog/2023/09/15/reverse-engineering-natively-compiled-dotnet-apps — accessed 2026-11-14 (stale-flagged)
- Il2CppDumper README/docs — https://github.com/perfare/il2cppdumper — accessed 2026-11-14
- JikGuard IL2CPP metadata encryption posts (vendor; Nov 2025, Mar 2026) — https://jikguard.github.io/2025/11/06/How-Games-Counter-IL2CppDumper-Reverse-Engineering ; https://jikguard.github.io/2026/03/05/Unity-Game-Packaging-and-Encryption-Solution — accessed 2026-11-14 (vendor-biased)
- AsmResolver (NuGet; conflicting version listings) — https://www.nuget.org/packages/AsmResolver — accessed 2026-11-14
- arXiv 2505.19887, LLM assembly deobfuscation evaluation (Mar 2025; native, not .NET) — https://arxiv.org/html/2505.19887 — accessed 2026-11-14
- arXiv 2604.08083, BinDeObfBench (2026; native pseudocode, not .NET) — https://arxiv.org/pdf/2604.08083 — accessed 2026-11-14
- DSTA ALFREDO report (agentic LLM + Ghidra, C programs) — https://www.dsta.gov.sg/staticfile/ydsp/projects/files/reports/Report%20-%20ALFREDO_%20Agentic%20LLM-Based%20Framework%20for%20Code%20Deobfuscation.pdf — accessed 2026-11-14

## Review log
- Scout 2026-11-14: research pass complete; no code or CLAUDE.md edits. Evaluator sign-off pending.
