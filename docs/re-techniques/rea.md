# rea (morluto/rea · npm rea-agents) — worked countermeasure analysis
- Category: ai-assisted (P0) — the reference instance for `disasm-mcp` + `agentic-re`
- Phase: deep analysis (feeds implementation). Built on
  `research/findings/2026-10-25-rea-weapons-inventory.md` (facts + citations there).
- Status: draft — needs Evaluator sign-off. Tiers are analysis proposals until a
  test validates them.
- Version pinned: rea 6.8.0 (2026-10-25). Tool names drift fast (4 minor releases
  in 13 days) — re-verify against `tools/list` before trusting any specific verb.

## What it is (one paragraph)
`rea` is an MCP server that turns any coding agent into an autonomous reverse
engineer. It does **not** patch, crack, or keygen — it **understands**: it drives
Ghidra/IDA/Hopper, JADX, Binwalk/Unblob, a PTY capturer, and Frida, then feeds
their output to an LLM with an evidence/coverage ledger so the agent knows when it
has "reconstructed" the target. The only in-process **modification** path is
Frida (caller-authored JS, unrestricted by rea). So defensively we face two jobs:
**(A) raise the cost of understanding** (everything static) and **(B) resist the
one modification path** (Frida) plus the execution-based observation paths.

## The three strategic fronts (how to read the matrix)
1. **Break the substrate** — degrade what Ghidra/JADX/Binwalk hand the agent.
   Classic anti-RE; still the highest-leverage front because rea rides on it.
2. **Break the AI layer** — degrade the *agent's* comprehension/automation.
   ⚠️ Honesty check: rea **pages** large output and keeps an evidence ledger, so
   crude context-flooding is blunted. The viable AI-layer plays are *semantic*
   (valid-but-misleading structure), *coverage-poisoning* (make the
   reconstruction-coverage metric unreachable), and *runtime evidence poisoning*,
   not raw size. Treat all of these as **hypotheses until measured** (see D7/D9).
3. **Relocate** — the only *Strong* tier. What rea can read, it can read; secrets
   and trust decisions that can't leak must live server-side (threat-model §one-law).

---

## Weapon → countermeasure matrix (part by part)
Grouped by the inventory's clusters. "Leverage" = the target requirement the
weapon depends on; deny/degrade it and the weapon weakens. Tiers are **vs rea
specifically**, honest about its paging/no-decrypt/PTY facts.

### Cluster B/C — Native static analysis & format inspectors (ELF/PE/Mach-O)
*Weapons:* `decompile_all`, `procedure_pseudo_code`, `analyze_function`,
call-graph/value-flow, `list_strings`/`list_names`, `inspect_binary_layout`,
`inspect_pe_load_config`, `inspect_byte_entropy`, Go/Rust/PyInstaller inspectors.
*Leverage:* a loadable image whose symbols, strings, and control flow decompile
cleanly; readable build metadata.

| Countermeasure | Tier vs rea | Named bypass | Harness hook |
|---|---|---|---|
| Strip symbols + debug info; flatten/rename to opaque | Meaningful | Pattern/lib signatures (FLIRT-style), the agent reasons from behavior | audit: symbols/debug present? · harden: strip |
| String encryption / on-demand decode | Speed-bump→Meaningful | Runtime key recovery (Frida/mem), decode-at-rest if key embedded | audit: plaintext-string density · harden: encrypt + loader |
| Control-flow flattening + opaque predicates (OLLVM-class) | Meaningful | Agent still summarizes; symbolic deobf (angr) reverses some | audit: CFG complexity baseline · harden: pass |
| Strip Go buildinfo / Rust cargo-auditable / PyInstaller metadata | Speed-bump | Metadata partially reconstructable | audit: metadata present? · harden: strip |
| Set binary hardening flags the agent reads as "hard" (full RELRO, NX, PIE, stack canary, CFG/CET) | Not a blocker (raises effort + our audit parity) | Flags don't stop decompile | audit: read same flags rea's `inspect_*` reads |
| Reduce entropy tells / avoid naive packing signature | Speed-bump | Entropy triage still flags; unpackers exist | audit: section entropy map |

*Note:* `inspect_pe_certificates`/`inspect_apk_signature` **do not verify** signatures
— they only read them. So a signature's defensive value is only in a **runtime
check that reports to a server**, not in its presence on disk.

### Cluster E — Recorded Linux crashes (`inspect_recorded_crash`)
*Leverage:* a core file the attacker obtained; "undumped memory is unknown."

| Countermeasure | Tier vs rea | Named bypass | Harness hook |
|---|---|---|---|
| Suppress core dumps for the shipped process (`setrlimit(RLIMIT_CORE,0)`, `prctl(PR_SET_DUMPABLE,0)`), mark secret regions `madvise(MADV_DONTDUMP)` | Speed-bump | Attacker enables cores on their own host; or reads memory live via Frida/GDB | audit: does binary set these? · harden: emit init-time guard · **good first slice (cheap, testable)** |

### Cluster F — PTY process capture (`capture_process_scenario`)
*Leverage:* a runnable target on Linux/macOS under a PTY; **no ptrace/Frida/LD_PRELOAD**.
So anti-ptrace does **not** fire here — only environment signals do.

| Countermeasure | Tier vs rea | Named bypass | Harness hook |
|---|---|---|---|
| Environment fingerprint: refuse/alter behavior when stdio is an unexpected TTY, parent chain is a Node/REA process, process group is foreign, or input arrives on suspiciously regular timing | Speed-bump | Trivially patched out once found; or run the binary directly outside rea (rea "is not a sandbox") | audit: any env self-checks? · harden: optional probe (low tier, label honestly) |

### Cluster G — Frida instrumentation (priority-1; the only modification path)
*Leverage:* ability to attach/spawn; spawn starts **paused**, scripts load **before resume**; Frida-Linux/Android attach is (per Frida) typically ptrace-based.
*Weapons:* `start_frida_session` (attach/spawn), `load_frida_script` (arbitrary JS, unrestricted by rea).

| Countermeasure | Tier vs rea | Named bypass | Harness hook |
|---|---|---|---|
| Anti-ptrace self-defense: `ptrace(PTRACE_TRACEME)` claim at init; poll `/proc/self/status` TracerPid; detect double-attach | Meaningful (vs attach & GDB) | Frida can hook the check itself; spawn-paused loads a bypass before our code runs | audit: anti-debug present? · harden: ptrace guard |
| Anti-Frida: scan maps for frida-agent/gum, named pipes, default port 27042, thread names; checksum hot functions | Meaningful | Frida stalker/stealth modes; attacker edits signatures | audit: anti-frida present? · harden: detector |
| Runtime code integrity / self-checksum of critical functions, verified **server-side** (attestation) | Meaningful→Strong (server-tied) | Hook the verifier; replay attested value — mitigated if server nonce-challenges | audit: integrity check present? · harden: checksum + attest |
| Defeat spawn-paused bypass: don't rely on a single early check; **continuous + server-nonce attestation** so a one-time hook at resume isn't enough | Meaningful | Sustained hooking; emulation | design rule baked into integrity hook |

### Cluster H — Debuggers (`debug-with-gdb`, Rizin, Cutter; Linux)
*Leverage:* ptrace-level attach. (MI-session status unresolved — open Q3.)

| Countermeasure | Tier vs rea | Named bypass | Harness hook |
|---|---|---|---|
| Same anti-ptrace guard as Cluster G (one control covers both) | Meaningful | Kernel-assisted/stealth debuggers; patch the guard | shared with G |

### Cluster I — Android (JADX/Apktool/JEB + adb)
*Leverage:* decompilable dex; APK pullable from any authorized device; `.so` only listed by path (rea has no native-lib analysis of its own — it reuses Track A tools).
*Weapons:* JADX decompile, signature read, adb pull/install/`force-stop`.

| Countermeasure | Tier vs rea | Named bypass | Harness hook |
|---|---|---|---|
| R8/DexGuard-class dex obfuscation (rename, string/class encryption, reflection) | Meaningful | JADX smali fallback; agent reasons from behavior | audit: dex obf posture · harden: config check |
| **Migrate sensitive logic into native `.so`** (rea lists .so by path only) then harden the .so as Track A | Meaningful | Agent pivots to Ghidra on the .so (Cluster B applies) — so layer B countermeasures there | audit: is logic in dex or native? |
| Runtime signature/pkg-name check reporting to server (not on-device trust) | Speed-bump | Frida hooks the check; attacker re-signs with own key | audit: anti-repackaging present? |
| Root/Frida/debug detection on device | Speed-bump→Meaningful | Magisk DenyList, Frida stealth | audit · harden: detector |
| Assume the APK + all bundled assets are **public** | — (framing) | n/a | drives "relocate" recommendations |

### Cluster J — iOS / Apple bundles
*Leverage:* unencrypted Mach-O/bundle members; rea does **no FairPlay decryption**.

| Countermeasure | Tier vs rea | Named bypass | Harness hook |
|---|---|---|---|
| Keep App Store/FairPlay encryption intact; don't ship a decrypted fat binary | Meaningful vs rea alone | On-device decrypt dump (frida-ios-dump class) on a jailbroken device | audit: encryption/segment posture |
| Obfuscate + move secrets out of `__TEXT`/plists/asset catalogs | Speed-bump→Meaningful | class-dump + agent reasoning | audit: plist/secret surface |

### Cluster D/K — Firmware & network (secondary for us)
*Leverage:* parseable (unencrypted) firmware; a traffic recording. rea does not decrypt firmware and (per packet doc) does not MITM itself.

| Countermeasure | Tier vs rea | Named bypass | Harness hook |
|---|---|---|---|
| Signed + encrypted firmware images | Strong vs rea's extractors | Key recovery from device; agent writes a custom decryptor | audit (if in scope) |
| TLS cert pinning / mTLS so captured traffic is opaque | Meaningful | SSL-pinning bypass via Frida (layer Cluster G defenses) | audit: pinning present? |

### Cluster L — Reconstruction-coverage ledger (the agent's "done" signal)
*Leverage:* rea gives the agent a **measurable stopping condition** (coverage %) and an unknowns ledger.
*Novel AI-layer idea:* make coverage **asymptotically unreachable** — e.g. a large space of reachable-looking-but-inert code paths, or semantics that never resolve to a stable reconstruction — so the agent churns without ever reaching "done." **Unvalidated hypothesis** (open Q9: we don't yet know coverage semantics). Flag as research, tier **Unknown**, do not ship claims.

---

## What becomes the harness (audit-first)
**Audit module (build first — CLAUDE.md "audit before harden"):** a native-binary
exposure scanner that reads the *same* signals rea's inspectors read and scores
them, so our report predicts what the attacker's agent will see:
- symbols/debug info present · string plaintext density · section entropy map ·
  hardening flags (RELRO/NX/PIE/canary/CFG) · Go/Rust/PyInstaller metadata ·
  presence of anti-debug / anti-Frida / integrity / core-dump guards ·
  (Android) dex-vs-native split & obfuscation posture.
Output: a scored, tiered posture report + "next highest-value hardening."

**Hardenings (apply + verify):** strip, string-encrypt, anti-ptrace guard,
anti-Frida detector, server-tied integrity/attestation, core-dump suppression,
(Android) native migration + anti-repackaging.

## Honest limits (state them in the harness output)
- Against a pure *analysis* tool you cannot prevent understanding of a shipped
  artifact — only raise cost. Expect *Speed-bump/Meaningful*, not *Strong*.
- rea's **paging** blunts naive anti-LLM bloat; AI-layer plays must be semantic
  and are **unproven** until we measure them.
- The only *Strong* tier is **server-side relocation** of secrets and trust decisions.
- Frida (a rea capability) can hook most on-device checks, so every client-side
  check's realistic job is *cost + detectability*, backed by server attestation.

## First implementation slice (recommended)
Prove the full pipeline on one weapon end-to-end:
1. **Audit:** ELF exposure scanner (symbols/strings/entropy/hardening-flags + "is a
   core-dump/anti-debug guard present?").
2. **Harden:** core-dump suppression guard **and/or** anti-ptrace guard on a sample
   ELF (both cheap, both directly deny a named rea weapon: Cluster E / Cluster G+H).
3. **Verify:** a test proving (a) the audit detects presence vs absence, and (b) the
   guard actually fires (core dump suppressed / ptrace attach refused).
This exercises Research→Analysis→Implementation→Testing on a real rea weapon.

## Open questions carried from research (need a sandboxed, operator-owned install)
Authoritative `tools/list`; whether rea screens Frida scripts; GDB/MI session
reality in 6.8.0; stripped-binary decompile behavior; `mitmdump` live use;
reconstruction-coverage semantics. (See research note §Open questions Q1–Q9.)

## Review log
- Primary (Opus) 2026-10-25: analysis drafted from the Scout inventory. Tiers are
  proposals; needs an Evaluator pass and, for the AI-layer rows (L, D7/D9),
  empirical validation before any claim ships.
