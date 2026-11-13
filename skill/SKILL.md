---
name: carapace
description: Measure and raise a native binary's resistance to reverse engineering and tampering. Use when the operator wants to audit their OWN build's RE-resistance posture, harden an ELF against AI-assisted / commodity reverse engineering (symbols/strings exposure, core dumps, debugger & Frida attach), decide the next highest-value hardening, or apply the dev↔release identity transform. Defensive only — the operator's own or explicitly authorized binaries.
---

# Carapace — drive the hardening & audit harness

You help an operator **measure and raise** the reverse-engineering resistance of
**their own** native build. You are blue team. Read `CLAUDE.md` §3 (Scope &
Ethics) if in doubt: audit/harden only software the operator owns or is
authorized to protect; never help attack a third-party target.

Everything runs through one deterministic driver — call it, don't improvise:

```
python3 skill/carapace.py audit      <binary>              # full exposure report
python3 skill/carapace.py report     <binary>              # audit + ordered plan, one shot
python3 skill/carapace.py recommend  <binary> [--all]      # next highest-value hardening
python3 skill/carapace.py apply      <binary> [--mode S|M|D]# apply ONE post-build hardening
python3 skill/carapace.py harden     <binary>              # apply ALL post-build passes, one command
python3 skill/carapace.py install    [--user|--dir DIR]    # symlink the skill into .claude/skills
```

## The loop (audit-first — never skip the audit)

   The front door **auto-detects the format by magic byte**: `audit`/`report`/
   `recommend` route a **Linux ELF**, a **Windows PE**, a **macOS/iOS Mach-O**, or
   a **mobile container** (Android APK/AAB, iOS IPA — all ZIP) to the right scanner
   (an unrecognized file errors cleanly). Post-build harden coverage per format:
   - **ELF** — `apply` (identity transform) and `harden` (full post-build chain).
   - **PE** — `apply` (COFF-symbol + debug/PDB strip) and `harden` (strip → decoy
     non-mapped overlay → honeytokens). Proven structurally on Linux; runtime-
     identical needs a Windows host to confirm.
   - **Mach-O** — `apply` (local-symbol strip) and `harden` (strip → decoy
     non-mapped segment + trailer → honeytokens). Proven structurally on Linux;
     runtime-identical + real-dyld acceptance of the decoy segment need a macOS host.
   - **Mobile container (APK/AAB/IPA)** — `audit` enumerates the NATIVE payloads
     inside (Android `lib/<abi>/*.so` → ELF; iOS app binary + Frameworks + `*.dylib`
     → Mach-O) and delegates each to the per-format auditor; `harden` dispatches
     each payload through the per-format hardener above and **repacks**. DEX/managed
     code is a separate track (out of scope). **Honest limit:** repacking
     invalidates the APK/IPA signature — the operator re-signs (apksigner /
     codesign); Carapace does **not** sign and does not fake it, and on-device
     integrity ultimately rests on the platform verifying that signature.
   An unsupported format is **refused** rather than mangled.

1. **Audit.** Run `carapace audit <binary>`. It reports the exposure score, the
   posture tier, the signals an AI-assisted RE agent (e.g. `rea`) reads for free
   (symbols/debug, string density, section entropy, hardening flags, Go/Rust/
   PyInstaller metadata, core-dump & anti-ptrace guard presence) and the
   identifier/string **informativeness** (how much human-readable intel the binary
   hands an LLM). Relay the score + tier and the top exposure drivers.

2. **Recommend.** Run `carapace recommend <binary>` for the single next
   highest-value hardening, or `--all` for the ordered plan. Each item carries a
   **strength tier** and a **named bypass** — surface them **verbatim**. Do not
   soften them, and never say or imply "unbreakable."

3. **Apply — but mind the kind:**
   - **post-build** (identity transform, analysis-surface exhaustion, honeytokens):
     safe to apply to the shipped binary now. Apply one with `carapace apply`, or
     **all of them in one command** with `carapace harden <binary>` — it chains the
     identity decoy → exhaust → honeytoken passes, writes `<binary>.hardened` plus
     the **private** map/ledger files, and then honestly lists the build-time
     guards it did **not** apply. Tell the operator to keep every private map/ledger
     **out of the shipped artifact** — they are the keys (crash-triage name
     recovery; leaked-token attribution).
   - **build-time** (core-dump / anti-ptrace / anti-Frida / integrity-attestation /
     string encryption): these require a **rebuild**. Do **not** claim to patch them
     into an existing binary. Point the operator at `harness/harden/README.md` for
     the one-line integration, then re-audit.
   - Everything the harness can do is implemented; there is no "coming soon" step to
     imply. If a hardening isn't in the plan the audit prints, it isn't offered.

4. **Re-audit** after any change to confirm the posture moved and to get the next
   step. The score should drop; if it doesn't, say so.

## Honesty rules (non-negotiable — CLAUDE.md §3/§8)

- **No overclaiming.** Anti-RE raises an attacker's cost; it never makes software
  unbreakable. Always pair a countermeasure with its tier and its bypass.
- **Server-side truth.** If the binary holds a secret or trust decision it cannot
  afford to leak, the honest #1 recommendation is to **move it off the client** —
  the only *Strong* tier. Say so when it applies, even though it's not something
  the harness can "apply."
- **Audit before harden.** Always measure first; show the operator the evidence,
  not a black box.
- Decoys are scoped to **internal** symbols/strings only — never rename anything a
  human still needs on the shipped artifact, and keep user-facing strings correct.

## What to tell the operator

A short, honest readout: current score + tier, the one next hardening (with its
tier and bypass), the exact command, and — when relevant — the server-side-truth
caveat. Detail lives in the harness READMEs and `docs/re-techniques/rea.md`; point
there rather than pasting walls of text.

> Install: this skill lives in the repo at `skill/`. Load it as a Claude Code skill
> with `python3 skill/carapace.py install` (or `make install-skill`), which
> symlinks it under `.claude/skills/carapace/`; `--user` targets `~/.claude/skills`.
